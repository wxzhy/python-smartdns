from __future__ import annotations

import asyncio
import queue
import uuid
from dataclasses import dataclass
from multiprocessing import shared_memory
from pathlib import Path
from typing import Any

import dns.message
import dns.rdataclass
import dns.resolver

from dns_forwarder.config import load_config
from dns_forwarder.logging import configure_logging
from dns_forwarder.pipeline import (
    NestedResolveRecursionError,
    RequestContext,
    build_answer_from_response,
)
from plugins.query_log_plugin import (
    QUERY_LOG_STORE_KEY,
    QueryLogEntry,
    QueryLogPayload,
    QueryLogStore,
)

from ..domainset import DOMAINSET_CONTEXT_KEY, DomainSet, DomainSetSnapshot
from ..ipset import IPSET_CONTEXT_KEY, IPSet, IPSetSnapshot
from ..runtime import RuntimeManager, install_loop_policy
from .ipc import (
    MSG_QUERY,
    MSG_QUERY_LOG,
    MSG_QUERY_RESPONSE,
    MSG_RESOLVE_REQUEST,
    MSG_RESOLVE_RESPONSE,
    MSG_STOP,
    MSG_WORKER_READY,
    deserialize_resolve_error,
)
from .shared import SharedIPSetSnapshot


@dataclass(frozen=True, slots=True)
class WorkerProcessState:
    config_path: str
    request_queues: tuple[Any, ...]
    result_queue: Any
    domain_snapshot: DomainSetSnapshot
    ip_snapshot: SharedIPSetSnapshot
    query_log_enabled: bool
    query_log_max_entries: int
    response_timeout: float


_WORKER_PROCESS_STATE: WorkerProcessState | None = None


class WorkerQueryLogStore(QueryLogStore):
    def __init__(
        self,
        max_entries: int,
        result_queue: Any,
        *,
        worker_id: int,
        generation: int,
    ) -> None:
        super().__init__(max_entries)
        self._result_queue = result_queue
        self._worker_id = worker_id
        self._generation = generation

    async def append(self, payload: QueryLogPayload) -> QueryLogEntry:
        try:
            self._result_queue.put_nowait(
                {
                    "type": MSG_QUERY_LOG,
                    "worker_id": self._worker_id,
                    "generation": self._generation,
                    "payload": payload.model_dump(mode="json"),
                }
            )
        except queue.Full:
            pass
        return QueryLogEntry(id=0, **payload.model_dump())


class WorkerNestedResolver:
    def __init__(
        self,
        *,
        worker_id: int,
        generation: int,
        result_queue: Any,
        response_timeout: float,
    ) -> None:
        self._worker_id = worker_id
        self._generation = generation
        self._result_queue = result_queue
        self._response_timeout = response_timeout
        self._pending: dict[str, tuple[asyncio.Future[bytes], dns.message.Message]] = {}

    async def resolve(
        self,
        context: RequestContext,
        qname: str,
        qtype: str,
    ) -> dns.resolver.Answer:
        signature = (qname, qtype)
        if signature in context._nested_resolve_chain:
            raise NestedResolveRecursionError(f"检测到内部解析递归 qname={qname} qtype={qtype}")
        if len(context._nested_resolve_chain) >= context._nested_resolve_max_depth:
            raise NestedResolveRecursionError(
                f"内部解析超过最大递归深度({context._nested_resolve_max_depth})"
            )

        resolve_id = uuid.uuid4().hex
        nested_request = dns.message.make_query(qname, qtype, rdclass=dns.rdataclass.IN)
        future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        self._pending[resolve_id] = future, nested_request
        request_message = {
            "type": MSG_RESOLVE_REQUEST,
            "worker_id": self._worker_id,
            "generation": self._generation,
            "resolve_id": resolve_id,
            "qname": qname,
            "qtype": qtype,
            "clientaddr": context.clientaddr,
            "listener_name": context.listener_name,
            "nested_resolve_chain": context._nested_resolve_chain + (signature,),
        }
        try:
            await asyncio.to_thread(self._result_queue.put, request_message)
            wire = await asyncio.wait_for(future, timeout=self._response_timeout)
        finally:
            self._pending.pop(resolve_id, None)
        return build_answer_from_response(nested_request, dns.message.from_wire(wire))

    def receive_response(self, message: dict[str, Any]) -> None:
        pending = self._pending.get(message["resolve_id"])
        if pending is None:
            return
        future, _ = pending
        if future.done():
            return

        error_type = message.get("error_type")
        if error_type:
            future.set_exception(deserialize_resolve_error(error_type, message.get("error", "")))
            return

        wire = message.get("wire")
        if isinstance(wire, bytes):
            future.set_result(wire)
        else:
            future.set_exception(RuntimeError("内部解析未返回响应"))


class WorkerRuntime:
    def __init__(
        self,
        *,
        worker_id: int,
        generation: int,
        config_path: Path,
        request_queue: Any,
        result_queue: Any,
        domain_snapshot: DomainSetSnapshot,
        ip_snapshot: SharedIPSetSnapshot,
        query_log_enabled: bool,
        query_log_max_entries: int,
        response_timeout: float,
    ) -> None:
        self._worker_id = worker_id
        self._generation = generation
        self._config_path = config_path
        self._request_queue = request_queue
        self._result_queue = result_queue
        self._domain_snapshot = domain_snapshot
        self._ip_snapshot = ip_snapshot
        self._query_log_enabled = query_log_enabled
        self._query_log_max_entries = query_log_max_entries
        self._response_timeout = response_timeout
        self._tasks: set[asyncio.Task[None]] = set()
        self._nested_resolver = WorkerNestedResolver(
            worker_id=worker_id,
            generation=generation,
            result_queue=result_queue,
            response_timeout=response_timeout,
        )

    async def run(self) -> None:
        manager = RuntimeManager(
            self._config_path,
            shared_contexts=self._build_shared_contexts(),
            nested_resolve_handler=self._nested_resolver.resolve,
        )
        await manager.load()
        self._result_queue.put(
            {
                "type": MSG_WORKER_READY,
                "worker_id": self._worker_id,
                "generation": self._generation,
            }
        )
        try:
            while True:
                message = await asyncio.to_thread(self._request_queue.get)
                message_type = message.get("type")
                if message_type == MSG_STOP:
                    break
                if message_type == MSG_RESOLVE_RESPONSE:
                    self._nested_resolver.receive_response(message)
                    continue
                if message_type == MSG_QUERY:
                    task = asyncio.create_task(self._handle_query(manager, message))
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
        finally:
            for task in self._tasks:
                task.cancel()
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)
            await manager.stop()

    def _build_shared_contexts(self) -> dict[str, Any]:
        shared_contexts: dict[str, Any] = {
            DOMAINSET_CONTEXT_KEY: DomainSet.from_snapshot(self._domain_snapshot),
            IPSET_CONTEXT_KEY: self._load_ipset_snapshot(),
        }
        if self._query_log_enabled:
            shared_contexts[QUERY_LOG_STORE_KEY] = WorkerQueryLogStore(
                self._query_log_max_entries,
                self._result_queue,
                worker_id=self._worker_id,
                generation=self._generation,
            )
        return shared_contexts

    def _load_ipset_snapshot(self) -> IPSet:
        ip_shared_memory = shared_memory.SharedMemory(name=self._ip_snapshot.name)
        try:
            payload = bytes(ip_shared_memory.buf[: self._ip_snapshot.size])
        finally:
            ip_shared_memory.close()
        return IPSet.from_snapshot(IPSetSnapshot(payload=payload))

    async def _handle_query(self, manager: RuntimeManager, message: dict[str, Any]) -> None:
        request_id = message["request_id"]
        try:
            request = dns.message.from_wire(message["wire"])
            response = await manager.process_query(
                request,
                message.get("clientaddr"),
                message["listener_name"],
            )
            response_message = {
                "type": MSG_QUERY_RESPONSE,
                "worker_id": self._worker_id,
                "generation": self._generation,
                "request_id": request_id,
                "wire": response.to_wire() if response is not None else None,
            }
        except Exception as exc:
            response_message = {
                "type": MSG_QUERY_RESPONSE,
                "worker_id": self._worker_id,
                "generation": self._generation,
                "request_id": request_id,
                "wire": None,
                "error": f"{type(exc).__name__}: {exc}",
            }
        await asyncio.to_thread(self._result_queue.put, response_message)


def worker_process_initializer(
    config_path: str,
    request_queues: tuple[Any, ...],
    result_queue: Any,
    domain_snapshot: DomainSetSnapshot,
    ip_snapshot: SharedIPSetSnapshot,
    query_log_enabled: bool,
    query_log_max_entries: int,
    response_timeout: float,
) -> None:
    global _WORKER_PROCESS_STATE
    _WORKER_PROCESS_STATE = WorkerProcessState(
        config_path=config_path,
        request_queues=request_queues,
        result_queue=result_queue,
        domain_snapshot=domain_snapshot,
        ip_snapshot=ip_snapshot,
        query_log_enabled=query_log_enabled,
        query_log_max_entries=query_log_max_entries,
        response_timeout=response_timeout,
    )


def worker_entry(worker_id: int, generation: int) -> None:
    if _WORKER_PROCESS_STATE is None:
        raise RuntimeError("worker process state 未初始化")

    state = _WORKER_PROCESS_STATE
    config_file = Path(state.config_path)
    configure_logging("INFO")
    config = load_config(config_file)
    configure_logging(config.runtime.log_level)
    install_loop_policy(config.runtime.loop_policy)
    runtime = WorkerRuntime(
        worker_id=worker_id,
        generation=generation,
        config_path=config_file,
        request_queue=state.request_queues[worker_id],
        result_queue=state.result_queue,
        domain_snapshot=state.domain_snapshot,
        ip_snapshot=state.ip_snapshot,
        query_log_enabled=state.query_log_enabled,
        query_log_max_entries=state.query_log_max_entries,
        response_timeout=state.response_timeout,
    )
    asyncio.run(runtime.run())
