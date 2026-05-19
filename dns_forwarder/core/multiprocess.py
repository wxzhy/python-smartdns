from __future__ import annotations

import asyncio
import itertools
import os
import queue
import shutil
import threading
import uuid
from dataclasses import dataclass
from multiprocessing import get_context, shared_memory
from pathlib import Path
from typing import Any

import dns.message
import dns.rcode
import dns.rdataclass
import dns.resolver

from dns_forwarder.config import AppConfig, ListenerProtocol, load_config
from dns_forwarder.logging import configure_logging, get_logger
from dns_forwarder.pipeline import (
    NestedResolveRecursionError,
    RequestContext,
    build_answer_from_response,
    make_error_response,
    sync_answer_response,
)
from dns_forwarder.server import TcpDnsServer, UdpDnsServer
from dns_forwarder.webui import WEBUI_RELOAD_ENDPOINT, ManagedUvicornServer, create_webui_app
from plugins.query_log_plugin import (
    QUERY_LOG_STORE_KEY,
    QueryLogEntry,
    QueryLogPayload,
    QueryLogStore,
)

from .domainset import DOMAINSET_CONTEXT_KEY, DomainSet, DomainSetSnapshot
from .front_cache import FrontCache
from .ipset import IPSET_CONTEXT_KEY, IPSet, IPSetSnapshot
from .runtime import RuntimeManager, RuntimeState, install_loop_policy

logger = get_logger("core.multiprocess")


@dataclass(frozen=True, slots=True)
class SharedIPSetSnapshot:
    name: str
    size: int


@dataclass(slots=True)
class SharedTreeResources:
    domain_snapshot: DomainSetSnapshot
    ip_snapshot: SharedIPSetSnapshot
    ip_shared_memory: shared_memory.SharedMemory
    temp_dir: Path

    @classmethod
    def build(cls, config: AppConfig, base_dir: Path) -> "SharedTreeResources":
        temp_path = _make_shared_temp_dir(base_dir)
        ip_shared_memory: shared_memory.SharedMemory | None = None

        try:
            domain_snapshot = DomainSet(config.tree_root.domain_dir).save_mmap(
                temp_path / "domainset.marisa"
            )
            ip_payload = IPSet(config.tree_root.ip_dir).to_snapshot().payload
            ip_shared_memory = shared_memory.SharedMemory(create=True, size=len(ip_payload))
            ip_shared_memory.buf[: len(ip_payload)] = ip_payload
        except Exception:
            if ip_shared_memory is not None:
                ip_shared_memory.close()
                try:
                    ip_shared_memory.unlink()
                except FileNotFoundError:
                    pass
            shutil.rmtree(temp_path, ignore_errors=True)
            raise
        return cls(
            domain_snapshot=domain_snapshot,
            ip_snapshot=SharedIPSetSnapshot(
                name=ip_shared_memory.name,
                size=len(ip_payload),
            ),
            ip_shared_memory=ip_shared_memory,
            temp_dir=temp_path,
        )

    def close(self) -> None:
        self.ip_shared_memory.close()
        try:
            self.ip_shared_memory.unlink()
        except FileNotFoundError:
            pass
        shutil.rmtree(self.temp_dir, ignore_errors=True)


@dataclass(slots=True)
class WorkerHandle:
    worker_id: int
    process: Any
    request_queue: Any


class WorkerQueryLogStore(QueryLogStore):
    def __init__(self, max_entries: int, result_queue: Any) -> None:
        super().__init__(max_entries)
        self._result_queue = result_queue

    async def append(self, payload: QueryLogPayload) -> QueryLogEntry:
        try:
            self._result_queue.put_nowait(
                {
                    "type": "query_log",
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
        result_queue: Any,
        response_timeout: float,
    ) -> None:
        self._worker_id = worker_id
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
            "type": "resolve_request",
            "worker_id": self._worker_id,
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
            future.set_exception(_deserialize_resolve_error(error_type, message.get("error", "")))
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
        self._result_queue.put({"type": "worker_ready", "worker_id": self._worker_id})
        try:
            while True:
                message = await asyncio.to_thread(self._request_queue.get)
                message_type = message.get("type")
                if message_type == "stop":
                    break
                if message_type == "resolve_response":
                    self._nested_resolver.receive_response(message)
                    continue
                if message_type == "query":
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
                "type": "query_response",
                "worker_id": self._worker_id,
                "request_id": request_id,
                "wire": response.to_wire() if response is not None else None,
            }
        except Exception as exc:
            response_message = {
                "type": "query_response",
                "worker_id": self._worker_id,
                "request_id": request_id,
                "wire": None,
                "error": f"{type(exc).__name__}: {exc}",
            }
        await asyncio.to_thread(self._result_queue.put, response_message)


class MultiprocessWorkerPool:
    def __init__(
        self,
        *,
        config_path: Path,
        config: AppConfig,
        resources: SharedTreeResources,
        manager: "MultiprocessRuntimeManager",
    ) -> None:
        self._config_path = config_path
        self._config = config
        self._resources = resources
        self._manager = manager
        self._start_method = config.runtime.multiprocess.resolved_start_method()
        self._mp_context = get_context(self._start_method)
        self._result_queue = self._mp_context.Queue(config.runtime.multiprocess.queue_size)
        self._workers: list[WorkerHandle] = []
        self._pending: dict[str, asyncio.Future[bytes | None]] = {}
        self._request_counter = itertools.count(1)
        self._worker_counter = itertools.count()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._reader_thread: threading.Thread | None = None
        self._stop_reader = threading.Event()
        self._supervisor_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        logger.info("worker 启动方式 start_method=%s", self._start_method)
        for worker_id in range(self._config.runtime.multiprocess.resolved_workers()):
            self._workers.append(self._start_worker(worker_id))
        self._start_result_reader()
        self._supervisor_task = asyncio.create_task(self._supervise_workers())

    async def stop(self) -> None:
        if self._supervisor_task is not None:
            self._supervisor_task.cancel()
            await asyncio.gather(self._supervisor_task, return_exceptions=True)
            self._supervisor_task = None

        for worker in self._workers:
            _put_nowait(worker.request_queue, {"type": "stop"})
        for worker in self._workers:
            worker.process.join(timeout=3)
            if worker.process.is_alive():
                worker.process.kill()
                worker.process.join(timeout=3)
            worker.request_queue.close()
            worker.request_queue.join_thread()
        self._workers.clear()

        for future in self._pending.values():
            if not future.done():
                future.set_exception(RuntimeError("worker pool stopped"))
        self._pending.clear()

        self._stop_reader.set()
        _put_nowait(self._result_queue, {"type": "stop_reader"})
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=3)
            self._reader_thread = None
        self._result_queue.close()
        self._result_queue.join_thread()

    async def process_query(
        self,
        request: dns.message.Message,
        clientaddr: Any,
        listener_name: str,
    ) -> dns.message.Message | None:
        request_id = f"{os.getpid()}-{next(self._request_counter)}"
        future: asyncio.Future[bytes | None] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        worker = self._next_worker()
        try:
            worker.request_queue.put_nowait(
                {
                    "type": "query",
                    "request_id": request_id,
                    "wire": request.to_wire(),
                    "clientaddr": clientaddr,
                    "listener_name": listener_name,
                }
            )
            wire = await asyncio.wait_for(
                future,
                timeout=self._config.runtime.multiprocess.response_timeout,
            )
        finally:
            self._pending.pop(request_id, None)
        if wire is None:
            return None
        return dns.message.from_wire(wire)

    def _start_result_reader(self) -> None:
        self._reader_thread = threading.Thread(target=self._read_results, daemon=True)
        self._reader_thread.start()

    def _read_results(self) -> None:
        while not self._stop_reader.is_set():
            try:
                message = self._result_queue.get()
            except (EOFError, OSError):
                return
            if message.get("type") == "stop_reader":
                return
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._handle_result, message)

    def _handle_result(self, message: dict[str, Any]) -> None:
        message_type = message.get("type")
        if message_type == "worker_ready":
            logger.info("worker 已启动 id=%s", message["worker_id"])
            return
        if message_type == "query_response":
            self._handle_query_response(message)
            return
        if message_type == "resolve_request":
            asyncio.create_task(self._handle_resolve_request(message))
            return
        if message_type == "query_log":
            asyncio.create_task(self._handle_query_log(message))

    def _handle_query_response(self, message: dict[str, Any]) -> None:
        future = self._pending.get(message["request_id"])
        if future is None or future.done():
            return
        error = message.get("error")
        if error:
            future.set_exception(RuntimeError(error))
            return
        future.set_result(message.get("wire"))

    async def _handle_resolve_request(self, message: dict[str, Any]) -> None:
        worker = self._worker_by_id(message["worker_id"])
        if worker is None:
            return
        response: dict[str, Any] = {
            "type": "resolve_response",
            "resolve_id": message["resolve_id"],
        }
        try:
            answer = await self._manager.resolve_nested_query(
                qname=message["qname"],
                qtype=message["qtype"],
                clientaddr=message.get("clientaddr"),
                listener_name=message["listener_name"],
                nested_resolve_chain=tuple(tuple(item) for item in message["nested_resolve_chain"]),
            )
            response["wire"] = sync_answer_response(answer).response.to_wire()
        except Exception as exc:
            response["error_type"] = _serialize_resolve_error_type(exc)
            response["error"] = str(exc)
        _put_nowait(worker.request_queue, response)

    async def _handle_query_log(self, message: dict[str, Any]) -> None:
        store = self._manager.get_query_log_store()
        if store is None:
            return
        payload = QueryLogPayload.model_validate(message["payload"])
        await store.append(payload)

    async def _supervise_workers(self) -> None:
        while True:
            await asyncio.sleep(0.5)
            for index, worker in enumerate(tuple(self._workers)):
                if worker.process.is_alive():
                    continue
                logger.warning("worker 已退出，准备重启 id=%s", worker.worker_id)
                worker.process.join(timeout=0)
                worker.request_queue.close()
                worker.request_queue.join_thread()
                replacement = self._start_worker(worker.worker_id)
                self._workers[index] = replacement

    def _start_worker(self, worker_id: int) -> WorkerHandle:
        request_queue = self._mp_context.Queue(self._config.runtime.multiprocess.queue_size)
        process = self._mp_context.Process(
            target=_worker_entry,
            kwargs={
                "worker_id": worker_id,
                "config_path": str(self._config_path),
                "request_queue": request_queue,
                "result_queue": self._result_queue,
                "domain_snapshot": self._resources.domain_snapshot,
                "ip_snapshot": self._resources.ip_snapshot,
                "query_log_enabled": RuntimeManager._is_query_log_plugin_enabled(self._config),
                "query_log_max_entries": _query_log_max_entries(self._config),
                "response_timeout": self._config.runtime.multiprocess.response_timeout,
            },
        )
        process.start()
        logger.info("worker 进程已启动 id=%s pid=%s", worker_id, process.pid)
        return WorkerHandle(worker_id=worker_id, process=process, request_queue=request_queue)

    def _next_worker(self) -> WorkerHandle:
        if not self._workers:
            raise RuntimeError("worker pool 尚未启动")
        start_index = next(self._worker_counter)
        for offset in range(len(self._workers)):
            worker = self._workers[(start_index + offset) % len(self._workers)]
            if worker.process.is_alive():
                return worker
        raise RuntimeError("没有可用 worker")

    def _worker_by_id(self, worker_id: int) -> WorkerHandle | None:
        for worker in self._workers:
            if worker.worker_id == worker_id:
                return worker
        return None


class MultiprocessRuntimeManager:
    def __init__(self, config_path: str | Path = "config.json") -> None:
        self.config_path = Path(config_path)
        self._runtime = RuntimeManager(self.config_path)
        self._lock = asyncio.Lock()
        self._listeners: list[UdpDnsServer | TcpDnsServer] = []
        self._webui_server: ManagedUvicornServer | None = None
        self._worker_pool: MultiprocessWorkerPool | None = None
        self._front_cache: FrontCache | None = None
        self._resources: SharedTreeResources | None = None

    @property
    def reload_endpoint(self) -> str:
        return WEBUI_RELOAD_ENDPOINT

    async def load(self) -> RuntimeState:
        async with self._lock:
            return await self._load_unlocked()

    async def start(self) -> None:
        async with self._lock:
            if self._services_started():
                logger.debug("多进程运行时已启动，忽略重复 start config=%s", self.config_path)
                return
            state = self.get_state_or_none()
            if state is None:
                state = await self._load_unlocked()

            self._resources = SharedTreeResources.build(state.config, self.config_path.parent)
            try:
                self._worker_pool = MultiprocessWorkerPool(
                    config_path=self.config_path,
                    config=state.config,
                    resources=self._resources,
                    manager=self,
                )
                await self._worker_pool.start()
                self._front_cache = FrontCache(state.config.runtime.multiprocess.front_cache_size)
                await self._start_services(state.config)
            except Exception:
                await self._cleanup_started_services()
                raise

    async def stop(self) -> None:
        async with self._lock:
            if self._webui_server is not None:
                await self._webui_server.stop()
                self._webui_server = None
            for listener in self._listeners:
                await listener.stop()
            self._listeners.clear()
            if self._worker_pool is not None:
                await self._worker_pool.stop()
                self._worker_pool = None
            await self._runtime.stop()
            if self._resources is not None:
                self._resources.close()
                self._resources = None
            self._front_cache = None

    async def reload(self) -> RuntimeState:
        async with self._lock:
            old_state = self.get_state()
            new_config = load_config(self.config_path)
            if self._services_started() and RuntimeManager._service_signature(
                old_state.config
            ) != RuntimeManager._service_signature(new_config):
                raise RuntimeError("listener 或 webui 地址变更需要重启进程")

            new_resources = SharedTreeResources.build(new_config, self.config_path.parent)
            new_worker_pool: MultiprocessWorkerPool | None = None
            try:
                new_worker_pool = MultiprocessWorkerPool(
                    config_path=self.config_path,
                    config=new_config,
                    resources=new_resources,
                    manager=self,
                )
                await new_worker_pool.start()
                new_state = await self._runtime.reload()
            except Exception:
                if new_worker_pool is not None:
                    await new_worker_pool.stop()
                new_resources.close()
                raise
            old_worker_pool = self._worker_pool
            old_resources = self._resources
            self._resources = new_resources
            self._worker_pool = new_worker_pool
            self._front_cache = FrontCache(new_state.config.runtime.multiprocess.front_cache_size)
            if old_worker_pool is not None:
                await old_worker_pool.stop()
            if old_resources is not None:
                old_resources.close()
            return new_state

    async def process_query(
        self,
        request: dns.message.Message,
        clientaddr: Any,
        listener_name: str,
    ) -> dns.message.Message | None:
        if self._worker_pool is None or self._front_cache is None:
            raise RuntimeError("多进程运行时尚未启动")

        while True:
            cached = self._front_cache.get_response(request)
            if cached is not None:
                return cached
            pending_key, pending = await self._front_cache.acquire_pending(request)
            if pending is None:
                break
            shared_response = await self._front_cache.wait_for_pending_response(pending, request)
            if shared_response is not None:
                return shared_response

        response: dns.message.Message | None = None
        cache_written = False
        try:
            response = await self._worker_pool.process_query(request, clientaddr, listener_name)
            cache_written = self._front_cache.put_response(request, response)
            return response
        except Exception:
            logger.exception("worker 处理请求失败 request_id=%s", request.id)
            response = make_error_response(request, dns.rcode.SERVFAIL)
            return response
        finally:
            await self._front_cache.complete_pending(
                pending_key,
                response,
                cache_written=cache_written,
            )

    async def resolve_nested_query(
        self,
        *,
        qname: str,
        qtype: str,
        clientaddr: Any,
        listener_name: str,
        nested_resolve_chain: tuple[tuple[str, str], ...],
    ) -> dns.resolver.Answer:
        state = self.get_state()
        return await state.pipeline.resolve_nested_query(
            qname,
            qtype,
            clientaddr,
            listener_name,
            nested_resolve_chain,
        )

    def get_state(self) -> RuntimeState:
        return self._runtime.get_state()

    def get_state_or_none(self) -> RuntimeState | None:
        try:
            return self.get_state()
        except RuntimeError:
            return None

    def get_status(self) -> dict[str, Any]:
        state = self.get_state()
        listeners: list[dict[str, Any]] = []
        for service in self._listeners:
            address = service.bound_address()
            listeners.append(
                {
                    "name": service.listener.name,
                    "protocol": service.listener.protocol.value,
                    "address": f"{address[0]}:{address[1]}" if address else None,
                }
            )
        if not listeners:
            for listener in state.config.listeners:
                listeners.append(
                    {
                        "name": listener.name,
                        "protocol": listener.protocol.value,
                        "address": None,
                    }
                )
        return {
            "title": "dns-forwarder",
            "config_path": str(self.config_path),
            "default_group": state.config.runtime.default_upstream_group,
            "listeners": listeners,
            "upstreams": [item.name for item in state.config.upstreams],
            "groups": [item.name for item in state.config.groups],
            "rules": [item.name for item in state.config.rules],
            "plugins": state.plugin_manager.describe(),
            "reload_endpoint": self.reload_endpoint,
            "error": "",
        }

    def get_query_log_store(self) -> QueryLogStore | None:
        return self._runtime.get_query_log_store()

    def is_query_log_plugin_enabled(self) -> bool:
        return RuntimeManager._is_query_log_plugin_enabled(self.get_state().config)

    def query_log_max_entries(self) -> int:
        return _query_log_max_entries(self.get_state().config)

    async def _load_unlocked(self) -> RuntimeState:
        state = await self._runtime.load()
        logger.info(
            "多进程运行时已加载 config=%s workers=%s",
            self.config_path,
            state.config.runtime.multiprocess.resolved_workers(),
        )
        return state

    async def _start_services(self, config: AppConfig) -> None:
        listeners: list[UdpDnsServer | TcpDnsServer] = []
        for listener in config.listeners:
            if not listener.enabled:
                continue
            service = (
                UdpDnsServer(listener, self)
                if listener.protocol is ListenerProtocol.UDP
                else TcpDnsServer(listener, self)
            )
            await service.start()
            listeners.append(service)
            bound_address = service.bound_address()
            logger.info(
                "master listener 已启动 name=%s protocol=%s address=%s:%s",
                listener.name,
                listener.protocol.value,
                bound_address[0] if bound_address else listener.host,
                bound_address[1] if bound_address else listener.port,
            )
        self._listeners = listeners

        if config.webui.enabled or config.webui.doh_enabled:
            server = ManagedUvicornServer(
                create_webui_app(self),
                config.webui.host,
                config.webui.port,
            )
            await server.start()
            self._webui_server = server

    def _services_started(self) -> bool:
        return bool(self._listeners) or self._webui_server is not None

    async def _cleanup_started_services(self) -> None:
        if self._webui_server is not None:
            await self._webui_server.stop()
            self._webui_server = None
        for listener in self._listeners:
            await listener.stop()
        self._listeners.clear()
        if self._worker_pool is not None:
            await self._worker_pool.stop()
            self._worker_pool = None
        if self._resources is not None:
            self._resources.close()
            self._resources = None
        self._front_cache = None


def _worker_entry(
    *,
    worker_id: int,
    config_path: str,
    request_queue: Any,
    result_queue: Any,
    domain_snapshot: DomainSetSnapshot,
    ip_snapshot: SharedIPSetSnapshot,
    query_log_enabled: bool,
    query_log_max_entries: int,
    response_timeout: float,
) -> None:
    config_file = Path(config_path)
    configure_logging("INFO")
    config = load_config(config_file)
    configure_logging(config.runtime.log_level)
    install_loop_policy(config.runtime.loop_policy)
    runtime = WorkerRuntime(
        worker_id=worker_id,
        config_path=config_file,
        request_queue=request_queue,
        result_queue=result_queue,
        domain_snapshot=domain_snapshot,
        ip_snapshot=ip_snapshot,
        query_log_enabled=query_log_enabled,
        query_log_max_entries=query_log_max_entries,
        response_timeout=response_timeout,
    )
    asyncio.run(runtime.run())


def _put_nowait(target_queue: Any, message: dict[str, Any]) -> None:
    try:
        target_queue.put_nowait(message)
    except queue.Full:
        pass


def _make_shared_temp_dir(base_dir: Path) -> Path:
    candidates = (base_dir, Path.cwd())
    for parent in candidates:
        try:
            parent.mkdir(parents=True, exist_ok=True)
            temp_path = parent / f"python-smartdns-{uuid.uuid4().hex}"
            temp_path.mkdir()
            return temp_path
        except OSError:
            continue
    raise RuntimeError("无法创建共享数据临时目录")


def _query_log_max_entries(config: AppConfig) -> int:
    for plugin in config.plugins:
        if plugin.enabled and plugin.module == "query_log_plugin":
            value = plugin.config.get("max_entries", 500)
            return int(value)
    return 500


def _serialize_resolve_error_type(exc: Exception) -> str:
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "NXDOMAIN"
    if isinstance(exc, NestedResolveRecursionError):
        return "NestedResolveRecursionError"
    return type(exc).__name__


def _deserialize_resolve_error(error_type: str, message: str) -> Exception:
    if error_type == "NXDOMAIN":
        return dns.resolver.NXDOMAIN()
    if error_type == "NestedResolveRecursionError":
        return NestedResolveRecursionError(message)
    return RuntimeError(message or error_type)
