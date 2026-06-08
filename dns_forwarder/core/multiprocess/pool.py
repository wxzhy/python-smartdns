from __future__ import annotations

import asyncio
import itertools
import os
import threading
from concurrent.futures import Future, ProcessPoolExecutor
from concurrent.futures import wait as wait_futures
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from multiprocessing import get_context
from pathlib import Path
from typing import Any

import dns.message

from dns_forwarder.config import AppConfig
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline import sync_answer_response
from plugins.query_log_plugin import QueryLogPayload

from .ipc import (
    MSG_QUERY,
    MSG_QUERY_LOG,
    MSG_QUERY_RESPONSE,
    MSG_RESOLVE_REQUEST,
    MSG_RESOLVE_RESPONSE,
    MSG_STOP,
    MSG_STOP_READER,
    MSG_WORKER_READY,
    close_queue,
    is_query_log_plugin_enabled,
    put_nowait,
    query_log_max_entries,
    serialize_resolve_error_type,
)
from .shared import SharedTreeResources
from .worker import worker_entry, worker_process_initializer

logger = get_logger("core.multiprocess")


@dataclass(slots=True)
class WorkerHandle:
    worker_id: int
    request_queue: Any
    future: Future[None]
    generation: int


class MultiprocessWorkerPool:
    STOP_TIMEOUT_SECONDS = 3.0

    def __init__(
        self,
        *,
        config_path: Path,
        config: AppConfig,
        resources: SharedTreeResources,
        manager: Any,
    ) -> None:
        self._config_path = config_path
        self._config = config
        self._resources = resources
        self._manager = manager
        self._start_method = config.runtime.multiprocess.resolved_start_method()
        self._mp_context = get_context(self._start_method)
        self._worker_count = config.runtime.multiprocess.resolved_workers()
        self._result_queue: Any | None = None
        self._request_queues: list[Any] = []
        self._executor: ProcessPoolExecutor | None = None
        self._workers: list[WorkerHandle] = []
        self._pending: dict[str, asyncio.Future[bytes | None]] = {}
        self._request_counter = itertools.count(1)
        self._worker_counter = itertools.count()
        self._generation_counter = itertools.count(1)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._reader_thread: threading.Thread | None = None
        self._stop_reader = threading.Event()
        self._supervisor_task: asyncio.Task[None] | None = None
        self._stopping = False
        self._restarting = False

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        logger.info("worker 启动方式 start_method=%s", self._start_method)
        self._create_ipc_resources()
        self._create_executor()
        self._start_workers()
        self._start_result_reader()
        self._supervisor_task = asyncio.create_task(self._supervise_workers())

    async def stop(self) -> None:
        self._stopping = True
        if self._supervisor_task is not None:
            self._supervisor_task.cancel()
            await asyncio.gather(self._supervisor_task, return_exceptions=True)
            self._supervisor_task = None

        for worker in self._workers:
            put_nowait(worker.request_queue, {"type": MSG_STOP})
        await self._stop_executor()

        self._fail_pending(RuntimeError("worker pool stopped"))

        await self._stop_result_reader()
        self._close_ipc_resources()

    def _create_ipc_resources(self) -> None:
        queue_size = self._config.runtime.multiprocess.queue_size
        self._result_queue = self._mp_context.Queue(queue_size)
        self._request_queues = [
            self._mp_context.Queue(queue_size) for _ in range(self._worker_count)
        ]

    def _create_executor(self) -> None:
        if self._result_queue is None:
            raise RuntimeError("result queue 尚未初始化")
        self._executor = ProcessPoolExecutor(
            max_workers=self._worker_count,
            mp_context=self._mp_context,
            initializer=worker_process_initializer,
            initargs=(
                str(self._config_path),
                tuple(self._request_queues),
                self._result_queue,
                self._resources.domain_snapshot,
                self._resources.ip_snapshot,
                is_query_log_plugin_enabled(self._config),
                query_log_max_entries(self._config),
                self._config.runtime.multiprocess.response_timeout,
            ),
        )

    def _start_workers(self) -> None:
        self._workers = [self._start_worker(worker_id) for worker_id in range(self._worker_count)]

    async def _stop_executor(self) -> None:
        executor = self._executor
        if executor is None:
            self._workers.clear()
            return

        futures = [worker.future for worker in self._workers]
        pending: set[Future[None]] = set()
        if futures:
            _, pending = await asyncio.to_thread(
                wait_futures,
                futures,
                timeout=self.STOP_TIMEOUT_SECONDS,
            )

        forced_shutdown = False
        if pending:
            logger.warning("worker 未在超时时间内退出，准备 terminate count=%s", len(pending))
            await asyncio.to_thread(executor.terminate_workers)
            forced_shutdown = True
            _, pending = await asyncio.to_thread(
                wait_futures,
                futures,
                timeout=self.STOP_TIMEOUT_SECONDS,
            )

        if pending:
            logger.warning("worker terminate 后仍未退出，准备 kill count=%s", len(pending))
            await asyncio.to_thread(executor.kill_workers)
            forced_shutdown = True

        if not forced_shutdown:
            await asyncio.to_thread(executor.shutdown, wait=True, cancel_futures=True)

        self._executor = None
        self._workers.clear()

    async def _stop_result_reader(self) -> None:
        self._stop_reader.set()
        if self._result_queue is not None:
            put_nowait(self._result_queue, {"type": MSG_STOP_READER})
        if self._reader_thread is not None:
            await asyncio.to_thread(self._reader_thread.join, self.STOP_TIMEOUT_SECONDS)
            self._reader_thread = None
        self._stop_reader.clear()

    def _close_ipc_resources(self) -> None:
        for item in self._request_queues:
            close_queue(item)
        self._request_queues.clear()
        if self._result_queue is not None:
            close_queue(self._result_queue)
            self._result_queue = None

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
                    "type": MSG_QUERY,
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
                if self._result_queue is None:
                    return
                message = self._result_queue.get()
            except (EOFError, OSError):
                return
            if message.get("type") == MSG_STOP_READER:
                return
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._handle_result, message)

    def _handle_result(self, message: dict[str, Any]) -> None:
        message_type = message.get("type")
        if message_type == MSG_WORKER_READY:
            if self._is_current_worker_message(message):
                logger.info(
                    "worker 已启动 id=%s generation=%s",
                    message["worker_id"],
                    message["generation"],
                )
            return
        if message_type == MSG_QUERY_RESPONSE:
            if not self._is_current_worker_message(message):
                return
            self._handle_query_response(message)
            return
        if message_type == MSG_RESOLVE_REQUEST:
            if not self._is_current_worker_message(message):
                return
            asyncio.create_task(self._handle_resolve_request(message))
            return
        if message_type == MSG_QUERY_LOG:
            if not self._is_current_worker_message(message):
                return
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
            "type": MSG_RESOLVE_RESPONSE,
            "resolve_id": message["resolve_id"],
            "generation": worker.generation,
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
            response["error_type"] = serialize_resolve_error_type(exc)
            response["error"] = str(exc)
        put_nowait(worker.request_queue, response)

    async def _handle_query_log(self, message: dict[str, Any]) -> None:
        store = self._manager.get_query_log_store()
        if store is None:
            return
        payload = QueryLogPayload.model_validate(message["payload"])
        await store.append(payload)

    async def _supervise_workers(self) -> None:
        while True:
            await asyncio.sleep(0.5)
            await self._restart_finished_workers_once()

    async def _restart_finished_workers_once(self) -> None:
        if self._restarting or self._stopping:
            return
        for index, worker in enumerate(tuple(self._workers)):
            if not worker.future.done():
                continue
            try:
                worker.future.result()
            except BrokenProcessPool as exc:
                await self._restart_broken_pool(exc)
                break
            except Exception:
                logger.exception(
                    "worker 任务异常退出，准备重启 id=%s generation=%s",
                    worker.worker_id,
                    worker.generation,
                )
            else:
                logger.warning(
                    "worker 任务已退出，准备重启 id=%s generation=%s",
                    worker.worker_id,
                    worker.generation,
                )
            if self._restarting or self._stopping:
                break
            self._workers[index] = self._start_worker(worker.worker_id)

    def _start_worker(self, worker_id: int) -> WorkerHandle:
        if self._executor is None:
            raise RuntimeError("worker executor 尚未启动")
        request_queue = self._request_queues[worker_id]
        generation = next(self._generation_counter)
        future = self._executor.submit(worker_entry, worker_id, generation)
        logger.info(
            "worker 任务已提交 id=%s generation=%s",
            worker_id,
            generation,
        )
        return WorkerHandle(
            worker_id=worker_id,
            request_queue=request_queue,
            future=future,
            generation=generation,
        )

    def _next_worker(self) -> WorkerHandle:
        if not self._workers:
            raise RuntimeError("worker pool 尚未启动")
        start_index = next(self._worker_counter)
        for offset in range(len(self._workers)):
            worker = self._workers[(start_index + offset) % len(self._workers)]
            if not worker.future.done():
                return worker
        raise RuntimeError("没有可用 worker")

    def _worker_by_id(self, worker_id: int) -> WorkerHandle | None:
        for worker in self._workers:
            if worker.worker_id == worker_id:
                return worker
        return None

    def _is_current_worker_message(self, message: dict[str, Any]) -> bool:
        worker_id = message.get("worker_id")
        generation = message.get("generation")
        if not isinstance(worker_id, int) or not isinstance(generation, int):
            return False
        worker = self._worker_by_id(worker_id)
        return worker is not None and worker.generation == generation

    async def _restart_broken_pool(self, exc: BrokenProcessPool) -> None:
        if self._restarting or self._stopping:
            return
        self._restarting = True
        logger.exception("worker pool 已损坏，准备重建")
        self._fail_pending(RuntimeError(f"worker pool broken: {exc}"))
        try:
            await self._stop_result_reader()
            await self._force_shutdown_executor()
            self._close_ipc_resources()
            self._workers.clear()
            self._create_ipc_resources()
            self._create_executor()
            self._start_workers()
            self._start_result_reader()
        finally:
            self._restarting = False

    async def _force_shutdown_executor(self) -> None:
        executor = self._executor
        if executor is None:
            return
        try:
            await asyncio.to_thread(executor.terminate_workers)
        except Exception:
            logger.exception("terminate worker pool 失败，尝试 kill")
            try:
                await asyncio.to_thread(executor.kill_workers)
            except Exception:
                logger.exception("kill worker pool 失败")
        finally:
            self._executor = None

    def _fail_pending(self, exc: Exception) -> None:
        for future in self._pending.values():
            if not future.done():
                future.set_exception(exc)
        self._pending.clear()
