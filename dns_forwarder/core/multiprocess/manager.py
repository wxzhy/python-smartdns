from __future__ import annotations

from pathlib import Path
from typing import Any
import anyio

import dns.message
import dns.rcode
import dns.resolver

from dns_forwarder.config import AppConfig, load_config
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline import make_error_response
from dns_forwarder.webui import WEBUI_RELOAD_ENDPOINT, ManagedUvicornServer, create_webui_app
from plugins.query_log_plugin import QueryLogStore

from ..front_cache import FrontCache
from ..runtime import RuntimeManager, RuntimeState
from ..services import DnsServer, build_listener_status, start_dns_listeners, stop_dns_listeners
from .ipc import query_log_max_entries
from .pool import MultiprocessWorkerPool
from .shared import SharedTreeResources

logger = get_logger("core.multiprocess")


class MultiprocessRuntimeManager:
    def __init__(self, config_path: str | Path = "config.json") -> None:
        self.config_path = Path(config_path)
        self._runtime = RuntimeManager(self.config_path)
        self._lock = anyio.Lock()
        self._listeners: list[DnsServer] = []
        self._webui_server: ManagedUvicornServer | None = None
        self._worker_pool: MultiprocessWorkerPool | None = None
        self._front_cache: FrontCache | None = None
        self._resources: SharedTreeResources | None = None
        self._tg_context: anyio.abc.TaskGroup | None = None
        self._tg: anyio.abc.TaskGroup | None = None

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

            self._tg_context = anyio.create_task_group()
            self._tg = await self._tg_context.__aenter__()

            self._resources = SharedTreeResources.build(state.config, self.config_path.parent)
            try:
                self._worker_pool = MultiprocessWorkerPool(
                    config_path=self.config_path,
                    config=state.config,
                    resources=self._resources,
                    manager=self,
                )
                await self._worker_pool.start(self._tg)
                self._front_cache = FrontCache(state.config.runtime.multiprocess.front_cache_size)
                await self._start_services(state.config, self._tg)
            except Exception:
                await self._cleanup_started_services()
                raise

    async def stop(self) -> None:
        async with self._lock:
            if self._webui_server is not None:
                await self._webui_server.stop()
                self._webui_server = None
            await stop_dns_listeners(self._listeners)
            if self._worker_pool is not None:
                await self._worker_pool.stop()
                self._worker_pool = None
            await self._runtime.stop()
            if self._resources is not None:
                self._resources.close()
                self._resources = None
            self._front_cache = None

            if self._tg_context is not None:
                await self._tg_context.__aexit__(None, None, None)
                self._tg_context = None
                self._tg = None

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
                if self._tg is not None:
                    await new_worker_pool.start(self._tg)
                else:
                    # 容错：如果 start 还未被调用或 tg 丢失，则由自己开启
                    raise RuntimeError("运行时暂未处于 start 状态")
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
        return {
            "title": "dns-forwarder",
            "config_path": str(self.config_path),
            "default_group": state.config.runtime.default_upstream_group,
            "listeners": build_listener_status(self._listeners, state.config.listeners),
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
        return query_log_max_entries(self.get_state().config)

    async def _load_unlocked(self) -> RuntimeState:
        state = await self._runtime.load()
        logger.info(
            "多进程运行时已加载 config=%s workers=%s",
            self.config_path,
            state.config.runtime.multiprocess.resolved_workers(),
        )
        return state

    async def _start_services(self, config: AppConfig, tg: anyio.abc.TaskGroup) -> None:
        self._listeners = await start_dns_listeners(
            config.listeners,
            self,
            tg,
            logger=logger,
            log_prefix="master listener 已启动",
        )

        if config.webui.enabled or config.webui.doh_enabled:
            server = ManagedUvicornServer(
                create_webui_app(self),
                config.webui.host,
                config.webui.port,
            )
            await server.start(tg)
            self._webui_server = server

    def _services_started(self) -> bool:
        return bool(self._listeners) or self._webui_server is not None

    async def _cleanup_started_services(self) -> None:
        if self._webui_server is not None:
            await self._webui_server.stop()
            self._webui_server = None
        await stop_dns_listeners(self._listeners)
        if self._worker_pool is not None:
            await self._worker_pool.stop()
            self._worker_pool = None
        if self._resources is not None:
            self._resources.close()
            self._resources = None
        self._front_cache = None

        if self._tg_context is not None:
            await self._tg_context.__aexit__(None, None, None)
            self._tg_context = None
            self._tg = None
