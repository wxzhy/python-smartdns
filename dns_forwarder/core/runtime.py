from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dns_forwarder.config import AppConfig, ListenerProtocol, load_config
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.logging import configure_logging, get_logger
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import PluginManager
from dns_forwarder.resolver import ResolverManager
from dns_forwarder.server import TcpDnsServer, UdpDnsServer
from dns_forwarder.webui import WEBUI_RELOAD_ENDPOINT, ManagedUvicornServer, create_webui_app
from plugins.query_log_plugin import QUERY_LOG_STORE_KEY, QueryLogStore

from .domainset import DOMAINSET_CONTEXT_KEY, DomainSet
from .ipset import IPSET_CONTEXT_KEY, IPSet

logger = get_logger("core.runtime")


@dataclass(slots=True)
class RuntimeState:
    config: AppConfig
    plugin_manager: PluginManager
    resolver_manager: ResolverManager
    dispatcher_registry: DispatcherRegistry
    pipeline: PipelineEngine


class RuntimeManager:
    def __init__(self, config_path: str | Path = "config.json") -> None:
        self.config_path = Path(config_path)
        self._lock = asyncio.Lock()
        self._state: RuntimeState | None = None
        self._listeners: list[UdpDnsServer | TcpDnsServer] = []
        self._webui_server: ManagedUvicornServer | None = None

    @property
    def reload_endpoint(self) -> str:
        return WEBUI_RELOAD_ENDPOINT

    async def load(self) -> RuntimeState:
        async with self._lock:
            self._state = await self._build_state()
            logger.info("运行时已加载 config=%s", self.config_path)
            return self._state

    async def start(self) -> None:
        async with self._lock:
            if self._state is None:
                self._state = await self._build_state()
            if self._listeners or self._webui_server is not None:
                logger.debug("运行时已启动，忽略重复 start config=%s", self.config_path)
                return
            logger.info("启动运行时 config=%s", self.config_path)
            await self._start_services(self._state.config)

    async def stop(self) -> None:
        async with self._lock:
            logger.info("停止运行时 config=%s", self.config_path)
            if self._webui_server is not None:
                await self._webui_server.stop()
                self._webui_server = None
            for listener in self._listeners:
                await listener.stop()
            self._listeners.clear()

    async def reload(self) -> RuntimeState:
        async with self._lock:
            logger.info("开始 reload config=%s", self.config_path)
            new_state = await self._build_state()
            if self._state is not None and self._services_started():
                if self._service_signature(self._state.config) != self._service_signature(
                    new_state.config
                ):
                    message = "listener 或 webui 地址变更需要重启进程"
                    logger.error("reload 失败 config=%s error=%s", self.config_path, message)
                    raise RuntimeError(message)
            self._state = new_state
            logger.info("reload 完成 config=%s", self.config_path)
            return new_state

    async def process_query(self, request: Any, clientaddr: Any, listener_name: str) -> Any:
        state = self.get_state()
        return await state.pipeline.handle_message(request, clientaddr, listener_name)

    def get_state(self) -> RuntimeState:
        if self._state is None:
            raise RuntimeError("runtime 尚未加载")
        return self._state

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
        if self._state is None:
            return None
        registration = self._state.plugin_manager.registry.context_registry.get(QUERY_LOG_STORE_KEY)
        if registration is None or registration.factory is not None:
            return None
        if not isinstance(registration.value, QueryLogStore):
            return None
        return registration.value

    async def _build_state(self) -> RuntimeState:
        config = load_config(self.config_path)
        configure_logging(config.runtime.log_level)
        logger.info(
            "加载配置完成 config=%s listeners=%s upstreams=%s plugins=%s log_level=%s",
            self.config_path,
            len(config.listeners),
            len(config.upstreams),
            len(config.plugins),
            config.runtime.log_level,
        )
        plugin_manager = await PluginManager.build(
            config.plugins,
            config.runtime.plugin_dirs,
            shared_contexts=self._build_shared_contexts(config),
        )
        resolver_manager = ResolverManager(config, plugin_manager.registry)
        dispatcher_registry = DispatcherRegistry()
        pipeline = PipelineEngine(config, resolver_manager, dispatcher_registry, plugin_manager)
        return RuntimeState(
            config=config,
            plugin_manager=plugin_manager,
            resolver_manager=resolver_manager,
            dispatcher_registry=dispatcher_registry,
            pipeline=pipeline,
        )

    def _build_shared_contexts(self, config: AppConfig) -> dict[str, Any]:
        shared_contexts: dict[str, Any] = {
            DOMAINSET_CONTEXT_KEY: DomainSet(config.tree_root.domain_dir),
            IPSET_CONTEXT_KEY: IPSet(config.tree_root.ip_dir),
        }
        if self._is_query_log_plugin_enabled(config):
            query_log_store = self.get_query_log_store()
            if query_log_store is not None:
                shared_contexts[QUERY_LOG_STORE_KEY] = query_log_store
        return shared_contexts

    async def _start_services(self, config: AppConfig) -> None:
        listeners: list[UdpDnsServer | TcpDnsServer] = []
        for listener in config.listeners:
            if not listener.enabled:
                continue
            if listener.protocol is ListenerProtocol.UDP:
                service = UdpDnsServer(listener, self)
            else:
                service = TcpDnsServer(listener, self)
            await service.start()
            listeners.append(service)
            bound_address = service.bound_address()
            logger.info(
                "listener 已启动 name=%s protocol=%s address=%s:%s",
                listener.name,
                listener.protocol.value,
                bound_address[0] if bound_address else listener.host,
                bound_address[1] if bound_address else listener.port,
            )
        self._listeners = listeners

        if config.webui.enabled or config.webui.doh_enabled:
            app = create_webui_app(self)
            server = ManagedUvicornServer(app, config.webui.host, config.webui.port)
            await server.start()
            self._webui_server = server
            logger.info(
                "http 服务已启动 address=%s:%s webui=%s doh=%s",
                config.webui.host,
                config.webui.port,
                config.webui.enabled,
                config.webui.doh_enabled,
            )

    def _services_started(self) -> bool:
        return bool(self._listeners) or self._webui_server is not None

    @staticmethod
    def _service_signature(config: AppConfig) -> tuple[Any, ...]:
        listeners = tuple(
            (listener.name, listener.protocol.value, listener.host, listener.port, listener.enabled)
            for listener in config.listeners
        )
        webui = (
            config.webui.enabled,
            config.webui.doh_enabled,
            config.webui.host,
            config.webui.port,
        )
        return listeners, webui

    @staticmethod
    def _is_query_log_plugin_enabled(config: AppConfig) -> bool:
        return any(
            plugin.enabled and plugin.module == "query_log_plugin"
            for plugin in config.plugins
        )


def install_loop_policy(loop_policy: str) -> None:
    if loop_policy not in {"auto", "winuvloop", "asyncio"}:
        raise ValueError(f"未知 loop_policy: {loop_policy}")
    if loop_policy == "asyncio":
        logger.info("使用 asyncio 默认事件循环")
        return
    if loop_policy in {"auto", "winuvloop"}:
        try:
            import winuvloop
        except ImportError:
            if loop_policy == "winuvloop":
                logger.error("请求使用 winuvloop，但依赖未安装")
                raise
            logger.info("winuvloop 不可用，回退到 asyncio 默认事件循环")
            return
        winuvloop.install()
        logger.info("已安装 winuvloop 事件循环策略")


async def serve(config_path: Path) -> None:
    manager = RuntimeManager(config_path)
    await manager.start()
    try:
        await asyncio.Event().wait()
    finally:
        await manager.stop()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="dns-forwarder skeleton")
    parser.add_argument("--config", default="config.json", help="配置文件路径")
    parser.add_argument("command", nargs="?", default="serve", choices=["serve", "check-config"])
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    config_path = Path(args.config)

    configure_logging("INFO")
    config = load_config(config_path)
    configure_logging(config.runtime.log_level)
    install_loop_policy(config.runtime.loop_policy)

    if args.command == "check-config":
        logger.info(
            "config ok: listeners=%s upstreams=%s plugins=%s",
            len(config.listeners),
            len(config.upstreams),
            len(config.plugins),
        )
        return

    try:
        asyncio.run(serve(config_path))
    except KeyboardInterrupt:
        logger.info("收到退出信号，服务停止")
