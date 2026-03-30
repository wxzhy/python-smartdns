from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dns_forwarder.config import AppConfig, ListenerProtocol, load_config
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import PluginManager
from dns_forwarder.resolver import ResolverManager
from dns_forwarder.server import TcpDnsServer, UdpDnsServer
from dns_forwarder.webui import ManagedUvicornServer, create_webui_app


@dataclass(slots=True)
class RuntimeState:
    config: AppConfig
    plugin_manager: PluginManager
    resolver_manager: ResolverManager
    dispatcher_registry: DispatcherRegistry
    pipeline: PipelineEngine


class RuntimeManager:
    def __init__(self, config_path: str | Path = "config.yaml") -> None:
        self.config_path = Path(config_path)
        self._lock = asyncio.Lock()
        self._state: RuntimeState | None = None
        self._listeners: list[UdpDnsServer | TcpDnsServer] = []
        self._webui_server: ManagedUvicornServer | None = None

    @property
    def reload_endpoint(self) -> str:
        if self._state is None:
            return "/admin/reload"
        return self._state.config.webui.reload_endpoint

    async def load(self) -> RuntimeState:
        async with self._lock:
            self._state = await self._build_state()
            return self._state

    async def start(self) -> None:
        async with self._lock:
            if self._state is None:
                self._state = await self._build_state()
            if self._listeners or self._webui_server is not None:
                return
            await self._start_services(self._state.config)

    async def stop(self) -> None:
        async with self._lock:
            if self._webui_server is not None:
                await self._webui_server.stop()
                self._webui_server = None
            for listener in self._listeners:
                await listener.stop()
            self._listeners.clear()

    async def reload(self) -> RuntimeState:
        async with self._lock:
            new_state = await self._build_state()
            if self._state is not None and self._services_started():
                if self._service_signature(self._state.config) != self._service_signature(new_state.config):
                    raise RuntimeError("listener 或 webui 地址变更需要重启进程")
            self._state = new_state
            return new_state

    async def process_query(self, request: Any, client: Any, listener_name: str) -> Any:
        state = self.get_state()
        return await state.pipeline.handle_message(request, client, listener_name)

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
            "reload_endpoint": state.config.webui.reload_endpoint,
            "error": "",
        }

    async def _build_state(self) -> RuntimeState:
        config = load_config(self.config_path)
        plugin_manager = await PluginManager.build(config.plugins, config.runtime.plugin_dirs)
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
        self._listeners = listeners

        if config.webui.enabled:
            app = create_webui_app(self)
            server = ManagedUvicornServer(app, config.webui.host, config.webui.port)
            await server.start()
            self._webui_server = server

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
            config.webui.host,
            config.webui.port,
            config.webui.reload_endpoint,
        )
        return listeners, webui


def install_loop_policy(loop_policy: str) -> None:
    if loop_policy not in {"auto", "winuvloop", "asyncio"}:
        raise ValueError(f"未知 loop_policy: {loop_policy}")
    if loop_policy == "asyncio":
        return
    if loop_policy in {"auto", "winuvloop"}:
        try:
            import winuvloop
        except ImportError:
            if loop_policy == "winuvloop":
                raise
            return
        winuvloop.install()


async def serve(config_path: Path) -> None:
    manager = RuntimeManager(config_path)
    await manager.start()
    try:
        await asyncio.Event().wait()
    finally:
        await manager.stop()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="dns-forwarder skeleton")
    parser.add_argument("--config", default="config.yaml", help="配置文件路径")
    parser.add_argument("command", nargs="?", default="serve", choices=["serve", "check-config"])
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    config_path = Path(args.config)
    config = load_config(config_path)
    install_loop_policy(config.runtime.loop_policy)

    if args.command == "check-config":
        print(
            "config ok:",
            f"listeners={len(config.listeners)}",
            f"upstreams={len(config.upstreams)}",
            f"plugins={len(config.plugins)}",
        )
        return

    try:
        asyncio.run(serve(config_path))
    except KeyboardInterrupt:
        pass
