from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

import anyio.to_thread

from dns_forwarder.config import AppConfig, ListenerProtocol, load_config
from dns_forwarder.logging import configure_logging, get_logger
from dns_forwarder.server import TcpDnsServer, UdpDnsServer
from dns_forwarder.webui import WEBUI_RELOAD_ENDPOINT, ManagedUvicornServer, create_webui_app
from plugins.query_log_plugin import QUERY_LOG_STORE_KEY, QueryLogStore

from .domainset import DOMAINSET_CONTEXT_KEY, DomainSet
from .ipset import IPSET_CONTEXT_KEY, IPSet
from .worker import PortalWorker, RuntimeState, build_runtime_state

logger = get_logger("core.runtime")


def _format_address(address: tuple[str, int] | None) -> str | None:
    """将 ``(host, port)`` 形式的地址格式化为 ``host:port``，无地址时返回 None。"""
    return f"{address[0]}:{address[1]}" if address else None


class RuntimeManager:
    def __init__(self, config_path: str | Path = "config.json") -> None:
        self.config_path = Path(config_path)
        self._lock = asyncio.Lock()
        self._state: RuntimeState | None = None
        self._workers: list[PortalWorker] = []
        self._next_worker_index = 0
        self._listeners: list[UdpDnsServer | TcpDnsServer] = []
        self._webui_server: ManagedUvicornServer | None = None

    @property
    def reload_endpoint(self) -> str:
        return WEBUI_RELOAD_ENDPOINT

    async def load(self) -> RuntimeState:
        async with self._lock:
            config = load_config(self.config_path)
            configure_logging(config.runtime.log_level)
            self._state = await self._build_worker_state(config)
            logger.info("运行时已加载 config=%s", self.config_path)
            return self._state

    async def start(self) -> None:
        async with self._lock:
            if self._state is None:
                config = load_config(self.config_path)
                configure_logging(config.runtime.log_level)
            else:
                config = self._state.config
            if self._workers or self._listeners or self._webui_server is not None:
                logger.debug("运行时已启动，忽略重复 start config=%s", self.config_path)
                return
            logger.info(
                "启动运行时 config=%s workers=%s", self.config_path, config.runtime.workers
            )
            await self._start_workers(config)
            await self._start_services(config)

    async def stop(self) -> None:
        async with self._lock:
            logger.info("停止运行时 config=%s", self.config_path)
            if self._webui_server is not None:
                await self._webui_server.stop()
                self._webui_server = None
            for listener in self._listeners:
                await listener.stop()
            self._listeners.clear()
            await self._stop_workers()

    async def reload(self) -> RuntimeState:
        async with self._lock:
            logger.info("开始 reload config=%s", self.config_path)
            config = load_config(self.config_path)
            configure_logging(config.runtime.log_level)
            self._log_config_loaded(config)
            if (
                self._state is not None
                and self._services_started()
                and self._service_signature(self._state.config)
                != self._service_signature(config)
            ):
                message = "listener 或 webui 地址变更需要重启进程"
                logger.error("reload 失败 config=%s error=%s", self.config_path, message)
                raise RuntimeError(message)
            if self._workers:
                shared_contexts = self._build_shared_contexts(config)
                # 预检：先在主侧临时 portal 完整构建一次新状态，确认配置可行；
                # 失败则抛异常且所有 worker 保持旧配置，避免半新半旧。
                preflight_state = await anyio.to_thread.run_sync(
                    self._build_preflight_state, shared_contexts
                )
                del preflight_state  # 预检状态仅用于验证可构建性，随即丢弃
                # 串行重建各 worker 状态，避免并发读取同一域名集/IP集文件。
                new_states: list[RuntimeState] = []
                try:
                    for worker in self._workers:
                        new_states.append(
                            await anyio.to_thread.run_sync(worker.reload, shared_contexts)
                        )
                except BaseException:
                    # 预检已通过但仍失败（极少见，如文件在预检后被改坏）：
                    # 保持 self._state 指向切换前的状态，避免对外暴露混合配置。
                    logger.exception("reload 中途失败，保持原 state config=%s", self.config_path)
                    raise
                # 全部 worker 切换完成后才更新主侧状态（webui 读取用）。
                self._state = new_states[0]
            else:
                self._state = await self._build_worker_state(config)
            logger.info("reload 完成 config=%s", self.config_path)
            return self._state

    async def process_query(self, request: Any, clientaddr: Any, listener_name: str) -> Any:
        if self._workers:
            worker = self._pick_worker()
            # BlockingPortal.call 是阻塞调用且要求 anyio worker 线程，
            # 必须经 anyio.to_thread 转发，不能直接在主 loop 内调用。
            return await anyio.to_thread.run_sync(
                worker.process_query_blocking, request, clientaddr, listener_name
            )
        state = self.get_state()
        return await state.pipeline.handle_message(request, clientaddr, listener_name)

    def get_state(self) -> RuntimeState:
        if self._state is None:
            raise RuntimeError("runtime 尚未加载")
        return self._state

    def get_status(self) -> dict[str, Any]:
        state = self.get_state()
        # 优先返回已绑定监听器的实际地址；若服务尚未启动则回退到配置项。
        listener_rows: list[dict[str, Any]] = [
            {
                "name": service.listener.name,
                "protocol": service.listener.protocol.value,
                "address": _format_address(service.bound_address()),
            }
            for service in self._listeners
        ]
        if not listener_rows:
            listener_rows = [
                {
                    "name": listener.name,
                    "protocol": listener.protocol.value,
                    "address": None,
                }
                for listener in state.config.listeners
            ]
        return {
            "title": "dns-forwarder",
            "config_path": str(self.config_path),
            "default_group": state.config.runtime.default_upstream_group,
            "listeners": listener_rows,
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

    async def _start_workers(self, config: AppConfig) -> None:
        shared_contexts = self._build_shared_contexts(config)
        workers = [
            PortalWorker(index, self.config_path, shared_contexts)
            for index in range(config.runtime.workers)
        ]
        try:
            # 逐个启动并等待各自完成初始化，保证先初始化后收包。
            for worker in workers:
                await anyio.to_thread.run_sync(worker.start)
        except BaseException:
            for worker in workers:
                await anyio.to_thread.run_sync(worker.stop)
            raise
        self._workers = workers
        self._next_worker_index = 0
        self._state = workers[0].state
        logger.info("worker 已全部启动 count=%s", len(workers))

    async def _stop_workers(self) -> None:
        workers, self._workers = self._workers, []
        self._state = None
        for worker in workers:
            await anyio.to_thread.run_sync(worker.stop)

    def _pick_worker(self) -> PortalWorker:
        worker = self._workers[self._next_worker_index % len(self._workers)]
        self._next_worker_index += 1
        return worker

    async def _build_worker_state(self, config: AppConfig) -> RuntimeState:
        """构建一份主侧 RuntimeState（仅在 worker 尚未启动的 load 阶段使用）。"""
        return await build_runtime_state(self.config_path, self._build_shared_contexts(config))

    def _build_preflight_state(self, shared_contexts: dict[str, Any]) -> RuntimeState:
        """在临时 blocking portal 中构建一次新 RuntimeState 以预检配置（同步，供 to_thread 调用）。

        构建过程中若创建了按 loop 缓存的共享 nameserver 会话，在 portal 退出前
        于同一 loop 内关闭，避免泄漏。
        """
        from anyio.from_thread import start_blocking_portal

        from dns_forwarder.resolver.nameservers import close_shared_sessions

        with start_blocking_portal(backend="asyncio") as portal:
            try:
                return portal.call(build_runtime_state, self.config_path, shared_contexts)
            finally:
                try:
                    portal.call(close_shared_sessions)
                except Exception:
                    logger.exception("reload 预检会话清理失败")

    def _log_config_loaded(self, config: AppConfig) -> None:
        logger.info(
            "加载配置完成 config=%s listeners=%s upstreams=%s plugins=%s log_level=%s",
            self.config_path,
            len(config.listeners),
            len(config.upstreams),
            len(config.plugins),
            config.runtime.log_level,
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
        return listeners, webui, config.runtime.workers

    @staticmethod
    def _is_query_log_plugin_enabled(config: AppConfig) -> bool:
        return any(
            plugin.enabled and plugin.module == "query_log_plugin" for plugin in config.plugins
        )


def install_loop_policy(loop_policy: str) -> None:
    """根据配置安装事件循环策略（asyncio / winuvloop，auto 时按可用性回退）。"""
    if loop_policy not in {"auto", "winuvloop", "asyncio"}:
        raise ValueError(f"未知 loop_policy: {loop_policy}")
    if loop_policy == "asyncio":
        logger.info("使用 asyncio 默认事件循环")
        return
    if loop_policy in {"auto", "winuvloop"}:
        try:
            import winuvloop  # noqa: PLC0415 - optional dependency, imported lazily
        except ImportError:
            if loop_policy == "winuvloop":
                logger.error("请求使用 winuvloop，但依赖未安装")
                raise
            logger.info("winuvloop 不可用，回退到 asyncio 默认事件循环")
            return
        winuvloop.install()
        logger.info("已安装 winuvloop 事件循环策略")


async def serve(config_path: Path) -> None:
    """启动运行时服务并阻塞直至收到中断信号，随后优雅停止。"""
    manager = RuntimeManager(config_path)
    await manager.start()
    try:
        await asyncio.Event().wait()
    finally:
        await manager.stop()


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器。"""
    parser = argparse.ArgumentParser(description="dns-forwarder skeleton")
    parser.add_argument("--config", default="config.json", help="配置文件路径")
    parser.add_argument("command", nargs="?", default="serve", choices=["serve", "check-config"])
    return parser


def main() -> None:
    """命令行入口：解析参数并执行 serve 或 check-config。"""
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
