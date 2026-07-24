from __future__ import annotations

import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from anyio.from_thread import start_blocking_portal

from dns_forwarder.config import load_config
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import PluginManager
from dns_forwarder.resolver import ResolverManager
from dns_forwarder.resolver.nameservers import close_shared_sessions as close_nameserver_sessions

if TYPE_CHECKING:
    from pathlib import Path

    import dns.message

    from dns_forwarder.config import AppConfig

logger = get_logger("core.worker")


@dataclass(slots=True)
class RuntimeState:
    config: AppConfig
    plugin_manager: PluginManager
    resolver_manager: ResolverManager
    dispatcher_registry: DispatcherRegistry
    pipeline: PipelineEngine


async def build_runtime_state(config_path: Path, shared_contexts: dict[str, Any]) -> RuntimeState:
    """在当前事件循环内构建一份完整的运行时状态（插件、解析器、调度器、流水线）。"""
    config = load_config(config_path)
    plugin_manager = await PluginManager.build(
        config.plugins,
        config.runtime.plugin_dirs,
        shared_contexts=shared_contexts,
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


class PortalWorker:
    """独立线程 + anyio blocking portal + 私有事件循环的请求处理 worker。

    线程启动后立即在自有 loop 内调用 ``_async_start`` 完成初始化
    （构建独立 RuntimeState、执行插件 setup），之后主循环通过
    :meth:`process_query_blocking` 经 portal 调用 dispatch 处理请求。
    """

    def __init__(self, index: int, config_path: Path, shared_contexts: dict[str, Any]) -> None:
        self.index = index
        self._config_path = config_path
        self._shared_contexts = shared_contexts
        self._state: RuntimeState | None = None
        self._portal: Any | None = None
        self._ready = threading.Event()
        self._start_error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run, name=f"dns-worker-{index}", daemon=True
        )

    @property
    def state(self) -> RuntimeState:
        if self._state is None:
            raise RuntimeError(f"worker {self.index} 尚未初始化")
        return self._state

    # ---- 主线程（同步上下文）调用 ----

    def start(self) -> None:
        """启动 worker 线程并阻塞至其完成初始化；初始化失败时抛出原始异常。"""
        self._thread.start()
        self._ready.wait()
        if self._start_error is not None:
            self._thread.join(timeout=5)
            raise RuntimeError(f"worker {self.index} 初始化失败") from self._start_error

    def process_query_blocking(
        self,
        request: dns.message.Message,
        clientaddr: Any,
        listener_name: str,
    ) -> dns.message.Message | None:
        """经 portal 调用 worker loop 内的 dispatch；只可从 anyio worker 线程调用。"""
        if self._portal is None:
            raise RuntimeError(f"worker {self.index} 尚未启动")
        return self._portal.call(self.state.pipeline.handle_message, request, clientaddr, listener_name)

    def reload(self, shared_contexts: dict[str, Any]) -> RuntimeState:
        """在 worker loop 内重建 RuntimeState（主线程同步调用）。"""
        if self._portal is None:
            raise RuntimeError(f"worker {self.index} 尚未启动")
        self._shared_contexts = shared_contexts
        return self._portal.call(self._async_reload)

    def stop(self) -> None:
        """停止 worker：在自有 loop 内关闭会话，随后停止 portal 并 join 线程。"""
        portal = self._portal
        if portal is None:
            return
        try:
            self._call_with_timeout(portal, self._async_stop, timeout=5.0)
        except Exception:
            logger.exception("worker %s 停止清理失败", self.index)
        # BlockingPortal.stop 是协程方法，必须经 portal.call 在 loop 内调用。
        portal.call(portal.stop, True)
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            logger.warning("worker %s 线程未在超时内退出", self.index)
        self._portal = None
        self._state = None

    @staticmethod
    def _call_with_timeout(
        portal: Any,
        func: Callable[[], Awaitable[Any]],
        *,
        timeout: float,
    ) -> None:
        """经 portal 调用协程并带超时；超时后取消任务避免阻塞关闭。"""
        future = portal.start_task_soon(func)
        try:
            future.result(timeout=timeout)
        except TimeoutError:
            logger.warning("worker 清理任务超时，取消执行")
            future.cancel()
            raise

    # ---- worker 线程体与 loop 内协程 ----

    def _run(self) -> None:
        try:
            with start_blocking_portal(backend="asyncio") as portal:
                self._portal = portal
                try:
                    portal.call(self._async_start)
                except BaseException as exc:  # noqa: BLE001 - 需要透传任意初始化异常
                    self._start_error = exc
                    self._ready.set()
                    return
                self._ready.set()
                # sleep_until_stopped 是协程方法，需经 portal.call 在 loop 内阻塞等待。
                portal.call(portal.sleep_until_stopped)
        except BaseException as exc:  # noqa: BLE001 - 线程级兜底，记录后退出
            if self._start_error is None:
                self._start_error = exc
            self._ready.set()
            logger.exception("worker %s 线程异常退出", self.index)

    async def _async_start(self) -> None:
        """提前初始化：在 worker 自有 loop 内构建 RuntimeState。"""
        self._state = await build_runtime_state(self._config_path, self._shared_contexts)
        logger.info("worker %s 初始化完成", self.index)

    async def _async_reload(self) -> RuntimeState:
        # 先关闭本 loop 持有的共享 nameserver 会话：配置（bootstrap/hosts/
        # servers/verify 等）变更后旧会话不复用，避免运行期报错或泄漏。
        await close_nameserver_sessions()
        self._state = await build_runtime_state(self._config_path, self._shared_contexts)
        return self._state

    async def _async_stop(self) -> None:
        # 仅关闭当前 loop 持有的共享会话（close_shared_sessions 按 loop 过滤）。
        await close_nameserver_sessions()
