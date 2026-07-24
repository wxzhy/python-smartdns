from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING
import anyio

import dns.resolver

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.logging import format_tags, get_logger
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult

from .base import DispatchStrategy

if TYPE_CHECKING:
    from dns_forwarder.resolver import ResolverManager

    from .registry import DispatcherRegistry


logger = get_logger("dispatcher.wait_all")


class WaitAllDispatchStrategy(DispatchStrategy):
    strategy_type = DispatchStrategyType.WAIT_ALL

    async def dispatch(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        resolver_manager: ResolverManager,
        registry: DispatcherRegistry,
        on_result: Callable[[UpstreamResult], None] | None = None,
    ) -> UpstreamResult:
        send_stream, receive_stream = anyio.create_memory_object_stream(len(group.upstreams))
        results: list[UpstreamResult] = []

        async def worker(target_name: str, s_stream: anyio.streams.memory.MemoryObjectSendStream[UpstreamResult]) -> None:
            async with s_stream:
                try:
                    res = await registry.dispatch_target(
                        context,
                        target_name,
                        self.strategy_type,
                        resolver_manager,
                        on_result=on_result,
                    )
                    await s_stream.send(res)
                except Exception:
                    pass

        async with receive_stream:
            async with anyio.create_task_group() as tg:
                for target_name in group.upstreams:
                    tg.start_soon(worker, target_name, send_stream.clone())
                await send_stream.aclose()

                async for res in receive_stream:
                    results.append(res)

        successes = [result for result in results if result.answer is not None]
        if successes:
            fastest = min(successes, key=lambda item: item.duration_ms)
            fastest.collected_results = tuple(results)
            logger.debug(
                "等待全部调度完成 request_id=%s group=%s fastest_upstream=%s duration_ms=%.2f success_count=%s tags=%s",
                context.request_id,
                group.name,
                fastest.upstream_name,
                fastest.duration_ms,
                len(successes),
                format_tags(fastest.tags),
            )
            return fastest

        fallback = self.pick_failure_result(results, "所有上游均失败")
        fallback.collected_results = tuple(results)
        if isinstance(fallback.error, dns.resolver.NXDOMAIN):
            logger.debug(
                "等待全部调度未命中成功结果，返回 NXDOMAIN request_id=%s group=%s",
                context.request_id,
                group.name,
            )
            return fallback
        logger.warning(
            "等待全部调度所有上游均失败 request_id=%s group=%s", context.request_id, group.name
        )
        return fallback
