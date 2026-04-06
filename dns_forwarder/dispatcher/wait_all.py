from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dns.resolver

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult

from .base import DispatchStrategy

if TYPE_CHECKING:
    from .registry import DispatcherRegistry
    from dns_forwarder.resolver import ResolverManager


logger = get_logger("dispatcher.wait_all")


class WaitAllDispatchStrategy(DispatchStrategy):
    strategy_type = DispatchStrategyType.WAIT_ALL

    async def dispatch(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        resolver_manager: "ResolverManager",
        registry: "DispatcherRegistry",
    ) -> UpstreamResult:
        tasks = [
            asyncio.create_task(registry.dispatch_target(context, target_name, resolver_manager))
            for target_name in group.upstreams
        ]

        try:
            results = await asyncio.gather(*tasks)
        finally:
            await self._cancel_pending_tasks(tasks)

        successes = [result for result in results if result.answer is not None]
        if successes:
            fastest = min(successes, key=lambda item: item.duration_ms)
            logger.debug(
                "等待全部调度完成 request_id=%s group=%s fastest_upstream=%s duration_ms=%.2f success_count=%s",
                context.request_id,
                group.name,
                fastest.upstream_name,
                fastest.duration_ms,
                len(successes),
            )
            return fastest

        fallback = self.pick_failure_result(results, "所有上游均失败")
        if isinstance(fallback.error, dns.resolver.NXDOMAIN):
            logger.debug("等待全部调度未命中成功结果，返回 NXDOMAIN request_id=%s group=%s", context.request_id, group.name)
            return fallback
        logger.warning("等待全部调度所有上游均失败 request_id=%s group=%s", context.request_id, group.name)
        return fallback

    @staticmethod
    async def _cancel_pending_tasks(tasks: list[asyncio.Task[UpstreamResult]]) -> None:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
