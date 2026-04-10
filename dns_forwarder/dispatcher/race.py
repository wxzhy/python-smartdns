from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dns.resolver

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.logging import format_tags, get_logger
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult

from .base import DispatchStrategy

if TYPE_CHECKING:
    from .registry import DispatcherRegistry
    from dns_forwarder.resolver import ResolverManager


logger = get_logger("dispatcher.race")


class RaceDispatchStrategy(DispatchStrategy):
    strategy_type = DispatchStrategyType.RACE

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
        failures: list[UpstreamResult] = []

        try:
            for task in asyncio.as_completed(tasks):
                result = await task
                if result.answer is not None:
                    logger.debug(
                        "并发调度命中 request_id=%s group=%s upstream=%s duration_ms=%.2f tags=%s",
                        context.request_id,
                        group.name,
                        result.upstream_name,
                        result.duration_ms,
                        format_tags(result.tags),
                    )
                    return result
                logger.debug(
                    "并发调度忽略失败结果 request_id=%s group=%s upstream=%s error=%s tags=%s",
                    context.request_id,
                    group.name,
                    result.upstream_name,
                    self.error_name(result),
                    format_tags(result.tags),
                )
                failures.append(result)
        finally:
            await self._cancel_pending_tasks(tasks)

        fallback = self.pick_failure_result(failures, "所有上游均失败")
        if isinstance(fallback.error, dns.resolver.NXDOMAIN):
            logger.debug("并发调度未命中成功结果，返回 NXDOMAIN request_id=%s group=%s", context.request_id, group.name)
            return fallback
        logger.warning("并发调度所有上游均失败 request_id=%s group=%s", context.request_id, group.name)
        return fallback

    @staticmethod
    async def _cancel_pending_tasks(tasks: list[asyncio.Task[UpstreamResult]]) -> None:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
