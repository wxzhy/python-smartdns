from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dns.resolver

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult

from .base import DispatchStrategy

if TYPE_CHECKING:
    from dns_forwarder.resolver import ResolverManager


logger = get_logger("dispatcher.race")


class RaceDispatchStrategy(DispatchStrategy):
    strategy_type = DispatchStrategyType.RACE

    async def dispatch(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        resolver_manager: "ResolverManager",
    ) -> UpstreamResult:
        tasks = [
            asyncio.create_task(resolver_manager.resolve(upstream_name, context))
            for upstream_name in group.upstreams
        ]
        first_error: UpstreamResult | None = None
        first_nxdomain: UpstreamResult | None = None

        try:
            for task in asyncio.as_completed(tasks):
                result = await task
                if result.answer is not None:
                    logger.debug(
                        "并发调度命中 request_id=%s group=%s upstream=%s duration_ms=%.2f",
                        context.request_id,
                        group.name,
                        result.upstream_name,
                        result.duration_ms,
                    )
                    return result
                if isinstance(result.error, dns.resolver.NXDOMAIN):
                    if first_nxdomain is None:
                        first_nxdomain = result
                    logger.debug(
                        "并发调度收到 NXDOMAIN request_id=%s group=%s upstream=%s",
                        context.request_id,
                        group.name,
                        result.upstream_name,
                    )
                    continue
                if first_error is None:
                    first_error = result
                logger.debug(
                    "并发调度记录错误 request_id=%s group=%s upstream=%s error=%s",
                    context.request_id,
                    group.name,
                    result.upstream_name,
                    self.error_name(result),
                )
        finally:
            await self._cancel_pending_tasks(tasks)

        if first_nxdomain is not None:
            logger.debug("并发调度未命中成功结果，返回 NXDOMAIN request_id=%s group=%s", context.request_id, group.name)
            return first_nxdomain
        logger.warning("并发调度所有上游均失败 request_id=%s group=%s", context.request_id, group.name)
        return first_error or self.default_result("所有上游均失败")

    @staticmethod
    async def _cancel_pending_tasks(tasks: list[asyncio.Task[UpstreamResult]]) -> None:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
