from __future__ import annotations

from typing import TYPE_CHECKING

import dns.resolver

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult

from .base import DispatchStrategy

if TYPE_CHECKING:
    from .registry import DispatcherRegistry
    from dns_forwarder.resolver import ResolverManager


logger = get_logger("dispatcher.sequential")


class SequentialDispatchStrategy(DispatchStrategy):
    strategy_type = DispatchStrategyType.SEQUENTIAL

    async def dispatch(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        resolver_manager: "ResolverManager",
        registry: "DispatcherRegistry",
    ) -> UpstreamResult:
        last_result: UpstreamResult | None = None
        for target_name in group.upstreams:
            result = await registry.dispatch_target(context, target_name, resolver_manager)
            if result.answer is not None:
                logger.debug(
                    "顺序调度命中 request_id=%s group=%s target=%s upstream=%s duration_ms=%.2f",
                    context.request_id,
                    group.name,
                    target_name,
                    result.upstream_name,
                    result.duration_ms,
                )
                return result
            if isinstance(result.error, dns.resolver.NXDOMAIN):
                logger.debug(
                    "顺序调度收到 NXDOMAIN，停止回退 request_id=%s group=%s target=%s upstream=%s",
                    context.request_id,
                    group.name,
                    target_name,
                    result.upstream_name,
                )
                return result
            logger.debug(
                "顺序调度回退 request_id=%s group=%s target=%s upstream=%s error=%s",
                context.request_id,
                group.name,
                target_name,
                result.upstream_name,
                self.error_name(result),
            )
            last_result = result
        logger.warning("顺序调度未得到可用结果 request_id=%s group=%s", context.request_id, group.name)
        return last_result or self.default_result("没有可用上游")
