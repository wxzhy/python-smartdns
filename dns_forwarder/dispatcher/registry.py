from __future__ import annotations

import asyncio
from collections.abc import Callable
from collections.abc import Iterable

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult, inherit_request_tags

from .base import DispatchStrategy
from .race import RaceDispatchStrategy
from .wait_all import WaitAllDispatchStrategy

logger = get_logger("dispatcher.registry")


class DispatcherRegistry:
    def __init__(self, strategies: Iterable[DispatchStrategy] | None = None) -> None:
        resolved_strategies = (
            (
                RaceDispatchStrategy(),
                WaitAllDispatchStrategy(),
            )
            if strategies is None
            else strategies
        )
        self._strategies = {strategy.strategy_type: strategy for strategy in resolved_strategies}

    def get(self, strategy: DispatchStrategyType) -> DispatchStrategy:
        return self._strategies[strategy]

    async def dispatch_group(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        strategy: DispatchStrategyType,
        resolver_manager,
        on_result: Callable[[UpstreamResult], None] | None = None,
    ) -> UpstreamResult:
        return await self.get(strategy).dispatch(
            context,
            group,
            resolver_manager,
            self,
            on_result=on_result,
        )

    async def dispatch_with_strategy(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        strategy: DispatchStrategyType,
        resolver_manager,
        on_result: Callable[[UpstreamResult], None] | None = None,
    ) -> UpstreamResult:
        return await self.dispatch_group(
            context,
            group,
            strategy,
            resolver_manager,
            on_result=on_result,
        )

    async def dispatch_group_name(
        self,
        context: RequestContext,
        group_name: str,
        strategy: DispatchStrategyType,
        resolver_manager,
        on_result: Callable[[UpstreamResult], None] | None = None,
    ) -> UpstreamResult:
        return await self.dispatch_group(
            context,
            resolver_manager.get_group(group_name),
            strategy,
            resolver_manager,
            on_result=on_result,
        )

    async def dispatch_target(
        self,
        context: RequestContext,
        target_name: str,
        strategy: DispatchStrategyType,
        resolver_manager,
        on_result: Callable[[UpstreamResult], None] | None = None,
    ) -> UpstreamResult:
        try:
            if resolver_manager.has_group(target_name):
                return await self.dispatch_group_name(
                    context,
                    target_name,
                    strategy,
                    resolver_manager,
                    on_result=on_result,
                )
            result = await resolver_manager.resolve(target_name, context)
            result = inherit_request_tags(result, context.tags)
            if on_result is not None:
                on_result(result)
            return result
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "调度目标执行失败 request_id=%s target=%s error=%s",
                context.request_id,
                target_name,
                type(exc).__name__,
            )
            result = UpstreamResult(
                upstream_name=target_name,
                duration_ms=0.0,
                error=exc,
                tags=context.tags.copy(),
            )
            if on_result is not None:
                on_result(result)
            return result
