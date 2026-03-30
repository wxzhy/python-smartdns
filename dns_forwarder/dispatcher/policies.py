from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Protocol

import dns.resolver

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult

if TYPE_CHECKING:
    from dns_forwarder.resolver import ResolverManager


class DispatchStrategy(Protocol):
    async def dispatch(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        resolver_manager: "ResolverManager",
    ) -> UpstreamResult: ...


class SequentialDispatchStrategy:
    async def dispatch(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        resolver_manager: "ResolverManager",
    ) -> UpstreamResult:
        last_result: UpstreamResult | None = None
        for upstream_name in group.upstreams:
            result = await resolver_manager.resolve(upstream_name, context)
            if result.answer is not None:
                return result
            if isinstance(result.error, dns.resolver.NXDOMAIN):
                return result
            last_result = result
        return last_result or UpstreamResult(upstream_name="unknown", duration_ms=0.0, error=RuntimeError("没有可用上游"))


class RaceDispatchStrategy:
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
                    for pending in tasks:
                        if not pending.done():
                            pending.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    return result
                if isinstance(result.error, dns.resolver.NXDOMAIN):
                    if first_nxdomain is None:
                        first_nxdomain = result
                    continue
                if first_error is None:
                    first_error = result
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        if first_nxdomain is not None:
            return first_nxdomain
        return first_error or UpstreamResult(upstream_name="unknown", duration_ms=0.0, error=RuntimeError("所有上游均失败"))


class DispatcherRegistry:
    def __init__(self) -> None:
        self._strategies: dict[DispatchStrategyType, DispatchStrategy] = {
            DispatchStrategyType.SEQUENTIAL: SequentialDispatchStrategy(),
            DispatchStrategyType.RACE: RaceDispatchStrategy(),
        }

    def get(self, strategy: DispatchStrategyType) -> DispatchStrategy:
        return self._strategies[strategy]
