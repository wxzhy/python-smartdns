from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING, ClassVar

import dns.resolver

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult

if TYPE_CHECKING:
    from dns_forwarder.resolver import ResolverManager

    from .registry import DispatcherRegistry


class DispatchStrategy(ABC):
    strategy_type: ClassVar[DispatchStrategyType]

    @abstractmethod
    async def dispatch(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        resolver_manager: "ResolverManager",
        registry: "DispatcherRegistry",
        on_result: Callable[[UpstreamResult], None] | None = None,
    ) -> UpstreamResult:
        raise NotImplementedError

    @staticmethod
    def default_result(message: str) -> UpstreamResult:
        return UpstreamResult(
            upstream_name="unknown",
            duration_ms=0.0,
            error=RuntimeError(message),
        )

    @staticmethod
    def error_name(result: UpstreamResult) -> str:
        if result.error is None:
            return ""
        return type(result.error).__name__

    @staticmethod
    async def _cancel_pending_tasks(tasks: list[asyncio.Task[UpstreamResult]]) -> None:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    @classmethod
    def pick_failure_result(
        cls,
        results: list[UpstreamResult],
        message: str,
    ) -> UpstreamResult:
        first_error: UpstreamResult | None = None
        first_nxdomain: UpstreamResult | None = None

        for result in results:
            if result.answer is not None:
                continue
            if isinstance(result.error, dns.resolver.NXDOMAIN):
                if first_nxdomain is None:
                    first_nxdomain = result
                continue
            if first_error is None:
                first_error = result

        return first_nxdomain or first_error or cls.default_result(message)
