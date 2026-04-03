from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult

if TYPE_CHECKING:
    from dns_forwarder.resolver import ResolverManager


class DispatchStrategy(ABC):
    strategy_type: ClassVar[DispatchStrategyType]

    @abstractmethod
    async def dispatch(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        resolver_manager: "ResolverManager",
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
