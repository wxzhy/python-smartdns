from __future__ import annotations

from collections.abc import Iterable

from dns_forwarder.config import DispatchStrategyType

from .base import DispatchStrategy
from .race import RaceDispatchStrategy
from .sequential import SequentialDispatchStrategy


class DispatcherRegistry:
    def __init__(self, strategies: Iterable[DispatchStrategy] | None = None) -> None:
        resolved_strategies = (
            (SequentialDispatchStrategy(), RaceDispatchStrategy())
            if strategies is None
            else strategies
        )
        self._strategies = {
            strategy.strategy_type: strategy for strategy in resolved_strategies
        }

    def get(self, strategy: DispatchStrategyType) -> DispatchStrategy:
        return self._strategies[strategy]
