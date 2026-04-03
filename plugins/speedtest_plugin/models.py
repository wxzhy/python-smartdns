from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Iterable


SPEEDTEST_CONTEXT_KEY = "speedtest.context"
SPEEDTEST_SERVICE_KEY = "speedtest.service"


@dataclass(slots=True, frozen=True)
class IpRttResult:
    ip: str
    ping_ms: float | None = None
    tcp80_ms: float | None = None
    tcp443_ms: float | None = None
    best_ms: float | None = None


@dataclass(slots=True)
class SpeedTestContext:
    ip_rtt_results: list[IpRttResult] = field(default_factory=list)
    _seen_ips: set[str] = field(default_factory=set, init=False, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    async def reserve_ips(self, ips: Iterable[str]) -> list[str]:
        async with self._lock:
            candidates = [ip for ip in ips if ip not in self._seen_ips]
            self._seen_ips.update(candidates)
            return candidates

    async def add_results(self, results: Iterable[IpRttResult]) -> None:
        async with self._lock:
            self.ip_rtt_results.extend(results)
