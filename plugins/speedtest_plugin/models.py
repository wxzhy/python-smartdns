from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass, field

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
        ordered_ips = list(dict.fromkeys(ips))
        incoming_ip_set = set(ordered_ips)
        async with self._lock:
            new_ip_set = incoming_ip_set - self._seen_ips
            candidates = [ip for ip in ordered_ips if ip in new_ip_set]
            self._seen_ips.update(new_ip_set)
            return candidates

    async def add_results(self, results: Iterable[IpRttResult]) -> None:
        async with self._lock:
            self.ip_rtt_results.extend(results)
