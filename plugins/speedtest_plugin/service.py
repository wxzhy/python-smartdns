from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from typing import TYPE_CHECKING

from async_lru import alru_cache
from icmplib import async_ping

from dns_forwarder.logging import get_logger

from .models import IpRttResult

if TYPE_CHECKING:
    from collections.abc import Awaitable

logger = get_logger("plugins.speedtest")

IPV4_VERSION = 4


class SpeedTestService:
    def __init__(  # noqa: PLR0913  # grouped config params; kept explicit for clarity
        self,
        *,
        cache_ttl_seconds: int,
        cache_maxsize: int,
        max_concurrency: int,
        probe_timeout: float,
        ping_count: int,
        ping_privileged: bool,
    ) -> None:
        self._probe_timeout = probe_timeout
        self._ping_count = ping_count
        self._ping_privileged = ping_privileged
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._measure_cached = self._build_measure_cache(
            cache_maxsize=cache_maxsize,
            cache_ttl_seconds=cache_ttl_seconds,
        )

    async def measure(self, ip: str) -> IpRttResult:
        return await self._measure_cached(ip)

    def cache_clear(self) -> None:
        self._measure_cached.cache_clear()

    def _build_measure_cache(self, *, cache_maxsize: int, cache_ttl_seconds: int):
        @alru_cache(maxsize=cache_maxsize, ttl=cache_ttl_seconds)
        async def measure_cached(ip: str) -> IpRttResult:
            return await self._measure_ip_uncached(ip)

        return measure_cached

    async def _measure_ip_uncached(self, ip: str) -> IpRttResult:
        probes = {
            "ping_ms": asyncio.create_task(self._run_probe(self._probe_icmp(ip))),
            "tcp80_ms": asyncio.create_task(self._run_probe(self._probe_tcp(ip, 80))),
            "tcp443_ms": asyncio.create_task(self._run_probe(self._probe_tcp(ip, 443))),
        }
        first_success_key: str | None = None
        first_success_value: float | None = None

        try:
            pending_map = dict(probes)
            while pending_map:
                task_map = {task: name for name, task in pending_map.items()}
                done, _ = await asyncio.wait(task_map, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    key = task_map[task]
                    pending_map.pop(key, None)
                    result = await task
                    if result is not None:
                        first_success_key = key
                        first_success_value = result
                        return IpRttResult(
                            ip=ip,
                            ping_ms=result if key == "ping_ms" else None,
                            tcp80_ms=result if key == "tcp80_ms" else None,
                            tcp443_ms=result if key == "tcp443_ms" else None,
                            best_ms=result,
                        )
        finally:
            for task in probes.values():
                if not task.done():
                    task.cancel()
            await asyncio.gather(*probes.values(), return_exceptions=True)

        return IpRttResult(
            ip=ip,
            ping_ms=first_success_value if first_success_key == "ping_ms" else None,
            tcp80_ms=first_success_value if first_success_key == "tcp80_ms" else None,
            tcp443_ms=first_success_value if first_success_key == "tcp443_ms" else None,
            best_ms=first_success_value,
        )

    async def _run_probe(self, probe: Awaitable[float | None]) -> float | None:
        async with self._semaphore:
            return await probe

    async def _probe_icmp(self, ip: str) -> float | None:
        started = time.perf_counter()
        try:
            host = await async_ping(
                ip,
                count=self._ping_count,
                timeout=self._probe_timeout,
                privileged=self._ping_privileged,
            )
        except Exception as exc:
            logger.debug("ICMP 探测失败 ip=%s error=%s", ip, type(exc).__name__)
            return None

        if not host.is_alive or not host.rtts:
            logger.debug("ICMP 探测未返回有效 RTT ip=%s", ip)
            return None

        duration_ms = (
            host.avg_rtt if host.avg_rtt is not None else ((time.perf_counter() - started) * 1000)
        )
        logger.debug("ICMP 探测完成 ip=%s duration_ms=%.2f", ip, duration_ms)
        return duration_ms

    async def _probe_tcp(self, ip: str, port: int) -> float | None:
        try:
            family, sockaddr = self._build_socket_target(ip, port)
        except ValueError:
            logger.debug("TCP 探测跳过无效 IP ip=%s port=%s", ip, port)
            return None

        loop = asyncio.get_running_loop()
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        started = time.perf_counter()
        try:
            await asyncio.wait_for(loop.sock_connect(sock, sockaddr), timeout=self._probe_timeout)
        except ConnectionRefusedError:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.debug(
                "TCP 探测收到拒绝连接 ip=%s port=%s duration_ms=%.2f", ip, port, duration_ms
            )
            return duration_ms
        except Exception as exc:
            logger.debug("TCP 探测失败 ip=%s port=%s error=%s", ip, port, type(exc).__name__)
            return None
        finally:
            sock.close()

        duration_ms = (time.perf_counter() - started) * 1000
        logger.debug("TCP 探测完成 ip=%s port=%s duration_ms=%.2f", ip, port, duration_ms)
        return duration_ms

    @staticmethod
    def _build_socket_target(ip: str, port: int) -> tuple[socket.AddressFamily, tuple]:
        parsed = ipaddress.ip_address(ip)
        if parsed.version == IPV4_VERSION:
            return socket.AF_INET, (ip, port)
        if not socket.has_ipv6:
            raise ValueError("当前环境不支持 IPv6")
        return socket.AF_INET6, (ip, port, 0, 0)
