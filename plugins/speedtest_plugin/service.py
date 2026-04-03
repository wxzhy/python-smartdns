from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections.abc import Awaitable

from async_lru import alru_cache
from icmplib import async_ping

from dns_forwarder.logging import get_logger

from .models import IpRttResult


logger = get_logger("plugins.speedtest")


class SpeedTestService:
    def __init__(
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
        self._measure_cached = alru_cache(maxsize=cache_maxsize, ttl=cache_ttl_seconds)(
            self._measure_ip_uncached
        )

    async def measure(self, ip: str) -> IpRttResult:
        return await self._measure_cached(ip)

    def cache_clear(self) -> None:
        self._measure_cached.cache_clear()

    async def _measure_ip_uncached(self, ip: str) -> IpRttResult:
        ping_task = asyncio.create_task(self._run_probe(self._probe_icmp(ip)))
        tcp80_task = asyncio.create_task(self._run_probe(self._probe_tcp(ip, 80)))
        tcp443_task = asyncio.create_task(self._run_probe(self._probe_tcp(ip, 443)))
        ping_ms, tcp80_ms, tcp443_ms = await asyncio.gather(ping_task, tcp80_task, tcp443_task)
        return IpRttResult(
            ip=ip,
            ping_ms=ping_ms,
            tcp80_ms=tcp80_ms,
            tcp443_ms=tcp443_ms,
            best_ms=self._best_rtt(ping_ms, tcp80_ms, tcp443_ms),
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

        duration_ms = host.avg_rtt if host.avg_rtt is not None else ((time.perf_counter() - started) * 1000)
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
            logger.debug("TCP 探测收到拒绝连接 ip=%s port=%s duration_ms=%.2f", ip, port, duration_ms)
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
        if parsed.version == 4:
            return socket.AF_INET, (ip, port)
        if not socket.has_ipv6:
            raise ValueError("当前环境不支持 IPv6")
        return socket.AF_INET6, (ip, port, 0, 0)

    @staticmethod
    def _best_rtt(*values: float | None) -> float | None:
        available = [value for value in values if value is not None]
        if not available:
            return None
        return min(available)
