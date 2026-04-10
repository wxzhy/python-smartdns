from __future__ import annotations

import asyncio

import dns.rdatatype
import dns.rrset
import dns.resolver
from pydantic import BaseModel, Field

from dns_forwarder.pipeline import RequestContext, UpstreamResult
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

from .models import (
    SPEEDTEST_CONTEXT_KEY,
    SPEEDTEST_SERVICE_KEY,
    SpeedTestContext,
)
from .service import SpeedTestService


class SpeedTestPluginConfig(BaseModel):
    cache_ttl_seconds: int = Field(default=900, ge=1)
    cache_maxsize: int = Field(default=4096, ge=1)
    max_concurrency: int = Field(default=64, ge=1)
    probe_timeout: float = Field(default=1.5, gt=0)
    ping_count: int = Field(default=1, ge=1, le=10)
    ping_privileged: bool = False
    response_ip_limit: int = Field(default=2, ge=1)


def get_speedtest_context(context: RequestContext) -> SpeedTestContext:
    speedtest_context = context.extensions[SPEEDTEST_CONTEXT_KEY]
    if not isinstance(speedtest_context, SpeedTestContext):
        raise TypeError("speedtest.context 类型不正确")
    return speedtest_context


class SpeedTestPlugin(Plugin):
    name = "speedtest-plugin"
    config_model = SpeedTestPluginConfig
    variables_model = EmptyModel
    ui_meta = {
        "title": "SpeedTest Plugin",
        "description": "在 upstream_response 阶段对响应 IP 执行 ICMP/TCP(80/443) 并发测速，并写入 speedtest.context。",
    }

    def __init__(self) -> None:
        super().__init__()
        self._service: SpeedTestService | None = None

    async def setup(self, registry: PluginRegistry) -> None:
        self._service = SpeedTestService(
            cache_ttl_seconds=self.runtime_config.cache_ttl_seconds,
            cache_maxsize=self.runtime_config.cache_maxsize,
            max_concurrency=self.runtime_config.max_concurrency,
            probe_timeout=self.runtime_config.probe_timeout,
            ping_count=self.runtime_config.ping_count,
            ping_privileged=self.runtime_config.ping_privileged,
        )
        registry.register_context(SPEEDTEST_SERVICE_KEY, self._service)
        registry.register_context_factory(SPEEDTEST_CONTEXT_KEY, SpeedTestContext)

    async def on_upstream_response(self, context: RequestContext, result: UpstreamResult) -> None:
        if self._service is None or result.answer is None:
            return

        speedtest_context = get_speedtest_context(context)
        await self._measure_new_ips(speedtest_context, self._extract_unique_ips(result.answer))

    @staticmethod
    def _extract_unique_ips(answer: dns.resolver.Answer) -> list[str]:
        if answer.rdtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return []
        if answer.rrset is None:
            return []

        ips: list[str] = []
        seen: set[str] = set()
        for record in answer.rrset:
            address = getattr(record, "address", None)
            if address is None or address in seen:
                continue
            seen.add(address)
            ips.append(address)
        return ips

    async def on_response(self, context: RequestContext) -> None:
        answer = context.final_answer
        if answer is None or answer.rrset is None:
            return
        if answer.rdtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return

        speedtest_context = get_speedtest_context(context)
        current_ips = self._extract_unique_ips(answer)
        if not current_ips:
            return
        await self._measure_new_ips(speedtest_context, current_ips)

        measured_results = {
            item.ip: item for item in speedtest_context.ip_rtt_results if item.best_ms is not None and item.ip in current_ips
        }
        if not measured_results:
            return

        original_order = {ip: index for index, ip in enumerate(current_ips)}
        sorted_ips = [
            item.ip
            for item in sorted(
                measured_results.values(),
                key=lambda item: (item.best_ms if item.best_ms is not None else float("inf"), original_order[item.ip]),
            )
        ]
        sorted_ips = sorted_ips[: self.runtime_config.response_ip_limit]
        if sorted_ips == current_ips:
            return

        answer.rrset = dns.rrset.from_text_list(
            answer.rrset.name,
            answer.rrset.ttl,
            answer.rdclass,
            answer.rdtype,
            sorted_ips,
        )

    async def _measure_new_ips(self, speedtest_context: SpeedTestContext, ips: list[str]) -> None:
        if self._service is None or not ips:
            return

        candidate_ips = await speedtest_context.reserve_ips(ips)
        if not candidate_ips:
            return

        measurements = await asyncio.gather(
            *(self._service.measure(ip) for ip in candidate_ips),
            return_exceptions=True,
        )
        successful_results = []
        for item in measurements:
            if isinstance(item, Exception):
                continue
            successful_results.append(item)
        await speedtest_context.add_results(successful_results)


plugin = SpeedTestPlugin()
