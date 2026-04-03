from __future__ import annotations

import asyncio

import dns.rdatatype
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
    cache_ttl_seconds: int = Field(default=3600, ge=1)
    cache_maxsize: int = Field(default=4096, ge=1)
    max_concurrency: int = Field(default=64, ge=1)
    probe_timeout: float = Field(default=1.5, gt=0)
    ping_count: int = Field(default=1, ge=1, le=10)
    ping_privileged: bool = False


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
        candidate_ips = await speedtest_context.reserve_ips(self._extract_unique_ips(result.answer))
        if not candidate_ips:
            return

        measurements = await asyncio.gather(
            *(self._service.measure(ip) for ip in candidate_ips),
            return_exceptions=True,
        )
        successful_results = [item for item in measurements if not isinstance(item, Exception)]
        await speedtest_context.add_results(successful_results)

    @staticmethod
    def _extract_unique_ips(answer: dns.resolver.Answer) -> list[str]:
        ips: list[str] = []
        seen: set[str] = set()
        for rrset in answer.response.answer:
            if rrset.rdtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
                continue
            for record in rrset:
                address = getattr(record, "address", None)
                if address is None or address in seen:
                    continue
                seen.add(address)
                ips.append(address)
        return ips


plugin = SpeedTestPlugin()
