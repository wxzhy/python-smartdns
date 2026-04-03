from __future__ import annotations

import asyncio

import dns.message
import dns.rrset

from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.plugin_api import PluginManager, PluginRegistry
from plugins.speedtest_plugin import (
    IpRttResult,
    SPEEDTEST_CONTEXT_KEY,
    SPEEDTEST_SERVICE_KEY,
    SpeedTestContext,
    SpeedTestPlugin,
    SpeedTestPluginConfig,
    SpeedTestService,
    get_speedtest_context,
)


class CountingSpeedTestService(SpeedTestService):
    def __init__(self) -> None:
        self.calls = 0
        super().__init__(
            cache_ttl_seconds=3600,
            cache_maxsize=128,
            max_concurrency=8,
            probe_timeout=0.1,
            ping_count=1,
            ping_privileged=False,
        )

    async def _measure_ip_uncached(self, ip: str) -> IpRttResult:
        self.calls += 1
        await asyncio.sleep(0.01)
        return IpRttResult(ip=ip, ping_ms=10.0, tcp80_ms=20.0, tcp443_ms=30.0, best_ms=10.0)


class StubSpeedTestService:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def measure(self, ip: str) -> IpRttResult:
        self.calls.append(ip)
        return IpRttResult(ip=ip, ping_ms=5.0, tcp80_ms=8.0, tcp443_ms=12.0, best_ms=5.0)


async def test_speedtest_service_deduplicates_inflight_requests() -> None:
    service = CountingSpeedTestService()

    first, second, third = await asyncio.gather(
        service.measure("203.0.113.10"),
        service.measure("203.0.113.10"),
        service.measure("203.0.113.10"),
    )

    assert first.ip == "203.0.113.10"
    assert second.ip == "203.0.113.10"
    assert third.ip == "203.0.113.10"
    assert service.calls == 1


async def test_speedtest_plugin_collects_unique_ip_rtts() -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(SpeedTestPluginConfig(), plugin.variables_model())
    registry = PluginRegistry()
    await plugin.setup(registry)
    manager = PluginManager([], registry)

    stub_service = StubSpeedTestService()
    plugin._service = stub_service

    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            "example.test.",
            60,
            "IN",
            "A",
            "203.0.113.10",
            "203.0.113.11",
        )
    )
    answer = build_answer_from_response(request, response)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
    )
    result = UpstreamResult(upstream_name="default", duration_ms=1.0, answer=answer)

    await plugin.on_upstream_response(context, result)
    await plugin.on_upstream_response(context, result)

    speedtest_context = get_speedtest_context(context)
    assert {item.ip for item in speedtest_context.ip_rtt_results} == {"203.0.113.10", "203.0.113.11"}
    assert len(speedtest_context.ip_rtt_results) == 2
    assert set(stub_service.calls) == {"203.0.113.10", "203.0.113.11"}
    assert len(stub_service.calls) == 2


def test_plugin_manager_build_context_extensions_creates_request_scoped_context() -> None:
    registry = PluginRegistry()
    service = object()
    registry.register_context(SPEEDTEST_SERVICE_KEY, service)
    registry.register_context_factory(SPEEDTEST_CONTEXT_KEY, SpeedTestContext)
    manager = PluginManager([], registry)

    first = manager.build_context_extensions()
    second = manager.build_context_extensions()

    assert first[SPEEDTEST_SERVICE_KEY] is service
    assert second[SPEEDTEST_SERVICE_KEY] is service
    assert isinstance(first[SPEEDTEST_CONTEXT_KEY], SpeedTestContext)
    assert isinstance(second[SPEEDTEST_CONTEXT_KEY], SpeedTestContext)
    assert first[SPEEDTEST_CONTEXT_KEY] is not second[SPEEDTEST_CONTEXT_KEY]


async def test_speedtest_plugin_setup_registers_service_and_context_extensions() -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(SpeedTestPluginConfig(cache_ttl_seconds=600), plugin.variables_model())
    registry = PluginRegistry()

    await plugin.setup(registry)

    manager = PluginManager([], registry)
    extensions = manager.build_context_extensions()

    assert SPEEDTEST_SERVICE_KEY in extensions
    assert SPEEDTEST_CONTEXT_KEY in extensions
    assert isinstance(extensions[SPEEDTEST_CONTEXT_KEY], SpeedTestContext)
