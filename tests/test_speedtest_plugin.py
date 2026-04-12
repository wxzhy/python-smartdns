from __future__ import annotations

import asyncio
import sys
import time

import dns.message
import dns.rrset
import pytest

from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.plugin_api import PluginManager, PluginRegistry
from plugins.speedtest_plugin import (
    IpRttResult,
    SPEEDTEST_CONTEXT_KEY,
    SPEEDTEST_SERVICE_KEY,
    SpeedTestContext,
    SpeedTestFallbackRuleConfig,
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


class ProbeRaceService(SpeedTestService):
    def __init__(self) -> None:
        self.completed: list[str] = []
        super().__init__(
            cache_ttl_seconds=900,
            cache_maxsize=32,
            max_concurrency=8,
            probe_timeout=0.5,
            ping_count=1,
            ping_privileged=False,
        )

    async def _probe_icmp(self, ip: str) -> float | None:
        await asyncio.sleep(0.05)
        self.completed.append("ping")
        return 50.0

    async def _probe_tcp(self, ip: str, port: int) -> float | None:
        if port == 80:
            await asyncio.sleep(0.01)
            self.completed.append("tcp80")
            return 10.0
        await asyncio.sleep(0.2)
        self.completed.append("tcp443")
        return 200.0


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


async def test_speedtest_service_cache_clear_invalidates_cached_ip_result() -> None:
    service = CountingSpeedTestService()

    first = await service.measure("203.0.113.10")
    service.cache_clear()
    second = await service.measure("203.0.113.10")

    assert first.ip == "203.0.113.10"
    assert second.ip == "203.0.113.10"
    assert service.calls == 2


async def test_speedtest_service_returns_first_success_without_waiting_for_all_probes() -> None:
    service = ProbeRaceService()
    started = time.perf_counter()

    result = await service.measure("203.0.113.10")
    elapsed = time.perf_counter() - started

    assert result.best_ms == 10.0
    assert result.tcp80_ms == 10.0
    assert result.ping_ms is None
    assert result.tcp443_ms is None
    assert elapsed < 0.12
    assert service.completed == ["tcp80"]


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


async def test_speedtest_plugin_skips_measurement_for_global_skip_tags() -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(SpeedTestPluginConfig(skip_tags=["direct"]), plugin.variables_model())
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
        )
    )
    answer = build_answer_from_response(request, response)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"direct"},
        extensions=manager.build_context_extensions(),
        final_answer=answer,
    )
    result = UpstreamResult(upstream_name="default", duration_ms=1.0, answer=answer, tags={"direct"})

    await plugin.on_upstream_response(context, result)
    await plugin.on_response(context)

    assert stub_service.calls == []
    assert {item.address for item in answer.rrset} == {"203.0.113.10"}


async def test_speedtest_plugin_skips_non_address_request_even_if_answer_is_address() -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(SpeedTestPluginConfig(response_ip_limit=1), plugin.variables_model())
    registry = PluginRegistry()
    await plugin.setup(registry)

    address_request = dns.message.make_query("example.test", "A")
    address_response = dns.message.make_response(address_request)
    address_response.answer.append(
        dns.rrset.from_text(
            "example.test.",
            60,
            "IN",
            "A",
            "203.0.113.10",
        )
    )
    address_answer = build_answer_from_response(address_request, address_response)
    context = RequestContext(
        request=dns.message.make_query("example.test", "TXT"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        final_answer=address_answer,
    )
    result = UpstreamResult(upstream_name="default", duration_ms=1.0, answer=address_answer)

    await plugin.on_upstream_response(context, result)
    await plugin.on_response(context)

    assert {item.address for item in address_answer.rrset} == {"203.0.113.10"}


async def test_speedtest_plugin_on_response_measures_only_new_ips_from_multi_ip_rrset() -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(SpeedTestPluginConfig(response_ip_limit=2), plugin.variables_model())
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
            "203.0.113.12",
        )
    )
    answer = build_answer_from_response(request, response)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
        final_answer=answer,
    )
    speedtest_context = get_speedtest_context(context)
    await speedtest_context.reserve_ips(["203.0.113.10", "203.0.113.11"])
    await speedtest_context.add_results(
        [
            IpRttResult(ip="203.0.113.10", best_ms=30.0),
            IpRttResult(ip="203.0.113.11", best_ms=20.0),
        ]
    )

    await plugin.on_response(context)

    assert stub_service.calls == ["203.0.113.12"]
    assert {item.ip for item in speedtest_context.ip_rtt_results} == {
        "203.0.113.10",
        "203.0.113.11",
        "203.0.113.12",
    }


async def test_speedtest_plugin_on_response_replaces_answer_rrset_with_fastest_ips_only() -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(SpeedTestPluginConfig(response_ip_limit=2), plugin.variables_model())
    registry = PluginRegistry()
    await plugin.setup(registry)
    manager = PluginManager([], registry)

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
            "203.0.113.12",
        )
    )
    answer = build_answer_from_response(request, response)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
        final_answer=answer,
    )
    speedtest_context = get_speedtest_context(context)
    await speedtest_context.add_results(
        [
            IpRttResult(ip="203.0.113.10", best_ms=30.0),
            IpRttResult(ip="203.0.113.11", best_ms=10.0),
            IpRttResult(ip="203.0.113.12", best_ms=20.0),
        ]
    )

    await plugin.on_response(context)

    assert {item.address for item in answer.rrset} == {"203.0.113.11", "203.0.113.12"}
    assert len(answer.rrset) == 2
    assert {item.address for item in answer.response.answer[0]} == {
        "203.0.113.10",
        "203.0.113.11",
        "203.0.113.12",
    }
    assert len(answer.response.answer[0]) == 3


async def test_speedtest_plugin_on_response_updates_ttl_and_expiration_when_replacing(monkeypatch) -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(
        SpeedTestPluginConfig(response_ip_limit=1, response_ttl_seconds=120),
        plugin.variables_model(),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)
    manager = PluginManager([], registry)

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
        final_answer=answer,
    )
    speedtest_context = get_speedtest_context(context)
    await speedtest_context.add_results(
        [
            IpRttResult(ip="203.0.113.10", best_ms=30.0),
            IpRttResult(ip="203.0.113.11", best_ms=10.0),
        ]
    )
    monkeypatch.setattr(sys.modules["plugins.speedtest_plugin.plugin"].time, "time", lambda: 1000.0)

    await plugin.on_response(context)

    assert [item.address for item in answer.rrset] == ["203.0.113.11"]
    assert answer.rrset.ttl == 120
    assert answer.expiration == pytest.approx(1120.0)


async def test_speedtest_plugin_on_response_keeps_answer_when_all_ips_timeout() -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(SpeedTestPluginConfig(response_ip_limit=2), plugin.variables_model())
    registry = PluginRegistry()
    await plugin.setup(registry)
    manager = PluginManager([], registry)

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
        final_answer=answer,
    )
    speedtest_context = get_speedtest_context(context)
    await speedtest_context.add_results(
        [
            IpRttResult(ip="203.0.113.10", best_ms=None),
            IpRttResult(ip="203.0.113.11", best_ms=None),
        ]
    )

    await plugin.on_response(context)

    assert {item.address for item in answer.rrset} == {"203.0.113.10", "203.0.113.11"}
    assert len(answer.rrset) == 2


async def test_speedtest_plugin_on_response_uses_fallback_ips_when_all_ips_timeout() -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(
        SpeedTestPluginConfig(
            response_ip_limit=2,
            response_ttl_seconds=180,
            fallback_rules=[
                SpeedTestFallbackRuleConfig(
                    match_tags=["proxy"],
                    ipv4_addresses=["10.10.0.2", "10.10.0.3"],
                )
            ],
        ),
        plugin.variables_model(),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)
    manager = PluginManager([], registry)

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
        tags={"proxy"},
        extensions=manager.build_context_extensions(),
        final_answer=answer,
    )
    speedtest_context = get_speedtest_context(context)
    await speedtest_context.add_results(
        [
            IpRttResult(ip="203.0.113.10", best_ms=None),
            IpRttResult(ip="203.0.113.11", best_ms=None),
        ]
    )

    await plugin.on_response(context)

    assert [item.address for item in answer.rrset] == ["10.10.0.2", "10.10.0.3"]
    assert answer.rrset.ttl == 180


async def test_speedtest_plugin_on_response_skips_excluded_fallback_rule() -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(
        SpeedTestPluginConfig(
            response_ip_limit=2,
            response_ttl_seconds=180,
            fallback_rules=[
                SpeedTestFallbackRuleConfig(
                    match_tags=["proxy"],
                    exclude_tags=["direct"],
                    ipv4_addresses=["10.10.0.2", "10.10.0.3"],
                ),
                SpeedTestFallbackRuleConfig(
                    match_tags=["proxy"],
                    ipv4_addresses=["10.20.0.2", "10.20.0.3"],
                ),
            ],
        ),
        plugin.variables_model(),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)
    manager = PluginManager([], registry)

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
        tags={"proxy", "direct"},
        extensions=manager.build_context_extensions(),
        final_answer=answer,
    )
    speedtest_context = get_speedtest_context(context)
    await speedtest_context.add_results(
        [
            IpRttResult(ip="203.0.113.10", best_ms=None),
            IpRttResult(ip="203.0.113.11", best_ms=None),
        ]
    )

    await plugin.on_response(context)

    assert [item.address for item in answer.rrset] == ["10.20.0.2", "10.20.0.3"]
    assert answer.rrset.ttl == 180


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
