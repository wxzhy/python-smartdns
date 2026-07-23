from __future__ import annotations

import asyncio
import sys
import time

import dns.message
import dns.rrset
import pytest

from dns_forwarder.config import AppConfig, PluginConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import LoadedPlugin, PluginManager, PluginRegistry
from plugins.ip_replace_plugin import (
    IpReplacePlugin,
    IpReplacePluginConfig,
    IpReplaceRuleConfig,
)
from plugins.speedtest_plugin import (
    SPEEDTEST_CONTEXT_KEY,
    SPEEDTEST_SERVICE_KEY,
    IpRttResult,
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


class MappedSpeedTestService:
    def __init__(self, results_by_ip: dict[str, float | None]) -> None:
        self._results_by_ip = results_by_ip
        self.calls: list[str] = []

    async def measure(self, ip: str) -> IpRttResult:
        self.calls.append(ip)
        best_ms = self._results_by_ip[ip]
        return IpRttResult(ip=ip, best_ms=best_ms)


async def build_plugin_manager_with_ip_replace_and_speedtest(
    speedtest_plugin: SpeedTestPlugin,
    *,
    replace_targets: list[str] | None = None,
    replace_ipv4_targets: list[str] | None = None,
    replace_ipv6_targets: list[str] | None = None,
) -> PluginManager:
    registry = PluginRegistry()
    ipv4_targets = (
        replace_ipv4_targets
        if replace_ipv4_targets is not None
        else (replace_targets or ["10.10.0.0/24"])
    )

    ip_replace_plugin = IpReplacePlugin()
    ip_replace_plugin.bind(
        IpReplacePluginConfig(
            rules=[
                IpReplaceRuleConfig(
                    name="proxy-map",
                    match_tags=["proxy"],
                    ipv4_targets=ipv4_targets,
                    ipv6_targets=replace_ipv6_targets or [],
                )
            ]
        ),
        ip_replace_plugin.variables_model(),
    )
    await ip_replace_plugin.setup(registry)
    await speedtest_plugin.setup(registry)

    return PluginManager(
        [
            LoadedPlugin(
                instance=speedtest_plugin,
                config=speedtest_plugin.runtime_config,
                variables=speedtest_plugin.runtime_variables,
                raw_config=PluginConfig(name="speedtest", module="speedtest_plugin"),
            ),
            LoadedPlugin(
                instance=ip_replace_plugin,
                config=ip_replace_plugin.runtime_config,
                variables=ip_replace_plugin.runtime_variables,
                raw_config=PluginConfig(name="ip_replace", module="ip_replace_plugin"),
            ),
        ],
        registry,
    )


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


class StaticResolverManager:
    def __init__(self, config: AppConfig, handlers: dict[str, object]) -> None:
        self._groups = {group.name: group for group in config.groups}
        self._handlers = handlers

    def get_group(self, group_name: str):
        return self._groups[group_name]

    def has_group(self, group_name: str) -> bool:
        return group_name in self._groups

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        handler = self._handlers[upstream_name]
        if callable(handler):
            return await handler(context)
        return handler


def build_wait_all_config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "runtime": {
                "plugin_dirs": ["plugins"],
                "default_upstream_group": "default",
                "loop_policy": "asyncio",
                "log_level": "DEBUG",
            },
            "tree_root": {
                "domain_dir": None,
                "ip_dir": None,
            },
            "listeners": [
                {"name": "udp", "protocol": "udp", "host": "127.0.0.1", "port": 0, "enabled": True},
            ],
            "nameservers": [
                {"name": "ns-a", "protocol": "do53", "address": "127.0.0.1", "port": 53},
                {"name": "ns-b", "protocol": "do53", "address": "127.0.0.1", "port": 54},
            ],
            "upstreams": [
                {"name": "resolver-a", "nameservers": ["ns-a"]},
                {"name": "resolver-b", "nameservers": ["ns-b"]},
            ],
            "groups": [
                {"name": "default", "upstreams": ["resolver-a", "resolver-b"]},
            ],
            "rules": [
                {
                    "name": "wait-all",
                    "enabled": True,
                    "match": {"match_tags": [], "exclude_tags": []},
                    "action": {"dispatcher": "wait_all"},
                }
            ],
            "plugins": [],
            "webui": {"enabled": False},
        }
    )


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
    assert {item.ip for item in speedtest_context.ip_rtt_results} == {
        "203.0.113.10",
        "203.0.113.11",
    }
    assert len(speedtest_context.ip_rtt_results) == 2
    assert set(stub_service.calls) == {"203.0.113.10", "203.0.113.11"}
    assert len(stub_service.calls) == 2


async def test_speedtest_plugin_logs_resolver_and_response_ips_on_upstream_response(
    capture_dns_logs,
    caplog,
) -> None:
    capture_dns_logs("DEBUG")
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
    result = UpstreamResult(upstream_name="resolver-a", duration_ms=1.0, answer=answer)

    await plugin.on_upstream_response(context, result)

    assert "测速收到响应" in caplog.text
    assert "resolver=resolver-a" in caplog.text
    assert "response_ips=" in caplog.text
    assert "203.0.113.10" in caplog.text
    assert "203.0.113.11" in caplog.text


async def test_speedtest_plugin_logs_each_wait_all_upstream_response(
    capture_dns_logs,
    caplog,
) -> None:
    capture_dns_logs("DEBUG")
    config = build_wait_all_config()
    plugin = SpeedTestPlugin()
    plugin.bind(SpeedTestPluginConfig(), plugin.variables_model())
    registry = PluginRegistry()
    await plugin.setup(registry)
    manager = PluginManager(
        [
            LoadedPlugin(
                instance=plugin,
                config=plugin.runtime_config,
                variables=plugin.runtime_variables,
                raw_config=PluginConfig(name="speedtest", module="speedtest_plugin"),
            )
        ],
        registry,
    )

    stub_service = StubSpeedTestService()
    plugin._service = stub_service

    async def resolve_a(context: RequestContext) -> UpstreamResult:
        await asyncio.sleep(0.02)
        request = context.request
        response = dns.message.make_response(request)
        response.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "A", "203.0.113.10"))
        return UpstreamResult(
            upstream_name="resolver-a",
            duration_ms=15.0,
            answer=build_answer_from_response(request, response),
        )

    async def resolve_b(context: RequestContext) -> UpstreamResult:
        await asyncio.sleep(0.01)
        request = context.request
        response = dns.message.make_response(request)
        response.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "A", "203.0.113.20"))
        return UpstreamResult(
            upstream_name="resolver-b",
            duration_ms=5.0,
            answer=build_answer_from_response(request, response),
        )

    engine = PipelineEngine(
        config,
        StaticResolverManager(
            config,
            {
                "resolver-a": resolve_a,
                "resolver-b": resolve_b,
            },
        ),
        DispatcherRegistry(),
        manager,
    )

    response = await engine.handle_message(
        dns.message.make_query("example.test", "A"),
        ("127.0.0.1", 5300),
        "udp",
    )

    assert response is not None
    assert stub_service.calls == ["203.0.113.20", "203.0.113.10"]
    assert caplog.text.count("测速收到响应") == 2
    assert "resolver=resolver-a" in caplog.text
    assert "resolver=resolver-b" in caplog.text


async def test_speedtest_plugin_measures_replaced_ips_after_upstream_ip_replace() -> None:
    speedtest_plugin = SpeedTestPlugin()
    speedtest_plugin.bind(SpeedTestPluginConfig(), speedtest_plugin.variables_model())
    manager = await build_plugin_manager_with_ip_replace_and_speedtest(speedtest_plugin)

    stub_service = StubSpeedTestService()
    speedtest_plugin._service = stub_service

    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            "example.test.",
            60,
            "IN",
            "A",
            "198.51.100.10",
        )
    )
    answer = build_answer_from_response(request, response)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
    )
    result = UpstreamResult(
        upstream_name="default",
        duration_ms=1.0,
        answer=answer,
        tags={"proxy"},
    )

    await manager.on_upstream_response(context, result)

    assert result.answer is not None
    assert [item.address for item in result.answer.rrset] == ["10.10.0.10"]
    assert stub_service.calls == ["10.10.0.10"]


async def test_speedtest_plugin_measures_replaced_ips_after_response_ip_replace() -> None:
    speedtest_plugin = SpeedTestPlugin()
    speedtest_plugin.bind(SpeedTestPluginConfig(), speedtest_plugin.variables_model())
    manager = await build_plugin_manager_with_ip_replace_and_speedtest(speedtest_plugin)

    stub_service = StubSpeedTestService()
    speedtest_plugin._service = stub_service

    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            "example.test.",
            60,
            "IN",
            "A",
            "198.51.100.20",
        )
    )
    answer = build_answer_from_response(request, response)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
        final_answer=answer,
        upstream_results=[UpstreamResult(upstream_name="default", duration_ms=1.0, tags={"proxy"})],
    )

    await manager.on_response(context)

    assert context.final_answer is not None
    assert [item.address for item in context.final_answer.rrset] == ["10.10.0.20"]
    assert stub_service.calls == ["10.10.0.20"]


async def test_speedtest_plugin_measures_all_ipv6_targets_after_upstream_ip_replace() -> None:
    speedtest_plugin = SpeedTestPlugin()
    speedtest_plugin.bind(SpeedTestPluginConfig(), speedtest_plugin.variables_model())
    manager = await build_plugin_manager_with_ip_replace_and_speedtest(
        speedtest_plugin,
        replace_ipv4_targets=[],
        replace_ipv6_targets=["fd10::1/128", "fd10::2/128", "fd10::3/128"],
    )

    stub_service = StubSpeedTestService()
    speedtest_plugin._service = stub_service

    request = dns.message.make_query("example.test", "AAAA")
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            "example.test.",
            60,
            "IN",
            "AAAA",
            "2001:db8::10",
        )
    )
    answer = build_answer_from_response(request, response)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
    )
    result = UpstreamResult(
        upstream_name="default",
        duration_ms=1.0,
        answer=answer,
        tags={"proxy"},
    )

    await manager.on_upstream_response(context, result)

    expected_ips = ["fd10::1", "fd10::2", "fd10::3"]
    assert result.answer is not None
    assert [item.address for item in result.answer.rrset] == expected_ips
    assert [item.address for item in result.answer.response.answer[0]] == expected_ips
    assert stub_service.calls == expected_ips


async def test_speedtest_plugin_limits_replaced_ipv4_targets_by_rtt() -> None:
    speedtest_plugin = SpeedTestPlugin()
    speedtest_plugin.bind(
        SpeedTestPluginConfig(response_ip_limit=2),
        speedtest_plugin.variables_model(),
    )
    manager = await build_plugin_manager_with_ip_replace_and_speedtest(
        speedtest_plugin,
        replace_ipv4_targets=["10.10.0.1/32", "10.10.0.2/32", "10.10.0.3/32"],
    )
    speedtest_plugin._service = MappedSpeedTestService(
        {
            "10.10.0.1": 30.0,
            "10.10.0.2": 10.0,
            "10.10.0.3": 20.0,
        }
    )

    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "A", "198.51.100.20"))
    answer = build_answer_from_response(request, response)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
        final_answer=answer,
    )
    result = UpstreamResult(
        upstream_name="default",
        duration_ms=1.0,
        answer=answer,
        tags={"proxy"},
    )
    context.upstream_results.append(result)

    await manager.on_upstream_response(context, result)
    await manager.on_response(context)

    expected_ips = ["10.10.0.2", "10.10.0.3"]
    assert [item.address for item in answer.rrset] == expected_ips
    assert [item.address for item in answer.response.answer[0]] == expected_ips
    assert speedtest_plugin._service.calls == ["10.10.0.1", "10.10.0.2", "10.10.0.3"]


async def test_speedtest_plugin_limits_replaced_ipv6_targets_by_rtt() -> None:
    speedtest_plugin = SpeedTestPlugin()
    speedtest_plugin.bind(
        SpeedTestPluginConfig(response_ip_limit=2),
        speedtest_plugin.variables_model(),
    )
    manager = await build_plugin_manager_with_ip_replace_and_speedtest(
        speedtest_plugin,
        replace_ipv4_targets=[],
        replace_ipv6_targets=["fd10::1/128", "fd10::2/128", "fd10::3/128"],
    )
    speedtest_plugin._service = MappedSpeedTestService(
        {
            "fd10::1": 30.0,
            "fd10::2": 10.0,
            "fd10::3": 20.0,
        }
    )

    request = dns.message.make_query("example.test", "AAAA")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "AAAA", "2001:db8::20"))
    answer = build_answer_from_response(request, response)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
        final_answer=answer,
    )
    result = UpstreamResult(
        upstream_name="default",
        duration_ms=1.0,
        answer=answer,
        tags={"proxy"},
    )
    context.upstream_results.append(result)

    await manager.on_upstream_response(context, result)
    await manager.on_response(context)

    expected_ips = ["fd10::2", "fd10::3"]
    assert [item.address for item in answer.rrset] == expected_ips
    assert [item.address for item in answer.response.answer[0]] == expected_ips
    assert speedtest_plugin._service.calls == ["fd10::1", "fd10::2", "fd10::3"]


async def test_speedtest_plugin_on_response_prefers_replaced_ip_from_other_wait_all_result() -> (
    None
):
    config = build_wait_all_config()
    speedtest_plugin = SpeedTestPlugin()
    speedtest_plugin.bind(
        SpeedTestPluginConfig(response_ip_limit=1),
        speedtest_plugin.variables_model(),
    )
    manager = await build_plugin_manager_with_ip_replace_and_speedtest(speedtest_plugin)
    speedtest_plugin._service = MappedSpeedTestService(
        {
            "203.0.113.10": 50.0,
            "10.10.0.20": 5.0,
        }
    )

    async def resolve_a(context: RequestContext) -> UpstreamResult:
        await asyncio.sleep(0.01)
        request = context.request
        response = dns.message.make_response(request)
        response.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "A", "203.0.113.10"))
        return UpstreamResult(
            upstream_name="resolver-a",
            duration_ms=5.0,
            answer=build_answer_from_response(request, response),
            tags=set(),
        )

    async def resolve_b(context: RequestContext) -> UpstreamResult:
        await asyncio.sleep(0.02)
        request = context.request
        response = dns.message.make_response(request)
        response.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "A", "198.51.100.20"))
        return UpstreamResult(
            upstream_name="resolver-b",
            duration_ms=10.0,
            answer=build_answer_from_response(request, response),
            tags={"proxy"},
        )

    engine = PipelineEngine(
        config,
        StaticResolverManager(
            config,
            {
                "resolver-a": resolve_a,
                "resolver-b": resolve_b,
            },
        ),
        DispatcherRegistry(),
        manager,
    )

    response = await engine.handle_message(
        dns.message.make_query("example.test", "A"),
        ("127.0.0.1", 5300),
        "udp",
    )

    assert response is not None
    assert [item.address for item in response.answer[0]] == ["10.10.0.20"]
    assert speedtest_plugin._service.calls == ["203.0.113.10", "10.10.0.20"]


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
    result = UpstreamResult(
        upstream_name="default", duration_ms=1.0, answer=answer, tags={"direct"}
    )

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
        "203.0.113.11",
        "203.0.113.12",
    }
    assert len(answer.response.answer[0]) == 2


@pytest.mark.parametrize(
    ("original_ttl", "configured_ttl", "expected_ttl"),
    [
        (60, 120, 120),
        (300, 120, 300),
    ],
)
async def test_speedtest_plugin_on_response_uses_larger_ttl_when_replacing(
    original_ttl: int,
    configured_ttl: int,
    expected_ttl: int,
    monkeypatch,
) -> None:
    plugin = SpeedTestPlugin()
    plugin.bind(
        SpeedTestPluginConfig(response_ip_limit=1, response_ttl_seconds=configured_ttl),
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
            original_ttl,
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
    assert answer.rrset.ttl == expected_ttl
    assert answer.expiration == pytest.approx(1000.0 + expected_ttl)


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
