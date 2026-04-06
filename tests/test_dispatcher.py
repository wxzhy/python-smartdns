from __future__ import annotations

import asyncio
from unittest.mock import Mock

import dns.message
import dns.resolver

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult


class StubResolverManager:
    def __init__(
        self,
        handlers: dict[str, object],
        groups: list[UpstreamGroupConfig] | None = None,
    ) -> None:
        self.handlers = handlers
        self.groups = {group.name: group for group in groups or []}
        self.calls: list[str] = []

    def get_group(self, group_name: str) -> UpstreamGroupConfig:
        return self.groups[group_name]

    def has_group(self, group_name: str) -> bool:
        return group_name in self.groups

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        self.calls.append(upstream_name)
        handler = self.handlers[upstream_name]
        if callable(handler):
            return await handler(context)
        return handler


def _success(
    name: str,
    *,
    delay: float = 0.0,
    duration_ms: float | None = None,
) -> object:
    async def inner(context: RequestContext) -> UpstreamResult:
        if delay:
            await asyncio.sleep(delay)
        answer = Mock(spec=dns.resolver.Answer)
        answer.response = dns.message.make_response(context.request)
        return UpstreamResult(
            upstream_name=name,
            duration_ms=duration_ms if duration_ms is not None else delay * 1000,
            answer=answer,
        )

    return inner


def _failure(name: str, delay: float = 0.0) -> object:
    async def inner(context: RequestContext) -> UpstreamResult:
        if delay:
            await asyncio.sleep(delay)
        return UpstreamResult(
            upstream_name=name,
            duration_ms=delay * 1000,
            error=RuntimeError(f"{name} failed"),
        )

    return inner


def _nxdomain(name: str, delay: float = 0.0) -> object:
    async def inner(context: RequestContext) -> UpstreamResult:
        if delay:
            await asyncio.sleep(delay)
        return UpstreamResult(
            upstream_name=name,
            duration_ms=delay * 1000,
            error=dns.resolver.NXDOMAIN(),
        )

    return inner


def _raising(name: str, delay: float = 0.0) -> object:
    async def inner(context: RequestContext) -> UpstreamResult:
        if delay:
            await asyncio.sleep(delay)
        raise RuntimeError(f"{name} exploded")

    return inner


def _build_context(qtype: str = "A") -> RequestContext:
    return RequestContext(
        request=dns.message.make_query("example.test", qtype),
        clientaddr=("127.0.0.1", 1),
        listener_name="udp",
    )


async def test_sequential_dispatcher_falls_back_only_on_error() -> None:
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(name="default", strategy=DispatchStrategyType.SEQUENTIAL, upstreams=["a", "b"])
    manager = StubResolverManager(
        {
            "a": _failure("a"),
            "b": _success("b"),
        }
    )

    result = await registry.dispatch_group(_build_context(), group, manager)

    assert result.upstream_name == "b"
    assert result.answer is not None


async def test_race_dispatcher_ignores_failure_until_success_arrives() -> None:
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(name="default", strategy=DispatchStrategyType.RACE, upstreams=["boom", "ok"])
    manager = StubResolverManager(
        {
            "boom": _raising("boom", delay=0.01),
            "ok": _success("ok", delay=0.03),
        }
    )

    result = await registry.dispatch_group(_build_context(), group, manager)

    assert result.upstream_name == "ok"
    assert result.answer is not None


async def test_sequential_dispatcher_stops_on_nested_nxdomain() -> None:
    registry = DispatcherRegistry()
    nested = UpstreamGroupConfig(
        name="nested",
        strategy=DispatchStrategyType.SEQUENTIAL,
        upstreams=["nx", "ok"],
    )
    parent = UpstreamGroupConfig(
        name="default",
        strategy=DispatchStrategyType.SEQUENTIAL,
        upstreams=["nested", "fallback"],
    )
    manager = StubResolverManager(
        {
            "nx": _nxdomain("nx"),
            "ok": _success("ok"),
            "fallback": _success("fallback"),
        },
        groups=[nested],
    )

    result = await registry.dispatch_group(_build_context(), parent, manager)

    assert isinstance(result.error, dns.resolver.NXDOMAIN)
    assert manager.calls == ["nx"]


async def test_wait_all_dispatcher_returns_fastest_success_by_duration() -> None:
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(
        name="default",
        strategy=DispatchStrategyType.WAIT_ALL,
        upstreams=["slow-finish-fast-rtt", "fast-finish-slow-rtt"],
    )
    manager = StubResolverManager(
        {
            "slow-finish-fast-rtt": _success("slow-finish-fast-rtt", delay=0.05, duration_ms=5.0),
            "fast-finish-slow-rtt": _success("fast-finish-slow-rtt", delay=0.01, duration_ms=20.0),
        }
    )

    result = await registry.dispatch_group(_build_context(), group, manager)

    assert result.upstream_name == "slow-finish-fast-rtt"


async def test_wait_all_dispatcher_prefers_success_over_errors_and_exceptions() -> None:
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(
        name="default",
        strategy=DispatchStrategyType.WAIT_ALL,
        upstreams=["error", "boom", "nx", "ok"],
    )
    manager = StubResolverManager(
        {
            "error": _failure("error", delay=0.01),
            "boom": _raising("boom", delay=0.02),
            "nx": _nxdomain("nx", delay=0.03),
            "ok": _success("ok", delay=0.04, duration_ms=8.0),
        }
    )

    result = await registry.dispatch_group(_build_context(), group, manager)

    assert result.upstream_name == "ok"
    assert result.answer is not None


async def test_wait_all_dispatcher_returns_nxdomain_when_no_success() -> None:
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(
        name="default",
        strategy=DispatchStrategyType.WAIT_ALL,
        upstreams=["error", "nx", "boom"],
    )
    manager = StubResolverManager(
        {
            "error": _failure("error", delay=0.01),
            "nx": _nxdomain("nx", delay=0.02),
            "boom": _raising("boom", delay=0.03),
        }
    )

    result = await registry.dispatch_group(_build_context(), group, manager)

    assert isinstance(result.error, dns.resolver.NXDOMAIN)


async def test_sequential_dispatcher_emits_fallback_debug_log(capture_dns_logs, caplog) -> None:
    capture_dns_logs("DEBUG")
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(name="default", strategy=DispatchStrategyType.SEQUENTIAL, upstreams=["a", "b"])
    manager = StubResolverManager(
        {
            "a": _failure("a"),
            "b": _success("b"),
        }
    )

    result = await registry.dispatch_group(_build_context(), group, manager)

    assert result.upstream_name == "b"
    assert "顺序调度回退" in caplog.text
