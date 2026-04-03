from __future__ import annotations

import asyncio
from unittest.mock import Mock

import dns.message
import dns.resolver

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult


class StubResolverManager:
    def __init__(self, handlers: dict[str, object]) -> None:
        self.handlers = handlers

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        handler = self.handlers[upstream_name]
        if callable(handler):
            return await handler(context)
        return handler


async def _success(name: str, delay: float = 0.0) -> object:
    async def inner(context: RequestContext) -> UpstreamResult:
        if delay:
            await asyncio.sleep(delay)
        answer = Mock(spec=dns.resolver.Answer)
        answer.response = dns.message.make_response(context.request)
        return UpstreamResult(
            upstream_name=name,
            duration_ms=delay * 1000,
            answer=answer,
        )

    return inner


async def _failure(name: str, delay: float = 0.0) -> object:
    async def inner(context: RequestContext) -> UpstreamResult:
        if delay:
            await asyncio.sleep(delay)
        return UpstreamResult(
            upstream_name=name,
            duration_ms=delay * 1000,
            error=RuntimeError(f"{name} failed"),
        )

    return inner


async def test_sequential_dispatcher_falls_back_only_on_error() -> None:
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(name="default", strategy=DispatchStrategyType.SEQUENTIAL, upstreams=["a", "b"])
    manager = StubResolverManager(
        {
            "a": await _failure("a"),
            "b": await _success("b"),
        }
    )
    context = RequestContext(
        request=dns.message.make_query("example.test", "A"),
        clientaddr=("127.0.0.1", 1),
        listener_name="udp",
    )

    result = await registry.get(group.strategy).dispatch(context, group, manager)

    assert result.upstream_name == "b"
    assert result.answer is not None


async def test_race_dispatcher_returns_first_success() -> None:
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(name="default", strategy=DispatchStrategyType.RACE, upstreams=["slow", "fast"])
    manager = StubResolverManager(
        {
            "slow": await _success("slow", delay=0.05),
            "fast": await _success("fast", delay=0.01),
        }
    )
    context = RequestContext(
        request=dns.message.make_query("example.test", "A"),
        clientaddr=("127.0.0.1", 1),
        listener_name="udp",
    )

    result = await registry.get(group.strategy).dispatch(context, group, manager)

    assert result.upstream_name == "fast"


async def test_sequential_dispatcher_stops_on_nxdomain() -> None:
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(name="default", strategy=DispatchStrategyType.SEQUENTIAL, upstreams=["a", "b"])
    manager = StubResolverManager(
        {
            "a": UpstreamResult(
                upstream_name="a",
                duration_ms=1,
                error=dns.resolver.NXDOMAIN(),
            ),
            "b": await _success("b"),
        }
    )
    context = RequestContext(
        request=dns.message.make_query("missing.test", "A"),
        clientaddr=("127.0.0.1", 1),
        listener_name="udp",
    )

    result = await registry.get(group.strategy).dispatch(context, group, manager)

    assert isinstance(result.error, dns.resolver.NXDOMAIN)


async def test_race_dispatcher_prefers_answer_over_nxdomain() -> None:
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(name="default", strategy=DispatchStrategyType.RACE, upstreams=["nx", "ok"])
    manager = StubResolverManager(
        {
            "nx": UpstreamResult(
                upstream_name="nx",
                duration_ms=1,
                error=dns.resolver.NXDOMAIN(),
            ),
            "ok": await _success("ok", delay=0.01),
        }
    )
    context = RequestContext(
        request=dns.message.make_query("example.test", "A"),
        clientaddr=("127.0.0.1", 1),
        listener_name="udp",
    )

    result = await registry.get(group.strategy).dispatch(context, group, manager)

    assert result.upstream_name == "ok"


async def test_sequential_dispatcher_emits_fallback_debug_log(capture_dns_logs, caplog) -> None:
    capture_dns_logs("DEBUG")
    registry = DispatcherRegistry()
    group = UpstreamGroupConfig(name="default", strategy=DispatchStrategyType.SEQUENTIAL, upstreams=["a", "b"])
    manager = StubResolverManager(
        {
            "a": await _failure("a"),
            "b": await _success("b"),
        }
    )
    context = RequestContext(
        request=dns.message.make_query("example.test", "A"),
        clientaddr=("127.0.0.1", 1),
        listener_name="udp",
    )

    result = await registry.get(group.strategy).dispatch(context, group, manager)

    assert result.upstream_name == "b"
    assert "顺序调度回退" in caplog.text
