from __future__ import annotations

from typing import Awaitable, Callable

import dns.message
import dns.rdatatype
import dns.rrset
import pytest

from dns_forwarder.config import AppConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import (
    RequestContext,
    UpstreamResult,
    build_answer_from_response,
    sync_answer_response,
)
from dns_forwarder.pipeline.engine import PipelineEngine


def build_config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "runtime": {
                "plugin_dirs": ["plugins"],
                "default_upstream_group": "default",
                "loop_policy": "asyncio",
                "log_level": "DEBUG",
            },
            "listeners": [
                {"name": "udp", "protocol": "udp", "host": "127.0.0.1", "port": 0, "enabled": True},
            ],
            "nameservers": [
                {"name": "local-ns", "protocol": "do53", "address": "127.0.0.1", "port": 53},
            ],
            "upstreams": [
                {
                    "name": "upstream-a",
                    "nameservers": ["local-ns"],
                },
            ],
            "groups": [
                {"name": "default", "strategy": "race", "upstreams": ["upstream-a"]},
            ],
            "rules": [],
            "plugins": [],
            "webui": {"enabled": False},
        }
    )


class RecordingPluginManager:
    def __init__(
        self,
        on_request: Callable[[RequestContext], Awaitable[None]] | None = None,
        on_upstream_response: Callable[[RequestContext, UpstreamResult], Awaitable[None]] | None = None,
        on_response: Callable[[RequestContext], Awaitable[None]] | None = None,
    ) -> None:
        self._on_request = on_request
        self._on_upstream_response = on_upstream_response
        self._on_response = on_response
        self.last_context: RequestContext | None = None

    def build_context_extensions(self) -> dict[str, object]:
        return {}

    def build_answer_registry(self) -> dict[str, object]:
        return {}

    async def on_request(self, context: RequestContext) -> None:
        self.last_context = context
        if self._on_request is not None:
            await self._on_request(context)

    async def on_upstream_response(self, context: RequestContext, result: UpstreamResult) -> None:
        self.last_context = context
        if self._on_upstream_response is not None:
            await self._on_upstream_response(context, result)

    async def on_response(self, context: RequestContext) -> None:
        self.last_context = context
        if self._on_response is not None:
            await self._on_response(context)


class StaticResolverManager:
    def __init__(self, config: AppConfig, result: UpstreamResult | None = None) -> None:
        self._groups = {group.name: group for group in config.groups}
        self._result = result or UpstreamResult(
            upstream_name="upstream-a",
            duration_ms=0.0,
            error=RuntimeError("resolver should not be called"),
        )

    def get_group(self, group_name: str):
        return self._groups[group_name]

    def has_group(self, group_name: str) -> bool:
        return group_name in self._groups

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        return self._result


def test_request_context_uses_txid_and_clientaddr() -> None:
    request = dns.message.make_query("example.test", "A")
    context = RequestContext(request=request, clientaddr=("127.0.0.1", 5300), listener_name="udp")

    assert context.request_id == request.id
    assert context.clientaddr == ("127.0.0.1", 5300)


def test_sync_answer_response_replaces_main_rrset_and_keeps_cname() -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 30, "IN", "CNAME", "target.example."))
    response.answer.append(dns.rrset.from_text("target.example.", 30, "IN", "A", "203.0.113.10"))
    answer = build_answer_from_response(request, response)

    answer.rrset = dns.rrset.from_text("target.example.", 120, "IN", "A", "198.51.100.10")
    sync_answer_response(answer)

    assert len(answer.response.answer) == 2
    assert answer.response.answer[0].rdtype == dns.rdatatype.CNAME
    assert answer.response.answer[1][0].address == "198.51.100.10"
    assert answer.rrset is answer.response.answer[1]


def test_sync_answer_response_removes_main_rrset_but_keeps_other_rrsets() -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 30, "IN", "CNAME", "target.example."))
    response.answer.append(dns.rrset.from_text("target.example.", 30, "IN", "A", "203.0.113.10"))
    answer = build_answer_from_response(request, response)

    answer.rrset = None
    sync_answer_response(answer)

    assert len(answer.response.answer) == 1
    assert answer.response.answer[0].rdtype == dns.rdatatype.CNAME
    assert answer.rrset is None


def test_sync_answer_response_rejects_mismatched_rrset_type() -> None:
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 30, "IN", "A", "203.0.113.10"))
    answer = build_answer_from_response(request, response)

    answer.rrset = dns.rrset.from_text("example.test.", 30, "IN", "AAAA", "2001:db8::1")

    with pytest.raises(ValueError):
        sync_answer_response(answer)


async def test_pipeline_builds_final_answer_from_plugin_response(
    capture_dns_logs,
    caplog,
) -> None:
    capture_dns_logs("DEBUG")
    config = build_config()
    request = dns.message.make_query("sample.internal", "A")

    async def plugin_on_request(context: RequestContext) -> None:
        response = dns.message.make_response(context.request)
        response.answer.append(
            dns.rrset.from_text(
                "sample.internal.",
                30,
                "IN",
                "A",
                "127.0.0.2",
            )
        )
        context.final_response = response

    plugin_manager = RecordingPluginManager(on_request=plugin_on_request)
    resolver_manager = StaticResolverManager(config)
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")

    assert response is not None
    assert response.answer[0][0].address == "127.0.0.2"
    assert plugin_manager.last_context is not None
    assert plugin_manager.last_context.request_id == request.id
    assert plugin_manager.last_context.clientaddr == ("127.0.0.1", 10000)
    assert plugin_manager.last_context.final_answer is not None
    assert plugin_manager.last_context.final_answer[0].address == "127.0.0.2"
    assert "收到 DNS 请求" in caplog.text
    assert "请求处理完成" in caplog.text


async def test_pipeline_builds_final_response_from_upstream_answer() -> None:
    config = build_config()
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            "example.test.",
            60,
            "IN",
            "A",
            "203.0.113.30",
        )
    )
    answer = build_answer_from_response(request, response)
    plugin_manager = RecordingPluginManager()
    resolver_manager = StaticResolverManager(
        config,
        UpstreamResult(upstream_name="upstream-a", duration_ms=5.0, answer=answer),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    final_response = await engine.handle_message(request, ("127.0.0.1", 20000), "udp")

    assert final_response is not None
    assert final_response.answer[0][0].address == "203.0.113.30"
    assert plugin_manager.last_context is not None
    assert plugin_manager.last_context.final_answer is answer
    assert plugin_manager.last_context.final_response is not None
    assert plugin_manager.last_context.final_response.answer[0][0].address == "203.0.113.30"


async def test_pipeline_syncs_rrset_change_from_on_upstream_response() -> None:
    config = build_config()
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "A", "203.0.113.30"))
    answer = build_answer_from_response(request, response)

    async def plugin_on_upstream_response(context: RequestContext, result: UpstreamResult) -> None:
        assert result.answer is not None
        result.answer.rrset = dns.rrset.from_text("example.test.", 90, "IN", "A", "198.51.100.7")

    plugin_manager = RecordingPluginManager(on_upstream_response=plugin_on_upstream_response)
    resolver_manager = StaticResolverManager(
        config,
        UpstreamResult(upstream_name="upstream-a", duration_ms=5.0, answer=answer),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    final_response = await engine.handle_message(request, ("127.0.0.1", 20000), "udp")

    assert final_response is not None
    assert final_response.answer[0][0].address == "198.51.100.7"
    assert plugin_manager.last_context is not None
    assert plugin_manager.last_context.final_answer is answer
    assert plugin_manager.last_context.final_answer.response.answer[0][0].address == "198.51.100.7"


async def test_pipeline_syncs_rrset_change_from_on_response() -> None:
    config = build_config()
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "A", "203.0.113.30"))
    answer = build_answer_from_response(request, response)

    async def plugin_on_response(context: RequestContext) -> None:
        assert context.final_answer is not None
        context.final_answer.rrset = dns.rrset.from_text("example.test.", 120, "IN", "A", "192.0.2.55")

    plugin_manager = RecordingPluginManager(on_response=plugin_on_response)
    resolver_manager = StaticResolverManager(
        config,
        UpstreamResult(upstream_name="upstream-a", duration_ms=5.0, answer=answer),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    final_response = await engine.handle_message(request, ("127.0.0.1", 20000), "udp")

    assert final_response is not None
    assert final_response.answer[0][0].address == "192.0.2.55"
    assert plugin_manager.last_context is not None
    assert plugin_manager.last_context.final_answer is answer
    assert plugin_manager.last_context.final_answer.response.answer[0][0].address == "192.0.2.55"


async def test_pipeline_supports_nested_dispatch_groups() -> None:
    config = AppConfig.model_validate(
        {
            "runtime": {
                "plugin_dirs": ["plugins"],
                "default_upstream_group": "default",
                "loop_policy": "asyncio",
                "log_level": "DEBUG",
            },
            "listeners": [
                {"name": "udp", "protocol": "udp", "host": "127.0.0.1", "port": 0, "enabled": True},
            ],
            "nameservers": [
                {"name": "local-ns", "protocol": "do53", "address": "127.0.0.1", "port": 53},
            ],
            "upstreams": [
                {
                    "name": "upstream-a",
                    "nameservers": ["local-ns"],
                },
            ],
            "groups": [
                {"name": "default", "strategy": "race", "upstreams": ["nested"]},
                {"name": "nested", "strategy": "race", "upstreams": ["upstream-a"]},
            ],
            "rules": [],
            "plugins": [],
            "webui": {"enabled": False},
        }
    )
    request = dns.message.make_query("example.test", "A")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "A", "203.0.113.88"))
    answer = build_answer_from_response(request, response)
    plugin_manager = RecordingPluginManager()
    resolver_manager = StaticResolverManager(
        config,
        UpstreamResult(upstream_name="upstream-a", duration_ms=5.0, answer=answer),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    final_response = await engine.handle_message(request, ("127.0.0.1", 20000), "udp")

    assert final_response is not None
    assert final_response.answer[0][0].address == "203.0.113.88"
    assert plugin_manager.last_context is not None
    assert plugin_manager.last_context.upstream_results[0].upstream_name == "upstream-a"
