from __future__ import annotations

from typing import Awaitable, Callable

import dns.message
import dns.rrset

from dns_forwarder.config import AppConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
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
            "upstreams": [
                {
                    "name": "upstream-a",
                    "protocol": "do53",
                    "host": "127.0.0.1",
                    "port": 53,
                },
            ],
            "groups": [
                {"name": "default", "strategy": "sequential", "upstreams": ["upstream-a"]},
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
        on_response: Callable[[RequestContext], Awaitable[None]] | None = None,
    ) -> None:
        self._on_request = on_request
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

    async def on_response(self, context: RequestContext) -> None:
        self.last_context = context
        if self._on_response is not None:
            await self._on_response(context)


class StaticResolverManager:
    def __init__(self, config: AppConfig, result: UpstreamResult | None = None) -> None:
        self._group = config.groups[0]
        self._result = result or UpstreamResult(
            upstream_name="upstream-a",
            duration_ms=0.0,
            error=RuntimeError("resolver should not be called"),
        )

    def get_group(self, group_name: str):
        return self._group

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        return self._result


def test_request_context_uses_txid_and_clientaddr() -> None:
    request = dns.message.make_query("example.test", "A")
    context = RequestContext(request=request, clientaddr=("127.0.0.1", 5300), listener_name="udp")

    assert context.request_id == request.id
    assert context.clientaddr == ("127.0.0.1", 5300)


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
