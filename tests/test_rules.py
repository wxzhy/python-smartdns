from __future__ import annotations

import asyncio

import dns.message
import dns.rrset

from dns_forwarder.config import AppConfig, DispatchStrategyType, RuleConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.rules import RuleEngine


class NullPluginManager:
    def __init__(self) -> None:
        self.last_context: RequestContext | None = None

    def build_context_extensions(self) -> dict[str, object]:
        return {}

    def build_answer_registry(self) -> dict[str, object]:
        return {}

    async def on_request(self, context: RequestContext) -> None:
        self.last_context = context

    async def on_upstream_response(self, context: RequestContext, result: UpstreamResult) -> None:
        self.last_context = context

    async def on_response(self, context: RequestContext) -> None:
        self.last_context = context


class StubResolverManager:
    def __init__(self, config: AppConfig, handlers: dict[str, object]) -> None:
        self._groups = {group.name: group for group in config.groups}
        self._handlers = handlers

    def get_group(self, group_name: str):
        return self._groups[group_name]

    def has_group(self, group_name: str) -> bool:
        return group_name in self._groups

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        handler = self._handlers[upstream_name]
        return await handler(context)


def _success(name: str, address: str, *, delay: float, duration_ms: float) -> object:
    async def inner(context: RequestContext) -> UpstreamResult:
        if delay:
            await asyncio.sleep(delay)
        response = dns.message.make_response(context.request)
        response.answer.append(
            dns.rrset.from_text(
                context.request.question[0].name.to_text(),
                60,
                "IN",
                "A",
                address,
            )
        )
        return UpstreamResult(
            upstream_name=name,
            duration_ms=duration_ms,
            answer=build_answer_from_response(context.request, response),
        )

    return inner


def test_rule_engine_returns_default_group_when_no_rule_matches() -> None:
    rule = RuleConfig.model_validate(
        {
            "name": "only-txt",
            "match": {
                "exact_domains": [],
                "suffix_domains": ["example.org"],
                "qtypes": ["TXT"],
            },
            "action": {
                "dispatcher": "wait_all",
            },
        }
    )
    engine = RuleEngine([rule], "default")

    selection = engine.select(dns.message.make_query("www.example.org", "A"))

    assert selection.rule_name is None
    assert selection.upstream_group == "default"
    assert selection.dispatcher is None


def test_rule_engine_allows_dispatcher_override_without_group_override() -> None:
    rule = RuleConfig.model_validate(
        {
            "name": "wait-addresses",
            "match": {
                "exact_domains": [],
                "suffix_domains": ["example.org"],
                "qtypes": ["A", "AAAA"],
            },
            "action": {
                "dispatcher": "wait_all",
            },
        }
    )
    engine = RuleEngine([rule], "default")

    selection = engine.select(dns.message.make_query("www.example.org", "A"))

    assert selection.rule_name == "wait-addresses"
    assert selection.upstream_group == "default"
    assert selection.dispatcher is DispatchStrategyType.WAIT_ALL


async def test_pipeline_uses_dispatcher_override_from_matched_rule() -> None:
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
            "upstreams": [
                {"name": "slow-finish-fast-rtt", "protocol": "do53", "host": "127.0.0.1", "port": 53},
                {"name": "fast-finish-slow-rtt", "protocol": "do53", "host": "127.0.0.1", "port": 54},
            ],
            "groups": [
                {
                    "name": "default",
                    "strategy": "race",
                    "upstreams": ["slow-finish-fast-rtt", "fast-finish-slow-rtt"],
                },
            ],
            "rules": [
                {
                    "name": "wait-a-records",
                    "enabled": True,
                    "match": {
                        "exact_domains": [],
                        "suffix_domains": ["example.org"],
                        "qtypes": ["A"],
                    },
                    "action": {
                        "dispatcher": "wait_all",
                    },
                }
            ],
            "plugins": [],
            "webui": {"enabled": False},
        }
    )
    resolver_manager = StubResolverManager(
        config,
        {
            "slow-finish-fast-rtt": _success(
                "slow-finish-fast-rtt",
                "203.0.113.10",
                delay=0.05,
                duration_ms=5.0,
            ),
            "fast-finish-slow-rtt": _success(
                "fast-finish-slow-rtt",
                "203.0.113.20",
                delay=0.01,
                duration_ms=20.0,
            ),
        },
    )
    plugin_manager = NullPluginManager()
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    response = await engine.handle_message(
        dns.message.make_query("www.example.org", "A"),
        ("127.0.0.1", 5300),
        "udp",
    )

    assert response is not None
    assert response.answer[0][0].address == "203.0.113.10"
    assert plugin_manager.last_context is not None
    assert plugin_manager.last_context.selected_rule == "wait-a-records"
    assert plugin_manager.last_context.selected_group == "default"
    assert plugin_manager.last_context.selected_dispatcher == "wait_all"
