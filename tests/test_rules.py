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
    def __init__(self, request_tags: set[str] | None = None) -> None:
        self.last_context: RequestContext | None = None
        self._request_tags = set() if request_tags is None else set(request_tags)

    def build_context_extensions(self) -> dict[str, object]:
        return {}

    def build_answer_registry(self) -> dict[str, object]:
        return {}

    async def on_request(self, context: RequestContext) -> None:
        self.last_context = context
        context.tags.update(self._request_tags)

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


def _build_context(qname: str, qtype: str = "A", *, tags: set[str] | None = None) -> RequestContext:
    return RequestContext(
        request=dns.message.make_query(qname, qtype),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags=set() if tags is None else set(tags),
    )


def test_rule_engine_returns_default_group_when_no_rule_matches() -> None:
    rule = RuleConfig.model_validate(
        {
            "name": "only-txt",
            "match": {
                "match_tags": ["proxy"],
            },
            "action": {
                "dispatcher": "wait_all",
            },
        }
    )
    engine = RuleEngine([rule], "default")

    selection = engine.select(_build_context("www.example.org", "A", tags={"direct"}))

    assert selection.rule_name is None
    assert selection.upstream_group == "default"
    assert selection.dispatcher is None


def test_rule_engine_allows_dispatcher_override_without_group_override() -> None:
    rule = RuleConfig.model_validate(
        {
            "name": "wait-addresses",
            "match": {
                "match_tags": ["proxy"],
            },
            "action": {
                "dispatcher": "wait_all",
            },
        }
    )
    engine = RuleEngine([rule], "default")

    selection = engine.select(_build_context("www.example.org", "A", tags={"proxy"}))

    assert selection.rule_name == "wait-addresses"
    assert selection.upstream_group == "default"
    assert selection.dispatcher is DispatchStrategyType.WAIT_ALL


def test_rule_engine_matches_tags_with_any_of_semantics() -> None:
    rule = RuleConfig.model_validate(
        {
            "name": "tagged-traffic",
            "match": {
                "match_tags": ["proxy", "domestic"],
            },
            "action": {
                "dispatcher": "wait_all",
            },
        }
    )
    engine = RuleEngine([rule], "default")

    selection = engine.select(_build_context("www.example.org", "A", tags={"domestic"}))

    assert selection.rule_name == "tagged-traffic"
    assert selection.dispatcher is DispatchStrategyType.WAIT_ALL


def test_rule_engine_ignores_ip_only_tags_not_present_on_request_context() -> None:
    rule = RuleConfig.model_validate(
        {
            "name": "ip-tag-only",
            "match": {
                "match_tags": ["from-ipset"],
            },
            "action": {
                "dispatcher": "wait_all",
            },
        }
    )
    engine = RuleEngine([rule], "default")

    selection = engine.select(_build_context("www.example.org", "A"))

    assert selection.rule_name is None
    assert selection.dispatcher is None


def test_rule_engine_honors_exclude_tags() -> None:
    rule = RuleConfig.model_validate(
        {
            "name": "proxy-only",
            "match": {
                "match_tags": ["proxy"],
                "exclude_tags": ["direct"],
            },
            "action": {
                "dispatcher": "wait_all",
            },
        }
    )
    engine = RuleEngine([rule], "default")

    selection = engine.select(_build_context("www.example.org", "A", tags={"proxy", "direct"}))

    assert selection.rule_name is None
    assert selection.dispatcher is None


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
            "nameservers": [
                {"name": "ns-slow", "protocol": "do53", "address": "127.0.0.1", "port": 53},
                {"name": "ns-fast", "protocol": "do53", "address": "127.0.0.1", "port": 54},
            ],
            "upstreams": [
                {"name": "slow-finish-fast-rtt", "nameservers": ["ns-slow"]},
                {"name": "fast-finish-slow-rtt", "nameservers": ["ns-fast"]},
            ],
            "groups": [
                {
                    "name": "default",
                    "upstreams": ["slow-finish-fast-rtt", "fast-finish-slow-rtt"],
                },
            ],
            "rules": [
                {
                    "name": "wait-a-records",
                    "enabled": True,
                    "match": {
                        "match_tags": ["wait-all"],
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
    plugin_manager = NullPluginManager({"wait-all"})
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
