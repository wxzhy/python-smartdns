from __future__ import annotations

from typing import TYPE_CHECKING

import dns.message
import dns.rrset
import pytest
from pydantic import ValidationError

from dns_forwarder.config import AppConfig, PluginConfig
from dns_forwarder.core import DOMAINSET_CONTEXT_KEY, DomainSet
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import EmptyModel, LoadedPlugin, Plugin, PluginManager, PluginRegistry
from plugins.block_plugin import BlockPlugin, BlockPluginConfig, BlockPluginRuleConfig
from plugins.tag_plugin import TagPlugin

if TYPE_CHECKING:
    from pathlib import Path


_BLOCK_TTL_LONG = 7200
_BLOCK_TTL_SHORT = 600


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_config() -> AppConfig:
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
                {"name": "local-ns", "protocol": "do53", "address": "127.0.0.1", "port": 53},
            ],
            "upstreams": [
                {
                    "name": "upstream-a",
                    "nameservers": ["local-ns"],
                },
            ],
            "groups": [
                {"name": "default", "upstreams": ["upstream-a"]},
            ],
            "rules": [],
            "plugins": [],
            "webui": {"enabled": False},
        }
    )


class CountingResolverManager:
    def __init__(self, config: AppConfig, result: UpstreamResult) -> None:
        self._groups = {group.name: group for group in config.groups}
        self._result = result
        self.calls = 0

    def get_group(self, group_name: str):
        return self._groups[group_name]

    def has_group(self, group_name: str) -> bool:
        return group_name in self._groups

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        self.calls += 1
        return self._result


def make_answer(request: dns.message.Message, qtype: str, *items: str):
    response = dns.message.make_response(request)
    if items:
        response.answer.append(
            dns.rrset.from_text(
                request.question[0].name.to_text(),
                60,
                "IN",
                qtype,
                *items,
            )
        )
    return build_answer_from_response(request, response)


def answer_addresses(answer) -> list[str]:
    if answer is None or answer.rrset is None:
        return []
    return [item.address for item in answer.rrset]


def build_plugin(*rules: BlockPluginRuleConfig) -> BlockPlugin:
    plugin = BlockPlugin()
    plugin.bind(
        BlockPluginConfig(rules=list(rules)),
        plugin.variables_model(),
    )
    return plugin


def build_rule(
    *,
    match_tags: list[str],
    addresses: dict[str, list[str]] | None = None,
    exclude_tags: list[str] | None = None,
    block_other: bool = False,
    response_ttl_seconds: int = 86400,
) -> BlockPluginRuleConfig:
    resolved = {} if addresses is None else dict(addresses)
    return BlockPluginRuleConfig(
        match_tags=match_tags,
        exclude_tags=[] if exclude_tags is None else exclude_tags,
        ipv4_addresses=resolved.get("ipv4", []),
        ipv6_addresses=resolved.get("ipv6", []),
        block_other=block_other,
        response_ttl_seconds=response_ttl_seconds,
    )


class RequestTaggingPlugin(Plugin):
    config_model = EmptyModel
    variables_model = EmptyModel

    def __init__(self, tags: set[str]) -> None:
        super().__init__()
        self.name = "request-tagging-plugin"
        self.request_order = -100
        self._tags = set(tags)

    async def on_request(self, context: RequestContext) -> None:
        context.tags.update(self._tags)


class RecordingPlugin(Plugin):
    config_model = EmptyModel
    variables_model = EmptyModel

    def __init__(self, name: str, *, request_order: int = 0, response_order: int = 0) -> None:
        super().__init__()
        self.name = name
        self.request_order = request_order
        self.response_order = response_order
        self.request_calls = 0
        self.response_calls = 0

    async def on_request(self, context: RequestContext) -> None:
        self.request_calls += 1

    async def on_response(self, context: RequestContext) -> None:
        self.response_calls += 1


def make_loaded_plugin(instance: Plugin) -> LoadedPlugin:
    return LoadedPlugin(
        instance=instance,
        config=instance.runtime_config,
        variables=instance.runtime_variables,
        raw_config=PluginConfig(name=instance.name, module=instance.name),
    )


def test_block_plugin_rule_config_requires_at_least_one_address_family() -> None:
    with pytest.raises(ValidationError, match="至少需要一个 IPv4、IPv6 地址或启用 block_other"):
        BlockPluginRuleConfig(match_tags=["blackhole"])


def test_block_plugin_rule_config_rejects_wrong_address_family() -> None:
    with pytest.raises(ValidationError, match="IPv4"):
        BlockPluginRuleConfig(match_tags=["blackhole"], ipv4_addresses=["::1"])


def test_block_plugin_rule_config_allows_block_other_without_address_family() -> None:
    rule = BlockPluginRuleConfig(match_tags=["blackhole"], block_other=True)

    assert rule.block_other is True
    assert rule.ipv4_addresses == []
    assert rule.ipv6_addresses == []


async def test_block_plugin_short_circuits_request_for_a() -> None:
    plugin = build_plugin(
        build_rule(
            match_tags=["blackhole"],
            addresses={"ipv4": ["127.0.0.1", "127.0.0.2"]},
            response_ttl_seconds=_BLOCK_TTL_LONG,
        )
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    context = RequestContext(
        request=dns.message.make_query("example.test", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"blackhole"},
    )

    await plugin.on_request(context)

    assert context.final_response is not None
    assert context.final_response.rcode() == 0
    assert context.final_answer is not None
    assert context.final_answer.rrset is not None
    assert set(answer_addresses(context.final_answer)) == {"127.0.0.1", "127.0.0.2"}
    assert context.final_answer.rrset.ttl == _BLOCK_TTL_LONG
    assert context.stop_processing is True


async def test_block_plugin_short_circuits_request_for_aaaa() -> None:
    plugin = build_plugin(
        build_rule(match_tags=["blackhole"], addresses={"ipv6": ["::1", "2001:db8::1"]})
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    context = RequestContext(
        request=dns.message.make_query("example.test", "AAAA"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"blackhole"},
    )

    await plugin.on_request(context)

    assert context.final_answer is not None
    assert context.final_answer.rrset is not None
    assert set(answer_addresses(context.final_answer)) == {"::1", "2001:db8::1"}


async def test_block_plugin_skips_non_address_query() -> None:
    plugin = build_plugin(
        build_rule(
            match_tags=["blackhole"],
            addresses={"ipv4": ["127.0.0.1"], "ipv6": ["::1"]},
        )
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    context = RequestContext(
        request=dns.message.make_query("example.test", "TXT"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"blackhole"},
    )

    await plugin.on_request(context)

    assert context.final_response is None
    assert context.final_answer is None


async def test_block_plugin_blocks_non_address_query_when_block_other_enabled() -> None:
    plugin = build_plugin(
        build_rule(
            match_tags=["blackhole"],
            block_other=True,
        )
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    context = RequestContext(
        request=dns.message.make_query("example.test", "TXT"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"blackhole"},
    )

    await plugin.on_request(context)

    assert context.final_response is not None
    assert context.final_response.rcode() == 0
    assert context.final_response.answer == []
    assert context.final_answer is not None
    assert context.final_answer.rrset is None
    assert context.stop_processing is True


async def test_block_plugin_rewrites_final_response_for_matching_result_tags() -> None:
    plugin = build_plugin(
        build_rule(
            match_tags=["blackhole"],
            addresses={"ipv4": ["127.0.0.1", "127.0.0.2"]},
            response_ttl_seconds=_BLOCK_TTL_SHORT,
        )
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    request = dns.message.make_query("example.test", "A")
    answer = make_answer(request, "A", "203.0.113.10")
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        final_answer=answer,
        final_response=answer.response,
        upstream_results=[
            UpstreamResult(
                upstream_name="upstream-a", duration_ms=1.0, answer=answer, tags={"blackhole"}
            )
        ],
    )

    await plugin.on_response(context)

    assert context.final_answer is not None
    assert context.final_answer.rrset is not None
    assert set(answer_addresses(context.final_answer)) == {"127.0.0.1", "127.0.0.2"}
    assert context.final_answer.rrset.ttl == _BLOCK_TTL_SHORT
    assert context.stop_processing is True


async def test_block_plugin_rewrites_non_address_response_to_empty_noerror_when_block_other_enabled() -> (  # noqa: E501
    None
):
    plugin = build_plugin(
        build_rule(
            match_tags=["blackhole"],
            block_other=True,
        )
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    request = dns.message.make_query("example.test", "TXT")
    answer = make_answer(request, "TXT", '"hello"')
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        final_answer=answer,
        final_response=answer.response,
        upstream_results=[
            UpstreamResult(
                upstream_name="upstream-a", duration_ms=1.0, answer=answer, tags={"blackhole"}
            )
        ],
    )

    await plugin.on_response(context)

    assert context.final_response is not None
    assert context.final_response.rcode() == 0
    assert context.final_response.answer == []
    assert context.final_answer is not None
    assert context.final_answer.rrset is None
    assert context.stop_processing is True


async def test_block_plugin_honors_exclude_tags() -> None:
    plugin = build_plugin(
        build_rule(
            match_tags=["blackhole"],
            addresses={"ipv4": ["127.0.0.1"]},
            exclude_tags=["direct"],
        )
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    context = RequestContext(
        request=dns.message.make_query("example.test", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"blackhole", "direct"},
    )

    await plugin.on_request(context)

    assert context.final_response is None
    assert context.final_answer is None


async def test_block_plugin_uses_first_rule_with_current_qtype_values() -> None:
    plugin = build_plugin(
        build_rule(match_tags=["proxy"], addresses={"ipv6": ["fd00::1"]}),
        build_rule(match_tags=["proxy"], addresses={"ipv4": ["127.0.0.8"]}),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    context = RequestContext(
        request=dns.message.make_query("example.test", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"proxy"},
    )

    await plugin.on_request(context)

    assert context.final_answer is not None
    assert answer_addresses(context.final_answer) == ["127.0.0.8"]


async def test_block_plugin_uses_later_block_other_rule_for_non_address_query() -> None:
    plugin = build_plugin(
        build_rule(match_tags=["proxy"], addresses={"ipv4": ["127.0.0.8"]}),
        build_rule(match_tags=["proxy"], block_other=True),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    context = RequestContext(
        request=dns.message.make_query("example.test", "TXT"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"proxy"},
    )

    await plugin.on_request(context)

    assert context.final_response is not None
    assert context.final_response.rcode() == 0
    assert context.final_response.answer == []


async def test_block_plugin_uses_first_matching_rule_when_multiple_have_current_qtype() -> None:
    plugin = build_plugin(
        build_rule(match_tags=["proxy"], addresses={"ipv4": ["127.0.0.10"]}),
        build_rule(match_tags=["proxy"], addresses={"ipv4": ["127.0.0.20"]}),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    context = RequestContext(
        request=dns.message.make_query("example.test", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags={"proxy"},
    )

    await plugin.on_request(context)

    assert context.final_answer is not None
    assert answer_addresses(context.final_answer) == ["127.0.0.10"]


async def test_block_plugin_works_after_tag_plugin_in_request_phase(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    domain_dir.mkdir()
    _write_lines(domain_dir / "blackhole.txt", ["example.test"])

    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, DomainSet(str(domain_dir)))

    tag_plugin = TagPlugin()
    tag_plugin.bind(tag_plugin.config_model(), tag_plugin.variables_model())
    await tag_plugin.setup(registry)

    block_plugin = build_plugin(
        build_rule(match_tags=["blackhole"], addresses={"ipv4": ["127.0.0.1"]})
    )
    await block_plugin.setup(registry)

    plugin_manager = PluginManager(
        [
            LoadedPlugin(
                instance=tag_plugin,
                config=tag_plugin.runtime_config,
                variables=tag_plugin.runtime_variables,
                raw_config=PluginConfig(name="tags", module="tag_plugin"),
            ),
            LoadedPlugin(
                instance=block_plugin,
                config=block_plugin.runtime_config,
                variables=block_plugin.runtime_variables,
                raw_config=PluginConfig(name="block", module="block_plugin"),
            ),
        ],
        registry,
    )
    config = build_config()
    upstream_answer = make_answer(dns.message.make_query("example.test", "A"), "A", "203.0.113.10")
    resolver_manager = CountingResolverManager(
        config,
        UpstreamResult(upstream_name="upstream-a", duration_ms=1.0, answer=upstream_answer),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    response = await engine.handle_message(
        dns.message.make_query("example.test", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )

    assert response is not None
    assert response.answer[0][0].address == "127.0.0.1"
    assert resolver_manager.calls == 0


async def test_block_plugin_stops_later_plugins_after_static_request_answer() -> None:
    registry = PluginRegistry()

    tag_plugin = RequestTaggingPlugin({"blackhole"})
    tag_plugin.bind(tag_plugin.config_model(), tag_plugin.variables_model())
    await tag_plugin.setup(registry)

    block_plugin = build_plugin(
        build_rule(match_tags=["blackhole"], addresses={"ipv4": ["127.0.0.1"]})
    )
    await block_plugin.setup(registry)

    observer = RecordingPlugin("observer", request_order=100, response_order=100)
    observer.bind(observer.config_model(), observer.variables_model())
    await observer.setup(registry)

    plugin_manager = PluginManager(
        [
            make_loaded_plugin(tag_plugin),
            make_loaded_plugin(block_plugin),
            make_loaded_plugin(observer),
        ],
        registry,
    )
    config = build_config()
    upstream_answer = make_answer(dns.message.make_query("example.test", "A"), "A", "203.0.113.10")
    resolver_manager = CountingResolverManager(
        config,
        UpstreamResult(upstream_name="upstream-a", duration_ms=1.0, answer=upstream_answer),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    response = await engine.handle_message(
        dns.message.make_query("example.test", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )

    assert response is not None
    assert response.answer[0][0].address == "127.0.0.1"
    assert resolver_manager.calls == 0
    assert observer.request_calls == 0
    assert observer.response_calls == 0


async def test_block_plugin_stops_later_response_plugins_after_rewrite() -> None:
    registry = PluginRegistry()

    block_plugin = build_plugin(
        build_rule(match_tags=["blackhole"], addresses={"ipv4": ["127.0.0.1"]})
    )
    await block_plugin.setup(registry)

    observer = RecordingPlugin("observer", response_order=1000)
    observer.bind(observer.config_model(), observer.variables_model())
    await observer.setup(registry)

    plugin_manager = PluginManager(
        [
            make_loaded_plugin(block_plugin),
            make_loaded_plugin(observer),
        ],
        registry,
    )
    config = build_config()
    request = dns.message.make_query("example.test", "A")
    upstream_answer = make_answer(request, "A", "203.0.113.10")
    resolver_manager = CountingResolverManager(
        config,
        UpstreamResult(
            upstream_name="upstream-a",
            duration_ms=1.0,
            answer=upstream_answer,
            tags={"blackhole"},
        ),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    response = await engine.handle_message(
        request,
        ("127.0.0.1", 10000),
        "udp",
    )

    assert response is not None
    assert response.answer[0][0].address == "127.0.0.1"
    assert resolver_manager.calls == 1
    assert observer.response_calls == 0
