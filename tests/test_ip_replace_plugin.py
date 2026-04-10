from __future__ import annotations

from pathlib import Path

import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest
from pydantic import ValidationError

from dns_forwarder.config import AppConfig, PluginConfig
from dns_forwarder.core import DOMAINSET_CONTEXT_KEY, IPSET_CONTEXT_KEY, DomainSet, IPSet
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import EmptyModel, LoadedPlugin, Plugin, PluginManager, PluginRegistry
from plugins.cache_plugin import CachePlugin, CachePluginConfig
from plugins.ip_replace_plugin import IpReplacePlugin, IpReplacePluginConfig, IpReplaceRuleConfig, IpReplaceService
from plugins.tag_plugin import TagPlugin


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
                {"name": "default", "strategy": "race", "upstreams": ["upstream-a"]},
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


class ResponseMutatingPlugin(Plugin):
    name = "response-mutator"
    config_model = EmptyModel
    variables_model = EmptyModel
    response_order = 100

    async def on_response(self, context: RequestContext) -> None:
        if not context.upstream_results:
            return
        if context.final_answer is None or context.final_answer.rrset is None:
            return
        context.final_answer.rrset = dns.rrset.from_text(
            context.final_answer.rrset.name.to_text(),
            120,
            "IN",
            "A",
            "203.0.113.99",
        )


def make_answer(request: dns.message.Message, *items: str) -> dns.resolver.Answer:
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            request.question[0].name.to_text(),
            60,
            "IN",
            dns.rdatatype.to_text(request.question[0].rdtype),
            *items,
        )
    )
    return build_answer_from_response(request, response)


def answer_addresses(answer: dns.resolver.Answer) -> list[str]:
    return [record.address for record in answer.rrset or () if hasattr(record, "address")]


async def build_plugin_manager_with_tag_replace_and_cache(tmp_path: Path) -> PluginManager:
    domain_dir = tmp_path / "domains"
    ip_dir = tmp_path / "ips"
    domain_dir.mkdir()
    ip_dir.mkdir()
    _write_lines(domain_dir / "proxy.txt", ["example.org"])

    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, DomainSet(str(domain_dir)))
    registry.register_context(IPSET_CONTEXT_KEY, IPSet(str(ip_dir)))

    tag_plugin = TagPlugin()
    tag_plugin.bind(tag_plugin.config_model(), tag_plugin.variables_model())
    await tag_plugin.setup(registry)

    ip_replace_plugin = IpReplacePlugin()
    ip_replace_config = IpReplacePluginConfig(
        rules=[
            IpReplaceRuleConfig(
                name="proxy-map",
                match_tags=["proxy"],
                ipv4_targets=["10.0.0.0/24"],
            )
        ]
    )
    ip_replace_plugin.bind(ip_replace_config, ip_replace_plugin.variables_model())
    await ip_replace_plugin.setup(registry)

    mutator = ResponseMutatingPlugin()
    mutator.bind(mutator.config_model(), mutator.variables_model())

    cache_plugin = CachePlugin()
    cache_config = CachePluginConfig()
    cache_plugin.bind(cache_config, cache_plugin.variables_model())
    await cache_plugin.setup(registry)

    return PluginManager(
        [
            LoadedPlugin(
                instance=tag_plugin,
                config=tag_plugin.runtime_config,
                variables=tag_plugin.runtime_variables,
                raw_config=PluginConfig(name="tags", module="tag_plugin"),
            ),
            LoadedPlugin(
                instance=ip_replace_plugin,
                config=ip_replace_config,
                variables=ip_replace_plugin.runtime_variables,
                raw_config=PluginConfig(name="ip_replace", module="ip_replace_plugin"),
            ),
            LoadedPlugin(
                instance=mutator,
                config=mutator.runtime_config,
                variables=mutator.runtime_variables,
                raw_config=PluginConfig(name="mutator", module="response_mutator"),
            ),
            LoadedPlugin(
                instance=cache_plugin,
                config=cache_config,
                variables=cache_plugin.runtime_variables,
                raw_config=PluginConfig(name="cache", module="cache_plugin"),
            ),
        ],
        registry,
    )


def test_ip_replace_rule_config_rejects_wrong_target_family() -> None:
    with pytest.raises(ValidationError, match="IPv4 CIDR"):
        IpReplaceRuleConfig(
            name="invalid-family",
            match_tags=["proxy"],
            ipv4_targets=["fd00::/64"],
        )


def test_ip_replace_rule_config_requires_at_least_one_target() -> None:
    with pytest.raises(ValidationError, match="至少需要一个 IPv4 或 IPv6 目标 CIDR"):
        IpReplaceRuleConfig(
            name="missing-targets",
            match_tags=["proxy"],
        )


def test_ip_replace_service_expands_ipv4_targets_and_deduplicates_stably() -> None:
    service = IpReplaceService(
        [
            IpReplaceRuleConfig(
                name="proxy-map",
                match_tags=["proxy"],
                ipv4_targets=["10.10.0.0/24", "10.20.0.0/24"],
            )
        ]
    )
    request = dns.message.make_query("example.org", "A")
    answer = make_answer(request, "198.51.100.1", "203.0.113.1")

    changed = service.replace_answer(answer, {"proxy"})

    assert changed is True
    assert answer_addresses(answer) == ["10.10.0.1", "10.20.0.1"]


def test_ip_replace_service_expands_ipv6_targets() -> None:
    service = IpReplaceService(
        [
            IpReplaceRuleConfig(
                name="proxy-map-v6",
                match_tags=["proxy"],
                ipv6_targets=["fd10:10::/64", "fd10:20::/64"],
            )
        ]
    )
    request = dns.message.make_query("example.org", "AAAA")
    answer = make_answer(request, "2001:db8:1::1234", "2001:db8:2::1234")

    changed = service.replace_answer(answer, {"proxy"})

    assert changed is True
    assert answer_addresses(answer) == ["fd10:10::1234", "fd10:20::1234"]


def test_ip_replace_service_skips_excluded_rule_and_uses_next_rule() -> None:
    service = IpReplaceService(
        [
            IpReplaceRuleConfig(
                name="skip-me",
                match_tags=["proxy"],
                exclude_tags=["direct"],
                ipv4_targets=["10.10.0.0/24"],
            ),
            IpReplaceRuleConfig(
                name="fallback",
                match_tags=["proxy"],
                ipv4_targets=["10.20.0.0/24"],
            ),
        ]
    )
    request = dns.message.make_query("example.org", "A")
    answer = make_answer(request, "198.51.100.9")

    changed = service.replace_answer(answer, {"proxy", "direct"})

    assert changed is True
    assert answer_addresses(answer) == ["10.20.0.9"]


def test_ip_replace_service_continues_when_first_rule_lacks_current_family_targets() -> None:
    service = IpReplaceService(
        [
            IpReplaceRuleConfig(
                name="ipv6-only",
                match_tags=["proxy"],
                ipv6_targets=["fd10:10::/64"],
            ),
            IpReplaceRuleConfig(
                name="ipv4-fallback",
                match_tags=["proxy"],
                ipv4_targets=["10.30.0.0/24"],
            ),
        ]
    )
    request = dns.message.make_query("example.org", "A")
    answer = make_answer(request, "198.51.100.7")

    changed = service.replace_answer(answer, {"proxy"})

    assert changed is True
    assert answer_addresses(answer) == ["10.30.0.7"]


def test_ip_replace_service_uses_first_applicable_rule_only() -> None:
    service = IpReplaceService(
        [
            IpReplaceRuleConfig(
                name="first",
                match_tags=["proxy"],
                ipv4_targets=["10.40.0.0/24"],
            ),
            IpReplaceRuleConfig(
                name="second",
                match_tags=["proxy"],
                ipv4_targets=["10.50.0.0/24"],
            ),
        ]
    )
    request = dns.message.make_query("example.org", "A")
    answer = make_answer(request, "198.51.100.8")

    changed = service.replace_answer(answer, {"proxy"})

    assert changed is True
    assert answer_addresses(answer) == ["10.40.0.8"]


def test_ip_replace_service_skips_non_address_answers() -> None:
    service = IpReplaceService(
        [
            IpReplaceRuleConfig(
                name="proxy-map",
                match_tags=["proxy"],
                ipv4_targets=["10.10.0.0/24"],
            )
        ]
    )
    request = dns.message.make_query("example.org", "TXT")
    response = dns.message.make_response(request)
    response.answer.append(dns.rrset.from_text("example.org.", 60, "IN", "TXT", "\"hello\""))
    answer = build_answer_from_response(request, response)

    changed = service.replace_answer(answer, {"proxy"})

    assert changed is False


def test_ip_replace_service_skips_when_global_skip_tags_match() -> None:
    service = IpReplaceService(
        [
            IpReplaceRuleConfig(
                name="proxy-map",
                match_tags=["proxy"],
                ipv4_targets=["10.10.0.0/24"],
            )
        ],
        skip_tags=["direct", "local"],
    )
    request = dns.message.make_query("example.org", "A")
    answer = make_answer(request, "198.51.100.11")

    changed = service.replace_answer(answer, {"proxy", "direct"})

    assert changed is False
    assert answer_addresses(answer) == ["198.51.100.11"]


def test_ip_replace_service_skips_non_noerror_address_answers() -> None:
    service = IpReplaceService(
        [
            IpReplaceRuleConfig(
                name="proxy-map",
                match_tags=["proxy"],
                ipv4_targets=["10.10.0.0/24"],
            )
        ]
    )
    request = dns.message.make_query("example.org", "A")
    answer = make_answer(request, "198.51.100.12")
    answer.response.set_rcode(dns.rcode.SERVFAIL)

    changed = service.replace_answer(answer, {"proxy"})

    assert changed is False
    assert answer_addresses(answer) == ["198.51.100.12"]


async def test_ip_replace_plugin_rewrites_upstream_answer_from_result_tags() -> None:
    plugin = IpReplacePlugin()
    plugin.bind(
        IpReplacePluginConfig(
            rules=[
                IpReplaceRuleConfig(
                    name="proxy-map",
                    match_tags=["proxy"],
                    ipv4_targets=["10.10.0.0/24", "10.20.0.0/24"],
                )
            ]
        ),
        plugin.variables_model(),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    context = RequestContext(
        request=dns.message.make_query("example.org", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions={},
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(context.request, "198.51.100.10"),
        tags={"proxy"},
    )

    await plugin.on_upstream_response(context, result)

    assert result.answer is not None
    assert answer_addresses(result.answer) == ["10.10.0.10", "10.20.0.10"]


async def test_ip_replace_plugin_honors_global_skip_tags() -> None:
    plugin = IpReplacePlugin()
    plugin.bind(
        IpReplacePluginConfig(
            skip_tags=["direct"],
            rules=[
                IpReplaceRuleConfig(
                    name="proxy-map",
                    match_tags=["proxy"],
                    ipv4_targets=["10.10.0.0/24"],
                )
            ],
        ),
        plugin.variables_model(),
    )
    registry = PluginRegistry()
    await plugin.setup(registry)

    context = RequestContext(
        request=dns.message.make_query("example.org", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions={},
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(context.request, "198.51.100.13"),
        tags={"proxy", "direct"},
    )

    await plugin.on_upstream_response(context, result)

    assert result.answer is not None
    assert answer_addresses(result.answer) == ["198.51.100.13"]


async def test_ip_replace_plugin_runs_after_tagging_and_before_cache(tmp_path: Path) -> None:
    config = build_config()
    plugin_manager = await build_plugin_manager_with_tag_replace_and_cache(tmp_path)
    request = dns.message.make_query("example.org", "A")
    answer = make_answer(request, "198.51.100.7")
    resolver_manager = CountingResolverManager(
        config,
        UpstreamResult(upstream_name="upstream-a", duration_ms=5.0, answer=answer),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    first_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")
    second_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")

    assert first_response is not None
    assert second_response is not None
    assert first_response.answer[0][0].address == "10.0.0.99"
    assert second_response.answer[0][0].address == "10.0.0.99"
    assert resolver_manager.calls == 1
