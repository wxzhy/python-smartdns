from __future__ import annotations

from pathlib import Path

import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

from dns_forwarder.config import AppConfig, PluginConfig
from dns_forwarder.core import DOMAINSET_CONTEXT_KEY, IPSET_CONTEXT_KEY, DomainSet, IPSet
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import LoadedPlugin, PluginManager, PluginRegistry
from plugins.cache_plugin import CachePlugin, CachePluginConfig
from plugins.ip_filter_plugin import IpFilterPlugin, IpFilterPluginConfig
from plugins.ip_replace_plugin import IpReplacePlugin, IpReplacePluginConfig, IpReplaceRuleConfig
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


def build_ipset(tmp_path: Path, items: dict[str, list[str]]) -> IPSet:
    ip_dir = tmp_path / "ips"
    ip_dir.mkdir()
    for tag, networks in items.items():
        _write_lines(ip_dir / f"{tag}.txt", networks)
    return IPSet(str(ip_dir))


def make_plugin(
    *,
    match_tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
    whitelist_tags: list[str] | None = None,
    blacklist_tags: list[str] | None = None,
) -> IpFilterPlugin:
    plugin = IpFilterPlugin()
    plugin.bind(
        IpFilterPluginConfig(
            match_tags=[] if match_tags is None else match_tags,
            exclude_tags=[] if exclude_tags is None else exclude_tags,
            whitelist_tags=[] if whitelist_tags is None else whitelist_tags,
            blacklist_tags=[] if blacklist_tags is None else blacklist_tags,
        ),
        plugin.variables_model(),
    )
    return plugin


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


def answer_addresses(answer: dns.resolver.Answer | None) -> list[str]:
    if answer is None or answer.rrset is None:
        return []
    return [record.address for record in answer.rrset if hasattr(record, "address")]


def make_context(
    request: dns.message.Message,
    *,
    tags: set[str] | None = None,
    ipset: IPSet | None = None,
) -> RequestContext:
    return RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        tags=set() if tags is None else set(tags),
        extensions={} if ipset is None else {IPSET_CONTEXT_KEY: ipset},
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


async def build_plugin_manager_with_tag_filter_replace_and_cache(tmp_path: Path) -> PluginManager:
    domain_dir = tmp_path / "domains"
    ip_dir = tmp_path / "ips"
    domain_dir.mkdir()
    ip_dir.mkdir()
    _write_lines(domain_dir / "proxy.txt", ["example.org"])
    _write_lines(ip_dir / "blocked.txt", ["203.0.113.0/24"])

    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, DomainSet(str(domain_dir)))
    registry.register_context(IPSET_CONTEXT_KEY, IPSet(str(ip_dir)))

    tag_plugin = TagPlugin()
    tag_plugin.bind(tag_plugin.config_model(), tag_plugin.variables_model())
    await tag_plugin.setup(registry)

    filter_plugin = make_plugin(match_tags=["proxy"], blacklist_tags=["blocked"])
    await filter_plugin.setup(registry)

    replace_plugin = IpReplacePlugin()
    replace_config = IpReplacePluginConfig(
        rules=[
            IpReplaceRuleConfig(
                name="proxy-map",
                match_tags=["proxy"],
                ipv4_targets=["10.0.0.0/24"],
            )
        ]
    )
    replace_plugin.bind(replace_config, replace_plugin.variables_model())
    await replace_plugin.setup(registry)

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
                instance=filter_plugin,
                config=filter_plugin.runtime_config,
                variables=filter_plugin.runtime_variables,
                raw_config=PluginConfig(name="ip_filter", module="ip_filter_plugin"),
            ),
            LoadedPlugin(
                instance=replace_plugin,
                config=replace_config,
                variables=replace_plugin.runtime_variables,
                raw_config=PluginConfig(name="ip_replace", module="ip_replace_plugin"),
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


async def test_ip_filter_plugin_setup_rejects_empty_filter_tags() -> None:
    plugin = make_plugin()

    with pytest.raises(ValueError, match="至少需要 whitelist_tags 或 blacklist_tags"):
        await plugin.setup(PluginRegistry())


async def test_ip_filter_plugin_filters_blacklist_only(tmp_path: Path) -> None:
    plugin = make_plugin(match_tags=["proxy"], blacklist_tags=["blocked"])
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "A")
    context = make_context(
        request,
        tags={"proxy"},
        ipset=build_ipset(tmp_path, {"blocked": ["203.0.113.0/24"]}),
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "198.51.100.10", "203.0.113.20", "198.51.100.11"),
    )
    before_addresses = answer_addresses(result.answer)

    await plugin.on_upstream_response(context, result)

    assert answer_addresses(result.answer) == [
        ip for ip in before_addresses if ip != "203.0.113.20"
    ]


async def test_ip_filter_plugin_filters_whitelist_only(tmp_path: Path) -> None:
    plugin = make_plugin(match_tags=["proxy"], whitelist_tags=["allowed"])
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "A")
    context = make_context(
        request,
        tags={"proxy"},
        ipset=build_ipset(tmp_path, {"allowed": ["198.51.100.0/24"]}),
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "198.51.100.10", "203.0.113.20", "198.51.100.11"),
    )
    before_addresses = answer_addresses(result.answer)

    await plugin.on_upstream_response(context, result)

    assert answer_addresses(result.answer) == [
        ip for ip in before_addresses if ip.startswith("198.51.100.")
    ]


async def test_ip_filter_plugin_combines_whitelist_and_blacklist(tmp_path: Path) -> None:
    plugin = make_plugin(
        match_tags=["proxy"], whitelist_tags=["allowed"], blacklist_tags=["blocked"]
    )
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "A")
    context = make_context(
        request,
        tags={"proxy"},
        ipset=build_ipset(
            tmp_path,
            {
                "allowed": ["198.51.100.0/24", "203.0.112.0/23"],
                "blocked": ["203.0.113.0/24"],
            },
        ),
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "198.51.100.10", "203.0.113.20", "198.51.100.11"),
    )
    before_addresses = answer_addresses(result.answer)

    await plugin.on_upstream_response(context, result)

    assert answer_addresses(result.answer) == [
        ip for ip in before_addresses if ip.startswith("198.51.100.")
    ]


async def test_ip_filter_plugin_matches_all_requests_when_match_tags_empty(tmp_path: Path) -> None:
    plugin = make_plugin(blacklist_tags=["blocked"])
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "A")
    context = make_context(
        request,
        tags=set(),
        ipset=build_ipset(tmp_path, {"blocked": ["203.0.113.0/24"]}),
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "198.51.100.10", "203.0.113.20"),
    )

    await plugin.on_upstream_response(context, result)

    assert answer_addresses(result.answer) == ["198.51.100.10"]


async def test_ip_filter_plugin_skips_when_request_tags_do_not_match(tmp_path: Path) -> None:
    plugin = make_plugin(match_tags=["proxy"], blacklist_tags=["blocked"])
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "A")
    context = make_context(
        request,
        tags={"direct"},
        ipset=build_ipset(tmp_path, {"blocked": ["203.0.113.0/24"]}),
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "198.51.100.10", "203.0.113.20"),
    )
    before_addresses = answer_addresses(result.answer)

    await plugin.on_upstream_response(context, result)

    assert answer_addresses(result.answer) == before_addresses


async def test_ip_filter_plugin_skips_when_request_hits_exclude_tags(tmp_path: Path) -> None:
    plugin = make_plugin(match_tags=["proxy"], exclude_tags=["direct"], blacklist_tags=["blocked"])
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "A")
    context = make_context(
        request,
        tags={"proxy", "direct"},
        ipset=build_ipset(tmp_path, {"blocked": ["203.0.113.0/24"]}),
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "198.51.100.10", "203.0.113.20"),
    )
    before_addresses = answer_addresses(result.answer)

    await plugin.on_upstream_response(context, result)

    assert answer_addresses(result.answer) == before_addresses


async def test_ip_filter_plugin_handles_untagged_ips_based_on_whitelist_presence(
    tmp_path: Path,
) -> None:
    plugin = make_plugin(match_tags=["proxy"], whitelist_tags=["allowed"])
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "A")
    context = make_context(
        request,
        tags={"proxy"},
        ipset=build_ipset(tmp_path, {"allowed": ["198.51.100.0/24"]}),
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "198.51.100.10", "192.0.2.20"),
    )

    await plugin.on_upstream_response(context, result)

    assert answer_addresses(result.answer) == ["198.51.100.10"]

    plugin_no_whitelist = make_plugin(match_tags=["proxy"], blacklist_tags=["blocked"])
    await plugin_no_whitelist.setup(PluginRegistry())
    second_result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "198.51.100.10", "192.0.2.20"),
    )
    before_second_addresses = answer_addresses(second_result.answer)

    await plugin_no_whitelist.on_upstream_response(context, second_result)

    assert answer_addresses(second_result.answer) == before_second_addresses


async def test_ip_filter_plugin_filters_aaaa_answers(tmp_path: Path) -> None:
    plugin = make_plugin(match_tags=["proxy"], blacklist_tags=["blocked"])
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "AAAA")
    context = make_context(
        request,
        tags={"proxy"},
        ipset=build_ipset(tmp_path, {"blocked": ["2001:db8:ffff::/48"]}),
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "2001:db8::10", "2001:db8:ffff::20"),
    )

    await plugin.on_upstream_response(context, result)

    assert answer_addresses(result.answer) == ["2001:db8::10"]


async def test_ip_filter_plugin_skips_non_noerror_and_non_address_answers(tmp_path: Path) -> None:
    plugin = make_plugin(match_tags=["proxy"], blacklist_tags=["blocked"])
    await plugin.setup(PluginRegistry())
    ipset = build_ipset(tmp_path, {"blocked": ["203.0.113.0/24"]})

    request_a = dns.message.make_query("example.org", "A")
    context_a = make_context(request_a, tags={"proxy"}, ipset=ipset)
    answer_a = make_answer(request_a, "203.0.113.20")
    answer_a.response.set_rcode(dns.rcode.SERVFAIL)
    result_a = UpstreamResult(upstream_name="upstream-a", duration_ms=1.0, answer=answer_a)
    await plugin.on_upstream_response(context_a, result_a)
    assert answer_addresses(result_a.answer) == ["203.0.113.20"]

    request_txt = dns.message.make_query("example.org", "TXT")
    context_txt = make_context(request_txt, tags={"proxy"}, ipset=ipset)
    response_txt = dns.message.make_response(request_txt)
    response_txt.answer.append(dns.rrset.from_text("example.org.", 60, "IN", "TXT", '"hello"'))
    answer_txt = build_answer_from_response(request_txt, response_txt)
    result_txt = UpstreamResult(upstream_name="upstream-a", duration_ms=1.0, answer=answer_txt)
    await plugin.on_upstream_response(context_txt, result_txt)
    assert result_txt.answer is not None
    assert result_txt.answer.rdtype == dns.rdatatype.TXT

    request_none = dns.message.make_query("example.org", "A")
    context_none = make_context(request_none, tags={"proxy"}, ipset=ipset)
    answer_none = make_answer(request_none, "203.0.113.21")
    answer_none.rrset = None
    result_none = UpstreamResult(upstream_name="upstream-a", duration_ms=1.0, answer=answer_none)
    await plugin.on_upstream_response(context_none, result_none)
    assert result_none.answer is not None
    assert result_none.answer.rrset is None


async def test_ip_filter_plugin_skips_non_address_request_even_if_answer_is_address() -> None:
    plugin = make_plugin(match_tags=["proxy"], blacklist_tags=["blocked"])
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "TXT")
    context = make_context(request, tags={"proxy"})
    address_answer = make_answer(dns.message.make_query("example.org", "A"), "203.0.113.20")
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=address_answer,
    )

    await plugin.on_upstream_response(context, result)

    assert answer_addresses(result.answer) == ["203.0.113.20"]


async def test_ip_filter_plugin_preserves_record_order(tmp_path: Path) -> None:
    plugin = make_plugin(match_tags=["proxy"], whitelist_tags=["allowed"])
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "A")
    context = make_context(
        request,
        tags={"proxy"},
        ipset=build_ipset(tmp_path, {"allowed": ["198.51.100.0/24", "192.0.2.0/24"]}),
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "192.0.2.30", "203.0.113.40", "198.51.100.10", "192.0.2.31"),
    )
    before_addresses = answer_addresses(result.answer)

    await plugin.on_upstream_response(context, result)

    assert answer_addresses(result.answer) == [
        ip for ip in before_addresses if ip != "203.0.113.40"
    ]


async def test_ip_filter_plugin_sets_empty_rrset_when_all_ips_are_filtered(tmp_path: Path) -> None:
    plugin = make_plugin(match_tags=["proxy"], blacklist_tags=["blocked"])
    await plugin.setup(PluginRegistry())
    request = dns.message.make_query("example.org", "A")
    context = make_context(
        request,
        tags={"proxy"},
        ipset=build_ipset(tmp_path, {"blocked": ["203.0.113.0/24"]}),
    )
    result = UpstreamResult(
        upstream_name="upstream-a",
        duration_ms=1.0,
        answer=make_answer(request, "203.0.113.10", "203.0.113.20"),
    )

    await plugin.on_upstream_response(context, result)

    assert result.answer is not None
    assert result.answer.rrset is None


async def test_ip_filter_plugin_keeps_empty_noerror_response_after_pipeline_finalize(
    tmp_path: Path,
) -> None:
    config = build_config()
    registry = PluginRegistry()
    registry.register_context(
        IPSET_CONTEXT_KEY, build_ipset(tmp_path, {"blocked": ["203.0.113.0/24"]})
    )
    plugin = make_plugin(blacklist_tags=["blocked"])
    await plugin.setup(registry)
    manager = PluginManager(
        [
            LoadedPlugin(
                instance=plugin,
                config=plugin.runtime_config,
                variables=plugin.runtime_variables,
                raw_config=PluginConfig(name="ip_filter", module="ip_filter_plugin"),
            )
        ],
        registry,
    )
    request = dns.message.make_query("example.org", "A")
    answer = make_answer(request, "203.0.113.10", "203.0.113.20")
    resolver_manager = CountingResolverManager(
        config,
        UpstreamResult(upstream_name="upstream-a", duration_ms=5.0, answer=answer),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), manager)

    response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")

    assert response is not None
    assert response.rcode() == dns.rcode.NOERROR
    assert response.answer == []


async def test_ip_filter_plugin_runs_before_ip_replace_and_cache(tmp_path: Path) -> None:
    config = build_config()
    plugin_manager = await build_plugin_manager_with_tag_filter_replace_and_cache(tmp_path)
    request = dns.message.make_query("example.org", "A")
    answer = make_answer(request, "198.51.100.7", "203.0.113.8")
    resolver_manager = CountingResolverManager(
        config,
        UpstreamResult(upstream_name="upstream-a", duration_ms=5.0, answer=answer),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), plugin_manager)

    first_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")
    second_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")

    assert first_response is not None
    assert second_response is not None
    assert first_response.answer[0][0].address == "10.0.0.7"
    assert second_response.answer[0][0].address == "10.0.0.7"
    assert len(first_response.answer[0]) == 1
    assert len(second_response.answer[0]) == 1
    assert resolver_manager.calls == 1
