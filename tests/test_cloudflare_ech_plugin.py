from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rdtypes.svcbbase
import dns.resolver
import dns.rrset

from dns_forwarder.config import AppConfig, PluginConfig
from dns_forwarder.core import IPSET_CONTEXT_KEY, IPSet
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import LoadedPlugin, PluginManager, PluginRegistry
from plugins.cache_plugin import CachePlugin
from plugins.cloudflare_ech_plugin import CloudflareEchPlugin, CloudflareEchPluginConfig
from plugins.https_plugin import HttpsPlugin
from plugins.tag_plugin import HAS_HINT_TAG

if TYPE_CHECKING:
    from pathlib import Path

HTTPS_PARAM_KEY = dns.rdtypes.svcbbase.ParamKey


@dataclass(frozen=True, slots=True)
class FinalState:
    answer: dns.resolver.Answer | None = None
    response: dns.message.Message | None = None


@dataclass(frozen=True, slots=True)
class TagSpec:
    request: set[str] | None = None
    result: set[str] | None = None


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_ipset(tmp_path: Path, items: dict[str, list[str]]) -> IPSet:
    ip_dir = tmp_path / "ips"
    ip_dir.mkdir()
    for tag, networks in items.items():
        _write_lines(ip_dir / f"{tag}.txt", networks)
    return IPSet(str(ip_dir))


def build_plugin(
    *,
    match_tags: list[str],
    exclude_tags: list[str] | None = None,
    skip_tags: list[str] | None = None,
) -> CloudflareEchPlugin:
    plugin = CloudflareEchPlugin()
    plugin.bind(
        CloudflareEchPluginConfig(
            match_tags=match_tags,
            exclude_tags=[] if exclude_tags is None else exclude_tags,
            skip_tags=[] if skip_tags is None else skip_tags,
        ),
        plugin.variables_model(),
    )
    return plugin


def make_https_answer(
    request: dns.message.Message,
    *records: str,
) -> dns.resolver.Answer:
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            request.question[0].name.to_text(),
            60,
            "IN",
            "HTTPS",
            *records,
        )
    )
    return build_answer_from_response(request, response)


def make_empty_answer(request: dns.message.Message) -> dns.resolver.Answer:
    response = dns.message.make_response(request)
    return build_answer_from_response(request, response)


def make_address_answer(
    request: dns.message.Message,
    address: str,
) -> dns.resolver.Answer:
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            request.question[0].name.to_text(),
            60,
            "IN",
            "A",
            address,
        )
    )
    return build_answer_from_response(request, response)


def make_context(
    request: dns.message.Message,
    *,
    final: FinalState | None = None,
    tags: TagSpec | None = None,
    ipset: IPSet | None = None,
    resolve_handler=None,
) -> RequestContext:
    final_answer = None if final is None else final.answer
    final_response = None if final is None else final.response
    request_tags = set() if tags is None else set(tags.request or ())
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        final_answer=final_answer,
        final_response=final_response,
        tags=request_tags,
        extensions={} if ipset is None else {IPSET_CONTEXT_KEY: ipset},
        _resolve_handler=resolve_handler,
    )
    if tags is not None and tags.result is not None:
        context.upstream_results.append(
            UpstreamResult(
                upstream_name="upstream-a",
                duration_ms=1.0,
                tags=set(tags.result),
            )
        )
    return context


class ResolveRecorder:
    def __init__(self, responses: dict[tuple[str, str], dns.resolver.Answer | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str]] = []

    async def resolve(
        self,
        context: RequestContext,
        qname: str,
        qtype: str,
    ) -> dns.resolver.Answer:
        key = (qname, qtype)
        self.calls.append(key)
        response = self.responses[key]
        if isinstance(response, Exception):
            raise response
        return response


def make_loaded_plugin(instance) -> LoadedPlugin:
    config = instance.runtime_config
    variables = instance.runtime_variables
    return LoadedPlugin(
        instance=instance,
        config=config,
        variables=variables,
        raw_config=PluginConfig(name=instance.name, module=instance.name.replace("-", "_")),
    )


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
                {"name": "upstream-a", "nameservers": ["local-ns"]},
            ],
            "groups": [
                {"name": "default", "upstreams": ["upstream-a"]},
            ],
            "rules": [],
            "plugins": [],
            "webui": {"enabled": False},
        }
    )


class QueryAwareResolverManager:
    def __init__(self, config: AppConfig, handlers: dict[tuple[str, str], UpstreamResult]) -> None:
        self._groups = {group.name: group for group in config.groups}
        self._handlers = handlers
        self.calls: list[tuple[str, str]] = []

    def get_group(self, group_name: str):
        return self._groups[group_name]

    def has_group(self, group_name: str) -> bool:
        return group_name in self._groups

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        question = context.request.question[0]
        key = (
            question.name.to_text().rstrip(".").lower(),
            dns.rdatatype.to_text(question.rdtype).upper(),
        )
        self.calls.append(key)
        return self._handlers[key]


async def test_cloudflare_ech_plugin_injects_ech_when_result_tags_match() -> None:
    plugin = build_plugin(match_tags=["cf"])
    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_https_answer(request, '1 . alpn="h2"')
    recorder = ResolveRecorder(
        {
            ("cloudflare-ech.com", "HTTPS"): make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . ech="AA=="',
            )
        }
    )
    context = make_context(
        request,
        final=FinalState(answer=answer),
        tags=TagSpec(result={"cf"}),
        resolve_handler=recorder.resolve,
    )

    await plugin.on_response(context)

    rdata = next(iter(answer.rrset))
    assert rdata.params[HTTPS_PARAM_KEY.ECH].ech == b"\x00"
    assert recorder.calls == [("cloudflare-ech.com", "HTTPS")]
    plugin._load_cloudflare_ech_cached.cache_clear()


async def test_cloudflare_ech_plugin_injects_service_mode_record_into_empty_noerror_answer() -> (
    None
):
    plugin = build_plugin(match_tags=["cf"])
    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_empty_answer(request)
    recorder = ResolveRecorder(
        {
            ("cloudflare-ech.com", "HTTPS"): make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . ech="AA=="',
            )
        }
    )
    context = make_context(
        request,
        final=FinalState(answer=answer),
        tags=TagSpec(result={"cf"}),
        resolve_handler=recorder.resolve,
    )

    await plugin.on_response(context)

    assert answer.rrset is not None
    rdata = next(iter(answer.rrset))
    assert rdata.priority == 1
    assert rdata.target.to_text() == "."
    assert rdata.params[HTTPS_PARAM_KEY.ECH].ech == b"\x00"
    assert recorder.calls == [("cloudflare-ech.com", "HTTPS")]
    plugin._load_cloudflare_ech_cached.cache_clear()


async def test_cloudflare_ech_plugin_caches_cloudflare_ech_between_responses() -> None:
    plugin = build_plugin(match_tags=["cf"])
    recorder = ResolveRecorder(
        {
            ("cloudflare-ech.com", "HTTPS"): make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . ech="AA=="',
            )
        }
    )

    for qname in ("first.test", "second.test"):
        request = dns.message.make_query(qname, "HTTPS")
        answer = make_https_answer(request, '1 . alpn="h2"')
        context = make_context(
            request,
            final=FinalState(answer=answer),
            tags=TagSpec(result={"cf"}),
            resolve_handler=recorder.resolve,
        )
        await plugin.on_response(context)

    assert recorder.calls == [("cloudflare-ech.com", "HTTPS")]
    plugin._load_cloudflare_ech_cached.cache_clear()


async def test_cloudflare_ech_plugin_skips_non_https_nxdomain_and_existing_ech() -> None:
    plugin = build_plugin(match_tags=["cf"])
    recorder = ResolveRecorder({})

    request_a = dns.message.make_query("example.test", "A")
    answer_a = make_address_answer(request_a, "203.0.113.10")
    context_a = make_context(
        request_a,
        final=FinalState(answer=answer_a),
        tags=TagSpec(result={"cf"}),
        resolve_handler=recorder.resolve,
    )
    await plugin.on_response(context_a)
    assert answer_a.rdtype == dns.rdatatype.A

    request_https = dns.message.make_query("example.test", "HTTPS")
    response_nx = dns.message.make_response(request_https)
    response_nx.set_rcode(dns.rcode.NXDOMAIN)
    context_nx = make_context(
        request_https,
        final=FinalState(response=response_nx),
        tags=TagSpec(result={"cf"}),
        resolve_handler=recorder.resolve,
    )
    await plugin.on_response(context_nx)

    answer_with_ech = make_https_answer(request_https, '1 . ech="AA=="')
    context_existing = make_context(
        request_https,
        final=FinalState(answer=answer_with_ech),
        tags=TagSpec(result={"cf"}),
        resolve_handler=recorder.resolve,
    )
    await plugin.on_response(context_existing)

    assert recorder.calls == []


async def test_cloudflare_ech_plugin_skips_non_https_request_even_if_final_answer_is_https() -> (
    None
):
    plugin = build_plugin(match_tags=["cf"])
    request = dns.message.make_query("example.test", "A")
    answer = make_https_answer(dns.message.make_query("example.test", "HTTPS"), '1 . alpn="h2"')
    recorder = ResolveRecorder(
        {
            ("cloudflare-ech.com", "HTTPS"): make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . ech="AA=="',
            )
        }
    )
    context = make_context(
        request,
        final=FinalState(answer=answer),
        tags=TagSpec(result={"cf"}),
        resolve_handler=recorder.resolve,
    )

    await plugin.on_response(context)

    rdata = next(iter(answer.rrset))
    assert HTTPS_PARAM_KEY.ECH not in rdata.params
    assert recorder.calls == []


async def test_cloudflare_ech_plugin_skips_when_exclude_tag_matches() -> None:
    plugin = build_plugin(match_tags=["cf"], exclude_tags=["skip"])
    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_https_answer(request, '1 . alpn="h2"')
    recorder = ResolveRecorder({})
    context = make_context(
        request,
        final=FinalState(answer=answer),
        tags=TagSpec(result={"cf", "skip"}),
        resolve_handler=recorder.resolve,
    )

    await plugin.on_response(context)

    rdata = next(iter(answer.rrset))
    assert HTTPS_PARAM_KEY.ECH not in rdata.params
    assert recorder.calls == []


async def test_cloudflare_ech_plugin_skips_when_request_tag_matches_skip_tags() -> None:
    plugin = build_plugin(match_tags=["cf"], skip_tags=["direct"])
    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_https_answer(request, '1 . alpn="h2"')
    recorder = ResolveRecorder({})
    context = make_context(
        request,
        final=FinalState(answer=answer),
        tags=TagSpec(request={"direct"}, result={"cf"}),
        resolve_handler=recorder.resolve,
    )

    await plugin.on_response(context)

    rdata = next(iter(answer.rrset))
    assert HTTPS_PARAM_KEY.ECH not in rdata.params
    assert recorder.calls == []


async def test_cloudflare_ech_plugin_skip_tags_short_circuits_before_a_subquery_or_ech_lookup() -> (
    None
):
    plugin = build_plugin(match_tags=["cf"], skip_tags=["direct"])
    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_https_answer(request, '1 . alpn="h2"')
    recorder = ResolveRecorder(
        {
            ("example.test", "A"): make_address_answer(
                dns.message.make_query("example.test", "A"), "203.0.113.25"
            ),
            ("cloudflare-ech.com", "HTTPS"): make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . ech="AA=="',
            ),
        }
    )
    context = make_context(
        request,
        final=FinalState(answer=answer),
        tags=TagSpec(request={"direct"}, result=set()),
        resolve_handler=recorder.resolve,
    )

    await plugin.on_response(context)

    rdata = next(iter(answer.rrset))
    assert HTTPS_PARAM_KEY.ECH not in rdata.params
    assert recorder.calls == []


async def test_cloudflare_ech_plugin_uses_hint_tags_without_a_subquery() -> None:
    plugin = build_plugin(match_tags=["cf"])
    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_https_answer(request, '1 . ipv4hint="203.0.113.10"')
    recorder = ResolveRecorder(
        {
            ("cloudflare-ech.com", "HTTPS"): make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . ech="AA=="',
            )
        }
    )
    context = make_context(
        request,
        final=FinalState(answer=answer),
        tags=TagSpec(result={"cf", HAS_HINT_TAG}),
        resolve_handler=recorder.resolve,
    )

    await plugin.on_response(context)

    rdata = next(iter(answer.rrset))
    assert rdata.params[HTTPS_PARAM_KEY.ECH].ech == b"\x00"
    assert recorder.calls == [("cloudflare-ech.com", "HTTPS")]
    plugin._load_cloudflare_ech_cached.cache_clear()


async def test_cloudflare_ech_plugin_skips_hint_miss_without_a_subquery() -> None:
    plugin = build_plugin(match_tags=["cf"])
    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_https_answer(request, '1 . ipv4hint="198.51.100.10"')
    recorder = ResolveRecorder({})
    context = make_context(
        request,
        final=FinalState(answer=answer),
        tags=TagSpec(result={HAS_HINT_TAG}),
        resolve_handler=recorder.resolve,
    )

    await plugin.on_response(context)

    rdata = next(iter(answer.rrset))
    assert HTTPS_PARAM_KEY.ECH not in rdata.params
    assert recorder.calls == []


async def test_cloudflare_ech_plugin_uses_a_subquery_when_no_hints(tmp_path: Path) -> None:
    plugin = build_plugin(match_tags=["cf"])
    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_https_answer(request, '1 . alpn="h2"')
    ipset = build_ipset(tmp_path, {"cf": ["203.0.113.0/24"]})
    recorder = ResolveRecorder(
        {
            ("example.test", "A"): make_address_answer(
                dns.message.make_query("example.test", "A"), "203.0.113.25"
            ),
            ("cloudflare-ech.com", "HTTPS"): make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . ech="AA=="',
            ),
        }
    )
    context = make_context(
        request,
        final=FinalState(answer=answer),
        tags=TagSpec(result=set()),
        ipset=ipset,
        resolve_handler=recorder.resolve,
    )

    await plugin.on_response(context)

    rdata = next(iter(answer.rrset))
    assert rdata.params[HTTPS_PARAM_KEY.ECH].ech == b"\x00"
    assert recorder.calls == [("example.test", "A"), ("cloudflare-ech.com", "HTTPS")]
    plugin._load_cloudflare_ech_cached.cache_clear()


async def test_cloudflare_ech_plugin_skips_when_a_subquery_misses_or_fails(tmp_path: Path) -> None:
    plugin = build_plugin(match_tags=["cf"])
    ipset = build_ipset(tmp_path, {"cf": ["203.0.113.0/24"]})

    miss_request = dns.message.make_query("miss.test", "HTTPS")
    miss_answer = make_https_answer(miss_request, '1 . alpn="h2"')
    miss_recorder = ResolveRecorder(
        {
            ("miss.test", "A"): make_address_answer(
                dns.message.make_query("miss.test", "A"), "198.51.100.20"
            ),
        }
    )
    miss_context = make_context(
        miss_request,
        final=FinalState(answer=miss_answer),
        tags=TagSpec(result=set()),
        ipset=ipset,
        resolve_handler=miss_recorder.resolve,
    )
    await plugin.on_response(miss_context)
    assert HTTPS_PARAM_KEY.ECH not in next(iter(miss_answer.rrset)).params

    fail_request = dns.message.make_query("fail.test", "HTTPS")
    fail_answer = make_https_answer(fail_request, '1 . alpn="h2"')
    fail_recorder = ResolveRecorder({("fail.test", "A"): RuntimeError("boom")})
    fail_context = make_context(
        fail_request,
        final=FinalState(answer=fail_answer),
        tags=TagSpec(result=set()),
        ipset=ipset,
        resolve_handler=fail_recorder.resolve,
    )
    await plugin.on_response(fail_context)
    assert HTTPS_PARAM_KEY.ECH not in next(iter(fail_answer.rrset)).params


async def test_cloudflare_ech_plugin_skips_when_cloudflare_query_fails_or_has_no_ech() -> None:
    plugin_no_ech = build_plugin(match_tags=["cf"])
    no_ech_request = dns.message.make_query("no-ech.test", "HTTPS")
    no_ech_answer = make_https_answer(no_ech_request, '1 . alpn="h2"')
    no_ech_recorder = ResolveRecorder(
        {
            ("cloudflare-ech.com", "HTTPS"): make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . alpn="h2"',
            )
        }
    )
    no_ech_context = make_context(
        no_ech_request,
        final=FinalState(answer=no_ech_answer),
        tags=TagSpec(result={"cf"}),
        resolve_handler=no_ech_recorder.resolve,
    )
    await plugin_no_ech.on_response(no_ech_context)
    assert HTTPS_PARAM_KEY.ECH not in next(iter(no_ech_answer.rrset)).params
    plugin_no_ech._load_cloudflare_ech_cached.cache_clear()

    plugin_fail = build_plugin(match_tags=["cf"])
    fail_request = dns.message.make_query("fail-ech.test", "HTTPS")
    fail_answer = make_https_answer(fail_request, '1 . alpn="h2"')
    fail_recorder = ResolveRecorder({("cloudflare-ech.com", "HTTPS"): RuntimeError("boom")})
    fail_context = make_context(
        fail_request,
        final=FinalState(answer=fail_answer),
        tags=TagSpec(result={"cf"}),
        resolve_handler=fail_recorder.resolve,
    )
    await plugin_fail.on_response(fail_context)
    assert HTTPS_PARAM_KEY.ECH not in next(iter(fail_answer.rrset)).params
    plugin_fail._load_cloudflare_ech_cached.cache_clear()


async def test_cloudflare_ech_plugin_injects_all_service_mode_records_and_keeps_alias_mode() -> (
    None
):
    plugin = build_plugin(match_tags=["cf"])
    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_https_answer(
        request,
        "0 .",
        '1 . alpn="h2"',
        '2 . ipv4hint="203.0.113.10"',
    )
    recorder = ResolveRecorder(
        {
            ("cloudflare-ech.com", "HTTPS"): make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . ech="AA=="',
            )
        }
    )
    context = make_context(
        request,
        final=FinalState(answer=answer),
        tags=TagSpec(result={"cf"}),
        resolve_handler=recorder.resolve,
    )

    await plugin.on_response(context)

    rdatas = {rdata.priority: rdata for rdata in answer.rrset}
    assert HTTPS_PARAM_KEY.ECH not in rdatas[0].params
    assert rdatas[1].params[HTTPS_PARAM_KEY.ECH].ech == b"\x00"
    assert rdatas[2].params[HTTPS_PARAM_KEY.ECH].ech == b"\x00"
    plugin._load_cloudflare_ech_cached.cache_clear()


async def test_cloudflare_ech_plugin_runs_before_https_and_cache_plugins() -> None:
    cloudflare_plugin = build_plugin(match_tags=["cf"])
    https_plugin = HttpsPlugin()
    cache_plugin = CachePlugin()
    registry = PluginRegistry()
    await cloudflare_plugin.setup(registry)
    for plugin in (https_plugin, cache_plugin):
        plugin.bind(plugin.config_model(), plugin.variables_model())
        await plugin.setup(registry)

    manager = PluginManager(
        [
            make_loaded_plugin(cloudflare_plugin),
            make_loaded_plugin(https_plugin),
            make_loaded_plugin(cache_plugin),
        ],
        registry,
    )
    config = build_config()
    request = dns.message.make_query("example.test", "HTTPS")
    handlers = {
        ("example.test", "HTTPS"): UpstreamResult(
            upstream_name="upstream-a",
            duration_ms=5.0,
            answer=make_https_answer(
                request,
                '1 . alpn="h3,h2" ipv4hint="203.0.113.10"',
            ),
            tags={"cf"},
        ),
        ("cloudflare-ech.com", "HTTPS"): UpstreamResult(
            upstream_name="upstream-a",
            duration_ms=2.0,
            answer=make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . ech="AA=="',
            ),
        ),
    }
    resolver_manager = QueryAwareResolverManager(config, handlers)
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), manager)

    first_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")
    second_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")

    assert first_response is not None
    assert second_response is not None
    first_rdata = next(iter(first_response.answer[0]))
    second_rdata = next(iter(second_response.answer[0]))
    assert first_rdata.params[HTTPS_PARAM_KEY.ECH].ech == b"\x00"
    assert second_rdata.params[HTTPS_PARAM_KEY.ECH].ech == b"\x00"
    assert first_rdata.params[HTTPS_PARAM_KEY.ALPN].ids == (b"h2",)
    assert second_rdata.params[HTTPS_PARAM_KEY.ALPN].ids == (b"h2",)
    assert HTTPS_PARAM_KEY.IPV4HINT not in first_rdata.params
    assert HTTPS_PARAM_KEY.IPV4HINT not in second_rdata.params
    assert resolver_manager.calls == [
        ("example.test", "HTTPS"),
        ("cloudflare-ech.com", "HTTPS"),
    ]
    cloudflare_plugin._load_cloudflare_ech_cached.cache_clear()


async def test_cloudflare_ech_plugin_handles_empty_noerror_answers_before_https_and_cache_plugins() -> (  # noqa: E501
    None
):
    cloudflare_plugin = build_plugin(match_tags=["cf"])
    https_plugin = HttpsPlugin()
    cache_plugin = CachePlugin()
    registry = PluginRegistry()
    await cloudflare_plugin.setup(registry)
    for plugin in (https_plugin, cache_plugin):
        plugin.bind(plugin.config_model(), plugin.variables_model())
        await plugin.setup(registry)

    manager = PluginManager(
        [
            make_loaded_plugin(cloudflare_plugin),
            make_loaded_plugin(https_plugin),
            make_loaded_plugin(cache_plugin),
        ],
        registry,
    )
    config = build_config()
    request = dns.message.make_query("empty.test", "HTTPS")
    handlers = {
        ("empty.test", "HTTPS"): UpstreamResult(
            upstream_name="upstream-a",
            duration_ms=5.0,
            answer=make_empty_answer(request),
            tags={"cf"},
        ),
        ("cloudflare-ech.com", "HTTPS"): UpstreamResult(
            upstream_name="upstream-a",
            duration_ms=2.0,
            answer=make_https_answer(
                dns.message.make_query("cloudflare-ech.com", "HTTPS"),
                '1 . ech="AA=="',
            ),
        ),
    }
    resolver_manager = QueryAwareResolverManager(config, handlers)
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), manager)

    first_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")
    second_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")

    assert first_response is not None
    assert second_response is not None
    assert len(first_response.answer) == 1
    assert len(second_response.answer) == 1
    first_rdata = next(iter(first_response.answer[0]))
    second_rdata = next(iter(second_response.answer[0]))
    assert first_rdata.priority == 1
    assert second_rdata.priority == 1
    assert first_rdata.target.to_text() == "."
    assert second_rdata.target.to_text() == "."
    assert first_rdata.params[HTTPS_PARAM_KEY.ECH].ech == b"\x00"
    assert second_rdata.params[HTTPS_PARAM_KEY.ECH].ech == b"\x00"
    assert resolver_manager.calls == [
        ("empty.test", "HTTPS"),
        ("cloudflare-ech.com", "HTTPS"),
    ]
    cloudflare_plugin._load_cloudflare_ech_cached.cache_clear()


async def test_ech_cache_is_per_instance() -> None:
    """类级 alru_cache 会被所有 worker 实例共享并跨 loop 清空；实例级则各自独立。"""
    from plugins.cloudflare_ech_plugin.plugin import CloudflareEchPlugin

    plugin_a = CloudflareEchPlugin()
    plugin_b = CloudflareEchPlugin()
    assert plugin_a._load_cloudflare_ech_cached is not plugin_b._load_cloudflare_ech_cached
