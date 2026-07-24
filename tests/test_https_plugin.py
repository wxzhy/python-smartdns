from __future__ import annotations

import dns.message
import dns.rrset

from dns_forwarder.config import AppConfig, PluginConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import (
    RequestContext,
    UpstreamResult,
    build_answer_from_response,
    sync_answer_response,
)
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import LoadedPlugin, PluginManager, PluginRegistry
from plugins.cache_plugin import CachePlugin
from plugins.https_plugin import HttpsPlugin


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


def make_loaded_plugin(instance) -> LoadedPlugin:
    config = instance.config_model()
    variables = instance.variables_model()
    instance.bind(config, variables)
    return LoadedPlugin(
        instance=instance,
        config=config,
        variables=variables,
        raw_config=PluginConfig(name=instance.name, module=instance.name.replace("-", "_")),
    )


_HTTPS_RECORD = (
    '1 . mandatory="alpn,ipv4hint,ech" alpn="h3,h2" ipv4hint="203.0.113.10" '
    'ech="AA==" ipv6hint="2001:db8::10"'
)


def make_https_answer(request: dns.message.Message):
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            request.question[0].name.to_text(),
            60,
            "IN",
            "HTTPS",
            _HTTPS_RECORD,
        )
    )
    return build_answer_from_response(request, response)


async def test_https_plugin_strips_h3_and_hints_but_keeps_other_params() -> None:
    plugin = HttpsPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    await plugin.setup(registry)

    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_https_answer(request)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        final_answer=answer,
        final_response=answer.response,
    )

    await plugin.on_response(context)
    sync_answer_response(answer)
    rdata = next(iter(answer.rrset))

    assert rdata.params[dns.rdtypes.svcbbase.ParamKey.ALPN].ids == (b"h2",)
    assert dns.rdtypes.svcbbase.ParamKey.IPV4HINT not in rdata.params
    assert dns.rdtypes.svcbbase.ParamKey.IPV6HINT not in rdata.params
    assert dns.rdtypes.svcbbase.ParamKey.ECH in rdata.params
    assert rdata.params[dns.rdtypes.svcbbase.ParamKey.MANDATORY].keys == (
        dns.rdtypes.svcbbase.ParamKey.ALPN,
        dns.rdtypes.svcbbase.ParamKey.ECH,
    )


async def test_https_plugin_removes_empty_alpn_and_no_default_alpn_when_needed() -> None:
    plugin = HttpsPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    await plugin.setup(registry)

    request = dns.message.make_query("example.test", "HTTPS")
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            request.question[0].name.to_text(),
            60,
            "IN",
            "HTTPS",
            '1 . mandatory="alpn,no-default-alpn" alpn="h3" no-default-alpn',
        )
    )
    answer = build_answer_from_response(request, response)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        final_answer=answer,
    )

    await plugin.on_response(context)

    rdata = next(iter(answer.rrset))
    assert dns.rdtypes.svcbbase.ParamKey.ALPN not in rdata.params
    assert dns.rdtypes.svcbbase.ParamKey.NO_DEFAULT_ALPN not in rdata.params
    assert dns.rdtypes.svcbbase.ParamKey.MANDATORY not in rdata.params


async def test_https_plugin_skips_non_https_request_even_if_final_answer_is_https() -> None:
    plugin = HttpsPlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    await plugin.setup(registry)

    request = dns.message.make_query("example.test", "A")
    answer = make_https_answer(dns.message.make_query("example.test", "HTTPS"))
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        final_answer=answer,
    )

    await plugin.on_response(context)

    rdata = next(iter(answer.rrset))
    assert rdata.params[dns.rdtypes.svcbbase.ParamKey.ALPN].ids == (b"h3", b"h2")
    assert dns.rdtypes.svcbbase.ParamKey.IPV4HINT in rdata.params
    assert dns.rdtypes.svcbbase.ParamKey.IPV6HINT in rdata.params


async def test_https_plugin_runs_before_cache_plugin_and_cached_response_stays_sanitized() -> None:
    https_plugin = HttpsPlugin()
    cache_plugin = CachePlugin()
    registry = PluginRegistry()
    for plugin in (https_plugin, cache_plugin):
        plugin.bind(plugin.config_model(), plugin.variables_model())
        await plugin.setup(registry)

    manager = PluginManager(
        [
            make_loaded_plugin(https_plugin),
            make_loaded_plugin(cache_plugin),
        ],
        registry,
    )
    request = dns.message.make_query("example.test", "HTTPS")
    answer = make_https_answer(request)
    resolver_manager = CountingResolverManager(
        build_config(),
        UpstreamResult(upstream_name="upstream-a", duration_ms=5.0, answer=answer),
    )
    engine = PipelineEngine(build_config(), resolver_manager, DispatcherRegistry(), manager)

    first_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")
    second_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")

    assert first_response is not None
    assert second_response is not None
    first_rdata = next(iter(first_response.answer[0]))
    second_rdata = next(iter(second_response.answer[0]))
    assert first_rdata.params[dns.rdtypes.svcbbase.ParamKey.ALPN].ids == (b"h2",)
    assert second_rdata.params[dns.rdtypes.svcbbase.ParamKey.ALPN].ids == (b"h2",)
    assert dns.rdtypes.svcbbase.ParamKey.IPV4HINT not in first_rdata.params
    assert dns.rdtypes.svcbbase.ParamKey.IPV6HINT not in first_rdata.params
    assert dns.rdtypes.svcbbase.ParamKey.IPV4HINT not in second_rdata.params
    assert dns.rdtypes.svcbbase.ParamKey.IPV6HINT not in second_rdata.params
    assert resolver_manager.calls == 1
