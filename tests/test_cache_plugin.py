from __future__ import annotations

import dns.message
import dns.rcode
import dns.resolver
import dns.rrset

from dns_forwarder.config import AppConfig, PluginConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import EmptyModel, LoadedPlugin, Plugin, PluginManager, PluginRegistry
from plugins.cache_plugin import CachePlugin, CachePluginConfig, DnsCacheService, get_cache_context


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

    async def on_response(self, context: RequestContext) -> None:
        if context.final_answer is None:
            return
        context.final_answer.rrset = dns.rrset.from_text(
            context.final_answer.rrset.name.to_text(),
            120,
            "IN",
            "A",
            "198.51.100.99",
        )


async def build_plugin_manager(
    config: CachePluginConfig | None = None,
) -> tuple[PluginManager, CachePlugin]:
    plugin = CachePlugin()
    plugin_config = config or CachePluginConfig()
    variables = plugin.variables_model()
    plugin.bind(plugin_config, variables)
    registry = PluginRegistry()
    await plugin.setup(registry)
    loaded = LoadedPlugin(
        instance=plugin,
        config=plugin_config,
        variables=variables,
        raw_config=PluginConfig(name="cache", module="cache_plugin"),
    )
    return PluginManager([loaded], registry), plugin


async def build_plugin_manager_with_mutator() -> tuple[PluginManager, CachePlugin]:
    plugin_manager, cache_plugin = await build_plugin_manager()
    mutator = ResponseMutatingPlugin()
    mutator.bind(mutator.config_model(), mutator.variables_model())
    loaded = [
        plugin_manager.loaded_plugins[0],
        LoadedPlugin(
            instance=mutator,
            config=mutator.config_model(),
            variables=mutator.variables_model(),
            raw_config=PluginConfig(name="mutator", module="response_mutator"),
        ),
    ]
    return PluginManager(loaded, plugin_manager.registry), cache_plugin


def make_answer(request: dns.message.Message, address: str) -> dns.resolver.Answer:
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


async def test_cache_plugin_hits_cache_during_request_phase() -> None:
    manager, plugin = await build_plugin_manager()
    assert plugin._service is not None

    request = dns.message.make_query("example.test", "A")
    plugin._service.put_answer(make_answer(request, "203.0.113.10"))
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
    )

    await manager.on_request(context)

    cache_context = get_cache_context(context)
    assert cache_context.hit is True
    assert context.metadata["cache_hit"] is True
    assert context.final_answer is not None
    assert context.final_answer[0].address == "203.0.113.10"


async def test_cache_plugin_writes_noerror_answer_and_serves_second_request_from_cache() -> None:
    manager, plugin = await build_plugin_manager()
    request = dns.message.make_query("example.test", "A")
    answer = make_answer(request, "203.0.113.20")
    resolver_manager = CountingResolverManager(
        build_config(),
        UpstreamResult(upstream_name="upstream-a", duration_ms=5.0, answer=answer),
    )
    engine = PipelineEngine(build_config(), resolver_manager, DispatcherRegistry(), manager)

    first_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")
    second_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")

    assert first_response is not None
    assert second_response is not None
    assert first_response.answer[0][0].address == "203.0.113.20"
    assert second_response.answer[0][0].address == "203.0.113.20"
    assert resolver_manager.calls == 1
    assert plugin._service is not None
    assert plugin._service.hits() >= 1


async def test_cache_plugin_skips_non_noerror_answers_on_write() -> None:
    manager, plugin = await build_plugin_manager()
    assert plugin._service is not None

    request = dns.message.make_query("missing.test", "A")
    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.SERVFAIL)
    context = RequestContext(
        request=request,
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        extensions=manager.build_context_extensions(),
        final_answer=build_answer_from_response(request, response),
        final_response=response,
    )

    await manager.on_response(context)

    assert plugin._service.get_for_request(request) is None


async def test_dns_cache_service_uses_dnspython_lru_cache() -> None:
    service = DnsCacheService(max_size=16)
    request = dns.message.make_query("example.test", "A")
    answer = make_answer(request, "203.0.113.30")

    service.put_answer(answer)
    cached = service.get_for_request(request)

    assert isinstance(service._cache, dns.resolver.LRUCache)
    assert cached is not None
    assert cached[0].address == "203.0.113.30"


async def test_dns_cache_service_reduces_ttl_on_cache_hit(monkeypatch) -> None:
    service = DnsCacheService(max_size=16)
    request = dns.message.make_query("example.test", "A")
    answer = make_answer(request, "203.0.113.31")
    answer.expiration = 1060.0

    monkeypatch.setattr("plugins.cache_plugin.service.time.time", lambda: 1000.0)
    service.put_answer(answer)

    monkeypatch.setattr("plugins.cache_plugin.service.time.time", lambda: 1012.4)
    cached = service.get_for_request(request)

    assert cached is not None
    assert cached.rrset is not None
    assert cached.rrset.ttl == 47
    assert cached.response.answer[0].ttl == 47


async def test_cache_plugin_runs_last_in_response_hooks_and_caches_mutated_answer() -> None:
    manager, _ = await build_plugin_manager_with_mutator()
    request = dns.message.make_query("example.test", "A")
    answer = make_answer(request, "203.0.113.40")
    resolver_manager = CountingResolverManager(
        build_config(),
        UpstreamResult(upstream_name="upstream-a", duration_ms=5.0, answer=answer),
    )
    engine = PipelineEngine(build_config(), resolver_manager, DispatcherRegistry(), manager)

    first_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")
    second_response = await engine.handle_message(request, ("127.0.0.1", 10000), "udp")

    assert first_response is not None
    assert second_response is not None
    assert first_response.answer[0][0].address == "198.51.100.99"
    assert second_response.answer[0][0].address == "198.51.100.99"
    assert resolver_manager.calls == 1
