from __future__ import annotations

from pathlib import Path

import dns.message

from dns_forwarder.config import AppConfig, PluginConfig
from dns_forwarder.core import DOMAINSET_CONTEXT_KEY, DomainSet
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import LoadedPlugin, PluginManager, PluginRegistry
from plugins.block_plugin import BlockPlugin, BlockPluginConfig
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


async def test_block_plugin_short_circuits_request_for_a() -> None:
    plugin = BlockPlugin()
    plugin.bind(BlockPluginConfig(match_tags=["blackhole"], response_ttl_seconds=7200), plugin.variables_model())
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
    assert [item.address for item in context.final_answer.rrset] == ["127.0.0.1"]
    assert context.final_answer.rrset.ttl == 7200


async def test_block_plugin_short_circuits_request_for_aaaa() -> None:
    plugin = BlockPlugin()
    plugin.bind(BlockPluginConfig(match_tags=["blackhole"]), plugin.variables_model())
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
    assert [item.address for item in context.final_answer.rrset] == ["::1"]


async def test_block_plugin_returns_empty_noerror_for_non_address_query() -> None:
    plugin = BlockPlugin()
    plugin.bind(BlockPluginConfig(match_tags=["blackhole"]), plugin.variables_model())
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


async def test_block_plugin_rewrites_final_response_for_matching_result_tags() -> None:
    plugin = BlockPlugin()
    plugin.bind(BlockPluginConfig(match_tags=["blackhole"], response_ttl_seconds=600), plugin.variables_model())
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
        upstream_results=[UpstreamResult(upstream_name="upstream-a", duration_ms=1.0, answer=answer, tags={"blackhole"})],
    )

    await plugin.on_response(context)

    assert context.final_answer is not None
    assert context.final_answer.rrset is not None
    assert [item.address for item in context.final_answer.rrset] == ["127.0.0.1"]
    assert context.final_answer.rrset.ttl == 600


async def test_block_plugin_works_after_tag_plugin_in_request_phase(tmp_path: Path) -> None:
    domain_dir = tmp_path / "domains"
    domain_dir.mkdir()
    _write_lines(domain_dir / "blackhole.txt", ["example.test"])

    registry = PluginRegistry()
    registry.register_context(DOMAINSET_CONTEXT_KEY, DomainSet(str(domain_dir)))

    tag_plugin = TagPlugin()
    tag_plugin.bind(tag_plugin.config_model(), tag_plugin.variables_model())
    await tag_plugin.setup(registry)

    block_plugin = BlockPlugin()
    block_plugin.bind(BlockPluginConfig(match_tags=["blackhole"]), block_plugin.variables_model())
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
