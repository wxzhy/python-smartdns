from __future__ import annotations

import asyncio
import inspect

import anyio
import anyio.from_thread
import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset

import plugins.query_log_plugin.service as query_log_service
from dns_forwarder.config import AppConfig, PluginConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline import RequestContext, UpstreamResult, build_answer_from_response
from dns_forwarder.pipeline.context import sync_answer_response
from dns_forwarder.pipeline.engine import PipelineEngine
from dns_forwarder.plugin_api import EmptyModel, LoadedPlugin, Plugin, PluginManager, PluginRegistry
from plugins.cache_plugin import CachePlugin, CachePluginConfig
from plugins.query_log_plugin import (
    QUERY_LOG_STORE_KEY,
    QueryLogPayload,
    QueryLogPlugin,
    QueryLogPluginConfig,
    QueryLogStore,
)
from plugins.sample_plugin import SamplePlugin, SamplePluginConfig, SamplePluginVariables

_LOG_DURATION_MS = 12.5
_LOG_ENTRY_COUNT = 2
_LOG_REPLAY_ID = 3
_LOG_PUSHED_ID = 4


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


class StaticResolverManager:
    def __init__(self, config: AppConfig, handler) -> None:
        self._groups = {group.name: group for group in config.groups}
        self._handler = handler
        self.calls = 0

    def get_group(self, group_name: str):
        return self._groups[group_name]

    def has_group(self, group_name: str) -> bool:
        return group_name in self._groups

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        self.calls += 1
        return self._handler(upstream_name, context)


class NestedResolvePlugin(Plugin):
    name = "nested-resolve-plugin"
    config_model = EmptyModel
    variables_model = EmptyModel

    async def on_request(self, context: RequestContext) -> None:
        qname = context.request.question[0].name.to_text().rstrip(".").lower()
        if qname != "outer.internal":
            return

        nested_answer = await context.resolve("sample.internal", "A")
        response = dns.message.make_response(context.request)
        answer = build_answer_from_response(context.request, response)
        answer.rrset = dns.rrset.from_text(
            context.request.question[0].name.to_text(),
            30,
            "IN",
            "A",
            nested_answer.rrset[0].address,
        )
        context.final_answer = sync_answer_response(answer)


def make_loaded_plugin(instance: Plugin, *, name: str, module: str) -> LoadedPlugin:
    return LoadedPlugin(
        instance=instance,
        config=instance.runtime_config,
        variables=instance.runtime_variables,
        raw_config=PluginConfig(name=name, module=module),
    )


def make_answer(request: dns.message.Message, *items: str):
    response = dns.message.make_response(request)
    if items:
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


def get_query_log_store(manager: PluginManager) -> QueryLogStore:
    registration = manager.registry.context_registry[QUERY_LOG_STORE_KEY]
    assert registration.factory is None
    store = registration.value
    assert isinstance(store, QueryLogStore)
    return store


async def build_manager(
    *plugins: Plugin,
) -> PluginManager:
    registry = PluginRegistry()
    loaded_plugins: list[LoadedPlugin] = []
    for plugin in plugins:
        await plugin.setup(registry)
        loaded_plugins.append(
            make_loaded_plugin(
                plugin,
                name=plugin.name,
                module=plugin.name.replace("-", "_"),
            )
        )
    return PluginManager(loaded_plugins, registry)


async def test_query_log_plugin_records_upstream_answer_once() -> None:
    config = build_config()
    query_log_plugin = QueryLogPlugin()
    query_log_plugin.bind(QueryLogPluginConfig(), query_log_plugin.variables_model())
    manager = await build_manager(query_log_plugin)

    def handler(upstream_name: str, context: RequestContext) -> UpstreamResult:
        return UpstreamResult(
            upstream_name=upstream_name,
            duration_ms=_LOG_DURATION_MS,
            answer=make_answer(context.request, "203.0.113.10"),
        )

    engine = PipelineEngine(
        config,
        StaticResolverManager(config, handler),
        DispatcherRegistry(),
        manager,
    )

    response = await engine.handle_message(
        dns.message.make_query("example.test", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )

    assert response is not None
    items = await get_query_log_store(manager).list_recent(10)
    assert len(items) == 1
    assert items[0].qname == "example.test"
    assert items[0].qtype == "A"
    assert items[0].rcode == "NOERROR"
    assert items[0].result_summary == "A 203.0.113.10"
    assert items[0].upstream == "upstream-a"
    assert items[0].duration_ms == _LOG_DURATION_MS


async def test_query_log_plugin_records_static_and_cache_short_circuit_requests() -> None:
    config = build_config()
    sample_plugin = SamplePlugin()
    sample_plugin.bind(
        SamplePluginConfig(domains=["sample.internal"], answer_name="sample.static_a"),
        SamplePluginVariables(address="127.0.0.1", ttl=30),
    )
    cache_plugin = CachePlugin()
    cache_plugin.bind(CachePluginConfig(), cache_plugin.variables_model())
    query_log_plugin = QueryLogPlugin()
    query_log_plugin.bind(QueryLogPluginConfig(), query_log_plugin.variables_model())
    manager = await build_manager(sample_plugin, cache_plugin, query_log_plugin)
    resolver_manager = StaticResolverManager(
        config,
        lambda upstream_name, context: UpstreamResult(
            upstream_name=upstream_name,
            duration_ms=1.0,
            answer=make_answer(context.request, "198.51.100.1"),
        ),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), manager)

    first = await engine.handle_message(
        dns.message.make_query("sample.internal", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )
    second = await engine.handle_message(
        dns.message.make_query("sample.internal", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )

    assert first is not None
    assert second is not None
    assert resolver_manager.calls == 0
    items = await get_query_log_store(manager).list_recent(10)
    assert len(items) == _LOG_ENTRY_COUNT
    assert items[0].result_summary == "A 127.0.0.1"
    assert items[0].upstream is None
    assert items[1].result_summary == "A 127.0.0.1"
    assert items[1].upstream is None


async def test_query_log_plugin_skips_nested_resolve_requests() -> None:
    config = build_config()
    nested_plugin = NestedResolvePlugin()
    nested_plugin.bind(nested_plugin.config_model(), nested_plugin.variables_model())
    sample_plugin = SamplePlugin()
    sample_plugin.bind(
        SamplePluginConfig(domains=["sample.internal"], answer_name="sample.static_a"),
        SamplePluginVariables(address="127.0.0.1", ttl=30),
    )
    query_log_plugin = QueryLogPlugin()
    query_log_plugin.bind(QueryLogPluginConfig(), query_log_plugin.variables_model())
    manager = await build_manager(nested_plugin, sample_plugin, query_log_plugin)
    resolver_manager = StaticResolverManager(
        config,
        lambda upstream_name, context: UpstreamResult(
            upstream_name=upstream_name,
            duration_ms=1.0,
            answer=make_answer(context.request, "198.51.100.1"),
        ),
    )
    engine = PipelineEngine(config, resolver_manager, DispatcherRegistry(), manager)

    response = await engine.handle_message(
        dns.message.make_query("outer.internal", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )

    assert response is not None
    items = await get_query_log_store(manager).list_recent(10)
    assert len(items) == 1
    assert items[0].qname == "outer.internal"


async def test_query_log_plugin_formats_noerror_empty_and_nxdomain() -> None:
    config = build_config()
    query_log_plugin = QueryLogPlugin()
    query_log_plugin.bind(QueryLogPluginConfig(), query_log_plugin.variables_model())
    manager = await build_manager(query_log_plugin)
    store = get_query_log_store(manager)

    def empty_handler(upstream_name: str, context: RequestContext) -> UpstreamResult:
        return UpstreamResult(
            upstream_name=upstream_name,
            duration_ms=5.0,
            answer=make_answer(context.request),
        )

    empty_engine = PipelineEngine(
        config,
        StaticResolverManager(config, empty_handler),
        DispatcherRegistry(),
        manager,
    )
    await empty_engine.handle_message(
        dns.message.make_query("empty.test", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )

    def nxdomain_handler(upstream_name: str, context: RequestContext) -> UpstreamResult:
        return UpstreamResult(
            upstream_name=upstream_name,
            duration_ms=7.5,
            error=dns.resolver.NXDOMAIN(),
        )

    nxdomain_engine = PipelineEngine(
        config,
        StaticResolverManager(config, nxdomain_handler),
        DispatcherRegistry(),
        manager,
    )
    await nxdomain_engine.handle_message(
        dns.message.make_query("missing.test", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )

    items = await store.list_recent(10)
    assert items[-2].qname == "empty.test"
    assert items[-2].rcode == "NOERROR"
    assert items[-2].result_summary == "NOERROR empty"
    assert items[-1].qname == "missing.test"
    assert items[-1].rcode == "NXDOMAIN"
    assert items[-1].result_summary == "NXDOMAIN"


async def test_query_log_store_rotates_replays_and_pushes_new_entries() -> None:
    store = QueryLogStore(max_entries=2, heartbeat_seconds=0.01)
    for index in range(1, 4):
        await store.append(
            QueryLogPayload(
                timestamp_ms=index,
                qname=f"example-{index}.test",
                qtype="A",
                listener="udp",
                rcode="NOERROR",
                result_summary=f"A 203.0.113.{index}",
            )
        )

    recent = await store.list_recent(10)
    assert [item.id for item in recent] == [2, _LOG_REPLAY_ID]

    stream = store.subscribe(after_id=2)
    replayed = await anext(stream)
    assert replayed is not None
    assert replayed.id == _LOG_REPLAY_ID

    await store.append(
        QueryLogPayload(
            timestamp_ms=4,
            qname="example-4.test",
            qtype="A",
            listener="udp",
            rcode="NOERROR",
            result_summary="A 203.0.113.4",
        )
    )
    pushed = await anext(stream)
    assert pushed is not None
    assert pushed.id == _LOG_PUSHED_ID
    await stream.aclose()


async def test_query_log_store_emits_heartbeat_when_idle() -> None:
    store = QueryLogStore(max_entries=2, heartbeat_seconds=0.01)
    stream = store.subscribe()
    heartbeat = await anext(stream)
    assert heartbeat is None
    await stream.aclose()


async def test_query_log_store_cross_loop_append_and_subscribe() -> None:
    """worker 线程（独立 loop）append，当前 loop subscribe —— 复现跨 loop 崩溃场景。"""
    store = QueryLogStore(max_entries=4, heartbeat_seconds=5.0)
    payload = QueryLogPayload(
        timestamp_ms=1,
        qname="cross.test",
        qtype="A",
        listener="udp",
        rcode="NOERROR",
        result_summary="A 203.0.113.1",
    )

    def append_in_portal() -> None:
        async def _append() -> None:
            await store.append(payload)

        with anyio.from_thread.start_blocking_portal(backend="asyncio") as portal:
            portal.call(_append)

    stream = store.subscribe()
    await anyio.to_thread.run_sync(append_in_portal)
    item = await anext(stream)
    assert item is not None
    assert item.qname == "cross.test"
    await stream.aclose()


async def test_query_log_store_avoids_loop_bound_asyncio_primitives() -> None:
    """跨 loop 安全的结构性断言：共享状态不得依赖绑定单个 loop 的 asyncio 原语。

    asyncio.Condition/Lock 等基于 _LoopBoundMixin，被多个事件循环（worker 线程
    各自的 loop + 主 loop）共享时会崩溃或死锁。单发场景下该竞态窗口极窄、无法
    确定性复现，故此处直接断言实现不使用这些原语（改用 threading.Lock +
    anyio.Event 等跨线程安全机制）。
    """
    store = QueryLogStore(max_entries=4)
    for value in vars(store).values():
        assert not isinstance(
            value, asyncio.Condition | asyncio.Lock | asyncio.Event | asyncio.Semaphore
        ), f"store 持有 loop 绑定的 asyncio 原语: {value!r}"
    loop_bound_names = {
        name
        for name, obj in vars(query_log_service).items()
        if inspect.isclass(obj) and issubclass(obj, asyncio.mixins._LoopBoundMixin)
    }
    assert not loop_bound_names, f"service 模块定义了 loop 绑定类型: {loop_bound_names}"
