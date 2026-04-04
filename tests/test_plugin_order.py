from __future__ import annotations

import dns.message

from dns_forwarder.config import PluginConfig
from dns_forwarder.pipeline import RequestContext, UpstreamResult
from dns_forwarder.plugin_api import EmptyModel, LoadedPlugin, Plugin, PluginManager, PluginRegistry


class OrderedPlugin(Plugin):
    config_model = EmptyModel
    variables_model = EmptyModel

    def __init__(
        self,
        name: str,
        events: list[str],
        *,
        request_order: int = 0,
        upstream_response_order: int = 0,
        response_order: int = 0,
    ) -> None:
        super().__init__()
        self.name = name
        self.request_order = request_order
        self.upstream_response_order = upstream_response_order
        self.response_order = response_order
        self._events = events

    async def on_request(self, context: RequestContext) -> None:
        self._events.append(f"request:{self.name}")

    async def on_upstream_response(self, context: RequestContext, result: UpstreamResult) -> None:
        self._events.append(f"upstream:{self.name}")

    async def on_response(self, context: RequestContext) -> None:
        self._events.append(f"response:{self.name}")


def make_loaded_plugin(instance: Plugin) -> LoadedPlugin:
    config = instance.config_model()
    variables = instance.variables_model()
    instance.bind(config, variables)
    return LoadedPlugin(
        instance=instance,
        config=config,
        variables=variables,
        raw_config=PluginConfig(name=instance.name, module=instance.name),
    )


def make_context() -> RequestContext:
    return RequestContext(
        request=dns.message.make_query("example.test", "A"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
    )


async def test_plugin_manager_sorts_request_hooks_by_request_order() -> None:
    events: list[str] = []
    manager = PluginManager(
        [
            make_loaded_plugin(OrderedPlugin("second", events, request_order=20)),
            make_loaded_plugin(OrderedPlugin("first", events, request_order=10)),
            make_loaded_plugin(OrderedPlugin("third", events, request_order=20)),
        ],
        PluginRegistry(),
    )
    context = make_context()

    await manager.on_request(context)

    assert events == ["request:first", "request:second", "request:third"]
    assert context.metadata["plugin_order"] == ["first", "second", "third"]


async def test_plugin_manager_sorts_upstream_and_response_hooks_independently() -> None:
    events: list[str] = []
    manager = PluginManager(
        [
            make_loaded_plugin(
                OrderedPlugin(
                    "first",
                    events,
                    upstream_response_order=30,
                    response_order=20,
                )
            ),
            make_loaded_plugin(
                OrderedPlugin(
                    "second",
                    events,
                    upstream_response_order=10,
                    response_order=30,
                )
            ),
            make_loaded_plugin(
                OrderedPlugin(
                    "third",
                    events,
                    upstream_response_order=20,
                    response_order=10,
                )
            ),
        ],
        PluginRegistry(),
    )
    context = make_context()
    result = UpstreamResult(upstream_name="upstream-a", duration_ms=5.0)

    await manager.on_upstream_response(context, result)
    await manager.on_response(context)

    assert events == [
        "upstream:second",
        "upstream:third",
        "upstream:first",
        "response:third",
        "response:first",
        "response:second",
    ]
