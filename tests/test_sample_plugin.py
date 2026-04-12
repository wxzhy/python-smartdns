from __future__ import annotations

import dns.message

from dns_forwarder.pipeline import RequestContext
from dns_forwarder.plugin_api import PluginManager, PluginRegistry
from plugins.sample_plugin import SamplePlugin


async def test_sample_plugin_skips_non_a_request() -> None:
    plugin = SamplePlugin()
    plugin.bind(plugin.config_model(), plugin.variables_model())
    registry = PluginRegistry()
    await plugin.setup(registry)
    manager = PluginManager([], registry)
    context = RequestContext(
        request=dns.message.make_query("sample.internal", "AAAA"),
        clientaddr=("127.0.0.1", 5300),
        listener_name="udp",
        answer_registry_refs=manager.build_answer_registry(),
    )

    await plugin.on_request(context)

    assert context.final_answer is None
    assert context.final_response is None
