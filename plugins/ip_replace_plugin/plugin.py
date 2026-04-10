from __future__ import annotations

from dns_forwarder.pipeline import RequestContext, UpstreamResult
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

from .models import IpReplacePluginConfig
from .service import IpReplaceService


class IpReplacePlugin(Plugin):
    name = "ip-replace-plugin"
    config_model = IpReplacePluginConfig
    variables_model = EmptyModel
    upstream_response_order = 100
    response_order = 500
    ui_meta = {
        "title": "IP Replace Plugin",
        "description": "按上游结果 tags 匹配规则，并用目标 IPv4/IPv6 CIDR 对正常 A/AAAA 响应做前缀替换。",
    }

    def __init__(self) -> None:
        super().__init__()
        self._service = IpReplaceService([])

    async def setup(self, registry: PluginRegistry) -> None:
        self._service = IpReplaceService(
            self.runtime_config.rules,
            skip_tags=self.runtime_config.skip_tags,
        )

    async def on_upstream_response(self, context: RequestContext, result: UpstreamResult) -> None:
        self._service.replace_answer(result.answer, result.tags)

    async def on_response(self, context: RequestContext) -> None:
        if not context.upstream_results:
            return
        self._service.replace_answer(context.final_answer, context.upstream_results[-1].tags)


plugin = IpReplacePlugin()
