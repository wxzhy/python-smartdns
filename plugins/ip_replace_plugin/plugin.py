from __future__ import annotations

from typing import TYPE_CHECKING

import dns.rdatatype

from dns_forwarder.logging import format_tags, get_logger
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

from .models import IpReplacePluginConfig
from .service import IpReplaceService

if TYPE_CHECKING:
    from dns_forwarder.pipeline import RequestContext, UpstreamResult

logger = get_logger("plugins.ip_replace")


ADDRESS_TYPES = {dns.rdatatype.A, dns.rdatatype.AAAA}


class IpReplacePlugin(Plugin):
    name = "ip-replace-plugin"
    config_model = IpReplacePluginConfig
    variables_model = EmptyModel
    upstream_response_order = 100
    response_order = 500
    ui_meta = {  # noqa: RUF012  # read-only frozen-style plugin metadata
        "title": "IP Replace Plugin",
        "description": (
            "按上游结果 tags 匹配规则，并用目标 IPv4/IPv6 CIDR 对正常 A/AAAA 响应做前缀替换。"
        ),
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
        if context.request.question[0].rdtype not in ADDRESS_TYPES:
            return
        if self._service.replace_answer(result.answer, result.tags, stage="upstream_response"):
            logger.debug(
                "IP 替换已应用 request_id=%s stage=upstream_response upstream=%s result_tags=%s",
                context.request_id,
                result.upstream_name,
                format_tags(result.tags),
            )

    async def on_response(self, context: RequestContext) -> None:
        if context.request.question[0].rdtype not in ADDRESS_TYPES:
            return
        if not context.upstream_results:
            return
        if self._service.replace_answer(
            context.final_answer, context.upstream_results[-1].tags, stage="response"
        ):
            logger.debug(
                "IP 替换已应用 request_id=%s stage=response qtype=%s result_tags=%s",
                context.request_id,
                dns.rdatatype.to_text(context.request.question[0].rdtype),
                format_tags(context.upstream_results[-1].tags),
            )


plugin = IpReplacePlugin()
