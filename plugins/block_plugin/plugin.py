from __future__ import annotations

import dns.message
import dns.rdatatype
import dns.rrset
from pydantic import BaseModel, Field, field_validator

from dns_forwarder.pipeline import RequestContext, build_answer_from_response
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry


class BlockPluginConfig(BaseModel):
    match_tags: list[str] = Field(default_factory=list)
    response_ttl_seconds: int = Field(default=86400, ge=1)
    ipv4_address: str = "127.0.0.1"
    ipv6_address: str = "::1"

    @field_validator("match_tags", mode="before")
    @classmethod
    def normalize_match_tags(cls, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        seen: set[str] = set()
        normalized: list[str] = []
        for item in value:
            tag = str(item).strip()
            if not tag or tag in seen:
                continue
            seen.add(tag)
            normalized.append(tag)
        return normalized


class BlockPlugin(Plugin):
    name = "block-plugin"
    config_model = BlockPluginConfig
    variables_model = EmptyModel
    request_order = -50
    response_order = 900
    ui_meta = {
        "title": "Block Plugin",
        "description": "按 tag 拦截请求或在响应末尾改写结果，对 A/AAAA 返回 localhost 地址。",
    }

    async def setup(self, registry: PluginRegistry) -> None:
        return None

    async def on_request(self, context: RequestContext) -> None:
        if not self._matches(context.tags):
            return
        self._apply_block_response(context)

    async def on_response(self, context: RequestContext) -> None:
        response_tags = set(context.tags)
        if context.upstream_results:
            response_tags.update(context.upstream_results[-1].tags)
        if not self._matches(response_tags):
            return
        self._apply_block_response(context)

    def _matches(self, tags: set[str]) -> bool:
        return bool(tags.intersection(self.runtime_config.match_tags))

    def _apply_block_response(self, context: RequestContext) -> None:
        response = dns.message.make_response(context.request)
        question = context.request.question[0]
        record = self._build_record(question.name.to_text(), question.rdtype)
        if record is not None:
            response.answer.append(record)
        context.final_response = response
        context.final_answer = build_answer_from_response(context.request, response)

    def _build_record(self, qname: str, rdtype: dns.rdatatype.RdataType) -> dns.rrset.RRset | None:
        if rdtype == dns.rdatatype.A:
            return dns.rrset.from_text(
                qname,
                self.runtime_config.response_ttl_seconds,
                "IN",
                "A",
                self.runtime_config.ipv4_address,
            )
        if rdtype == dns.rdatatype.AAAA:
            return dns.rrset.from_text(
                qname,
                self.runtime_config.response_ttl_seconds,
                "IN",
                "AAAA",
                self.runtime_config.ipv6_address,
            )
        return None


plugin = BlockPlugin()
