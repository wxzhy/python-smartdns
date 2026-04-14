from __future__ import annotations

from ipaddress import ip_address

import dns.message
import dns.rdatatype
import dns.rrset
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from dns_forwarder.logging import format_tags, get_logger
from dns_forwarder.pipeline import RequestContext, build_answer_from_response
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

logger = get_logger("plugins.block")


class StrictPluginModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BlockPluginRuleConfig(StrictPluginModel):
    match_tags: list[str] = Field(default_factory=list, min_length=1)
    exclude_tags: list[str] = Field(default_factory=list)
    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
    block_other: bool = False
    response_ttl_seconds: int = Field(default=86400, ge=1)

    @field_validator("match_tags", "exclude_tags", mode="before")
    @classmethod
    def normalize_tags(cls, value: list[str] | None) -> list[str]:
        return _normalize_tags(value)

    @field_validator("ipv4_addresses", mode="before")
    @classmethod
    def normalize_ipv4_addresses(cls, value: list[str] | None) -> list[str]:
        return _normalize_addresses(value, version=4)

    @field_validator("ipv6_addresses", mode="before")
    @classmethod
    def normalize_ipv6_addresses(cls, value: list[str] | None) -> list[str]:
        return _normalize_addresses(value, version=6)

    @model_validator(mode="after")
    def validate_addresses(self) -> "BlockPluginRuleConfig":
        if not self.ipv4_addresses and not self.ipv6_addresses and not self.block_other:
            raise ValueError("静态应答规则至少需要一个 IPv4、IPv6 地址或启用 block_other")
        return self


class BlockPluginConfig(StrictPluginModel):
    rules: list[BlockPluginRuleConfig] = Field(default_factory=list)


class BlockPlugin(Plugin):
    name = "block-plugin"
    config_model = BlockPluginConfig
    variables_model = EmptyModel
    request_order = -50
    response_order = 900
    ui_meta = {
        "title": "Static Answer Plugin",
        "description": "按 tag 返回静态 A/AAAA 结果，或对非 A/AAAA 查询直接返回空的 NOERROR。",
    }

    async def setup(self, registry: PluginRegistry) -> None:
        return None

    async def on_request(self, context: RequestContext) -> None:
        self._apply_static_response(context, context.tags, phase="request")

    async def on_response(self, context: RequestContext) -> None:
        response_tags = set(context.tags)
        if context.upstream_results:
            response_tags.update(context.upstream_results[-1].tags)
        self._apply_static_response(context, response_tags, phase="response")

    def _apply_static_response(
        self, context: RequestContext, tags: set[str], *, phase: str
    ) -> None:
        question = context.request.question[0]
        rule = self._resolve_rule(tags, question.rdtype)
        if rule is None:
            return

        response = dns.message.make_response(context.request)
        addresses: list[str] = []
        if question.rdtype == dns.rdatatype.A:
            addresses = rule.ipv4_addresses
            response.answer.append(
                self._build_record(question.name.to_text(), question.rdtype, rule)
            )
        elif question.rdtype == dns.rdatatype.AAAA:
            addresses = rule.ipv6_addresses
            response.answer.append(
                self._build_record(question.name.to_text(), question.rdtype, rule)
            )
        context.final_response = response
        context.final_answer = build_answer_from_response(context.request, response)
        context.stop_processing = True
        logger.debug(
            "静态应答已应用 request_id=%s phase=%s qname=%s qtype=%s tags=%s address_count=%s ttl=%s block_other=%s",
            context.request_id,
            phase,
            question.name.to_text().rstrip("."),
            dns.rdatatype.to_text(question.rdtype),
            format_tags(tags),
            len(addresses),
            rule.response_ttl_seconds,
            rule.block_other,
        )

    def _resolve_rule(
        self,
        tags: set[str],
        rdtype: dns.rdatatype.RdataType,
    ) -> BlockPluginRuleConfig | None:
        for rule in self.runtime_config.rules:
            if self._has_any_tag(tags, rule.exclude_tags):
                continue
            if not self._has_any_tag(tags, rule.match_tags):
                continue
            if rdtype == dns.rdatatype.A and rule.ipv4_addresses:
                return rule
            if rdtype == dns.rdatatype.AAAA and rule.ipv6_addresses:
                return rule
            if rdtype not in {dns.rdatatype.A, dns.rdatatype.AAAA} and rule.block_other:
                return rule
        return None

    def _build_record(
        self,
        qname: str,
        rdtype: dns.rdatatype.RdataType,
        rule: BlockPluginRuleConfig,
    ) -> dns.rrset.RRset:
        if rdtype == dns.rdatatype.A:
            return dns.rrset.from_text_list(
                qname,
                rule.response_ttl_seconds,
                "IN",
                "A",
                rule.ipv4_addresses,
            )
        return dns.rrset.from_text_list(
            qname,
            rule.response_ttl_seconds,
            "IN",
            "AAAA",
            rule.ipv6_addresses,
        )

    @staticmethod
    def _has_any_tag(current_tags: set[str], configured_tags: list[str]) -> bool:
        return bool(current_tags.intersection(configured_tags))


def _normalize_tags(value: list[str] | None) -> list[str]:
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


def _normalize_addresses(value: list[str] | None, *, version: int) -> list[str]:
    if value is None:
        return []
    seen: set[str] = set()
    normalized: list[str] = []
    for item in value:
        address = ip_address(str(item).strip())
        if address.version != version:
            family = "IPv4" if version == 4 else "IPv6"
            raise ValueError(f"静态应答地址必须是 {family}")
        text = address.compressed
        if text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return normalized


plugin = BlockPlugin()
