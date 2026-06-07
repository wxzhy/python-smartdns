from __future__ import annotations

import dns.message
import dns.rdatatype
import dns.rrset
from pydantic import BaseModel, Field, field_validator

from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline import build_answer_from_response, sync_answer_response
from dns_forwarder.core.domainset import normalize_domain
from dns_forwarder.plugin_api import Plugin, PluginRegistry

logger = get_logger("plugins.sample")


class SamplePluginConfig(BaseModel):
    domains: list[str] = Field(default_factory=lambda: ["sample.internal"])
    answer_name: str = "sample.static_a"

    @field_validator("domains", mode="before")
    @classmethod
    def normalize_domains(cls, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        return [normalize_domain(item) for item in value]


class SamplePluginVariables(BaseModel):
    address: str = "127.0.0.1"
    ttl: int = 30


class SamplePlugin(Plugin):
    name = "sample-plugin"
    config_model = SamplePluginConfig
    variables_model = SamplePluginVariables
    ui_meta = {
        "title": "Sample Plugin",
        "description": "示例插件：通过修改 dns.resolver.Answer.rrset 返回一个静态 A 记录。",
    }

    async def setup(self, registry: PluginRegistry) -> None:
        registry.register_context("sample.loaded", True)
        registry.register_resolver("sample.meta", {"kind": "static-answer"})
        registry.register_answer(self.runtime_config.answer_name, self._build_static_answer)

    async def on_request(self, context) -> None:
        question = context.request.question[0]
        if question.rdtype != dns.rdatatype.A:
            return
        qname = question.name.to_text().rstrip(".").lower()
        if qname not in self.runtime_config.domains:
            return
        builder = context.answer_registry_refs[self.runtime_config.answer_name]
        answer = build_answer_from_response(context.request, builder(context))
        answer.rrset = dns.rrset.from_text(
            question.name.to_text(),
            self.runtime_variables.ttl,
            "IN",
            "A",
            self.runtime_variables.address,
        )
        context.final_answer = sync_answer_response(answer)
        logger.debug(
            "示例插件命中 request_id=%s qname=%s answer_name=%s address=%s ttl=%s",
            context.request_id,
            qname,
            self.runtime_config.answer_name,
            self.runtime_variables.address,
            self.runtime_variables.ttl,
        )

    def _build_static_answer(self, context) -> dns.message.Message:
        return dns.message.make_response(context.request)


plugin = SamplePlugin()
