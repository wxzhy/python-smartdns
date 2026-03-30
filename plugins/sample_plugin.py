from __future__ import annotations

import dns.message
import dns.rrset
from pydantic import BaseModel, Field, field_validator

from dns_forwarder.plugin_api import Plugin, PluginRegistry


def _normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value:
        raise ValueError("域名不能为空")
    return value


class SamplePluginConfig(BaseModel):
    domains: list[str] = Field(default_factory=lambda: ["sample.internal"])
    answer_name: str = "sample.static_a"

    @field_validator("domains", mode="before")
    @classmethod
    def normalize_domains(cls, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        return [_normalize_domain(item) for item in value]


class SamplePluginVariables(BaseModel):
    address: str = "127.0.0.1"
    ttl: int = 30


class SamplePlugin(Plugin):
    name = "sample-plugin"
    config_model = SamplePluginConfig
    variables_model = SamplePluginVariables
    ui_meta = {
        "title": "Sample Plugin",
        "description": "示例插件：对指定域名直接返回一个静态 A 记录。",
    }

    async def setup(self, registry: PluginRegistry) -> None:
        registry.register_context("sample.loaded", True)
        registry.register_resolver("sample.meta", {"kind": "static-answer"})
        registry.register_answer(self.runtime_config.answer_name, self._build_static_answer)

    async def on_request(self, context) -> None:
        question = context.request.question[0]
        qname = question.name.to_text().rstrip(".").lower()
        if qname not in self.runtime_config.domains:
            return
        builder = context.answer_registry_refs[self.runtime_config.answer_name]
        context.final_response = builder(context)

    def _build_static_answer(self, context) -> dns.message.Message:
        question = context.request.question[0]
        response = dns.message.make_response(context.request)
        rrset = dns.rrset.from_text(
            question.name.to_text(),
            self.runtime_variables.ttl,
            "IN",
            "A",
            self.runtime_variables.address,
        )
        response.answer.append(rrset)
        return response


plugin = SamplePlugin()
