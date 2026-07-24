from __future__ import annotations

from pydantic import Field, field_validator

from dns_forwarder.core.domainset import normalize_domain
from dns_forwarder.plugin_api import StrictPluginModel


class RedirectPluginConfig(StrictPluginModel):
    redirects: dict[str, str] = Field(default_factory=dict)

    @field_validator("redirects", mode="before")
    @classmethod
    def normalize_redirects(cls, value: dict[str, str] | None) -> dict[str, str]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError("redirects 必须是对象映射")

        normalized: dict[str, str] = {}
        for source, target in value.items():
            normalized_source = normalize_domain(source)
            normalized_target = normalize_domain(target)
            if normalized_source == normalized_target:
                raise ValueError("redirect 源域名与目标域名不能相同")
            normalized[normalized_source] = normalized_target
        return normalized
