from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


def normalize_domain(value: str) -> str:
    domain = str(value).strip().rstrip(".").lower()
    if not domain:
        raise ValueError("域名不能为空")
    return domain


class StrictPluginModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


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
