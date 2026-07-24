from __future__ import annotations

from ipaddress import ip_network

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

IPV4_VERSION = 4


class StrictPluginModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IpReplaceRuleConfig(StrictPluginModel):
    name: str
    match_tags: list[str] = Field(default_factory=list, min_length=1)
    exclude_tags: list[str] = Field(default_factory=list)
    ipv4_targets: list[str] = Field(default_factory=list)
    ipv6_targets: list[str] = Field(default_factory=list)

    @field_validator("match_tags", "exclude_tags", mode="before")
    @classmethod
    def normalize_tags(cls, value: list[str] | None) -> list[str]:
        return _normalize_tags(value)

    @field_validator("ipv4_targets", mode="before")
    @classmethod
    def normalize_ipv4_targets(cls, value: list[str] | None) -> list[str]:
        return _normalize_networks(value, version=4)

    @field_validator("ipv6_targets", mode="before")
    @classmethod
    def normalize_ipv6_targets(cls, value: list[str] | None) -> list[str]:
        return _normalize_networks(value, version=6)

    @model_validator(mode="after")
    def validate_targets(self) -> IpReplaceRuleConfig:
        if not self.ipv4_targets and not self.ipv6_targets:
            raise ValueError("替换规则至少需要一个 IPv4 或 IPv6 目标 CIDR")
        return self


class IpReplacePluginConfig(StrictPluginModel):
    skip_tags: list[str] = Field(default_factory=list)
    rules: list[IpReplaceRuleConfig] = Field(default_factory=list)

    @field_validator("skip_tags", mode="before")
    @classmethod
    def normalize_skip_tags(cls, value: list[str] | None) -> list[str]:
        return _normalize_tags(value)


def _normalize_networks(value: list[str] | None, *, version: int) -> list[str]:
    if value is None:
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        network = ip_network(str(item).strip(), strict=False)
        if network.version != version:
            family = "IPv4" if version == IPV4_VERSION else "IPv6"
            raise ValueError(f"目标网段必须是 {family} CIDR")
        text = network.with_prefixlen
        if text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return normalized


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
