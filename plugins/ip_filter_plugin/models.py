from __future__ import annotations

from pydantic import Field, field_validator

from dns_forwarder.plugin_api import StrictPluginModel, normalize_tag_list


class IpFilterPluginConfig(StrictPluginModel):
    match_tags: list[str] = Field(default_factory=list)
    exclude_tags: list[str] = Field(default_factory=list)
    whitelist_tags: list[str] = Field(default_factory=list)
    blacklist_tags: list[str] = Field(default_factory=list)

    @field_validator(
        "match_tags",
        "exclude_tags",
        "whitelist_tags",
        "blacklist_tags",
        mode="before",
    )
    @classmethod
    def normalize_tags(cls, value: list[str] | None) -> list[str]:
        return normalize_tag_list(value)
