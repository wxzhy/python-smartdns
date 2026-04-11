from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictPluginModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


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
