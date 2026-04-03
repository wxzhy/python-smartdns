from __future__ import annotations

from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict, YamlConfigSettingsSource


def _normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value:
        raise ValueError("域名不能为空")
    return value


def _unique_names(items: list[Any], field_name: str) -> None:
    seen: set[str] = set()
    for item in items:
        value = getattr(item, field_name)
        if value in seen:
            raise ValueError(f"存在重复名称: {value}")
        seen.add(value)


class ListenerProtocol(StrEnum):
    UDP = "udp"
    TCP = "tcp"


class UpstreamProtocol(StrEnum):
    DO53 = "do53"
    DOH = "doh"
    DOT = "dot"
    DOQ = "doq"


class DispatchStrategyType(StrEnum):
    SEQUENTIAL = "sequential"
    RACE = "race"


class RuntimeConfig(BaseModel):
    plugin_dirs: list[str] = Field(default_factory=lambda: ["plugins"])
    loop_policy: str = "auto"
    default_upstream_group: str = "default"
    log_level: str = "INFO"

    @field_validator("plugin_dirs")
    @classmethod
    def validate_plugin_dirs(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("至少需要一个插件目录")
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError(f"未知 log_level: {value}")
        return normalized


class ListenerConfig(BaseModel):
    name: str
    protocol: ListenerProtocol
    host: str = "127.0.0.1"
    port: int = Field(default=53, ge=0, le=65535)
    enabled: bool = True


class EDNSClientSubnetConfig(BaseModel):
    address: IPv4Address | IPv6Address
    source_prefix: int | None = Field(default=None, ge=0, le=128)
    scope_prefix: int = Field(default=0, ge=0, le=128)

    @model_validator(mode="after")
    def validate_prefix_range(self) -> "EDNSClientSubnetConfig":
        max_bits = 32 if isinstance(self.address, IPv4Address) else 128
        if self.source_prefix is not None and self.source_prefix > max_bits:
            raise ValueError(f"source_prefix 超出地址位数: {max_bits}")
        if self.scope_prefix > max_bits:
            raise ValueError(f"scope_prefix 超出地址位数: {max_bits}")
        return self


class EDNSConfig(BaseModel):
    enabled: bool = False
    payload: int = Field(default=1232, ge=512, le=65535)
    client_subnet: EDNSClientSubnetConfig | None = None


class UpstreamConfig(BaseModel):
    name: str
    protocol: UpstreamProtocol = UpstreamProtocol.DO53
    host: str
    port: int = Field(default=53, ge=1, le=65535)
    timeout: float = Field(default=1.0, gt=0)
    lifetime: float = Field(default=3.0, gt=0)
    use_tcp: bool = False
    edns: EDNSConfig | None = None


class UpstreamGroupConfig(BaseModel):
    name: str
    strategy: DispatchStrategyType = DispatchStrategyType.SEQUENTIAL
    upstreams: list[str] = Field(min_length=1)


class RuleMatchConfig(BaseModel):
    exact_domains: list[str] = Field(default_factory=list)
    suffix_domains: list[str] = Field(default_factory=list)
    qtypes: list[str] = Field(default_factory=list)

    @field_validator("exact_domains", "suffix_domains", mode="before")
    @classmethod
    def normalize_domains(cls, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        return [_normalize_domain(item) for item in value]

    @field_validator("qtypes", mode="before")
    @classmethod
    def normalize_qtypes(cls, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        return [item.strip().upper() for item in value if item.strip()]

    @model_validator(mode="after")
    def validate_any_matcher(self) -> "RuleMatchConfig":
        if not self.exact_domains and not self.suffix_domains and not self.qtypes:
            raise ValueError("规则至少需要一个匹配条件")
        return self


class RuleActionConfig(BaseModel):
    upstream_group: str


class RuleConfig(BaseModel):
    name: str
    enabled: bool = True
    match: RuleMatchConfig
    action: RuleActionConfig


class PluginConfig(BaseModel):
    name: str
    module: str
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    variables: dict[str, Any] = Field(default_factory=dict)


class WebUIConfig(BaseModel):
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=0, le=65535)
    reload_endpoint: str = "/admin/reload"


class AppConfig(BaseSettings):
    """应用主配置。"""

    model_config = SettingsConfigDict(
        extra="ignore",
        env_prefix="DNS_FORWARDER_",
        env_nested_delimiter="__",
        yaml_file="config.yaml",
        yaml_file_encoding="utf-8",
    )

    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    listeners: list[ListenerConfig] = Field(default_factory=list)
    upstreams: list[UpstreamConfig] = Field(default_factory=list)
    groups: list[UpstreamGroupConfig] = Field(default_factory=list)
    rules: list[RuleConfig] = Field(default_factory=list)
    plugins: list[PluginConfig] = Field(default_factory=list)
    webui: WebUIConfig = Field(default_factory=WebUIConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )

    @model_validator(mode="after")
    def validate_references(self) -> "AppConfig":
        _unique_names(self.listeners, "name")
        _unique_names(self.upstreams, "name")
        _unique_names(self.groups, "name")
        _unique_names(self.rules, "name")
        _unique_names(self.plugins, "name")

        upstream_names = {item.name for item in self.upstreams}
        group_names = {item.name for item in self.groups}

        if not self.listeners:
            raise ValueError("至少需要一个 listener")
        if not self.upstreams:
            raise ValueError("至少需要一个 upstream")
        if not self.groups:
            raise ValueError("至少需要一个 upstream group")
        if self.runtime.default_upstream_group not in group_names:
            raise ValueError(f"default_upstream_group 未定义: {self.runtime.default_upstream_group}")

        for upstream in self.upstreams:
            if upstream.protocol is not UpstreamProtocol.DO53:
                raise ValueError(f"当前版本仅支持 do53 upstream: {upstream.name}")

        for group in self.groups:
            missing = set(group.upstreams) - upstream_names
            if missing:
                missing_names = ", ".join(sorted(missing))
                raise ValueError(f"group {group.name} 引用了不存在的 upstream: {missing_names}")

        for rule in self.rules:
            if rule.action.upstream_group not in group_names:
                raise ValueError(
                    f"rule {rule.name} 引用了不存在的 upstream_group: {rule.action.upstream_group}"
                )

        return self
