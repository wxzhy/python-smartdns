from __future__ import annotations

import multiprocessing
import os
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Annotated, Any, Literal

import dns.rdatatype
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict
from pydantic_settings.sources.providers.json import JsonConfigSettingsSource


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


class NameserverProtocol(StrEnum):
    AIODNS = "aiodns"
    DO53 = "do53"
    DO53_CUSTOM = "do53_custom"
    DOH = "doh"
    DOH_CUSTOM = "doh_custom"
    DOH_HTTPX = "httpx"
    DOH_AIOHTTP = "aiohttp"
    DOH_CURL_CFFI = "curl"
    DOT = "dot"
    DOQ = "doq"
    DNSCRYPT = "dnscrypt"


class HTTPVersionType(StrEnum):
    DEFAULT = "default"
    H1 = "h1"
    H2 = "h2"
    H3 = "h3"


class DispatchStrategyType(StrEnum):
    RACE = "race"
    WAIT_ALL = "wait_all"


class StrictConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


WorkerCount = Annotated[int, Field(ge=1)] | Literal["auto"]
MultiprocessStartMethod = Literal["auto", "spawn", "forkserver", "fork"]


class MultiprocessConfig(StrictConfigModel):
    workers: WorkerCount = 1
    start_method: MultiprocessStartMethod = "auto"
    queue_size: int = Field(default=1024, ge=1)
    response_timeout: float = Field(default=10.0, gt=0)
    front_cache_size: int = Field(default=100000, ge=1)

    @field_validator("workers", mode="before")
    @classmethod
    def normalize_workers(cls, value: Any) -> Any:
        if isinstance(value, str):
            stripped = value.strip().lower()
            return "auto" if stripped == "auto" else value
        return value

    @field_validator("start_method", mode="before")
    @classmethod
    def normalize_start_method(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    def resolved_workers(self) -> int:
        if self.workers != "auto":
            return self.workers
        process_cpu_count = getattr(os, "process_cpu_count", None)
        count = process_cpu_count() if callable(process_cpu_count) else os.cpu_count()
        return max(1, count or 1)

    def resolved_start_method(self, available_methods: list[str] | None = None) -> str:
        methods = (
            list(available_methods)
            if available_methods is not None
            else multiprocessing.get_all_start_methods()
        )
        if self.start_method == "auto":
            if "forkserver" in methods:
                return "forkserver"
            if "spawn" in methods:
                return "spawn"
            return methods[0]
        if self.start_method not in methods:
            available = ", ".join(methods)
            raise ValueError(
                "当前平台不支持 multiprocessing start_method="
                f"{self.start_method}，可用: {available}"
            )
        return self.start_method


class RuntimeConfig(StrictConfigModel):
    plugin_dirs: list[str] = Field(default_factory=lambda: ["plugins"])
    loop_policy: str = "auto"
    default_upstream_group: str = "default"
    default_upstream_policy: DispatchStrategyType = DispatchStrategyType.RACE
    bootstrap_resolver: list[str] = Field(default_factory=list)
    hosts: dict[str, list[str]] = Field(default_factory=dict)
    fingerprint: str | None = None
    log_level: str = "INFO"
    multiprocess: MultiprocessConfig = Field(default_factory=MultiprocessConfig)

    @field_validator("plugin_dirs")
    @classmethod
    def validate_plugin_dirs(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("至少需要一个插件目录")
        return value

    @field_validator("bootstrap_resolver", mode="before")
    @classmethod
    def normalize_bootstrap_resolver(cls, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        seen: set[str] = set()
        normalized: list[str] = []
        for item in value:
            address = str(item).strip()
            if not address or address in seen:
                continue
            seen.add(address)
            normalized.append(address)
        return normalized

    @field_validator("hosts", mode="before")
    @classmethod
    def normalize_hosts(cls, value: dict[str, list[str]] | None) -> dict[str, list[str]]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("hosts 必须是 domain -> [ip] 映射")

        normalized: dict[str, list[str]] = {}
        for raw_domain, raw_addresses in value.items():
            domain = str(raw_domain).strip().rstrip(".").lower()
            if not domain:
                raise ValueError("hosts domain 不能为空")
            if not isinstance(raw_addresses, list):
                raise ValueError(f"hosts {domain} 必须是 IP 列表")

            addresses: list[str] = []
            seen: set[str] = set()
            for raw_address in raw_addresses:
                address_text = str(raw_address).strip()
                if not address_text:
                    continue
                address = ip_address(address_text).compressed
                if address in seen:
                    continue
                seen.add(address)
                addresses.append(address)
            if not addresses:
                raise ValueError(f"hosts {domain} 至少需要一个 IP")
            normalized[domain] = addresses
        return normalized

    @field_validator("fingerprint", mode="before")
    @classmethod
    def normalize_fingerprint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError(f"未知 log_level: {value}")
        return normalized


class TreeRootConfig(StrictConfigModel):
    domain_dir: str | None = None
    ip_dir: str | None = None

    @field_validator("domain_dir", "ip_dir", mode="before")
    @classmethod
    def normalize_dir(cls, value: str | None) -> str | None:
        if value is None:
            return None
        path = str(value).strip()
        return path or None


class ListenerConfig(StrictConfigModel):
    name: str
    protocol: ListenerProtocol
    host: str = "127.0.0.1"
    port: int = Field(default=53, ge=0, le=65535)
    enabled: bool = True


class ECSConfig(RootModel[str]):
    @field_validator("root")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        network = ip_network(value, strict=False)
        return network.with_prefixlen

    @property
    def subnet(self) -> IPv4Network | IPv6Network:
        return ip_network(self.root, strict=False)


class BaseNameserverConfig(StrictConfigModel):
    name: str


class AiodnsNameserverConfig(BaseNameserverConfig):
    protocol: Literal[NameserverProtocol.AIODNS] = NameserverProtocol.AIODNS
    servers: list[str] = Field(min_length=1)
    port: int = Field(default=53, ge=1, le=65535)
    tcp: bool = False
    timeout: float = Field(default=1.0, gt=0)

    @field_validator("servers", mode="before")
    @classmethod
    def normalize_servers(cls, value: Any) -> Any:
        if not isinstance(value, list):
            return value
        seen: set[str] = set()
        normalized: list[str] = []
        for item in value:
            server = str(item).strip()
            if not server or server in seen:
                continue
            seen.add(server)
            normalized.append(server)
        return normalized


class Do53NameserverConfig(BaseNameserverConfig):
    protocol: Literal[NameserverProtocol.DO53] = NameserverProtocol.DO53
    address: str
    port: int = Field(default=53, ge=1, le=65535)


class Do53CustomNameserverConfig(BaseNameserverConfig):
    protocol: Literal[NameserverProtocol.DO53_CUSTOM] = NameserverProtocol.DO53_CUSTOM
    address: str
    port: int = Field(default=53, ge=1, le=65535)
    use_tricks: bool = True


class DoHNameserverConfig(BaseNameserverConfig):
    protocol: Literal[NameserverProtocol.DOH] = NameserverProtocol.DOH
    url: str
    bootstrap_address: str | None = None
    verify: bool | str = True
    want_get: bool = False
    http_version: HTTPVersionType = HTTPVersionType.DEFAULT


class DoHCustomNameserverConfig(BaseNameserverConfig):
    protocol: Literal[NameserverProtocol.DOH_CUSTOM] = NameserverProtocol.DOH_CUSTOM
    url: str
    bootstrap_address: str | None = None
    verify: bool | str = False
    want_get: bool = False
    http_version: HTTPVersionType = HTTPVersionType.DEFAULT


class BaseHTTPClientDoHNameserverConfig(BaseNameserverConfig):
    url: str
    want_get: bool = False
    http_version: HTTPVersionType = HTTPVersionType.DEFAULT
    http_host: str | None = None


class BaseTLSHTTPClientDoHNameserverConfig(BaseHTTPClientDoHNameserverConfig):
    verify: bool | str = True
    server_hostname: str | None = None


class DoHHttpxNameserverConfig(BaseTLSHTTPClientDoHNameserverConfig):
    protocol: Literal[NameserverProtocol.DOH_HTTPX] = NameserverProtocol.DOH_HTTPX

    @model_validator(mode="after")
    def validate_http_version(self) -> "DoHHttpxNameserverConfig":
        if self.http_version in {HTTPVersionType.H1, HTTPVersionType.H3}:
            raise ValueError("httpx 仅支持 default / h2")
        if self.verify is not True:
            raise ValueError("httpx 不支持按请求配置 verify")
        return self


class DoHAiohttpNameserverConfig(BaseTLSHTTPClientDoHNameserverConfig):
    protocol: Literal[NameserverProtocol.DOH_AIOHTTP] = NameserverProtocol.DOH_AIOHTTP

    @model_validator(mode="after")
    def validate_http_version(self) -> "DoHAiohttpNameserverConfig":
        if self.http_version in {HTTPVersionType.H2, HTTPVersionType.H3}:
            raise ValueError("aiohttp 仅支持 default / h1")
        return self


class DoHCurlCffiNameserverConfig(BaseHTTPClientDoHNameserverConfig):
    protocol: Literal[NameserverProtocol.DOH_CURL_CFFI] = NameserverProtocol.DOH_CURL_CFFI
    verify: bool = True


class DoTNameserverConfig(BaseNameserverConfig):
    protocol: Literal[NameserverProtocol.DOT] = NameserverProtocol.DOT
    address: str
    port: int = Field(default=853, ge=1, le=65535)
    hostname: str | None = None
    verify: bool | str = True


class DoQNameserverConfig(BaseNameserverConfig):
    protocol: Literal[NameserverProtocol.DOQ] = NameserverProtocol.DOQ
    address: str
    port: int = Field(default=853, ge=1, le=65535)
    server_hostname: str | None = None
    verify: bool | str = True


class DNSCryptNameserverConfig(BaseNameserverConfig):
    protocol: Literal[NameserverProtocol.DNSCRYPT] = NameserverProtocol.DNSCRYPT
    address: str
    provider_name: str
    provider_pk: str
    private_key: str | None = None
    port: int = Field(default=53, ge=1, le=65535)
    cert_timeout: float = Field(default=5.0, gt=0)


NameserverConfig = Annotated[
    AiodnsNameserverConfig
    | Do53NameserverConfig
    | Do53CustomNameserverConfig
    | DoHNameserverConfig
    | DoHCustomNameserverConfig
    | DoHHttpxNameserverConfig
    | DoHAiohttpNameserverConfig
    | DoHCurlCffiNameserverConfig
    | DoTNameserverConfig
    | DoQNameserverConfig
    | DNSCryptNameserverConfig,
    Field(discriminator="protocol"),
]


class UpstreamConfig(StrictConfigModel):
    name: str
    nameservers: list[str] = Field(min_length=1)
    timeout: float = Field(default=0.5, gt=0)
    lifetime: float = Field(default=1, gt=0)
    use_tcp: bool = False
    ecs: ECSConfig | None = None


class UpstreamGroupConfig(StrictConfigModel):
    name: str
    upstreams: list[str] = Field(min_length=1)


class RuleMatchConfig(StrictConfigModel):
    match_tags: list[str] = Field(default_factory=list)
    exclude_tags: list[str] = Field(default_factory=list)
    qtypes: list[str] = Field(default_factory=list)

    @field_validator("match_tags", "exclude_tags", mode="before")
    @classmethod
    def normalize_tags(cls, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        seen: set[str] = set()
        normalized: list[str] = []
        for item in value:
            tag = item.strip()
            if not tag or tag in seen:
                continue
            seen.add(tag)
            normalized.append(tag)
        return normalized

    @field_validator("qtypes", mode="before")
    @classmethod
    def normalize_qtypes(cls, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        seen: set[str] = set()
        normalized: list[str] = []
        for item in value:
            raw = str(item).strip()
            if not raw:
                continue
            qtype = dns.rdatatype.to_text(dns.rdatatype.from_text(raw)).upper()
            if qtype in seen:
                continue
            seen.add(qtype)
            normalized.append(qtype)
        return normalized


class RuleActionConfig(StrictConfigModel):
    upstream_group: str | None = None
    dispatcher: DispatchStrategyType | None = None

    @model_validator(mode="after")
    def validate_action_target(self) -> "RuleActionConfig":
        if self.upstream_group is None and self.dispatcher is None:
            raise ValueError("rule action 至少需要 upstream_group 或 dispatcher")
        return self


class RuleConfig(StrictConfigModel):
    name: str
    enabled: bool = True
    match: RuleMatchConfig
    action: RuleActionConfig


class PluginConfig(StrictConfigModel):
    name: str
    module: str
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    variables: dict[str, Any] = Field(default_factory=dict)


class WebUIConfig(StrictConfigModel):
    enabled: bool = True
    doh_enabled: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=0, le=65535)
    username: str = Field(default="admin", min_length=1)
    password: str = Field(default="change-me", min_length=1)


class AppConfig(BaseSettings):
    """应用主配置。"""

    model_config = SettingsConfigDict(
        extra="forbid",
        env_prefix="DNS_FORWARDER_",
        env_nested_delimiter="__",
        json_file="config.json",
        json_file_encoding="utf-8",
    )

    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    tree_root: TreeRootConfig = Field(default_factory=TreeRootConfig)
    listeners: list[ListenerConfig] = Field(default_factory=list)
    nameservers: list[NameserverConfig] = Field(default_factory=list)
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
            JsonConfigSettingsSource(settings_cls),
            file_secret_settings,
        )

    @model_validator(mode="after")
    def validate_references(self) -> "AppConfig":
        self._validate_unique_names()
        nameserver_names = {item.name for item in self.nameservers}
        upstream_names = {item.name for item in self.upstreams}
        group_names = {item.name for item in self.groups}

        self._validate_required_config(group_names, upstream_names)
        self._validate_upstream_nameserver_refs(nameserver_names)
        self._validate_group_target_refs(group_names, upstream_names)
        self._validate_group_cycles(group_names)

        self._validate_rule_refs(group_names)

        return self

    def _validate_unique_names(self) -> None:
        _unique_names(self.listeners, "name")
        _unique_names(self.nameservers, "name")
        _unique_names(self.upstreams, "name")
        _unique_names(self.groups, "name")
        _unique_names(self.rules, "name")
        _unique_names(self.plugins, "name")

    def _validate_required_config(
        self,
        group_names: set[str],
        upstream_names: set[str],
    ) -> None:
        duplicated_target_names = sorted(upstream_names & group_names)

        if not self.listeners and not self.webui.enabled and not self.webui.doh_enabled:
            raise ValueError("至少需要一个 listener，或启用 webui / DoH")
        if not self.nameservers:
            raise ValueError("至少需要一个 nameserver")
        if not self.upstreams:
            raise ValueError("至少需要一个 upstream")
        if not self.groups:
            raise ValueError("至少需要一个 upstream group")
        if self.runtime.default_upstream_group not in group_names:
            raise ValueError(
                f"default_upstream_group 未定义: {self.runtime.default_upstream_group}"
            )
        if duplicated_target_names:
            duplicated_names = ", ".join(duplicated_target_names)
            raise ValueError(f"group 与 upstream 名称冲突: {duplicated_names}")

    def _validate_upstream_nameserver_refs(self, nameserver_names: set[str]) -> None:
        for upstream in self.upstreams:
            missing = set(upstream.nameservers) - nameserver_names
            if missing:
                missing_names = ", ".join(sorted(missing))
                raise ValueError(
                    f"upstream {upstream.name} 引用了不存在的 nameserver: {missing_names}"
                )

    def _validate_group_target_refs(
        self,
        group_names: set[str],
        upstream_names: set[str],
    ) -> None:
        available_target_names = upstream_names | group_names
        for group in self.groups:
            missing = set(group.upstreams) - available_target_names
            if missing:
                missing_names = ", ".join(sorted(missing))
                raise ValueError(f"group {group.name} 引用了不存在的 target: {missing_names}")

    def _validate_rule_refs(self, group_names: set[str]) -> None:
        for rule in self.rules:
            if (
                rule.action.upstream_group is not None
                and rule.action.upstream_group not in group_names
            ):
                raise ValueError(
                    f"rule {rule.name} 引用了不存在的 upstream_group: {rule.action.upstream_group}"
                )

    def _validate_group_cycles(self, group_names: set[str]) -> None:
        adjacency = {
            group.name: [target for target in group.upstreams if target in group_names]
            for group in self.groups
        }
        visiting: set[str] = set()
        visited: set[str] = set()

        def dfs(group_name: str, path: list[str]) -> None:
            if group_name in visiting:
                cycle_start = path.index(group_name)
                cycle = " -> ".join(path[cycle_start:] + [group_name])
                raise ValueError(f"group 引用存在循环: {cycle}")
            if group_name in visited:
                return

            visiting.add(group_name)
            path.append(group_name)
            for nested_group in adjacency[group_name]:
                dfs(nested_group, path)
            path.pop()
            visiting.remove(group_name)
            visited.add(group_name)

        for group_name in adjacency:
            dfs(group_name, [])
