from __future__ import annotations

from typing import TYPE_CHECKING

from dns_forwarder.config import (
    AiodnsNameserverConfig,
    DNSCryptNameserverConfig,
    Do53CustomNameserverConfig,
    Do53NameserverConfig,
    DoHAiohttpNameserverConfig,
    DoHCurlCffiNameserverConfig,
    DoHCustomNameserverConfig,
    DoHHttpxNameserverConfig,
    DoHNameserverConfig,
    DoQNameserverConfig,
    DoTNameserverConfig,
    NameserverConfig,
)

from .aiodns import build_nameserver as build_aiodns_nameserver
from .aiodns import close_shared_sessions as close_aiodns_sessions
from .dnscrypt import build_nameserver as build_dnscrypt_nameserver
from .do53 import build_nameserver as build_do53_nameserver
from .do53_custom import build_nameserver as build_do53_custom_nameserver
from .doh import build_nameserver as build_doh_nameserver
from .doh_aiohttp import (
    build_nameserver as build_doh_aiohttp_nameserver,
)
from .doh_aiohttp import (
    close_shared_sessions as close_doh_aiohttp_sessions,
)
from .doh_curl_cffi import (
    build_nameserver as build_doh_curl_cffi_nameserver,
)
from .doh_curl_cffi import (
    close_shared_sessions as close_doh_curl_cffi_sessions,
)
from .doh_custom import (
    build_nameserver as build_doh_custom_nameserver,
)
from .doh_custom import (
    close_shared_sessions as close_doh_custom_sessions,
)
from .doh_httpx import (
    build_nameserver as build_doh_httpx_nameserver,
)
from .doh_httpx import (
    close_shared_sessions as close_doh_httpx_sessions,
)
from .doq import build_nameserver as build_doq_nameserver
from .dot import build_nameserver as build_dot_nameserver

if TYPE_CHECKING:
    from collections.abc import Iterable

    import dns.nameserver


def build_nameserver(  # noqa: PLR0911 -- dispatch over config types, one return per branch is natural
    config: NameserverConfig,
    bootstrap_resolver: list[str] | None = None,
    fingerprint: str | None = None,
    hosts: dict[str, list[str]] | None = None,
) -> dns.nameserver.Nameserver:
    bootstrap_resolver = bootstrap_resolver or []
    hosts = hosts or {}
    if isinstance(config, AiodnsNameserverConfig):
        return build_aiodns_nameserver(config)
    if isinstance(config, Do53NameserverConfig):
        return build_do53_nameserver(config)
    if isinstance(config, Do53CustomNameserverConfig):
        return build_do53_custom_nameserver(config, hosts)
    if isinstance(config, DoHNameserverConfig):
        return build_doh_nameserver(config)
    if isinstance(config, DoHCustomNameserverConfig):
        return build_doh_custom_nameserver(config)
    if isinstance(config, DoHHttpxNameserverConfig):
        return build_doh_httpx_nameserver(config)
    if isinstance(config, DoHAiohttpNameserverConfig):
        return build_doh_aiohttp_nameserver(config, bootstrap_resolver, hosts)
    if isinstance(config, DoHCurlCffiNameserverConfig):
        return build_doh_curl_cffi_nameserver(config, bootstrap_resolver, fingerprint, hosts)
    if isinstance(config, DoTNameserverConfig):
        return build_dot_nameserver(config)
    if isinstance(config, DoQNameserverConfig):
        return build_doq_nameserver(config)
    if isinstance(config, DNSCryptNameserverConfig):
        return build_dnscrypt_nameserver(config)
    raise TypeError(f"不支持的 nameserver 配置类型: {type(config).__name__}")


def build_nameserver_map(
    configs: Iterable[NameserverConfig],
    bootstrap_resolver: list[str] | None = None,
    fingerprint: str | None = None,
    hosts: dict[str, list[str]] | None = None,
) -> dict[str, dns.nameserver.Nameserver]:
    return {
        config.name: build_nameserver(config, bootstrap_resolver, fingerprint, hosts)
        for config in configs
    }


async def close_shared_sessions() -> None:
    await close_aiodns_sessions()
    await close_doh_custom_sessions()
    await close_doh_httpx_sessions()
    await close_doh_aiohttp_sessions()
    await close_doh_curl_cffi_sessions()


__all__ = [
    "build_nameserver",
    "build_nameserver_map",
    "close_shared_sessions",
]
