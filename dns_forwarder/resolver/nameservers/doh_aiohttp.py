from __future__ import annotations

import ssl as ssl_module
from typing import Any

import dns.asyncbackend
import dns.message
import dns.nameserver

from dns_forwarder.config import DoHAiohttpNameserverConfig, HTTPVersionType

from .doh_client_common import (
    build_doh_request,
    parse_doh_response,
    url_hostname,
    url_port,
)

try:  # pragma: no cover - dependency availability is checked at query time
    import aiohttp
    from aiohttp.resolver import AsyncResolver
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]
    AsyncResolver = None  # type: ignore[assignment]


_SHARED_SESSION: Any | None = None
_SHARED_BOOTSTRAP_RESOLVER: tuple[str, ...] | None = None


def _get_shared_session(bootstrap_resolver: tuple[str, ...]) -> Any:
    global _SHARED_BOOTSTRAP_RESOLVER, _SHARED_SESSION
    if _SHARED_SESSION is None or _SHARED_SESSION.closed:
        if aiohttp is None or AsyncResolver is None:  # pragma: no cover
            raise RuntimeError("aiohttp and aiodns are required for doh_aiohttp")
        resolver = (
            AsyncResolver(nameservers=list(bootstrap_resolver))
            if bootstrap_resolver
            else None
        )
        connector = aiohttp.TCPConnector(resolver=resolver, limit=500)
        _SHARED_SESSION = aiohttp.ClientSession(connector=connector)
        _SHARED_BOOTSTRAP_RESOLVER = bootstrap_resolver
        return _SHARED_SESSION

    if _SHARED_BOOTSTRAP_RESOLVER != bootstrap_resolver:
        raise RuntimeError("doh_aiohttp bootstrap_resolver changed while session is active")
    return _SHARED_SESSION


async def close_shared_sessions() -> None:
    global _SHARED_BOOTSTRAP_RESOLVER, _SHARED_SESSION
    session = _SHARED_SESSION
    _SHARED_SESSION = None
    _SHARED_BOOTSTRAP_RESOLVER = None
    if session is not None and not session.closed:
        await session.close()


class DoHAiohttpNameserver(dns.nameserver.Nameserver):
    def __init__(
        self,
        url: str,
        *,
        verify: bool | str,
        want_get: bool,
        http_version: HTTPVersionType,
        http_host: str | None,
        server_hostname: str | None,
        bootstrap_resolver: list[str],
    ) -> None:
        self.url = url
        self.verify = verify
        self.want_get = want_get
        self.http_version = http_version
        self.http_host = http_host
        self.server_hostname = server_hostname
        self.bootstrap_resolver = tuple(bootstrap_resolver)

    def __str__(self) -> str:
        return self.url

    def kind(self) -> str:
        return "DoH-AIOHTTP"

    def is_always_max_size(self) -> bool:
        return True

    def answer_nameserver(self) -> str:
        return url_hostname(self.url) or self.url

    def answer_port(self) -> int:
        return url_port(self.url)

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        raise NotImplementedError("doh_aiohttp only supports async queries")

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        _ = source, source_port, max_size, backend
        doh_request = build_doh_request(
            request,
            self.url,
            want_get=self.want_get,
            http_host=self.http_host,
        )
        session = _get_shared_session(self.bootstrap_resolver)
        async with session.request(
            doh_request.method,
            doh_request.url,
            headers=doh_request.headers,
            data=doh_request.body,
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=_ssl_arg(self.verify),
            server_hostname=self.server_hostname,
        ) as response:
            response.raise_for_status()
            content = await response.read()
        return parse_doh_response(
            content,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
        )


def _ssl_arg(verify: bool | str) -> bool | ssl_module.SSLContext:
    if isinstance(verify, str):
        return ssl_module.create_default_context(cafile=verify)
    return verify


def build_nameserver(
    config: DoHAiohttpNameserverConfig,
    bootstrap_resolver: list[str],
) -> DoHAiohttpNameserver:
    return DoHAiohttpNameserver(
        config.url,
        verify=config.verify,
        want_get=config.want_get,
        http_version=config.http_version,
        http_host=config.http_host,
        server_hostname=config.server_hostname,
        bootstrap_resolver=bootstrap_resolver,
    )
