from __future__ import annotations

from typing import Any

import dns.asyncbackend
import dns.message
import dns.nameserver

from dns_forwarder.config import DoHHttpxNameserverConfig, HTTPVersionType

from .doh_client_common import (
    build_doh_request,
    parse_doh_response,
    replace_url_hostname,
    url_hostname,
    url_port,
)

try:  # pragma: no cover - dependency availability is checked at build time
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


_SHARED_CLIENTS: dict[tuple[bool | str, bool], Any] = {}


def _get_shared_client(verify: bool | str, http2: bool) -> Any:
    key = (verify, http2)
    client = _SHARED_CLIENTS.get(key)
    if client is None:
        if httpx is None:  # pragma: no cover
            raise RuntimeError("httpx is required for doh_httpx")
        client = httpx.AsyncClient(
            http2=http2,
            limits=httpx.Limits(
                max_connections=500,
                max_keepalive_connections=50,
                keepalive_expiry=30,
            ),
            verify=verify,
        )
        _SHARED_CLIENTS[key] = client
    return client


async def close_shared_sessions() -> None:
    clients = list(_SHARED_CLIENTS.values())
    _SHARED_CLIENTS.clear()
    for client in clients:
        await client.aclose()


class DoHHttpxNameserver(dns.nameserver.Nameserver):
    def __init__(
        self,
        url: str,
        *,
        verify: bool | str,
        want_get: bool,
        http_version: HTTPVersionType,
        http_host: str | None,
        server_hostname: str | None,
    ) -> None:
        self.url = url
        self.verify = verify
        self.want_get = want_get
        self.http_version = http_version
        self.http_host = http_host
        self.server_hostname = server_hostname
        self.effective_url = replace_url_hostname(url, server_hostname)
        self._client = _get_shared_client(verify, http_version is not HTTPVersionType.H1)

    def __str__(self) -> str:
        return self.effective_url

    def kind(self) -> str:
        return "DoH-HTTPX"

    def is_always_max_size(self) -> bool:
        return True

    def answer_nameserver(self) -> str:
        return url_hostname(self.effective_url) or self.effective_url

    def answer_port(self) -> int:
        return url_port(self.effective_url)

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
        raise NotImplementedError("doh_httpx only supports async queries")

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
            self.effective_url,
            want_get=self.want_get,
            http_host=self.http_host,
        )
        response = await self._client.request(
            doh_request.method,
            doh_request.url,
            headers=doh_request.headers,
            content=doh_request.body,
            timeout=timeout,
        )
        response.raise_for_status()
        return parse_doh_response(
            response.content,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
        )


def build_nameserver(config: DoHHttpxNameserverConfig) -> DoHHttpxNameserver:
    return DoHHttpxNameserver(
        config.url,
        verify=config.verify,
        want_get=config.want_get,
        http_version=config.http_version,
        http_host=config.http_host,
        server_hostname=config.server_hostname,
    )
