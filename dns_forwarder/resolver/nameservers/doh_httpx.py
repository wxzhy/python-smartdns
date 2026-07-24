from __future__ import annotations

from typing import Any

import dns.asyncbackend
import dns.message

from dns_forwarder.config import DoHHttpxNameserverConfig

from .doh_client_common import (
    BaseAsyncDoHNameserver,
    build_doh_request,
    parse_doh_response,
)

try:  # pragma: no cover - dependency availability is checked at build time
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


_SHARED_CLIENT: Any | None = None


def _get_shared_client() -> Any:
    global _SHARED_CLIENT
    if _SHARED_CLIENT is None:
        if httpx is None:  # pragma: no cover
            raise RuntimeError("httpx is required for httpx nameserver")
        _SHARED_CLIENT = httpx.AsyncClient(
            http2=True,
            limits=httpx.Limits(
                max_connections=500,
                max_keepalive_connections=50,
                keepalive_expiry=30,
            ),
            verify=True,
        )
    return _SHARED_CLIENT


async def close_shared_sessions() -> None:
    global _SHARED_CLIENT
    client = _SHARED_CLIENT
    _SHARED_CLIENT = None
    if client is not None:
        await client.aclose()


class DoHHttpxNameserver(BaseAsyncDoHNameserver):
    def kind(self) -> str:
        return "DoH-HTTPX"

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
        response = await _get_shared_client().request(
            doh_request.method,
            doh_request.url,
            headers=doh_request.headers,
            content=doh_request.body,
            timeout=timeout,
            extensions=_request_extensions(self.server_hostname),
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


def _request_extensions(server_hostname: str | None) -> dict[str, str] | None:
    if server_hostname is None:
        return None
    return {"sni_hostname": server_hostname}
