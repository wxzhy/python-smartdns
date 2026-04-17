from __future__ import annotations

from typing import Any

import dns.asyncbackend
import dns.asyncquery
import dns.message
import dns.nameserver
import dns.query

from dns_forwarder.config import DoHCustomNameserverConfig

from .doh import HTTP_VERSION_MAP

try:  # pragma: no cover - guarded for environments without DoH extras
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


_SHARED_CLIENT: Any | None = None


def _get_shared_client() -> Any:
    global _SHARED_CLIENT
    if _SHARED_CLIENT is None:
        if httpx is None:  # pragma: no cover
            raise RuntimeError("httpx is required for doh_custom shared client")
        _SHARED_CLIENT = httpx.AsyncClient(
            http2=True,
            limits=httpx.Limits(
                max_connections=500,
                max_keepalive_connections=50,
                keepalive_expiry=30,
            ),
            verify=False,
        )
    return _SHARED_CLIENT


class DoHCustomNameserver(dns.nameserver.DoHNameserver):
    def _can_use_shared_client(self) -> bool:
        return (
            httpx is not None
            and self.bootstrap_address is None
            and self.verify is False
            and self.http_version
            in {
                dns.query.HTTPVersion.DEFAULT,
                dns.query.HTTPVersion.H1,
                dns.query.HTTPVersion.H2,
            }
        )

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
        _ = max_size
        _ = backend
        kwargs = {
            "timeout": timeout,
            "source": source,
            "source_port": source_port,
            "bootstrap_address": self.bootstrap_address,
            "one_rr_per_rrset": one_rr_per_rrset,
            "ignore_trailing": ignore_trailing,
            "verify": self.verify,
            "post": not self.want_get,
            "http_version": self.http_version,
        }
        if self._can_use_shared_client():
            return await dns.asyncquery.https(
                request,
                self.url,
                client=_get_shared_client(),
                **kwargs,
            )
        return await dns.asyncquery.https(
            request,
            self.url,
            **kwargs,
        )


def build_nameserver(config: DoHCustomNameserverConfig) -> DoHCustomNameserver:
    return DoHCustomNameserver(
        config.url,
        bootstrap_address=config.bootstrap_address,
        verify=config.verify,
        want_get=config.want_get,
        http_version=HTTP_VERSION_MAP[config.http_version],
    )
