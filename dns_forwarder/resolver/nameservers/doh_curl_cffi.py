from __future__ import annotations

from typing import Any

import dns.asyncbackend
import dns.message
import dns.nameserver

from dns_forwarder.config import DoHCurlCffiNameserverConfig, HTTPVersionType

from .doh_client_common import (
    build_doh_request,
    is_ip_address,
    parse_doh_response,
    replace_url_hostname,
    url_hostname,
    url_port,
)

try:  # pragma: no cover - dependency availability is checked at build time
    from curl_cffi import CurlHttpVersion, CurlOpt
    from curl_cffi.requests import AsyncSession
except ImportError:  # pragma: no cover
    CurlHttpVersion = None  # type: ignore[assignment]
    CurlOpt = None  # type: ignore[assignment]
    AsyncSession = None  # type: ignore[assignment]


_SHARED_SESSIONS: dict[
    tuple[bool | str, HTTPVersionType, tuple[str, ...], tuple[str, ...]],
    Any,
] = {}


def _get_shared_session(
    *,
    verify: bool | str,
    http_version: HTTPVersionType,
    bootstrap_resolver: tuple[str, ...],
    resolve_entries: tuple[str, ...],
) -> Any:
    key = (verify, http_version, bootstrap_resolver, resolve_entries)
    session = _SHARED_SESSIONS.get(key)
    if session is None:
        if AsyncSession is None or CurlOpt is None:  # pragma: no cover
            raise RuntimeError("curl_cffi is required for doh_curl_cffi")
        curl_options: dict[Any, Any] = {}
        if bootstrap_resolver:
            curl_options[CurlOpt.DNS_SERVERS] = ",".join(bootstrap_resolver)
        if resolve_entries:
            # curl_cffi exposes RESOLVE as a built-in slist option; use it for
            # IP URL + hostname SNI without depending on unsupported CONNECT_TO.
            curl_options[CurlOpt.RESOLVE] = list(resolve_entries)
        if isinstance(verify, str):
            curl_options[CurlOpt.CAINFO] = verify

        session = AsyncSession(
            max_clients=500,
            verify=False if verify is False else True,
            curl_options=curl_options or None,
            http_version=_curl_http_version(http_version),
        )
        _SHARED_SESSIONS[key] = session
    return session


async def close_shared_sessions() -> None:
    sessions = list(_SHARED_SESSIONS.values())
    _SHARED_SESSIONS.clear()
    for session in sessions:
        await session.close()


class DoHCurlCffiNameserver(dns.nameserver.Nameserver):
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
        self.effective_url = replace_url_hostname(url, server_hostname)
        self.resolve_entries = _build_resolve_entries(url, server_hostname)
        self._session = _get_shared_session(
            verify=verify,
            http_version=http_version,
            bootstrap_resolver=self.bootstrap_resolver,
            resolve_entries=self.resolve_entries,
        )

    def __str__(self) -> str:
        return self.effective_url

    def kind(self) -> str:
        return "DoH-CURL-CFFI"

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
        raise NotImplementedError("doh_curl_cffi only supports async queries")

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
        response = await self._session.request(
            doh_request.method,
            doh_request.url,
            data=doh_request.body,
            headers=doh_request.headers,
            timeout=timeout,
        )
        response.raise_for_status()
        return parse_doh_response(
            response.content,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
        )


def _curl_http_version(http_version: HTTPVersionType) -> Any:
    if CurlHttpVersion is None:  # pragma: no cover
        return None
    return {
        HTTPVersionType.DEFAULT: None,
        HTTPVersionType.H1: CurlHttpVersion.V1_1,
        HTTPVersionType.H2: CurlHttpVersion.V2_0,
        HTTPVersionType.H3: CurlHttpVersion.V3,
    }[http_version]


def _build_resolve_entries(url: str, server_hostname: str | None) -> tuple[str, ...]:
    original_host = url_hostname(url)
    if not server_hostname or not original_host or server_hostname == original_host:
        return ()
    if not is_ip_address(original_host):
        return ()
    return (f"{server_hostname}:{url_port(url)}:{_resolve_address(original_host)}",)


def _resolve_address(address: str) -> str:
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address


def build_nameserver(
    config: DoHCurlCffiNameserverConfig,
    bootstrap_resolver: list[str],
) -> DoHCurlCffiNameserver:
    return DoHCurlCffiNameserver(
        config.url,
        verify=config.verify,
        want_get=config.want_get,
        http_version=config.http_version,
        http_host=config.http_host,
        server_hostname=config.server_hostname,
        bootstrap_resolver=bootstrap_resolver,
    )
