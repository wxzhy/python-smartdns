from __future__ import annotations

from ipaddress import ip_address
from typing import Any

import dns.asyncbackend
import dns.message
import dns.nameserver

from dns_forwarder.config import DoHCurlCffiNameserverConfig, HTTPVersionType

from .doh_client_common import (
    build_doh_request,
    parse_doh_response,
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


FrozenHosts = tuple[tuple[str, tuple[str, ...]], ...]
_SHARED_SESSIONS: dict[tuple[str, ...], Any] = {}


def _get_shared_session(resolve_entries: tuple[str, ...] = ()) -> Any:
    session = _SHARED_SESSIONS.get(resolve_entries)
    if session is None:
        if AsyncSession is None:  # pragma: no cover
            raise RuntimeError("curl_cffi is required for curl nameserver")
        kwargs: dict[str, Any] = {"max_clients": 500}
        if resolve_entries:
            if CurlOpt is None:  # pragma: no cover
                raise RuntimeError("curl_cffi is required for curl nameserver")
            kwargs["curl_options"] = {CurlOpt.RESOLVE: list(resolve_entries)}
        session = AsyncSession(**kwargs)
        _SHARED_SESSIONS[resolve_entries] = session
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
        fingerprint: str | None,
        bootstrap_resolver: list[str],
        hosts: dict[str, list[str]],
    ) -> None:
        self.url = url
        self.verify = verify
        self.want_get = want_get
        self.http_version = http_version
        self.http_host = http_host
        self.fingerprint = fingerprint
        self.resolve_entries = _curl_resolve_entries(_freeze_hosts(hosts), url_port(url))
        _ = bootstrap_resolver

    def __str__(self) -> str:
        return self.url

    def kind(self) -> str:
        return "DoH-CURL-CFFI"

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
        raise NotImplementedError("curl nameserver only supports async queries")

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
        response = await _get_shared_session(self.resolve_entries).request(
            doh_request.method,
            doh_request.url,
            data=doh_request.body,
            headers=doh_request.headers,
            timeout=timeout,
            verify=self.verify,
            http_version=_curl_http_version(self.http_version),
            impersonate=self.fingerprint,
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


def _freeze_hosts(hosts: dict[str, list[str]] | None) -> FrozenHosts:
    if not hosts:
        return ()
    return tuple(sorted((host, tuple(addresses)) for host, addresses in hosts.items()))


def _curl_resolve_entries(hosts: FrozenHosts, port: int) -> tuple[str, ...]:
    return tuple(
        f"{host}:{port}:{','.join(_curl_resolve_address(address) for address in addresses)}"
        for host, addresses in hosts
    )


def _curl_resolve_address(address: str) -> str:
    ip = ip_address(address)
    if ip.version == 6:
        return f"[{ip.compressed}]"
    return ip.compressed


def build_nameserver(
    config: DoHCurlCffiNameserverConfig,
    bootstrap_resolver: list[str],
    fingerprint: str | None,
    hosts: dict[str, list[str]],
) -> DoHCurlCffiNameserver:
    return DoHCurlCffiNameserver(
        config.url,
        verify=config.verify,
        want_get=config.want_get,
        http_version=config.http_version,
        http_host=config.http_host,
        fingerprint=fingerprint,
        bootstrap_resolver=bootstrap_resolver,
        hosts=hosts,
    )
