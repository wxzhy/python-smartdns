from __future__ import annotations

import asyncio
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
# 共享会话以 (loop id, resolve_entries) 为键：每个事件循环（含 portal worker 线程）
# 持有独立会话，避免跨 loop 复用；无运行中 loop 时 loop 部分回退为 None。
_SHARED_SESSIONS: dict[tuple[int | None, tuple[str, ...]], Any] = {}
IPV6_VERSION = 6


def _loop_key() -> int | None:
    try:
        return id(asyncio.get_running_loop())
    except RuntimeError:
        return None


def _get_shared_session(resolve_entries: tuple[str, ...] = ()) -> Any:
    key = (_loop_key(), resolve_entries)
    session = _SHARED_SESSIONS.get(key)
    if session is None:
        if AsyncSession is None:  # pragma: no cover
            raise RuntimeError("curl_cffi is required for curl nameserver")
        kwargs: dict[str, Any] = {"max_clients": 500}
        if resolve_entries:
            if CurlOpt is None:  # pragma: no cover
                raise RuntimeError("curl_cffi is required for curl nameserver")
            kwargs["curl_options"] = {CurlOpt.RESOLVE: list(resolve_entries)}
        session = AsyncSession(**kwargs)
        _SHARED_SESSIONS[key] = session
    return session


async def close_shared_sessions() -> None:
    # 仅关闭并移除当前运行 loop 的会话，保证在持有它的 loop 内完成关闭。
    loop_key = _loop_key()
    keys = [key for key in _SHARED_SESSIONS if key[0] == loop_key]
    for key in keys:
        await _SHARED_SESSIONS.pop(key).close()


class DoHCurlCffiNameserver(dns.nameserver.Nameserver):
    def __init__(  # noqa: PLR0913  # 形参与 dnspython Nameserver 接口一致
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

    def query(  # noqa: PLR0913  # 形参与 dnspython Nameserver 接口一致
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

    async def async_query(  # noqa: PLR0913  # 形参与 dnspython Nameserver 接口一致
        self,
        request: dns.message.QueryMessage,
        timeout: float,  # noqa: ASYNC109  # timeout 属 dnspython/socket 接口契约
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
    if ip.version == IPV6_VERSION:
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
