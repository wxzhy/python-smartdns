from __future__ import annotations

import asyncio
import socket
import ssl as ssl_module
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any

import dns.asyncbackend
import dns.message
import dns.nameserver

from .doh_client_common import (
    build_doh_request,
    parse_doh_response,
    url_hostname,
    url_port,
)

if TYPE_CHECKING:
    from dns_forwarder.config import DoHAiohttpNameserverConfig, HTTPVersionType

try:  # pragma: no cover - dependency availability is checked at query time
    import aiohttp
    from aiohttp.resolver import AsyncResolver
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]
    AsyncResolver = None  # type: ignore[assignment]


FrozenHosts = tuple[tuple[str, tuple[str, ...]], ...]
_NUMERIC_SOCKET_FLAGS = socket.AI_NUMERICHOST | socket.AI_NUMERICSERV
IPV6_VERSION = 6

# 模块级共享 aiohttp 会话缓存：以事件循环 id 为键（无运行中 loop 时回退 None），
# 每个 loop（含 portal worker 线程）持有独立会话，避免跨 loop 复用。
# 值为 (bootstrap_resolver, hosts, session) 三元组。
_SHARED: dict[int | None, tuple[tuple[str, ...], FrozenHosts, Any]] = {}


def _loop_key() -> int | None:
    try:
        return id(asyncio.get_running_loop())
    except RuntimeError:
        return None


if AsyncResolver is not None:

    class HostsAsyncResolver(AsyncResolver):  # type: ignore[misc]
        def __init__(self, hosts: FrozenHosts, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._hosts = dict(hosts)

        async def resolve(
            self,
            host: str,
            port: int = 0,
            family: socket.AddressFamily = socket.AF_INET,
        ) -> list[dict[str, Any]]:
            addresses = self._hosts.get(_normalize_host(host))
            if addresses is None:
                return await super().resolve(host, port, family)

            results = _hosts_resolve_results(host, port, family, addresses)
            if not results:
                raise OSError(None, "DNS lookup failed")
            return results

else:  # pragma: no cover
    HostsAsyncResolver = None  # type: ignore[assignment]


def _get_shared_session(bootstrap_resolver: tuple[str, ...], hosts: FrozenHosts) -> Any:
    key = _loop_key()
    cached = _SHARED.get(key)
    if cached is None or cached[2].closed:
        if aiohttp is None or AsyncResolver is None:  # pragma: no cover
            raise RuntimeError("aiohttp and aiodns are required for aiohttp nameserver")
        resolver = _build_resolver(bootstrap_resolver, hosts)
        connector = aiohttp.TCPConnector(resolver=resolver, limit=500, keepalive_timeout=30)
        session = aiohttp.ClientSession(connector=connector)
        _SHARED[key] = (bootstrap_resolver, hosts, session)
        return session

    if bootstrap_resolver != cached[0] or hosts != cached[1]:
        raise RuntimeError("aiohttp bootstrap_resolver/hosts changed while session is active")
    return cached[2]


async def close_shared_sessions() -> None:
    # 仅关闭并移除当前运行 loop 的会话，保证在持有它的 loop 内完成关闭。
    cached = _SHARED.pop(_loop_key(), None)
    if cached is not None:
        session = cached[2]
        if not session.closed:
            await session.close()


def _build_resolver(bootstrap_resolver: tuple[str, ...], hosts: FrozenHosts) -> Any:
    if hosts:
        if HostsAsyncResolver is None:  # pragma: no cover
            raise RuntimeError("aiohttp and aiodns are required for aiohttp nameserver")
        if bootstrap_resolver:
            return HostsAsyncResolver(hosts, nameservers=list(bootstrap_resolver))
        return HostsAsyncResolver(hosts)
    if bootstrap_resolver:
        return AsyncResolver(nameservers=list(bootstrap_resolver))
    return None


def _freeze_hosts(hosts: dict[str, list[str]] | None) -> FrozenHosts:
    if not hosts:
        return ()
    return tuple(sorted((host, tuple(addresses)) for host, addresses in hosts.items()))


def _normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


def _hosts_resolve_results(
    host: str,
    port: int,
    family: socket.AddressFamily,
    addresses: tuple[str, ...],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for address in addresses:
        ip = ip_address(address)
        address_family = socket.AF_INET6 if ip.version == IPV6_VERSION else socket.AF_INET
        if family not in (socket.AF_UNSPEC, address_family):
            continue
        results.append(
            {
                "hostname": host,
                "host": ip.compressed,
                "port": port,
                "family": address_family,
                "proto": 0,
                "flags": _NUMERIC_SOCKET_FLAGS,
            }
        )
    return results


class DoHAiohttpNameserver(dns.nameserver.Nameserver):
    def __init__(  # noqa: PLR0913  # 形参与 dnspython Nameserver 接口一致
        self,
        url: str,
        *,
        verify: bool | str,
        want_get: bool,
        http_version: HTTPVersionType,
        http_host: str | None,
        server_hostname: str | None,
        bootstrap_resolver: list[str],
        hosts: dict[str, list[str]],
    ) -> None:
        self.url = url
        self.verify = verify
        self.want_get = want_get
        self.http_version = http_version
        self.http_host = http_host
        self.server_hostname = server_hostname
        self.bootstrap_resolver = tuple(bootstrap_resolver)
        self.hosts = _freeze_hosts(hosts)

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
        raise NotImplementedError("aiohttp nameserver only supports async queries")

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
        session = _get_shared_session(self.bootstrap_resolver, self.hosts)
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
    hosts: dict[str, list[str]],
) -> DoHAiohttpNameserver:
    return DoHAiohttpNameserver(
        config.url,
        verify=config.verify,
        want_get=config.want_get,
        http_version=config.http_version,
        http_host=config.http_host,
        server_hostname=config.server_hostname,
        bootstrap_resolver=bootstrap_resolver,
        hosts=hosts,
    )
