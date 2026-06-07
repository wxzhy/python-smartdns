from __future__ import annotations

import socket
import ssl as ssl_module
from ipaddress import ip_address
from typing import Any

import dns.asyncbackend
import dns.message

from dns_forwarder.config import DoHAiohttpNameserverConfig, HTTPVersionType

from .doh_client_common import (
    BaseAsyncDoHNameserver,
    build_doh_request,
    freeze_hosts,
    FrozenHosts,
    parse_doh_response,
)

try:  # pragma: no cover - dependency availability is checked at query time
    import aiohttp
    from aiohttp.resolver import AsyncResolver
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]
    AsyncResolver = None  # type: ignore[assignment]


_NUMERIC_SOCKET_FLAGS = socket.AI_NUMERICHOST | socket.AI_NUMERICSERV
_SHARED_SESSION: Any | None = None
_SHARED_BOOTSTRAP_RESOLVER: tuple[str, ...] | None = None
_SHARED_HOSTS: FrozenHosts | None = None


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
    global _SHARED_BOOTSTRAP_RESOLVER, _SHARED_HOSTS, _SHARED_SESSION
    if _SHARED_SESSION is None or _SHARED_SESSION.closed:
        if aiohttp is None or AsyncResolver is None:  # pragma: no cover
            raise RuntimeError("aiohttp and aiodns are required for aiohttp nameserver")
        resolver = _build_resolver(bootstrap_resolver, hosts)
        connector = aiohttp.TCPConnector(resolver=resolver, limit=500, keepalive_timeout=30)
        _SHARED_SESSION = aiohttp.ClientSession(connector=connector)
        _SHARED_BOOTSTRAP_RESOLVER = bootstrap_resolver
        _SHARED_HOSTS = hosts
        return _SHARED_SESSION

    if _SHARED_BOOTSTRAP_RESOLVER != bootstrap_resolver or _SHARED_HOSTS != hosts:
        raise RuntimeError("aiohttp bootstrap_resolver/hosts changed while session is active")
    return _SHARED_SESSION


async def close_shared_sessions() -> None:
    global _SHARED_BOOTSTRAP_RESOLVER, _SHARED_HOSTS, _SHARED_SESSION
    session = _SHARED_SESSION
    _SHARED_SESSION = None
    _SHARED_BOOTSTRAP_RESOLVER = None
    _SHARED_HOSTS = None
    if session is not None and not session.closed:
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
        address_family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
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


class DoHAiohttpNameserver(BaseAsyncDoHNameserver):
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
        hosts: dict[str, list[str]],
    ) -> None:
        super().__init__(
            url,
            verify=verify,
            want_get=want_get,
            http_version=http_version,
            http_host=http_host,
            server_hostname=server_hostname,
        )
        self.bootstrap_resolver = tuple(bootstrap_resolver)
        self.hosts = freeze_hosts(hosts)

    def kind(self) -> str:
        return "DoH-AIOHTTP"

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
