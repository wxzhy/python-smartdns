from __future__ import annotations

import asyncio
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
    from dns_forwarder.config import DoHHttpxNameserverConfig, HTTPVersionType

try:  # pragma: no cover - dependency availability is checked at build time
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


# 模块级共享 httpx 客户端缓存：以事件循环 id 为键，每个 loop（含 portal worker 线程）
# 持有独立客户端，避免跨 loop 复用。仅在无运行中 loop 的环境（如同步测试）回退到键 None。
_SHARED_CLIENTS: dict[int | None, Any] = {}


def _loop_key() -> int | None:
    try:
        return id(asyncio.get_running_loop())
    except RuntimeError:
        return None


def _get_shared_client() -> Any:
    key = _loop_key()
    client = _SHARED_CLIENTS.get(key)
    if client is None:
        if httpx is None:  # pragma: no cover
            raise RuntimeError("httpx is required for httpx nameserver")
        client = httpx.AsyncClient(
            http2=True,
            limits=httpx.Limits(
                max_connections=500,
                max_keepalive_connections=50,
                keepalive_expiry=30,
            ),
            verify=True,
        )
        _SHARED_CLIENTS[key] = client
    return client


async def close_shared_sessions() -> None:
    # 仅关闭并移除当前运行 loop 的客户端，保证在持有它的 loop 内完成关闭。
    client = _SHARED_CLIENTS.pop(_loop_key(), None)
    if client is not None:
        await client.aclose()


class DoHHttpxNameserver(dns.nameserver.Nameserver):
    def __init__(  # noqa: PLR0913  # 形参与 dnspython Nameserver 接口一致
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

    def __str__(self) -> str:
        return self.url

    def kind(self) -> str:
        return "DoH-HTTPX"

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
        raise NotImplementedError("httpx nameserver only supports async queries")

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
