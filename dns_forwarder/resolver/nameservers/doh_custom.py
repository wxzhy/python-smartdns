from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import dns.asyncbackend
import dns.asyncquery
import dns.message
import dns.nameserver
import dns.query

from .doh import HTTP_VERSION_MAP

if TYPE_CHECKING:
    from dns_forwarder.config import DoHCustomNameserverConfig

try:  # pragma: no cover - guarded for environments without DoH extras
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


# 共享客户端以 (loop id, verify) 为键：每个事件循环（含 portal worker 线程）持有
# 独立客户端，避免跨 loop 复用；无运行中 loop 时 loop 部分回退为 None。
_SHARED_CLIENTS: dict[tuple[int | None, bool], Any] = {}


def _loop_key() -> int | None:
    try:
        return id(asyncio.get_running_loop())
    except RuntimeError:
        return None


def _get_shared_client(verify: bool = True) -> Any:
    key = (_loop_key(), verify)
    client = _SHARED_CLIENTS.get(key)
    if client is None:
        if httpx is None:  # pragma: no cover
            raise RuntimeError("httpx is required for doh_custom shared client")
        client = httpx.AsyncClient(
            http2=True,
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
    # 仅关闭并移除当前运行 loop 的客户端，保证在持有它的 loop 内完成关闭。
    loop_key = _loop_key()
    keys = [key for key in _SHARED_CLIENTS if key[0] == loop_key]
    for key in keys:
        await _SHARED_CLIENTS.pop(key).aclose()


class DoHCustomNameserver(dns.nameserver.DoHNameserver):
    def _can_use_shared_client(self) -> bool:
        return (
            httpx is not None
            and self.bootstrap_address is None
            and isinstance(self.verify, bool)
            and self.http_version
            in {
                dns.query.HTTPVersion.DEFAULT,
                dns.query.HTTPVersion.H1,
                dns.query.HTTPVersion.H2,
            }
        )

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
                client=_get_shared_client(self.verify),
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
