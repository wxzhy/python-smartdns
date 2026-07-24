from __future__ import annotations

import socket

import dns.asyncbackend
import dns.asyncquery
import dns.inet
import dns.message
import dns.nameserver

from dns_forwarder.config import Do53CustomNameserverConfig

from ._trick_tcp import TrickyStreamSocket
from ._trick_udp import TrickyDatagramSocket
from .doh_client_common import freeze_hosts


def _source_tuple(af: int, source: str | None, source_port: int) -> tuple[str, int] | None:
    if not source and not source_port:
        return None
    if source is None:
        if af == socket.AF_INET:
            source = "0.0.0.0"
        elif af == socket.AF_INET6:
            source = "::"
        else:  # pragma: no cover - UDP path always has a concrete address family
            raise NotImplementedError(f"unknown address family {af}")
    return (source, source_port)


class Do53CustomNameserver(dns.nameserver.Do53Nameserver):
    def __init__(
        self,
        address: str,
        port: int = 53,
        *,
        use_tricks: bool = True,
        hosts: dict[str, list[str]] | None = None,
    ) -> None:
        super().__init__(address, port)
        self.use_tricks = use_tricks
        self.hosts = freeze_hosts(hosts)

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
        if max_size:
            tricky_sock = TrickyStreamSocket(
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
                hosts=self.hosts,
                source=source,
                source_port=source_port,
                use_tricks=self.use_tricks,
            )
            try:
                await tricky_sock.connect((self.address, self.port), timeout)
                return await dns.asyncquery.tcp(
                    request,
                    self.address,
                    timeout=timeout,
                    port=self.port,
                    source=source,
                    source_port=source_port,
                    backend=backend,
                    one_rr_per_rrset=one_rr_per_rrset,
                    ignore_trailing=ignore_trailing,
                    sock=tricky_sock,
                )
            finally:
                await tricky_sock.close()

        if not self.use_tricks:
            return await super().async_query(
                request,
                timeout,
                source,
                source_port,
                max_size,
                backend,
                one_rr_per_rrset,
                ignore_trailing,
            )

        af = dns.inet.af_for_address(self.address)
        tricky_sock = TrickyDatagramSocket(af, socket.SOCK_DGRAM)
        try:
            source_address = _source_tuple(af, source, source_port)
            if source_address is not None:
                tricky_sock.bind(source_address)
            return await dns.asyncquery.udp(
                request,
                self.address,
                timeout=timeout,
                port=self.port,
                source=source,
                source_port=source_port,
                raise_on_truncation=True,
                backend=backend,
                one_rr_per_rrset=one_rr_per_rrset,
                ignore_trailing=ignore_trailing,
                ignore_errors=True,
                ignore_unexpected=True,
                sock=tricky_sock,
            )
        finally:
            await tricky_sock.close()


def build_nameserver(
    config: Do53CustomNameserverConfig,
    hosts: dict[str, list[str]],
) -> Do53CustomNameserver:
    return Do53CustomNameserver(
        config.address,
        config.port,
        use_tricks=config.use_tricks,
        hosts=hosts,
    )
