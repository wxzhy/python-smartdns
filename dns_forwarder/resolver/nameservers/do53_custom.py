from __future__ import annotations

import socket

import dns.asyncbackend
import dns.asyncquery
import dns.inet
import dns.message
import dns.nameserver

from dns_forwarder.config import Do53CustomNameserverConfig

from ._trick_sockets import TrickyDatagramSocket, TrickyStreamSocket


class Do53CustomNameserver(dns.nameserver.Do53Nameserver):
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
            af = dns.inet.af_for_address(self.address)
            tricky_sock = TrickyStreamSocket(af, socket.SOCK_STREAM)
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

        af = dns.inet.af_for_address(self.address)
        tricky_sock = TrickyDatagramSocket(af, socket.SOCK_DGRAM)
        try:
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


def build_nameserver(config: Do53CustomNameserverConfig) -> Do53CustomNameserver:
    return Do53CustomNameserver(config.address, config.port)
