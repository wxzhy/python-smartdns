from __future__ import annotations

import socket
from collections.abc import Awaitable
from ipaddress import ip_address
from typing import Any
import anyio

import aiohappyeyeballs
import dns.asyncbackend
from aiohappyeyeballs import AddrInfoType

FrozenHosts = tuple[tuple[str, tuple[str, ...]], ...]


async def _wait_for(awaitable: Awaitable[Any], timeout: float | None) -> Any:
    if timeout is None:
        return await awaitable
    with anyio.fail_after(timeout):
        return await awaitable


class TrickyStreamSocket(dns.asyncbackend.StreamSocket):
    def __init__(
        self,
        family: int,
        sock_type: int,
        *,
        hosts: FrozenHosts = (),
        source: str | None = None,
        source_port: int = 0,
        use_tricks: bool = True,
    ) -> None:
        super().__init__(family, sock_type)
        self._socket: socket.socket | None = None
        self.hosts = hosts
        self._hosts = dict(self.hosts)
        self._source = source
        self._source_port = source_port
        self.use_tricks = use_tricks
        self.closed = False

    async def connect(self, address: tuple[str, int], timeout: float | None) -> None:
        host, port = address
        addr_infos = await _resolve_addr_infos(host, port, self._hosts)
        local_addr_infos = _local_addr_infos(self._source, self._source_port)
        sock = await _wait_for(
            aiohappyeyeballs.start_connection(
                addr_infos,
                local_addr_infos=local_addr_infos,
                happy_eyeballs_delay=0.25,
                socket_factory=_tcp_socket_factory,
            ),
            timeout,
        )
        self._socket = sock
        self.family = sock.family

    async def sendall(self, what: bytes, timeout: float | None) -> None:
        sock = self._require_socket()
        if self.use_tricks and len(what) > 32:
            data = what[:16] + b"\x00"
            sock.sendall(data, socket.MSG_OOB)
            what = what[16:]

        async def _send() -> None:
            total_sent = 0
            while total_sent < len(what):
                await anyio.wait_socket_writable(sock)
                sent = sock.send(what[total_sent:])
                if sent == 0:
                    raise OSError("Socket connection broken")
                total_sent += sent

        await _wait_for(_send(), timeout)

    async def recv(self, size: int, timeout: float | None) -> bytes:
        sock = self._require_socket()

        async def _recv() -> bytes:
            await anyio.wait_socket_readable(sock)
            return sock.recv(size)

        return await _wait_for(_recv(), timeout)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    async def getpeername(self) -> tuple[str, int] | None:
        if self._socket is None:
            return None
        try:
            return self._socket.getpeername()
        except OSError:
            return None

    async def getsockname(self) -> tuple[str, int]:
        return self._require_socket().getsockname()

    async def getpeercert(self, timeout: float | None) -> None:
        _ = timeout
        return None

    def _require_socket(self) -> socket.socket:
        if self._socket is None:
            raise OSError("TCP socket is not connected")
        return self._socket


async def _resolve_addr_infos(
    host: str,
    port: int,
    hosts: dict[str, tuple[str, ...]],
) -> list[AddrInfoType]:
    addresses = hosts.get(_normalize_host(host))
    if addresses is not None:
        return [_addr_info_from_address(host, port, address) for address in addresses]

    return await anyio.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )


def _addr_info_from_address(host: str, port: int, address: str) -> AddrInfoType:
    ip = ip_address(address)
    if ip.version == 6:
        return (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            host,
            (ip.compressed, port, 0, 0),
        )
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        host,
        (ip.compressed, port),
    )


def _local_addr_infos(source: str | None, source_port: int) -> list[AddrInfoType] | None:
    if not source and not source_port:
        return None
    if source:
        return [_addr_info_from_address("", source_port, source)]
    return [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("0.0.0.0", source_port)),
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::", source_port, 0, 0)),
    ]


def _tcp_socket_factory(addr_info: AddrInfoType) -> socket.socket:
    family, sock_type, proto, _, _ = addr_info
    sock = socket.socket(family=family, type=sock_type, proto=proto)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def _normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lower()
