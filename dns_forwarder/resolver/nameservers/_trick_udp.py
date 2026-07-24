from __future__ import annotations

import socket
from collections.abc import Awaitable
from typing import Any
import anyio

import dns.asyncbackend


async def _wait_for(awaitable: Awaitable[Any], timeout: float | None) -> Any:
    if timeout is None:
        return await awaitable
    with anyio.fail_after(timeout):
        return await awaitable


class TrickyDatagramSocket(dns.asyncbackend.DatagramSocket):
    def __init__(self, family: int, sock_type: int) -> None:
        super().__init__(family, sock_type)
        self._socket = socket.socket(family, sock_type)
        self._socket.setblocking(False)
        self.closed = False

    def bind(self, address: tuple[str, int]) -> None:
        self._socket.bind(address)

    async def sendto(
        self,
        what: bytes,
        where: tuple[str, int],
        timeout: float | None,
    ) -> int:
        async def _send() -> int:
            await anyio.wait_socket_writable(self._socket)
            return self._socket.sendto(what, where)

        return await _wait_for(_send(), timeout)

    async def recvfrom(
        self,
        size: int,
        timeout: float | None,
    ) -> tuple[bytes, tuple[str, int]]:
        _ = size
        async def _recv() -> tuple[bytes, tuple[str, int]]:
            for _ in range(5):
                await anyio.wait_socket_readable(self._socket)
                data, addr = self._socket.recvfrom(65535)
                if len(data) > 32 and data[10:12] == b"\x00\x01":
                    return data, addr
            raise anyio.FailAfterTimeout("UDP recvfrom timeout")

        try:
            return await _wait_for(_recv(), timeout)
        except (anyio.FailAfterTimeout, TimeoutError) as exc:
            raise TimeoutError("UDP recvfrom timeout") from exc

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._socket.close()

    async def getpeername(self) -> tuple[str, int] | None:
        try:
            return self._socket.getpeername()
        except OSError:
            return None

    async def getsockname(self) -> tuple[str, int]:
        return self._socket.getsockname()

    async def getpeercert(self, timeout: float | None) -> None:
        _ = timeout
        return None
