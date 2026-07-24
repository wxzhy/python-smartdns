from __future__ import annotations

import asyncio
import socket

import dns.asyncbackend

# 阈值常量：tricks 协议过滤短数据包。
_TRICK_MIN_BYTES = 32


class _TrickyDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self._queue: asyncio.Queue[tuple[bytes, tuple[str, int]] | Exception] = asyncio.Queue()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._queue.put_nowait((data, addr))

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        self._queue.put_nowait(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        self.transport = None
        self._queue.put_nowait(exc or EOFError("EOF"))

    async def recvfrom(
        self,
        timeout: float | None,  # noqa: ASYNC109  # timeout 属 dnspython/socket 接口契约
    ) -> tuple[bytes, tuple[str, int]]:
        if timeout is None:
            item = await self._queue.get()
        else:
            item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()


class TrickyDatagramSocket(dns.asyncbackend.DatagramSocket):
    def __init__(self, family: int, sock_type: int) -> None:
        super().__init__(family, sock_type)
        self._socket = socket.socket(family, sock_type)
        self._socket.setblocking(False)
        self._protocol = _TrickyDatagramProtocol()
        self._transport: asyncio.DatagramTransport | None = None
        self._endpoint_lock: asyncio.Lock | None = None
        self.closed = False

    def bind(self, address: tuple[str, int]) -> None:
        self._socket.bind(address)

    async def _ensure_endpoint(self) -> None:
        if self._transport is not None:
            return
        if self._endpoint_lock is None:
            self._endpoint_lock = asyncio.Lock()
        async with self._endpoint_lock:
            if self._transport is not None:
                return
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: self._protocol,
                sock=self._socket,
            )
            self._transport = transport  # type: ignore[assignment]

    async def sendto(
        self,
        what: bytes,
        where: tuple[str, int],
        timeout: float | None,  # noqa: ASYNC109  # timeout 属 dnspython/socket 接口契约
    ) -> int:
        _ = timeout
        await self._ensure_endpoint()
        assert self._transport is not None
        self._transport.sendto(what, where)
        return len(what)

    async def recvfrom(
        self,
        size: int,
        timeout: float | None,  # noqa: ASYNC109  # timeout 属 dnspython/socket 接口契约
    ) -> tuple[bytes, tuple[str, int]]:
        _ = size
        await self._ensure_endpoint()
        for _ in range(5):
            data, addr = await self._protocol.recvfrom(timeout)
            if len(data) > _TRICK_MIN_BYTES and data[10:12] == b"\x00\x01":
                return data, addr
        raise TimeoutError("UDP recvfrom timeout")

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self._transport is not None:
            self._protocol.close()
            await asyncio.sleep(0)
            self._transport = None
            return
        self._socket.close()

    async def getpeername(self) -> tuple[str, int] | None:
        try:
            return self._socket.getpeername()
        except OSError:
            return None

    async def getsockname(self) -> tuple[str, int]:
        return self._socket.getsockname()

    async def getpeercert(self, timeout: float | None) -> None:  # noqa: ASYNC109 -- 实现 dns backend 接口契约
        _ = timeout
