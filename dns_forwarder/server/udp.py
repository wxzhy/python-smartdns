from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dns.message

from dns_forwarder.config import ListenerConfig

if TYPE_CHECKING:
    from dns_forwarder.core.runtime import RuntimeManager


class _DatagramHandler(asyncio.DatagramProtocol):
    def __init__(self, server: "UdpDnsServer") -> None:
        self.server = server

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.server.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.create_task(self.server.handle_datagram(data, addr))


class UdpDnsServer:
    def __init__(self, listener: ListenerConfig, runtime_manager: "RuntimeManager") -> None:
        self.listener = listener
        self.runtime_manager = runtime_manager
        self.transport: asyncio.BaseTransport | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DatagramHandler(self),
            local_addr=(self.listener.host, self.listener.port),
        )
        self.transport = transport

    async def stop(self) -> None:
        if self.transport is not None:
            self.transport.close()
            self.transport = None

    async def handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.transport is None:
            return

        try:
            request = dns.message.from_wire(data)
        except Exception:
            return

        response = await self.runtime_manager.process_query(request, addr, self.listener.name)
        if response is None:
            return
        self.transport.sendto(response.to_wire(), addr)

    def bound_address(self) -> tuple[str, int] | None:
        if self.transport is None:
            return None
        sockname = self.transport.get_extra_info("sockname")
        if sockname is None:
            return None
        return sockname[0], sockname[1]
