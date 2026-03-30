from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dns.message

from dns_forwarder.config import ListenerConfig

if TYPE_CHECKING:
    from dns_forwarder.core.runtime import RuntimeManager


class TcpDnsServer:
    def __init__(self, listener: ListenerConfig, runtime_manager: "RuntimeManager") -> None:
        self.listener = listener
        self.runtime_manager = runtime_manager
        self.server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.listener.host,
            port=self.listener.port,
        )

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client = writer.get_extra_info("peername")
        try:
            while True:
                length_bytes = await reader.readexactly(2)
                payload_length = int.from_bytes(length_bytes, "big")
                payload = await reader.readexactly(payload_length)
                try:
                    request = dns.message.from_wire(payload)
                except Exception:
                    break

                response = await self.runtime_manager.process_query(request, client, self.listener.name)
                if response is None:
                    continue

                wire = response.to_wire()
                writer.write(len(wire).to_bytes(2, "big") + wire)
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    def bound_address(self) -> tuple[str, int] | None:
        if self.server is None or not self.server.sockets:
            return None
        sockname = self.server.sockets[0].getsockname()
        return sockname[0], sockname[1]
