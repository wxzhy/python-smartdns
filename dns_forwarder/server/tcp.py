from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dns.message

from dns_forwarder.config import ListenerConfig
from dns_forwarder.logging import get_logger

if TYPE_CHECKING:
    from dns_forwarder.core.runtime import RuntimeManager


logger = get_logger("server.tcp")


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
        logger.debug("TCP listener 已绑定 name=%s address=%r", self.listener.name, self.bound_address())

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
            logger.debug("TCP listener 已停止 name=%s", self.listener.name)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        clientaddr = writer.get_extra_info("peername")
        logger.debug("TCP 客户端连接 name=%s client=%r", self.listener.name, clientaddr)
        try:
            while True:
                length_bytes = await reader.readexactly(2)
                payload_length = int.from_bytes(length_bytes, "big")
                payload = await reader.readexactly(payload_length)
                logger.debug(
                    "TCP 收到请求 name=%s client=%r payload_length=%s",
                    self.listener.name,
                    clientaddr,
                    payload_length,
                )
                try:
                    request = dns.message.from_wire(payload)
                except Exception:
                    logger.warning("TCP 请求解析失败 name=%s client=%r", self.listener.name, clientaddr)
                    break

                response = await self.runtime_manager.process_query(request, clientaddr, self.listener.name)
                if response is None:
                    logger.debug("TCP 请求被丢弃 name=%s client=%r", self.listener.name, clientaddr)
                    continue

                wire = response.to_wire()
                writer.write(len(wire).to_bytes(2, "big") + wire)
                await writer.drain()
                logger.debug(
                    "TCP 响应已发送 name=%s client=%r response_length=%s",
                    self.listener.name,
                    clientaddr,
                    len(wire),
                )
        except asyncio.IncompleteReadError:
            logger.debug("TCP 客户端断开 name=%s client=%r", self.listener.name, clientaddr)
        finally:
            writer.close()
            await writer.wait_closed()

    def bound_address(self) -> tuple[str, int] | None:
        if self.server is None or not self.server.sockets:
            return None
        sockname = self.server.sockets[0].getsockname()
        return sockname[0], sockname[1]
