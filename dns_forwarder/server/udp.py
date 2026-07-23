from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import dns.message

from dns_forwarder.config import ListenerConfig
from dns_forwarder.logging import get_logger

if TYPE_CHECKING:
    from dns_forwarder.core.runtime import RuntimeManager


logger = get_logger("server.udp")


class _DatagramHandler(asyncio.DatagramProtocol):
    def __init__(self, server: UdpDnsServer) -> None:
        self.server = server

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.server.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        logger.debug(
            "UDP 收到请求 name=%s client=%r payload_length=%s",
            self.server.listener.name,
            addr,
            len(data),
        )
        # UDP 数据报处理以 fire-and-forget 任务执行，无需持有 task 引用。
        asyncio.create_task(self.server.handle_datagram(data, addr))  # noqa: RUF006


class UdpDnsServer:
    def __init__(self, listener: ListenerConfig, runtime_manager: RuntimeManager) -> None:
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
        logger.debug(
            "UDP listener 已绑定 name=%s address=%r", self.listener.name, self.bound_address()
        )

    async def stop(self) -> None:
        if self.transport is not None:
            self.transport.close()
            self.transport = None
            logger.debug("UDP listener 已停止 name=%s", self.listener.name)

    async def handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.transport is None:
            return

        try:
            request = dns.message.from_wire(data)
        except Exception:
            logger.warning("UDP 请求解析失败 name=%s client=%r", self.listener.name, addr)
            return

        response = await self.runtime_manager.process_query(request, addr, self.listener.name)
        if response is None:
            logger.debug("UDP 请求被丢弃 name=%s client=%r", self.listener.name, addr)
            return
        self.transport.sendto(response.to_wire(), addr)
        logger.debug("UDP 响应已发送 name=%s client=%r", self.listener.name, addr)

    def bound_address(self) -> tuple[str, int] | None:
        if self.transport is None:
            return None
        sockname = self.transport.get_extra_info("sockname")
        if sockname is None:
            return None
        return sockname[0], sockname[1]
