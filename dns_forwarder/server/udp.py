from __future__ import annotations

from typing import TYPE_CHECKING
import anyio
import dns.message

from dns_forwarder.config import ListenerConfig
from dns_forwarder.logging import get_logger

if TYPE_CHECKING:
    from dns_forwarder.core.runtime import RuntimeManager

logger = get_logger("server.udp")


class UdpDnsServer:
    def __init__(self, listener: ListenerConfig, runtime_manager: RuntimeManager) -> None:
        self.listener = listener
        self.runtime_manager = runtime_manager
        self.socket: anyio.abc.UDPSocket | None = None
        self._tg: anyio.abc.TaskGroup | None = None

    async def start(self, tg: anyio.abc.TaskGroup) -> None:
        self.socket = await anyio.create_udp_socket(
            local_host=self.listener.host,
            local_port=self.listener.port,
        )
        self._tg = tg
        logger.debug(
            "UDP listener 已绑定 name=%s address=%r", self.listener.name, self.bound_address()
        )
        tg.start_soon(self._serve)

    async def stop(self) -> None:
        if self.socket is not None:
            await self.socket.aclose()
            self.socket = None
            logger.debug("UDP listener 已停止 name=%s", self.listener.name)

    async def _serve(self) -> None:
        try:
            assert self.socket is not None
            async for data, addr in self.socket:
                logger.debug(
                    "UDP 收到请求 name=%s client=%r payload_length=%s",
                    self.listener.name,
                    addr,
                    len(data),
                )
                if self._tg is not None:
                    self._tg.start_soon(self.handle_datagram, data, addr)
        except anyio.ClosedResourceError:
            pass
        except Exception as e:
            logger.error("UDP listener 服务异常 name=%s error=%s", self.listener.name, e)

    async def handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.socket is None:
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

        try:
            await self.socket.send((response.to_wire(), addr))
            logger.debug("UDP 响应已发送 name=%s client=%r", self.listener.name, addr)
        except anyio.ClosedResourceError:
            pass
        except Exception as e:
            logger.warning("UDP 响应发送失败 name=%s client=%r error=%s", self.listener.name, addr, e)

    def bound_address(self) -> tuple[str, int] | None:
        if self.socket is None:
            return None
        addr = self.socket.extra(anyio.abc.SocketAttribute.local_address)
        if addr is None:
            return None
        return addr[0], addr[1]
