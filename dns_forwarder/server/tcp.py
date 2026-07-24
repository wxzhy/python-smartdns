from __future__ import annotations

from typing import TYPE_CHECKING
import anyio
from anyio.streams.buffered import BufferedByteReceiveStream
import dns.message

from dns_forwarder.config import ListenerConfig
from dns_forwarder.logging import get_logger

if TYPE_CHECKING:
    from dns_forwarder.core.runtime import RuntimeManager

logger = get_logger("server.tcp")


class TcpDnsServer:
    def __init__(self, listener: ListenerConfig, runtime_manager: RuntimeManager) -> None:
        self.listener = listener
        self.runtime_manager = runtime_manager
        self.listener_socket: anyio.abc.Listener[anyio.abc.SocketStream] | None = None
        self._tg: anyio.abc.TaskGroup | None = None

    async def start(self, tg: anyio.abc.TaskGroup) -> None:
        self.listener_socket = await anyio.create_tcp_listener(
            local_host=self.listener.host,
            local_port=self.listener.port,
        )
        self._tg = tg
        logger.debug(
            "TCP listener 已绑定 name=%s address=%r", self.listener.name, self.bound_address()
        )
        tg.start_soon(self._serve)

    async def stop(self) -> None:
        if self.listener_socket is not None:
            await self.listener_socket.aclose()
            self.listener_socket = None
            logger.debug("TCP listener 已停止 name=%s", self.listener.name)

    async def _serve(self) -> None:
        try:
            assert self.listener_socket is not None
            await self.listener_socket.serve(self.handle_client)
        except anyio.ClosedResourceError:
            pass
        except Exception as e:
            logger.error("TCP listener 服务异常 name=%s error=%s", self.listener.name, e)

    async def handle_client(self, client: anyio.abc.SocketStream) -> None:
        clientaddr = client.extra(anyio.abc.SocketAttribute.remote_address)
        logger.debug("TCP 客户端连接 name=%s client=%r", self.listener.name, clientaddr)
        buffered = BufferedByteReceiveStream(client)
        try:
            async with client:
                while True:
                    length_bytes = await buffered.receive_exactly(2)
                    payload_length = int.from_bytes(length_bytes, "big")
                    payload = await buffered.receive_exactly(payload_length)
                    logger.debug(
                        "TCP 收到请求 name=%s client=%r payload_length=%s",
                        self.listener.name,
                        clientaddr,
                        payload_length,
                    )
                    try:
                        request = dns.message.from_wire(payload)
                    except Exception:
                        logger.warning(
                            "TCP 请求解析失败 name=%s client=%r", self.listener.name, clientaddr
                        )
                        break

                    response = await self.runtime_manager.process_query(
                        request, clientaddr, self.listener.name
                    )
                    if response is None:
                        logger.debug("TCP 请求被丢弃 name=%s client=%r", self.listener.name, clientaddr)
                        continue

                    wire = response.to_wire()
                    await client.send(len(wire).to_bytes(2, "big") + wire)
                    logger.debug(
                        "TCP 响应已发送 name=%s client=%r response_length=%s",
                        self.listener.name,
                        clientaddr,
                        len(wire),
                    )
        except (anyio.EndOfStream, anyio.ClosedResourceError):
            logger.debug("TCP 客户端断开 name=%s client=%r", self.listener.name, clientaddr)
        except Exception as e:
            logger.error("TCP 连接处理异常 name=%s client=%r error=%s", self.listener.name, clientaddr, e)

    def bound_address(self) -> tuple[str, int] | None:
        if self.listener_socket is None:
            return None
        addr = self.listener_socket.extra(anyio.abc.SocketAttribute.local_address)
        if addr is None:
            return None
        return addr[0], addr[1]
