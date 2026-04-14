from __future__ import annotations

import asyncio
import json
from pathlib import Path

import dns.asyncquery
import dns.message
import dns.rcode
import dns.rrset

from dns_forwarder.core.runtime import RuntimeManager


class FakeUpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, address: str | None, rcode: int = dns.rcode.NOERROR) -> None:
        self.address = address
        self.rcode = rcode
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.transport is None:
            return
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        response.set_rcode(self.rcode)
        if self.address is not None and self.rcode == dns.rcode.NOERROR:
            rrset = dns.rrset.from_text(
                query.question[0].name.to_text(), 30, "IN", "A", self.address
            )
            response.answer.append(rrset)
        self.transport.sendto(response.to_wire(), addr)


async def start_fake_upstream(
    answer: str | None, rcode: int = dns.rcode.NOERROR
) -> tuple[asyncio.DatagramTransport, int]:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: FakeUpstreamProtocol(answer, rcode=rcode),
        local_addr=("127.0.0.1", 0),
    )
    port = transport.get_extra_info("sockname")[1]
    return transport, port


def write_integration_config(path: Path, upstream_port: int) -> None:
    plugin_dir = str((Path(__file__).resolve().parents[1] / "plugins").resolve())
    data = {
        "runtime": {
            "plugin_dirs": [plugin_dir],
            "default_upstream_group": "default",
            "loop_policy": "asyncio",
        },
        "listeners": [
            {"name": "udp", "protocol": "udp", "host": "127.0.0.1", "port": 0, "enabled": True},
            {"name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": 0, "enabled": True},
        ],
        "nameservers": [
            {
                "name": "local-ns",
                "protocol": "do53",
                "address": "127.0.0.1",
                "port": upstream_port,
            }
        ],
        "upstreams": [
            {
                "name": "local",
                "nameservers": ["local-ns"],
                "timeout": 0.2,
                "lifetime": 0.5,
                "use_tcp": False,
            }
        ],
        "groups": [
            {"name": "default", "strategy": "race", "upstreams": ["local"]},
        ],
        "rules": [],
        "plugins": [],
        "webui": {
            "enabled": False,
            "host": "127.0.0.1",
            "port": 0,
            "username": "admin",
            "password": "change-me",
        },
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


async def test_udp_and_tcp_listeners_forward_queries(tmp_path: Path) -> None:
    upstream_transport, upstream_port = await start_fake_upstream("203.0.113.10")
    config_path = tmp_path / "config.json"
    write_integration_config(config_path, upstream_port)
    manager = RuntimeManager(config_path)
    await manager.start()

    try:
        status = manager.get_status()
        address_map = {item["name"]: item["address"] for item in status["listeners"]}
        udp_host, udp_port = address_map["udp"].split(":")
        tcp_host, tcp_port = address_map["tcp"].split(":")

        udp_response = await dns.asyncquery.udp(
            dns.message.make_query("example.test", "A"),
            where=udp_host,
            port=int(udp_port),
            timeout=1.0,
        )
        tcp_response = await dns.asyncquery.tcp(
            dns.message.make_query("example.test", "A"),
            where=tcp_host,
            port=int(tcp_port),
            timeout=1.0,
        )

        assert udp_response.answer[0][0].address == "203.0.113.10"
        assert tcp_response.answer[0][0].address == "203.0.113.10"
    finally:
        await manager.stop()
        upstream_transport.close()


async def test_nxdomain_from_upstream_returns_nxdomain(tmp_path: Path) -> None:
    upstream_transport, upstream_port = await start_fake_upstream(None, rcode=dns.rcode.NXDOMAIN)
    config_path = tmp_path / "config.json"
    write_integration_config(config_path, upstream_port)
    manager = RuntimeManager(config_path)
    await manager.start()

    try:
        status = manager.get_status()
        udp_host, udp_port = next(
            item["address"] for item in status["listeners"] if item["name"] == "udp"
        ).split(":")
        udp_response = await dns.asyncquery.udp(
            dns.message.make_query("missing.test", "A"),
            where=udp_host,
            port=int(udp_port),
            timeout=1.0,
        )
        assert udp_response.rcode() == dns.rcode.NXDOMAIN
    finally:
        await manager.stop()
        upstream_transport.close()
