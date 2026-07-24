from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import anyio.from_thread
import anyio.to_thread
import dns.asyncquery
import dns.message
import pytest
from httpx import ASGITransport, AsyncClient

import dns_forwarder.resolver.nameservers.doh_httpx as doh_httpx
from dns_forwarder.core.runtime import RuntimeManager
from dns_forwarder.core.worker import PortalWorker
from dns_forwarder.webui import create_webui_app

from test_udp_tcp_integration import start_fake_upstream


def write_worker_config(
    path: Path,
    upstream_port: int,
    *,
    workers: int = 1,
    doh_enabled: bool = False,
) -> dict[str, Any]:
    plugin_dir = str((Path(__file__).resolve().parents[1] / "plugins").resolve())
    data: dict[str, Any] = {
        "runtime": {
            "plugin_dirs": [plugin_dir],
            "default_upstream_group": "default",
            "loop_policy": "asyncio",
            "workers": workers,
        },
        "listeners": [
            {"name": "udp", "protocol": "udp", "host": "127.0.0.1", "port": 0, "enabled": True},
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
            {"name": "default", "upstreams": ["local"]},
        ],
        "rules": [],
        "plugins": [],
        "webui": {
            "enabled": False,
            "doh_enabled": doh_enabled,
            "host": "127.0.0.1",
            "port": 0,
            "username": "admin",
            "password": "change-me",
        },
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return data


async def test_worker_lifecycle_process_query(tmp_path: Path) -> None:
    upstream_transport, upstream_port = await start_fake_upstream("203.0.113.10")
    config_path = tmp_path / "config.json"
    write_worker_config(config_path, upstream_port)
    worker = PortalWorker(0, config_path, {})
    try:
        # start 会阻塞至 worker 在自有 loop 内完成初始化（提前调用 _async_start）。
        await anyio.to_thread.run_sync(worker.start)
        assert worker.state.config.runtime.workers == 1

        request = dns.message.make_query("example.test", "A")
        response = await anyio.to_thread.run_sync(
            worker.process_query_blocking, request, ("127.0.0.1", 53000), "udp"
        )
        assert response is not None
        assert response.answer[0][0].address == "203.0.113.10"
    finally:
        await anyio.to_thread.run_sync(worker.stop)
        upstream_transport.close()

    assert not worker._thread.is_alive()


async def test_worker_start_error_propagates(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{ not json", encoding="utf-8")
    worker = PortalWorker(0, config_path, {})
    with pytest.raises(RuntimeError, match="初始化失败"):
        await anyio.to_thread.run_sync(worker.start)
    assert not worker._thread.is_alive()


async def test_per_loop_shared_httpx_clients() -> None:
    class FakeResponse:
        def __init__(self, content: bytes) -> None:
            self.content = content

        def raise_for_status(self) -> None:
            return None

    def run_isolated_query() -> tuple[int, int]:
        """在独立 blocking portal（独立 loop）内执行一次 DoH 查询并关闭会话。

        返回 (loop_id, 查询时缓存中的客户端数量)。
        """
        with anyio.from_thread.start_blocking_portal(backend="asyncio") as portal:

            async def run_query() -> tuple[int, int]:
                from dns_forwarder.resolver.nameservers.doh_httpx import DoHHttpxNameserver

                request = dns.message.make_query("example.test", "A")
                response_wire = dns.message.make_response(request).to_wire()

                nameserver = DoHHttpxNameserver(
                    "https://1.1.1.1/dns-query",
                    verify=True,
                    want_get=True,
                    http_version="h2",
                    http_host=None,
                    server_hostname=None,
                )

                class StubClient:
                    async def request(self, *_args: Any, **_kwargs: Any) -> FakeResponse:
                        return FakeResponse(response_wire)

                    async def aclose(self) -> None:
                        return None

                # 直接以当前 loop 的键注入 stub 客户端，避免真实网络访问。
                key = doh_httpx._loop_key()
                doh_httpx._SHARED_CLIENTS[key] = StubClient()
                await nameserver.async_query(
                    request,
                    timeout=1.0,
                    source=None,
                    source_port=0,
                    max_size=False,
                    backend=None,
                )
                count = len(doh_httpx._SHARED_CLIENTS)
                await doh_httpx.close_shared_sessions()
                # 返回 loop 对象本身而非 id()：loop 关闭并被 GC 后 id 可能被复用，
                # 导致误判两次运行共享同一 loop。
                return asyncio.get_running_loop(), count

            return portal.call(run_query)

    loop_a, count_a = await anyio.to_thread.run_sync(run_isolated_query)
    loop_b, count_b = await anyio.to_thread.run_sync(run_isolated_query)
    # 两个独立 loop 各自只持有自己的客户端，且互不共享。
    assert loop_a is not loop_b
    assert count_a == 1
    assert count_b == 1


async def test_doh_cross_thread_with_two_workers(tmp_path: Path) -> None:
    upstream_transport, upstream_port = await start_fake_upstream("203.0.113.10")
    config_path = tmp_path / "config.json"
    write_worker_config(config_path, upstream_port, workers=2, doh_enabled=True)
    manager = RuntimeManager(config_path)
    await manager.start()
    try:
        app = create_webui_app(manager)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            wire = dns.message.make_query("example.test", "A").to_wire()
            response = await client.post(
                "/dns-query",
                content=wire,
                headers={"content-type": "application/dns-message"},
            )
        assert response.status_code == 200
        message = dns.message.from_wire(response.content)
        assert message.answer[0][0].address == "203.0.113.10"
    finally:
        await manager.stop()
        upstream_transport.close()


async def test_reload_updates_all_workers(tmp_path: Path) -> None:
    upstream_transport, upstream_port = await start_fake_upstream("203.0.113.10")
    config_path = tmp_path / "config.json"
    write_worker_config(config_path, upstream_port, workers=2)
    manager = RuntimeManager(config_path)
    await manager.start()
    try:
        states_before = [worker.state for worker in manager._workers]
        await manager.reload()
        states_after = [worker.state for worker in manager._workers]
        assert all(
            before is not after
            for before, after in zip(states_before, states_after, strict=True)
        )
        assert manager.get_state() is states_after[0]
    finally:
        await manager.stop()
        upstream_transport.close()


async def test_udp_listener_serves_through_portal(tmp_path: Path) -> None:
    upstream_transport, upstream_port = await start_fake_upstream("203.0.113.10")
    config_path = tmp_path / "config.json"
    write_worker_config(config_path, upstream_port, workers=2)
    manager = RuntimeManager(config_path)
    await manager.start()
    try:
        status = manager.get_status()
        udp_host, udp_port = next(
            item["address"] for item in status["listeners"] if item["name"] == "udp"
        ).split(":")
        for _ in range(4):
            response = await dns.asyncquery.udp(
                dns.message.make_query("example.test", "A"),
                where=udp_host,
                port=int(udp_port),
                timeout=1.0,
            )
            assert response.answer[0][0].address == "203.0.113.10"
    finally:
        await manager.stop()
        upstream_transport.close()


async def test_reload_closes_shared_sessions_before_rebuild(tmp_path: Path) -> None:
    """reload 必须先关闭本 loop 的共享 nameserver 会话，否则配置变更后
    aiohttp 会话因 bootstrap 不一致而对后续每个查询 raise。"""
    import dns_forwarder.resolver.nameservers.doh_aiohttp as doh_aiohttp

    upstream_transport, upstream_port = await start_fake_upstream("203.0.113.10")
    config_path = tmp_path / "config.json"
    write_worker_config(config_path, upstream_port)
    worker = PortalWorker(0, config_path, {})
    try:
        await anyio.to_thread.run_sync(worker.start)

        def inject_and_reload() -> None:
            """在 worker loop 内注入一个 bootstrap 为 ("8.8.8.8",) 的 aiohttp 会话，然后 reload。"""

            async def _inject() -> None:
                import aiohttp

                key = doh_aiohttp._loop_key()
                doh_aiohttp._SHARED[key] = (("8.8.8.8",), frozenset(), aiohttp.ClientSession())

            worker._portal.call(_inject)
            # reload 应已关闭并移除旧会话；若未关闭，会话仍残留在 _SHARED 中。
            worker.reload({})

        def check_removed() -> bool:
            async def _check() -> bool:
                return doh_aiohttp._loop_key() in doh_aiohttp._SHARED

            return worker._portal.call(_check)

        await anyio.to_thread.run_sync(inject_and_reload)
        key_present = await anyio.to_thread.run_sync(check_removed)
        assert not key_present
    finally:
        await anyio.to_thread.run_sync(worker.stop)
        upstream_transport.close()
