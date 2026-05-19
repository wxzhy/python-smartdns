from __future__ import annotations

import asyncio
import itertools
import json
from concurrent.futures import Future
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from typing import Any

import dns.asyncquery
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

from dns_forwarder.core.multiprocess import (
    MultiprocessRuntimeManager,
    MultiprocessWorkerPool,
    WorkerHandle,
)


class FakeExecutor:
    def __init__(self) -> None:
        self.submitted: list[tuple[Any, int, int, Future[None]]] = []
        self.terminated = 0
        self.killed = 0
        self.shutdown_args: tuple[bool, bool] | None = None

    def submit(self, fn: Any, worker_id: int, generation: int) -> Future[None]:
        future: Future[None] = Future()
        self.submitted.append((fn, worker_id, generation, future))
        return future

    def terminate_workers(self) -> None:
        self.terminated += 1

    def kill_workers(self) -> None:
        self.killed += 1

    def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
        self.shutdown_args = (wait, cancel_futures)


class FakeUpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, address: str) -> None:
        self.address = address
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.transport is None:
            return
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        response.answer.append(
            dns.rrset.from_text(
                query.question[0].name.to_text(),
                30,
                "IN",
                "A",
                self.address,
            )
        )
        self.transport.sendto(response.to_wire(), addr)


async def start_fake_upstream(address: str) -> tuple[asyncio.DatagramTransport, int]:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: FakeUpstreamProtocol(address),
        local_addr=("127.0.0.1", 0),
    )
    return transport, transport.get_extra_info("sockname")[1]


def write_config(
    path: Path,
    *,
    upstream_port: int = 53,
    listeners_enabled: bool = False,
    query_log_enabled: bool = False,
    redirect_enabled: bool = False,
) -> None:
    plugin_dir = str((Path(__file__).resolve().parents[1] / "plugins").resolve())
    data = {
        "runtime": {
            "plugin_dirs": [plugin_dir],
            "default_upstream_group": "default",
            "loop_policy": "asyncio",
            "log_level": "INFO",
            "multiprocess": {
                "workers": 2,
                "start_method": "spawn",
                "queue_size": 32,
                "response_timeout": 5.0,
                "front_cache_size": 128,
            },
        },
        "tree_root": {"domain_dir": None, "ip_dir": None},
        "listeners": [
            {
                "name": "udp",
                "protocol": "udp",
                "host": "127.0.0.1",
                "port": 0,
                "enabled": listeners_enabled,
            },
            {
                "name": "tcp",
                "protocol": "tcp",
                "host": "127.0.0.1",
                "port": 0,
                "enabled": listeners_enabled,
            },
        ],
        "nameservers": [
            {
                "name": "local-ns",
                "protocol": "do53",
                "address": "127.0.0.1",
                "port": upstream_port,
            }
        ],
        "upstreams": [{"name": "local", "nameservers": ["local-ns"], "timeout": 0.2}],
        "groups": [{"name": "default", "upstreams": ["local"]}],
        "rules": [],
        "plugins": [
            {
                "name": "sample",
                "module": "sample_plugin",
                "enabled": not redirect_enabled,
                "config": {"domains": ["sample.internal"], "answer_name": "sample.static_a"},
                "variables": {"address": "127.0.0.9", "ttl": 30},
            },
            {
                "name": "redirect",
                "module": "redirect_plugin",
                "enabled": redirect_enabled,
                "config": {"redirects": {"alias.test": "target.test"}},
                "variables": {},
            },
            {
                "name": "query-log",
                "module": "query_log_plugin",
                "enabled": query_log_enabled,
                "config": {"max_entries": 20},
                "variables": {},
            },
        ],
        "webui": {"enabled": False, "doh_enabled": False},
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


async def wait_for_query_log(manager: MultiprocessRuntimeManager) -> list:
    store = manager.get_query_log_store()
    assert store is not None
    for _ in range(50):
        entries = await store.list_recent(10)
        if entries:
            return entries
        await asyncio.sleep(0.05)
    return []


def make_worker_pool_stub(executor: FakeExecutor) -> MultiprocessWorkerPool:
    pool = object.__new__(MultiprocessWorkerPool)
    pool._executor = executor
    pool._request_queues = [object()]
    pool._workers = []
    pool._generation_counter = itertools.count(2)
    pool._restarting = False
    pool._stopping = False
    return pool


async def test_worker_future_exception_resubmits_same_worker_id() -> None:
    executor = FakeExecutor()
    pool = make_worker_pool_stub(executor)
    old_future: Future[None] = Future()
    old_future.set_exception(RuntimeError("boom"))
    old_queue = pool._request_queues[0]
    pool._workers = [
        WorkerHandle(
            worker_id=0,
            request_queue=old_queue,
            future=old_future,
            generation=1,
        )
    ]

    await pool._restart_finished_workers_once()

    assert len(executor.submitted) == 1
    _, worker_id, generation, replacement_future = executor.submitted[0]
    assert worker_id == 0
    assert generation == 2
    assert pool._workers[0].worker_id == 0
    assert pool._workers[0].request_queue is old_queue
    assert pool._workers[0].future is replacement_future


async def test_worker_future_broken_pool_triggers_full_restart() -> None:
    executor = FakeExecutor()
    pool = make_worker_pool_stub(executor)
    old_future: Future[None] = Future()
    broken = BrokenProcessPool("broken")
    old_future.set_exception(broken)
    pool._workers = [
        WorkerHandle(
            worker_id=0,
            request_queue=pool._request_queues[0],
            future=old_future,
            generation=1,
        )
    ]
    calls: list[BrokenProcessPool] = []

    async def restart_broken_pool(exc: BrokenProcessPool) -> None:
        calls.append(exc)
        pool._restarting = True

    pool._restart_broken_pool = restart_broken_pool

    await pool._restart_finished_workers_once()

    assert calls == [broken]
    assert not executor.submitted


async def test_stop_executor_uses_shutdown_for_graceful_workers() -> None:
    executor = FakeExecutor()
    pool = make_worker_pool_stub(executor)
    future: Future[None] = Future()
    future.set_result(None)
    pool._workers = [
        WorkerHandle(
            worker_id=0,
            request_queue=pool._request_queues[0],
            future=future,
            generation=1,
        )
    ]

    await pool._stop_executor()

    assert executor.shutdown_args == (True, True)
    assert executor.terminated == 0
    assert executor.killed == 0
    assert pool._executor is None
    assert not pool._workers


async def test_stop_executor_terminates_and_kills_pending_workers(monkeypatch) -> None:
    monkeypatch.setattr(MultiprocessWorkerPool, "STOP_TIMEOUT_SECONDS", 0.01)
    executor = FakeExecutor()
    pool = make_worker_pool_stub(executor)
    future: Future[None] = Future()
    pool._workers = [
        WorkerHandle(
            worker_id=0,
            request_queue=pool._request_queues[0],
            future=future,
            generation=1,
        )
    ]

    await pool._stop_executor()

    assert executor.terminated == 1
    assert executor.killed == 1
    assert executor.shutdown_args is None
    assert pool._executor is None
    assert not pool._workers


async def test_multiprocess_process_query_and_query_log(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    write_config(config_path, query_log_enabled=True)
    manager = MultiprocessRuntimeManager(config_path)
    await manager.start()

    try:
        response = await manager.process_query(
            dns.message.make_query("sample.internal", "A"),
            ("127.0.0.1", 10000),
            "udp",
        )
        assert response is not None
        assert response.answer[0][0].address == "127.0.0.9"

        entries = await wait_for_query_log(manager)
        assert entries
        assert entries[-1].qname == "sample.internal"
        assert entries[-1].rcode == "NOERROR"
    finally:
        await manager.stop()


async def test_multiprocess_udp_and_tcp_listeners_forward_to_workers(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    write_config(config_path, listeners_enabled=True)
    manager = MultiprocessRuntimeManager(config_path)
    await manager.start()

    try:
        status = manager.get_status()
        address_map = {item["name"]: item["address"] for item in status["listeners"]}
        udp_host, udp_port = address_map["udp"].split(":")
        tcp_host, tcp_port = address_map["tcp"].split(":")

        udp_response = await dns.asyncquery.udp(
            dns.message.make_query("sample.internal", "A"),
            where=udp_host,
            port=int(udp_port),
            timeout=2.0,
        )
        tcp_response = await dns.asyncquery.tcp(
            dns.message.make_query("sample.internal", "A"),
            where=tcp_host,
            port=int(tcp_port),
            timeout=2.0,
        )

        assert udp_response.answer[0][0].address == "127.0.0.9"
        assert tcp_response.answer[0][0].address == "127.0.0.9"
    finally:
        await manager.stop()


async def test_multiprocess_worker_nested_resolve_uses_master(tmp_path: Path) -> None:
    upstream_transport, upstream_port = await start_fake_upstream("203.0.113.77")
    config_path = tmp_path / "config.json"
    write_config(config_path, upstream_port=upstream_port, redirect_enabled=True)
    manager = MultiprocessRuntimeManager(config_path)
    await manager.start()

    try:
        response = await manager.process_query(
            dns.message.make_query("alias.test", "A"),
            ("127.0.0.1", 10000),
            "udp",
        )

        assert response is not None
        assert response.rcode() == dns.rcode.NOERROR
        assert response.answer[0].rdtype == dns.rdatatype.CNAME
        assert response.answer[1][0].address == "203.0.113.77"
    finally:
        await manager.stop()
        upstream_transport.close()
