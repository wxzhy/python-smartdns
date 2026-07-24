# 多线程架构审查问题修复实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复多线程改造审查发现的 5 个问题：QueryLogStore 跨 loop 崩溃/死锁、ECH 插件共享 alru_cache、reload 不关闭旧共享会话、QueryLogStore.resize 无锁、reload 部分失败导致多 worker 配置不一致。

**Architecture:** QueryLogStore 改为 `threading.Lock` 保护 deque + 每订阅者一个 `anyio.Event` 通知（已实证：`anyio.Event.set()` 可跨线程/跨 loop 调用并正确唤醒 waiter；`asyncio.Event.set()` 同样可行）。ECH 缓存改为实例级 wrapper；worker reload 前关闭本 loop 共享会话；RuntimeManager.reload 先预检（临时 portal 构建新 state），全部可行才切换。

**Tech Stack:** Python 3.14t (free-threaded)、anyio (blocking portal, Event)、async_lru、pytest + anyio

## Global Constraints

- 日志用 `get_logger` 返回的 %-style proxy，不用 f-string 拼日志
- 测试为 async 函数（项目已配置 anyio pytest 插件），可直接 `await`
- WebUI 侧 `QueryLogStore` 的公开接口签名保持兼容：`append`/`list_recent`/`subscribe`/`resize`/`max_entries` 的调用点（`plugins/query_log_plugin/plugin.py`、`dns_forwarder/webui/app.py`）不改
- 所有修复必须保持 `python -m pytest tests/ -q` 中除已知环境性失败（tags/geosite 外部数据缺失）外全部通过

---

### Task 1: QueryLogStore 跨 loop 安全改造

**Files:**
- Modify: `plugins/query_log_plugin/service.py`
- Test: `tests/test_query_log_plugin.py`

**Interfaces:**
- Consumes: `anyio.Event`（实证可跨线程 `set()`）、`threading.Lock`、`collections.deque`；`QueryLogPayload`、`QueryLogEntry`（models.py，不变）
- Produces: 新 `QueryLogStore` 公开接口（所有签名保持不变，调用点零改动）：
  - `__init__(self, max_entries: int, *, heartbeat_seconds: float = 15.0)`
  - `append(self, payload: QueryLogPayload) -> QueryLogEntry`（保持 `async def`，体内只用 `threading.Lock`，不绑定 loop）
  - `list_recent(self, limit: int) -> list[QueryLogEntry]`（保持 `async def`）
  - `subscribe(self, after_id: int | None = None) -> AsyncIterator[QueryLogEntry | None]`（保持 async generator；`None` 为心跳）
  - `resize(self, max_entries: int) -> None`（同步，加锁）
  - `max_entries` property（不变）

- [ ] **Step 1: 写失败测试 —— 跨 loop append + subscribe 不死锁不报错**

在 `tests/test_query_log_plugin.py` 末尾追加：

```python
async def test_query_log_store_cross_loop_append_and_subscribe() -> None:
    """worker 线程（独立 loop）append，当前 loop subscribe —— 复现 asyncio.Condition 跨 loop 崩溃。"""
    import anyio.from_thread

    store = QueryLogStore(max_entries=4, heartbeat_seconds=5.0)
    payload = QueryLogPayload(
        timestamp_ms=1,
        qname="cross.test",
        qtype="A",
        listener="udp",
        rcode="NOERROR",
        result_summary="A 203.0.113.1",
    )

    def append_in_portal() -> None:
        async def _append() -> None:
            await store.append(payload)

        with anyio.from_thread.start_blocking_portal(backend="asyncio") as portal:
            portal.call(_append)

    stream = store.subscribe()
    await anyio.to_thread.run_sync(append_in_portal)
    item = await anext(stream)
    assert item is not None
    assert item.qname == "cross.test"
    await stream.aclose()
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/test_query_log_plugin.py::test_query_log_store_cross_loop_append_and_subscribe -x -q`
Expected: FAIL（`RuntimeError: ... is bound to a different event loop` 或 `Lock is not acquired.`）

- [ ] **Step 3: 重写 service.py 为线程安全实现**

完整替换 `plugins/query_log_plugin/service.py`：

```python
from __future__ import annotations

import threading
from collections import deque
from typing import TYPE_CHECKING

import anyio

from .models import QueryLogEntry, QueryLogPayload

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class _Subscription:
    """单个订阅者：append 时经 ``event.set()`` 跨线程/跨 loop 唤醒。

    anyio.Event.set() 可在任意线程调用（内部走 loop.call_soon_threadsafe），
    唤醒后订阅者在自己的 loop 内从 deque 拉取新条目，避免跨 loop 使用
    asyncio.Condition 导致的崩溃/死锁。
    """

    __slots__ = ("event",)

    def __init__(self) -> None:
        self.event = anyio.Event()


class QueryLogStore:
    """跨事件循环安全的查询日志存储。

    数据（deque、id 计数、订阅列表）由 ``threading.Lock`` 保护，可被任意
    worker 线程写入；订阅者在自己的 loop 内等待各自的 ``anyio.Event``，
    被唤醒后从 deque 拉取增量，无任何跨 loop 的 asyncio 同步原语。
    """

    def __init__(self, max_entries: int, *, heartbeat_seconds: float = 15.0) -> None:
        self._max_entries = max_entries
        self._heartbeat_seconds = heartbeat_seconds
        self._entries: deque[QueryLogEntry] = deque(maxlen=max_entries)
        self._next_id = 1
        self._lock = threading.Lock()
        self._subscriptions: list[_Subscription] = []

    @property
    def max_entries(self) -> int:
        return self._max_entries

    def resize(self, max_entries: int) -> None:
        with self._lock:
            if max_entries == self._max_entries:
                return
            self._max_entries = max_entries
            self._entries = deque(self._entries, maxlen=max_entries)

    async def append(self, payload: QueryLogPayload) -> QueryLogEntry:
        """追加一条日志并唤醒所有订阅者（可在任意线程/loop 调用）。"""
        with self._lock:
            entry = QueryLogEntry(id=self._next_id, **payload.model_dump())
            self._next_id += 1
            self._entries.append(entry)
            subscriptions = list(self._subscriptions)
        for subscription in subscriptions:
            subscription.event.set()
        return entry

    async def list_recent(self, limit: int) -> list[QueryLogEntry]:
        if limit <= 0:
            return []
        with self._lock:
            items = list(self._entries)
            max_entries = self._max_entries
        return items[-min(limit, max_entries):]

    def _entries_after(self, entry_id: int) -> list[QueryLogEntry]:
        with self._lock:
            return [item for item in self._entries if item.id > entry_id]

    async def subscribe(self, after_id: int | None = None) -> AsyncIterator[QueryLogEntry | None]:
        last_seen_id = 0 if after_id is None else max(after_id, 0)
        subscription = _Subscription()
        with self._lock:
            self._subscriptions.append(subscription)
        try:
            while True:
                items = self._entries_after(last_seen_id)
                if not items:
                    # 重建 Event 再等待，避免错过"检查后、等待前"到达的唤醒。
                    subscription.event = anyio.Event()
                    items = self._entries_after(last_seen_id)
                if not items:
                    with anyio.move_on_after(self._heartbeat_seconds) as scope:
                        await subscription.event.wait()
                    if scope.cancelled_caught:
                        yield None  # 心跳
                    continue
                for item in items:
                    last_seen_id = item.id
                    yield item
        finally:
            with self._lock:
                if subscription in self._subscriptions:
                    self._subscriptions.remove(subscription)
```

设计要点（已实现的原型验证过）：
- `append`/`list_recent` 保持 `async def`（调用点 `await` 不变），体内只用 `threading.Lock` 和 `event.set()`，不绑定任何 loop
- 订阅侧等待前"重建 Event → 再查一次 deque"消除检查-等待竞态；被旧 Event 的迟到的 set 唤醒后重查 deque 为空也只是多一次循环，不会丢条目（新条目写入的是 deque，不是 Event）
- `resize` 加锁，与其他 worker 的并发 `append` 互斥

- [ ] **Step 4: 运行 query_log 全部测试**

Run: `python -m pytest tests/test_query_log_plugin.py -q`
Expected: 全部 PASS（含新增的跨 loop 测试与原有的 rotate/replay/heartbeat 测试）

- [ ] **Step 5: 运行 webui 与 runtime 相关测试确认接口兼容**

Run: `python -m pytest tests/test_runtime_and_webui.py tests/test_portal_workers.py -q`
Expected: 除已知 tags/geosite 环境失败外全部 PASS

- [ ] **Step 6: Commit**

```bash
git add plugins/query_log_plugin/service.py tests/test_query_log_plugin.py
git commit -m "fix: QueryLogStore 跨 loop 安全，改用线程锁 + anyio 线程安全订阅队列"
```

---

### Task 2: ECH 插件 alru_cache 改为实例级

**Files:**
- Modify: `plugins/cloudflare_ech_plugin/plugin.py:201`
- Test: `tests/test_cloudflare_ech_plugin.py`

**Interfaces:**
- Consumes: `async_lru.alru_cache`；`plugins/speedtest_plugin/service.py:50-55` 的实例级缓存模式
- Produces: `CloudflareEchPlugin.__init__` 中新增 `self._load_cloudflare_ech_cached`（实例级 alru_cache wrapper）；原 `_load_cloudflare_ech` 去掉装饰器改名 `_load_cloudflare_ech_uncached(resolve_key: object) -> tuple[bytes, int] | None`

- [ ] **Step 1: 写失败测试 —— 两个实例的缓存互不共享**

在 `tests/test_cloudflare_ech_plugin.py` 末尾追加：

```python
async def test_ech_cache_is_per_instance() -> None:
    """类级 alru_cache 会被所有 worker 实例共享并跨 loop 清空；实例级则各自独立。"""
    from plugins.cloudflare_ech_plugin.plugin import CloudflareEchPlugin

    plugin_a = CloudflareEchPlugin()
    plugin_b = CloudflareEchPlugin()
    assert plugin_a._load_cloudflare_ech_cached is not plugin_b._load_cloudflare_ech_cached
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/test_cloudflare_ech_plugin.py::test_ech_cache_is_per_instance -x -q`
Expected: FAIL with `AttributeError: 'CloudflareEchPlugin' object has no attribute '_load_cloudflare_ech_cached'`

- [ ] **Step 3: 改造 plugin.py**

在 `CloudflareEchPlugin.__init__`（现有 `self._cloudflare_resolvers: dict = {}` 附近）添加：

```python
        @alru_cache(maxsize=1, ttl=300)
        async def load_cached(resolve_key: object) -> tuple[bytes, int] | None:
            return await self._load_cloudflare_ech_uncached(resolve_key)

        self._load_cloudflare_ech_cached = load_cached
```

将原方法改为无装饰器：

```python
    async def _load_cloudflare_ech_uncached(self, resolve_key: object) -> tuple[bytes, int] | None:
        resolve = self._cloudflare_resolvers.get(resolve_key)
        if resolve is None:
            return None
        try:
            answer = await resolve(CLOUDFLARE_ECH_DOMAIN, "HTTPS")
        except Exception as exc:
            self._logger.debug("获取 Cloudflare ECH 失败 error=%s", type(exc).__name__)
            return None

        extracted = self._extract_ech_bytes(answer)
        if extracted is None:
            self._logger.debug("Cloudflare ECH 响应未包含可用 ech 参数")
        return extracted
```

并把 `_load_cloudflare_ech_for_context` 中的调用从 `await self._load_cloudflare_ech(resolve_key)` 改为 `await self._load_cloudflare_ech_cached(resolve_key)`。

- [ ] **Step 4: 运行测试**

Run: `python -m pytest tests/test_cloudflare_ech_plugin.py -q`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add plugins/cloudflare_ech_plugin/plugin.py tests/test_cloudflare_ech_plugin.py
git commit -m "fix: ECH 查询缓存改为实例级 alru_cache，避免跨 worker 共享清空与跨线程 cancel"
```

---

### Task 3: worker reload 前关闭旧共享会话

**Files:**
- Modify: `dns_forwarder/core/worker.py:169-172`
- Modify: `dns_forwarder/resolver/nameservers/aiodns.py:104-108`（close 按 loop 过滤，与其他模块对称）
- Test: `tests/test_portal_workers.py`

**Interfaces:**
- Consumes: `dns_forwarder.resolver.nameservers.close_shared_sessions`（聚合入口，已按 loop 过滤 httpx/aiohttp/curl/custom；aiodns 需修）
- Produces: `PortalWorker._async_reload` 行为变化：先 `await close_nameserver_sessions()` 再 `build_runtime_state`；aiodns `close_shared_sessions` 只关闭当前 loop 的 resolver

- [ ] **Step 1: 写失败测试 —— reload 后 aiohttp bootstrap 变更不报错**

在 `tests/test_portal_workers.py` 末尾追加：

```python
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
```

注意：配置中需启用一个 aiohttp DoH nameserver 才会走 `_get_shared_session`；本测试直接注入 `_SHARED` 验证关闭语义即可，无需真实 DoH 上游。

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest tests/test_portal_workers.py::test_reload_closes_shared_sessions_before_rebuild -x -q`
Expected: FAIL（reload 未关闭会话，`doh_aiohttp._loop_key() in doh_aiohttp._SHARED` 为 True）

- [ ] **Step 3: 修改 worker.py `_async_reload`**

```python
    async def _async_reload(self) -> RuntimeState:
        # 先关闭本 loop 持有的共享 nameserver 会话：配置（bootstrap/hosts/
        # servers/verify 等）变更后旧会话不复用，避免运行期报错或泄漏。
        await close_nameserver_sessions()
        self._state = await build_runtime_state(self._config_path, self._shared_contexts)
        return self._state
```

- [ ] **Step 4: 修改 aiodns.py `close_shared_sessions` 按 loop 过滤**

```python
async def close_shared_sessions() -> None:
    # 仅关闭当前 loop 的 resolver，与其他 nameserver 模块行为一致。
    current_loop_id = id(asyncio.get_running_loop())
    stale_keys = [key for key in _RESOLVERS if key[0] == current_loop_id]
    for key in stale_keys:
        resolver = _RESOLVERS.pop(key)
        await resolver.close()
```

（`_RESOLVERS` 的键形如 `(loop_id, servers, port, timeout, tcp)`，首元素为 loop id——实现者先读 aiodns.py 确认键结构再写过滤条件。）

- [ ] **Step 5: 运行测试**

Run: `python -m pytest tests/test_portal_workers.py tests/test_custom_nameservers.py tests/test_doh_server.py -q`
Expected: 全部 PASS

- [ ] **Step 6: Commit**

```bash
git add dns_forwarder/core/worker.py dns_forwarder/resolver/nameservers/aiodns.py tests/test_portal_workers.py
git commit -m "fix: worker reload 前关闭本 loop 共享 nameserver 会话，aiodns close 按 loop 过滤"
```

---

### Task 4: reload 预检 —— 避免部分失败导致多 worker 配置不一致

**Files:**
- Modify: `dns_forwarder/core/runtime.py:77-105`（`reload` 方法）
- Test: `tests/test_portal_workers.py`

**Interfaces:**
- Consumes: `build_runtime_state(config_path, shared_contexts)`（worker.py）；`start_blocking_portal`
- Produces: `RuntimeManager.reload` 新行为：在切换任何 worker 前，先在主侧临时 portal 中完整构建一次新 `RuntimeState` 预检；预检失败则抛异常且**所有 worker 保持旧配置不变**；预检成功才逐个 worker reload。`self._state` 在全部 worker 切换完成后才更新为 worker 0 的新 state。

- [ ] **Step 1: 写失败测试 —— 预检失败时所有 worker 保持旧配置**

在 `tests/test_portal_workers.py` 末尾追加：

```python
async def test_reload_preflight_failure_keeps_all_workers_on_old_config(tmp_path: Path) -> None:
    """新配置构建失败时，任何 worker 都不应被切换（避免半新半旧）。"""
    upstream_transport, upstream_port = await start_fake_upstream("203.0.113.10")
    config_path = tmp_path / "config.json"
    write_worker_config(config_path, upstream_port, workers=2)
    manager = RuntimeManager(config_path)
    await manager.start()
    try:
        states_before = [worker.state for worker in manager._workers]
        # 写入非法配置使 build_runtime_state 失败。
        config_path.write_text("{ not json", encoding="utf-8")
        with pytest.raises(Exception):
            await manager.reload()
        states_after = [worker.state for worker in manager._workers]
        assert states_after == states_before
        # 恢复合法配置后服务仍可用。
        write_worker_config(config_path, upstream_port, workers=2)
        await manager.reload()
    finally:
        await manager.stop()
        upstream_transport.close()
```

- [ ] **Step 2: 运行测试确认当前行为**

Run: `python -m pytest tests/test_portal_workers.py::test_reload_preflight_failure_keeps_all_workers_on_old_config -x -q`
Expected: 当前实现下若第一个 worker 的 reload 就失败，states 不变，此测试可能直接 PASS；为验证预检语义，补充断言 `manager.get_state() is states_before[0]`（`self._state` 也不应被更新）。若 PASS 则记录行为并继续（预检是防御性增强：当前失败点在 worker 0 时恰好无害，但失败点在 worker 1 时会产生半新半旧）。

补充一个真正复现半新半旧的测试：monkeypatch 第二个 worker 的 reload 抛错：

```python
async def test_reload_failure_on_second_worker_rolls_back_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upstream_transport, upstream_port = await start_fake_upstream("203.0.113.10")
    config_path = tmp_path / "config.json"
    write_worker_config(config_path, upstream_port, workers=2)
    manager = RuntimeManager(config_path)
    await manager.start()
    try:
        state_before = manager.get_state()
        original_run_sync = anyio.to_thread.run_sync
        failing_worker = manager._workers[1]

        async def run_sync_with_failure(func, *args):
            if func == failing_worker.reload:
                raise RuntimeError("模拟 worker 1 重建失败")
            return await original_run_sync(func, *args)

        monkeypatch.setattr(
            "dns_forwarder.core.runtime.anyio.to_thread.run_sync", run_sync_with_failure
        )
        with pytest.raises(RuntimeError, match="模拟 worker 1 重建失败"):
            await manager.reload()
        # 原子语义：失败后对外暴露的 state 仍是切换前的。
        assert manager.get_state() is state_before
    finally:
        await manager.stop()
        upstream_transport.close()
```

Run: `python -m pytest tests/test_portal_workers.py::test_reload_failure_on_second_worker_rolls_back_state -x -q`
Expected: FAIL（当前实现中 worker 0 已切换，`self._state` 已更新为新 state）

- [ ] **Step 3: 修改 runtime.py `reload`**

将 reload 中 worker 重建段改为：

```python
            if self._workers:
                shared_contexts = self._build_shared_contexts(config)
                # 预检：先在主侧临时 portal 完整构建一次新状态，确认配置可行；
                # 失败则抛异常且所有 worker 保持旧配置，避免半新半旧。
                preflight_state = await anyio.to_thread.run_sync(
                    self._build_preflight_state, shared_contexts
                )
                del preflight_state  # 预检状态仅用于验证可构建性，随即丢弃
                # 串行重建各 worker 状态，避免并发读取同一域名集/IP集文件。
                new_states: list[RuntimeState] = []
                try:
                    for worker in self._workers:
                        new_states.append(
                            await anyio.to_thread.run_sync(worker.reload, shared_contexts)
                        )
                except BaseException:
                    # 预检已通过但仍失败（极少见，如文件在预检后被改坏）：
                    # 保持 self._state 指向切换前的状态，避免对外暴露混合配置。
                    logger.exception("reload 中途失败，保持原 state config=%s", self.config_path)
                    raise
                # 全部 worker 切换完成后才更新主侧状态（webui 读取用）。
                self._state = new_states[0]
            else:
                self._state = await self._build_worker_state(config)
```

新增方法：

```python
    def _build_preflight_state(self, shared_contexts: dict[str, Any]) -> RuntimeState:
        """在临时 blocking portal 中构建一次新 RuntimeState 以预检配置（同步，供 to_thread 调用）。

        构建过程中若创建了按 loop 缓存的共享 nameserver 会话，在 portal 退出前
        于同一 loop 内关闭，避免泄漏。
        """
        from anyio.from_thread import start_blocking_portal

        from dns_forwarder.resolver.nameservers import close_shared_sessions

        with start_blocking_portal(backend="asyncio") as portal:
            try:
                return portal.call(build_runtime_state, self.config_path, shared_contexts)
            finally:
                try:
                    portal.call(close_shared_sessions)
                except Exception:
                    logger.exception("reload 预检会话清理失败")
```

（`build_runtime_state` 已在 runtime.py 头部 import：`from .worker import PortalWorker, RuntimeState, build_runtime_state`。`build_runtime_state` 与 `close_shared_sessions` 均为协程函数，`portal.call` 可直接调用。）

- [ ] **Step 4: 运行测试**

Run: `python -m pytest tests/test_portal_workers.py tests/test_runtime_and_webui.py -q`
Expected: 除已知 tags/geosite 环境失败外全部 PASS

- [ ] **Step 5: Commit**

```bash
git add dns_forwarder/core/runtime.py tests/test_portal_workers.py
git commit -m "fix: reload 预检新配置可构建性，全部 worker 切换完成后才更新主侧 state"
```

---

### Task 5: 全量回归 + 提交

- [ ] **Step 1: 全量测试**

Run: `python -m pytest tests/ -q`
Expected: 仅 `test_webui_server_uses_current_event_loop`（tags/geosite 外部数据缺失的已知环境失败）失败，其余全部 PASS

- [ ] **Step 2: 最终确认无遗漏提交**

Run: `git status --short && git log --oneline -5`
Expected: 工作区干净，4 个 fix 提交在列
