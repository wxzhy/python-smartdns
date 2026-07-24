from __future__ import annotations

import threading
from collections import deque
from collections.abc import AsyncIterator

import anyio

from .models import QueryLogEntry, QueryLogPayload


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
