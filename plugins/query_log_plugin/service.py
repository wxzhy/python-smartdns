from __future__ import annotations

import asyncio
from collections import deque
from typing import TYPE_CHECKING

from .models import QueryLogEntry, QueryLogPayload

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class QueryLogStore:
    def __init__(self, max_entries: int, *, heartbeat_seconds: float = 15.0) -> None:
        self._max_entries = max_entries
        self._heartbeat_seconds = heartbeat_seconds
        self._entries: deque[QueryLogEntry] = deque(maxlen=max_entries)
        self._next_id = 1
        self._condition = asyncio.Condition()

    @property
    def max_entries(self) -> int:
        return self._max_entries

    def resize(self, max_entries: int) -> None:
        if max_entries == self._max_entries:
            return
        self._max_entries = max_entries
        self._entries = deque(self._entries, maxlen=max_entries)

    async def append(self, payload: QueryLogPayload) -> QueryLogEntry:
        async with self._condition:
            entry = QueryLogEntry(id=self._next_id, **payload.model_dump())
            self._next_id += 1
            self._entries.append(entry)
            self._condition.notify_all()
            return entry

    async def list_recent(self, limit: int) -> list[QueryLogEntry]:
        if limit <= 0:
            return []
        async with self._condition:
            items = list(self._entries)
        return items[-min(limit, self._max_entries) :]

    async def subscribe(self, after_id: int | None = None) -> AsyncIterator[QueryLogEntry | None]:
        last_seen_id = 0 if after_id is None else max(after_id, 0)
        while True:
            items: list[QueryLogEntry] = []
            heartbeat = False
            async with self._condition:
                items = self._entries_after(last_seen_id)
                if not items:
                    try:
                        await asyncio.wait_for(
                            self._condition.wait(),
                            timeout=self._heartbeat_seconds,
                        )
                    except TimeoutError:
                        heartbeat = True
                    else:
                        items = self._entries_after(last_seen_id)
                if items:
                    last_seen_id = items[-1].id
            if items:
                for item in items:
                    yield item
                continue
            if heartbeat:
                yield None

    def _entries_after(self, entry_id: int) -> list[QueryLogEntry]:
        return [item for item in self._entries if item.id > entry_id]
