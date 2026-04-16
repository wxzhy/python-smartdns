from __future__ import annotations

from pydantic import BaseModel, Field

QUERY_LOG_STORE_KEY = "query_log.store"


class QueryLogPluginConfig(BaseModel):
    max_entries: int = Field(default=500, ge=1)


class QueryLogPayload(BaseModel):
    timestamp_ms: int
    qname: str
    qtype: str
    listener: str
    rcode: str
    result_summary: str
    upstream: str | None = None
    duration_ms: float | None = None


class QueryLogEntry(QueryLogPayload):
    id: int
