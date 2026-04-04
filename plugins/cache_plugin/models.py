from __future__ import annotations

from dataclasses import dataclass

import dns.resolver


CACHE_CONTEXT_KEY = "cache.context"
CACHE_SERVICE_KEY = "cache.service"


@dataclass(slots=True)
class CachePluginContext:
    hit: bool = False
    key: dns.resolver.CacheKey | None = None
