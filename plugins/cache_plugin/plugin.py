from __future__ import annotations

import dns.rcode
import dns.resolver
from pydantic import BaseModel, Field

from dns_forwarder.pipeline import (
    RequestContext,
    build_answer_from_response,
    make_error_response,
    sync_answer_response,
)
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

from .models import CACHE_CONTEXT_KEY, CACHE_SERVICE_KEY, CachePluginContext
from .service import DnsCacheService


class CachePluginConfig(BaseModel):
    max_size: int = Field(default=100000, ge=1)


def get_cache_context(context: RequestContext) -> CachePluginContext:
    cache_context = context.extensions[CACHE_CONTEXT_KEY]
    if not isinstance(cache_context, CachePluginContext):
        raise TypeError("cache.context 类型不正确")
    return cache_context


class CachePlugin(Plugin):
    name = "cache-plugin"
    config_model = CachePluginConfig
    variables_model = EmptyModel
    response_order = 1000
    ui_meta = {
        "title": "Cache Plugin",
        "description": "在 request 阶段查 dnspython 缓存，并合并相同 cache key 的并发请求；在 response 阶段最后写入 NOERROR 响应。",
    }

    def __init__(self) -> None:
        super().__init__()
        self._service: DnsCacheService | None = None

    async def setup(self, registry: PluginRegistry) -> None:
        self._service = DnsCacheService(max_size=self.runtime_config.max_size)
        registry.register_context(CACHE_SERVICE_KEY, self._service)
        registry.register_context_factory(CACHE_CONTEXT_KEY, CachePluginContext)

    async def on_request(self, context: RequestContext) -> None:
        if self._service is None:
            return

        cache_context = get_cache_context(context)
        cache_context.key = self._service.make_key_from_request(context.request)
        while True:
            cached_answer = self._service.get_for_request(context.request)
            if cached_answer is not None:
                cache_context.hit = True
                context.metadata["cache_hit"] = True
                context.final_answer = cached_answer
                return

            pending = await self._service.acquire_pending(cache_context.key)
            if pending is None:
                cache_context.pending_owner = True
                return

            shared_response = await self._service.wait_for_pending_response(pending, context.request)
            if shared_response is None:
                continue

            cache_context.shared = True
            context.metadata["cache_shared"] = True
            context.final_response = shared_response
            context.final_answer = build_answer_from_response(context.request, shared_response)
            return

    async def on_response(self, context: RequestContext) -> None:
        if self._service is None:
            return

        cache_context = get_cache_context(context)
        if cache_context.hit or cache_context.shared:
            return

        response_to_share = self._resolve_response_to_share(context)
        if cache_context.pending_owner and cache_context.key is not None:
            await self._service.complete_pending(cache_context.key, response_to_share)

        if context.final_answer is not None:
            if context.final_response is not None and context.final_response.rcode() != dns.rcode.NOERROR:
                return
            self._service.put_answer(sync_answer_response(context.final_answer))
            return

        if context.final_response is None or context.final_response.rcode() != dns.rcode.NOERROR:
            return
        self._service.put_answer(build_answer_from_response(context.request, context.final_response))

    @staticmethod
    def _resolve_response_to_share(context: RequestContext):
        if context.final_answer is not None:
            return sync_answer_response(context.final_answer).response
        if context.final_response is not None:
            return context.final_response

        response = make_error_response(context.request, dns.rcode.SERVFAIL)
        context.final_response = response
        return response


plugin = CachePlugin()
