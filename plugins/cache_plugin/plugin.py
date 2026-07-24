from __future__ import annotations

import dns.rcode
import dns.resolver
from pydantic import BaseModel, Field

from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline import (
    RequestContext,
    build_answer_from_response,
    make_error_response,
    sync_answer_response,
)
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

from .models import CACHE_CONTEXT_KEY, CACHE_SERVICE_KEY, CachePluginContext
from .service import DnsCacheService

logger = get_logger("plugins.cache")


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
    ui_meta = {  # noqa: RUF012  # read-only frozen-style plugin metadata
        "title": "Cache Plugin",
        "description": (
            "在 request 阶段查 dnspython 缓存，并合并相同 cache key 的并发请求；"
            "在 response 阶段最后写入 NOERROR 响应。"
        ),
    }

    def __init__(self) -> None:
        super().__init__()
        self._service: DnsCacheService | None = None

    async def setup(self, registry: PluginRegistry) -> None:
        self._service = DnsCacheService(max_size=self.runtime_config.max_size)
        registry.register_context(CACHE_SERVICE_KEY, self._service)
        registry.register_context_factory(CACHE_CONTEXT_KEY, CachePluginContext)
        logger.debug("缓存插件初始化完成 max_size=%s", self.runtime_config.max_size)

    async def on_request(self, context: RequestContext) -> None:
        if self._service is None:
            return

        cache_context = get_cache_context(context)
        question = context.request.question[0]
        qname = question.name.to_text().rstrip(".")
        qtype = dns.rdatatype.to_text(question.rdtype)
        cache_context.key = self._service.make_key_from_request(context.request)
        while True:
            cached_answer = self._service.get_for_request(context.request)
            if cached_answer is not None:
                cache_context.hit = True
                context.metadata["cache_hit"] = True
                context.final_answer = cached_answer
                context.stop_processing = True
                logger.debug(
                    "缓存命中 request_id=%s qname=%s qtype=%s ttl=%s",
                    context.request_id,
                    qname,
                    qtype,
                    cached_answer.rrset.ttl if cached_answer.rrset is not None else "none",
                )
                return

            pending = await self._service.acquire_pending(cache_context.key)
            if pending is None:
                cache_context.pending_owner = True
                logger.debug(
                    "缓存未命中，当前请求成为并发 owner request_id=%s qname=%s qtype=%s",
                    context.request_id,
                    qname,
                    qtype,
                )
                return

            logger.debug(
                "检测到并发相同请求，等待 owner 完成 request_id=%s qname=%s qtype=%s",
                context.request_id,
                qname,
                qtype,
            )
            shared_response = await self._service.wait_for_pending_response(
                pending, context.request
            )
            if shared_response is None:
                logger.debug(
                    "并发请求等待结束后回到缓存重查 request_id=%s qname=%s qtype=%s",
                    context.request_id,
                    qname,
                    qtype,
                )
                continue

            cache_context.shared = True
            context.metadata["cache_shared"] = True
            context.final_response = shared_response
            context.final_answer = build_answer_from_response(context.request, shared_response)
            context.stop_processing = True
            logger.debug(
                "并发请求复用 owner 响应 request_id=%s qname=%s qtype=%s",
                context.request_id,
                qname,
                qtype,
            )
            return

    async def on_response(self, context: RequestContext) -> None:
        if self._service is None:
            return

        cache_context = get_cache_context(context)
        if cache_context.hit or cache_context.shared:
            return

        question = context.request.question[0]
        qname = question.name.to_text().rstrip(".")
        qtype = dns.rdatatype.to_text(question.rdtype)
        answer_to_cache = self._resolve_cacheable_answer(context)
        if answer_to_cache is not None:
            self._service.put_answer(answer_to_cache)
            logger.debug(
                "响应已写入缓存 request_id=%s qname=%s qtype=%s ttl=%s",
                context.request_id,
                qname,
                qtype,
                answer_to_cache.rrset.ttl if answer_to_cache.rrset is not None else "none",
            )
        else:
            logger.debug(
                "响应未写入缓存 request_id=%s qname=%s qtype=%s final_rcode=%s",
                context.request_id,
                qname,
                qtype,
                context.final_response.rcode() if context.final_response is not None else "none",
            )

        if cache_context.pending_owner and cache_context.key is not None:
            if answer_to_cache is not None:
                await self._service.complete_pending(cache_context.key, None)
                logger.debug(
                    "并发 owner 完成并唤醒 follower 回查缓存 request_id=%s qname=%s qtype=%s",
                    context.request_id,
                    qname,
                    qtype,
                )
            else:
                response_to_share = self._resolve_response_to_share(context)
                await self._service.complete_pending(cache_context.key, response_to_share)
                logger.debug(
                    "并发 owner 直接共享不可缓存响应 request_id=%s qname=%s qtype=%s rcode=%s",
                    context.request_id,
                    qname,
                    qtype,
                    response_to_share.rcode(),
                )

    async def on_finish(self, context: RequestContext) -> None:
        if self._service is None:
            return

        cache_context = get_cache_context(context)
        if not cache_context.pending_owner or cache_context.key is None:
            return
        if not await self._service.has_pending(cache_context.key):
            return

        response_to_share = self._resolve_response_to_share(context)
        await self._service.complete_pending(cache_context.key, response_to_share)

    @staticmethod
    def _resolve_response_to_share(context: RequestContext):
        if context.final_answer is not None:
            return sync_answer_response(context.final_answer).response
        if context.final_response is not None:
            return context.final_response

        response = make_error_response(context.request, dns.rcode.SERVFAIL)
        context.final_response = response
        return response

    @staticmethod
    def _resolve_cacheable_answer(context: RequestContext) -> dns.resolver.Answer | None:
        if context.final_answer is not None:
            if (
                context.final_response is not None
                and context.final_response.rcode() != dns.rcode.NOERROR
            ):
                return None
            return sync_answer_response(context.final_answer)

        if context.final_response is None or context.final_response.rcode() != dns.rcode.NOERROR:
            return None
        return build_answer_from_response(context.request, context.final_response)


plugin = CachePlugin()
