from __future__ import annotations

import time
from typing import TYPE_CHECKING

import dns.rcode
import dns.rdatatype
import dns.resolver

from dns_forwarder.logging import get_logger
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

from .models import QUERY_LOG_STORE_KEY, QueryLogPayload, QueryLogPluginConfig
from .service import QueryLogStore

if TYPE_CHECKING:
    from dns_forwarder.pipeline import RequestContext

logger = get_logger("plugins.query_log")


def get_query_log_store(context: RequestContext) -> QueryLogStore:
    store = context.extensions[QUERY_LOG_STORE_KEY]
    if not isinstance(store, QueryLogStore):
        raise TypeError("query_log.store 类型不正确")
    return store


class QueryLogPlugin(Plugin):
    name = "query-log-plugin"
    config_model = QueryLogPluginConfig
    variables_model = EmptyModel
    ui_meta = {  # noqa: RUF012  # read-only frozen-style plugin metadata
        "title": "Query Log Plugin",
        "description": "记录外部查询的时间、类型和结果摘要，并供 WebUI 实时观测。",
    }

    def __init__(self) -> None:
        super().__init__()
        self._store: QueryLogStore | None = None

    async def setup(self, registry: PluginRegistry) -> None:
        existing = registry.context_registry.get(QUERY_LOG_STORE_KEY)
        if (
            existing is not None
            and existing.factory is None
            and isinstance(existing.value, QueryLogStore)
        ):
            existing.value.resize(self.runtime_config.max_entries)
            self._store = existing.value
            return

        self._store = QueryLogStore(self.runtime_config.max_entries)
        registry.register_context(QUERY_LOG_STORE_KEY, self._store)

    async def on_observe(self, context: RequestContext) -> None:
        if self._store is None or context.is_nested_resolve or context.final_response is None:
            return

        question = context.request.question[0]
        payload = QueryLogPayload(
            timestamp_ms=int(time.time() * 1000),
            qname=question.name.to_text().rstrip(".").lower(),
            qtype=dns.rdatatype.to_text(question.rdtype).upper(),
            listener=context.listener_name,
            rcode=dns.rcode.to_text(context.final_response.rcode()),
            result_summary=self._build_result_summary(context.final_answer, context.final_response),
            upstream=context.upstream_results[-1].upstream_name
            if context.upstream_results
            else None,
            duration_ms=context.upstream_results[-1].duration_ms
            if context.upstream_results
            else None,
        )
        entry = await self._store.append(payload)
        logger.debug(
            "查询日志已记录 request_id=%s entry_id=%s qname=%s qtype=%s rcode=%s",
            context.request_id,
            entry.id,
            payload.qname,
            payload.qtype,
            payload.rcode,
        )

    @staticmethod
    def _build_result_summary(
        answer: dns.resolver.Answer | None,
        response,
    ) -> str:
        rcode = response.rcode()
        rcode_text = dns.rcode.to_text(rcode)
        if rcode != dns.rcode.NOERROR:
            return rcode_text
        if answer is None or answer.rrset is None:
            return "NOERROR empty"

        if answer.rdtype in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return QueryLogPlugin._format_address_summary(answer)

        if answer.rdtype == dns.rdatatype.HTTPS:
            return f"HTTPS x{len(answer.rrset)}"

        return f"{dns.rdatatype.to_text(answer.rdtype)} x{len(answer.rrset)}"

    @staticmethod
    def _format_address_summary(answer: dns.resolver.Answer) -> str:
        addresses = [
            record.address
            for record in answer.rrset
            if getattr(record, "address", None) is not None
        ]
        if not addresses:
            return f"{dns.rdatatype.to_text(answer.rdtype)} x{len(answer.rrset)}"
        display = ", ".join(addresses[:3])
        extra = len(addresses) - 3
        if extra > 0:
            return f"{dns.rdatatype.to_text(answer.rdtype)} {display} +{extra}"
        return f"{dns.rdatatype.to_text(answer.rdtype)} {display}"


plugin = QueryLogPlugin()
