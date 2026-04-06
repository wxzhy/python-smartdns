from __future__ import annotations

from typing import Any

import dns.message
import dns.opcode
import dns.rdatatype
import dns.rcode
import dns.resolver

from dns_forwarder.config import AppConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline.context import (
    RequestContext,
    build_answer_from_response,
    clone_response_for_request,
    make_error_response,
    sync_answer_response,
)
from dns_forwarder.plugin_api import PluginManager
from dns_forwarder.resolver import ResolverManager
from dns_forwarder.rules import RuleEngine


class PipelineEngine:
    def __init__(
        self,
        config: AppConfig,
        resolver_manager: ResolverManager,
        dispatcher_registry: DispatcherRegistry,
        plugin_manager: PluginManager,
    ) -> None:
        self._resolver_manager = resolver_manager
        self._dispatcher_registry = dispatcher_registry
        self._plugin_manager = plugin_manager
        self._rule_engine = RuleEngine(config.rules, config.runtime.default_upstream_group)
        self._logger = get_logger("pipeline.engine")

    async def handle_message(
        self,
        request: dns.message.Message,
        clientaddr: Any,
        listener_name: str,
    ) -> dns.message.Message | None:
        if request.opcode() != dns.opcode.QUERY or len(request.question) != 1:
            self._logger.warning(
                "收到非法 DNS 请求 request_id=%s listener=%s client=%r opcode=%s question_count=%s",
                request.id,
                listener_name,
                clientaddr,
                request.opcode(),
                len(request.question),
            )
            return make_error_response(request, dns.rcode.FORMERR)

        question = request.question[0]
        qname = question.name.to_text().rstrip(".").lower()
        qtype = dns.rdatatype.to_text(question.rdtype).upper()
        self._logger.debug(
            "收到 DNS 请求 request_id=%s listener=%s client=%r qname=%s qtype=%s",
            request.id,
            listener_name,
            clientaddr,
            qname,
            qtype,
        )

        context = RequestContext(
            request=request,
            clientaddr=clientaddr,
            listener_name=listener_name,
            extensions=self._plugin_manager.build_context_extensions(),
            answer_registry_refs=self._plugin_manager.build_answer_registry(),
        )

        try:
            await self._plugin_manager.on_request(context)
            if context.drop_request:
                self._logger.debug(
                    "请求被插件丢弃 request_id=%s listener=%s client=%r",
                    context.request_id,
                    context.listener_name,
                    context.clientaddr,
                )
                return None

            if context.final_answer is None and context.final_response is None:
                selection = self._rule_engine.select(request)
                context.selected_rule = selection.rule_name
                context.selected_group = selection.upstream_group
                self._logger.debug(
                    "选择上游组 request_id=%s rule=%s group=%s dispatcher=%s",
                    context.request_id,
                    context.selected_rule or "",
                    context.selected_group,
                    selection.dispatcher.value if selection.dispatcher is not None else "",
                )
                group = self._resolver_manager.get_group(context.selected_group)
                context.selected_dispatcher = (
                    selection.dispatcher.value if selection.dispatcher is not None else group.strategy.value
                )
                if selection.dispatcher is None:
                    result = await self._dispatcher_registry.dispatch_group(
                        context,
                        group,
                        self._resolver_manager,
                    )
                else:
                    result = await self._dispatcher_registry.dispatch_with_strategy(
                        context,
                        group,
                        selection.dispatcher,
                        self._resolver_manager,
                    )
                context.upstream_results.append(result)
                self._logger.debug(
                    "dispatcher 返回 request_id=%s upstream=%s success=%s error=%s",
                    context.request_id,
                    result.upstream_name,
                    result.success,
                    type(result.error).__name__ if result.error is not None else "",
                )
                await self._plugin_manager.on_upstream_response(context, result)
                if context.final_answer is None and context.final_response is None:
                    if result.answer is not None:
                        context.final_answer = result.answer
                    elif isinstance(result.error, dns.resolver.NXDOMAIN):
                        context.final_response = make_error_response(request, dns.rcode.NXDOMAIN)

            await self._plugin_manager.on_response(context)
            if context.drop_request:
                self._logger.debug(
                    "响应阶段被插件丢弃 request_id=%s listener=%s client=%r",
                    context.request_id,
                    context.listener_name,
                    context.clientaddr,
                )
                return None

            self._finalize_context(context)
            self._logger.debug(
                "请求处理完成 request_id=%s listener=%s rcode=%s has_answer=%s rrset_size=%s",
                context.request_id,
                context.listener_name,
                context.final_response.rcode() if context.final_response is not None else "none",
                context.final_answer is not None,
                len(context.final_answer) if context.final_answer is not None else 0,
            )

            if context.final_response is None:
                self._logger.error("最终响应为空 request_id=%s，返回 SERVFAIL", context.request_id)
                return make_error_response(request, dns.rcode.SERVFAIL)
            return clone_response_for_request(context.final_response, request)
        except Exception as exc:
            context.metadata["pipeline_error"] = repr(exc)
            self._logger.exception(
                "处理请求失败 request_id=%s listener=%s client=%r",
                context.request_id,
                context.listener_name,
                context.clientaddr,
            )
            return make_error_response(request, dns.rcode.SERVFAIL)

    def _finalize_context(self, context: RequestContext) -> None:
        if context.final_answer is None and context.final_response is not None:
            context.final_answer = build_answer_from_response(context.request, context.final_response)
            return

        if context.final_response is None and context.final_answer is not None:
            sync_answer_response(context.final_answer)
            context.final_response = clone_response_for_request(context.final_answer.response, context.request)
            return

        if context.final_answer is None and context.final_response is None:
            self._logger.error("未生成最终答案 request_id=%s，使用 SERVFAIL", context.request_id)
            context.final_response = make_error_response(context.request, dns.rcode.SERVFAIL)
            context.final_answer = build_answer_from_response(context.request, context.final_response)
            return

        if context.final_answer is not None and context.final_response is not None:
            sync_answer_response(context.final_answer)
            context.final_response = clone_response_for_request(context.final_answer.response, context.request)
