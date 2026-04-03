from __future__ import annotations

from typing import Any

import dns.message
import dns.opcode
import dns.rdatatype
import dns.rcode
import dns.resolver

from dns_forwarder.config import AppConfig, RuleConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline.context import (
    RequestContext,
    build_answer_from_response,
    clone_response_for_request,
    make_error_response,
)
from dns_forwarder.plugin_api import PluginManager
from dns_forwarder.resolver import ResolverManager


class PipelineEngine:
    def __init__(
        self,
        config: AppConfig,
        resolver_manager: ResolverManager,
        dispatcher_registry: DispatcherRegistry,
        plugin_manager: PluginManager,
    ) -> None:
        self._config = config
        self._resolver_manager = resolver_manager
        self._dispatcher_registry = dispatcher_registry
        self._plugin_manager = plugin_manager
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
                context.selected_group = self._match_upstream_group(request)
                self._logger.debug(
                    "选择上游组 request_id=%s group=%s",
                    context.request_id,
                    context.selected_group,
                )
                group = self._resolver_manager.get_group(context.selected_group)
                strategy = self._dispatcher_registry.get(group.strategy)
                result = await strategy.dispatch(context, group, self._resolver_manager)
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

    def _match_upstream_group(self, request: dns.message.Message) -> str:
        question = request.question[0]
        qname = question.name.to_text().rstrip(".").lower()
        qtype = dns.rdatatype.to_text(question.rdtype).upper()

        for rule in self._config.rules:
            if not rule.enabled:
                continue
            if self._rule_matches(rule, qname, qtype):
                self._logger.debug(
                    "规则命中 request_id=%s rule=%s upstream_group=%s",
                    request.id,
                    rule.name,
                    rule.action.upstream_group,
                )
                return rule.action.upstream_group

        self._logger.debug(
            "未命中规则 request_id=%s 使用默认 upstream_group=%s",
            request.id,
            self._config.runtime.default_upstream_group,
        )
        return self._config.runtime.default_upstream_group

    @staticmethod
    def _rule_matches(rule: RuleConfig, qname: str, qtype: str) -> bool:
        match = rule.match

        if match.qtypes and qtype not in match.qtypes:
            return False

        exact_matched = not match.exact_domains or qname in match.exact_domains
        suffix_matched = not match.suffix_domains or any(
            qname == suffix or qname.endswith(f".{suffix}") for suffix in match.suffix_domains
        )

        if match.exact_domains and match.suffix_domains:
            return exact_matched or suffix_matched
        if match.exact_domains:
            return exact_matched
        if match.suffix_domains:
            return suffix_matched
        return True

    def _finalize_context(self, context: RequestContext) -> None:
        if context.final_answer is None and context.final_response is not None:
            context.final_answer = build_answer_from_response(context.request, context.final_response)
            return

        if context.final_response is None and context.final_answer is not None:
            context.final_response = clone_response_for_request(context.final_answer.response, context.request)
            return

        if context.final_answer is None and context.final_response is None:
            self._logger.error("未生成最终答案 request_id=%s，使用 SERVFAIL", context.request_id)
            context.final_response = make_error_response(context.request, dns.rcode.SERVFAIL)
            context.final_answer = build_answer_from_response(context.request, context.final_response)
