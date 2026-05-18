from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from dns_forwarder.config import AppConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.logging import format_tags, get_logger
from dns_forwarder.pipeline.context import (
    NestedResolveHandler,
    NestedResolveRecursionError,
    RequestContext,
    UpstreamResult,
    build_answer_from_response,
    clone_response_for_request,
    make_error_response,
    sync_answer_response,
)
from dns_forwarder.plugin_api import PluginManager
from dns_forwarder.resolver import ResolverManager
from dns_forwarder.rules import RuleEngine


class PipelineEngine:
    MAX_NESTED_RESOLVE_DEPTH = 8

    def __init__(
        self,
        config: AppConfig,
        resolver_manager: ResolverManager,
        dispatcher_registry: DispatcherRegistry,
        plugin_manager: PluginManager,
        nested_resolve_handler: NestedResolveHandler | None = None,
    ) -> None:
        self._resolver_manager = resolver_manager
        self._dispatcher_registry = dispatcher_registry
        self._plugin_manager = plugin_manager
        self._nested_resolve_handler = nested_resolve_handler
        self._rule_engine = RuleEngine(config.rules, config.runtime.default_upstream_group)
        self._default_dispatcher = config.runtime.default_upstream_policy
        self._logger = get_logger("pipeline.engine")

    async def handle_message(
        self,
        request: dns.message.Message,
        clientaddr: Any,
        listener_name: str,
    ) -> dns.message.Message | None:
        error_response = self._validate_request_or_error(request, clientaddr, listener_name)
        if error_response is not None:
            return error_response

        context = self._build_context(
            request=request,
            clientaddr=clientaddr,
            listener_name=listener_name,
        )

        try:
            if await self._run_request_phase(context):
                return None

            if await self._run_response_phase(context):
                return None

            self._finalize_context(context)
            await self._observe_context(context)
            final_result_tags = (
                format_tags(context.upstream_results[-1].tags) if context.upstream_results else "[]"
            )
            self._logger.debug(
                "请求处理完成 request_id=%s listener=%s rcode=%s has_answer=%s rrset_size=%s request_tags=%s result_tags=%s",
                context.request_id,
                context.listener_name,
                context.final_response.rcode() if context.final_response is not None else "none",
                context.final_answer is not None,
                len(context.final_answer) if context.final_answer is not None else 0,
                format_tags(context.tags),
                final_result_tags,
            )

            if context.final_response is None:
                self._logger.error("最终响应为空 request_id=%s，返回 SERVFAIL", context.request_id)
                return make_error_response(request, dns.rcode.SERVFAIL)
            return clone_response_for_request(context.final_response, request)
        except asyncio.CancelledError:
            error_response = make_error_response(request, dns.rcode.SERVFAIL)
            context.final_response = error_response
            context.final_answer = build_answer_from_response(request, error_response)
            raise
        except Exception as exc:
            context.metadata["pipeline_error"] = repr(exc)
            error_response = make_error_response(request, dns.rcode.SERVFAIL)
            context.final_response = error_response
            context.final_answer = build_answer_from_response(request, error_response)
            self._logger.exception(
                "处理请求失败 request_id=%s listener=%s client=%r",
                context.request_id,
                context.listener_name,
                context.clientaddr,
            )
            return error_response
        finally:
            await self._finish_context(context)

    def _validate_request_or_error(
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
        if question.rdclass != dns.rdataclass.IN:
            self._logger.warning(
                "收到不支持的 DNS 请求 class request_id=%s listener=%s client=%r qclass=%s qname=%s",
                request.id,
                listener_name,
                clientaddr,
                dns.rdataclass.to_text(question.rdclass),
                question.name.to_text().rstrip("."),
            )
            return make_error_response(request, dns.rcode.FORMERR)

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
        return None

    async def _run_request_phase(self, context: RequestContext) -> bool:
        await self._plugin_manager.on_request(context)
        if context.drop_request:
            self._logger.debug(
                "请求被插件丢弃 request_id=%s listener=%s client=%r tags=%s",
                context.request_id,
                context.listener_name,
                context.clientaddr,
                format_tags(context.tags),
            )
            return True

        if context.stop_processing:
            self._logger.debug(
                "请求在 request 阶段短路返回 request_id=%s listener=%s tags=%s",
                context.request_id,
                context.listener_name,
                format_tags(context.tags),
            )
            return False

        if context.final_answer is not None or context.final_response is not None:
            return False

        upstream_hook_tasks: list[asyncio.Task[None]] = []
        result = await self._dispatch_context(
            context,
            on_result=lambda item: upstream_hook_tasks.append(
                asyncio.create_task(self._plugin_manager.on_upstream_response(context, item))
            ),
        )
        await self._wait_upstream_hook_tasks(upstream_hook_tasks)
        self._logger.debug(
            "dispatcher 返回 request_id=%s upstream=%s success=%s error=%s tags=%s",
            context.request_id,
            result.upstream_name,
            result.success,
            type(result.error).__name__ if result.error is not None else "",
            format_tags(result.tags),
        )
        if context.final_answer is None and context.final_response is None:
            if result.answer is not None:
                context.final_answer = result.answer
            elif isinstance(result.error, dns.resolver.NXDOMAIN):
                context.final_response = make_error_response(context.request, dns.rcode.NXDOMAIN)
        return False

    async def _run_response_phase(self, context: RequestContext) -> bool:
        if context.stop_processing:
            return False

        await self._plugin_manager.on_response(context)
        if context.drop_request:
            self._logger.debug(
                "响应阶段被插件丢弃 request_id=%s listener=%s client=%r tags=%s",
                context.request_id,
                context.listener_name,
                context.clientaddr,
                format_tags(context.tags),
            )
            return True
        return False

    def _build_context(
        self,
        request: dns.message.Message,
        clientaddr: Any,
        listener_name: str,
        *,
        extensions: dict[str, Any] | None = None,
        answer_registry_refs: dict[str, Any] | None = None,
        nested_resolve_chain: tuple[tuple[str, str], ...] = (),
    ) -> RequestContext:
        return RequestContext(
            request=request,
            clientaddr=clientaddr,
            listener_name=listener_name,
            extensions=(
                self._plugin_manager.build_context_extensions()
                if extensions is None
                else dict(extensions)
            ),
            answer_registry_refs=(
                self._plugin_manager.build_answer_registry()
                if answer_registry_refs is None
                else dict(answer_registry_refs)
            ),
            _resolve_handler=self._nested_resolve_handler or self._resolve_nested,
            _nested_resolve_chain=nested_resolve_chain,
            _nested_resolve_max_depth=self.MAX_NESTED_RESOLVE_DEPTH,
        )

    async def _dispatch_context(
        self,
        context: RequestContext,
        on_result: Callable[[UpstreamResult], None] | None = None,
    ) -> UpstreamResult:
        selection = self._rule_engine.select(context)
        context.selected_rule = selection.rule_name
        context.selected_group = selection.upstream_group
        selected_dispatcher = selection.dispatcher or self._default_dispatcher
        self._logger.debug(
            "选择上游组 request_id=%s rule=%s group=%s dispatcher=%s tags=%s",
            context.request_id,
            context.selected_rule or "",
            context.selected_group,
            selected_dispatcher.value,
            format_tags(context.tags),
        )
        group = self._resolver_manager.get_group(context.selected_group)
        context.selected_dispatcher = selected_dispatcher.value
        result = await self._dispatcher_registry.dispatch_group(
            context,
            group,
            selected_dispatcher,
            self._resolver_manager,
            on_result=on_result,
        )
        context.upstream_results.append(result)
        return result

    @staticmethod
    async def _wait_upstream_hook_tasks(tasks: list[asyncio.Task[None]]) -> None:
        if not tasks:
            return
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for item in results:
            if isinstance(item, BaseException):
                raise item

    async def _resolve_nested(
        self,
        context: RequestContext,
        qname: str,
        qtype: str,
    ) -> dns.resolver.Answer:
        signature = (qname, qtype)
        if signature in context._nested_resolve_chain:
            raise NestedResolveRecursionError(f"检测到内部解析递归 qname={qname} qtype={qtype}")
        if len(context._nested_resolve_chain) >= context._nested_resolve_max_depth:
            raise NestedResolveRecursionError(
                f"内部解析超过最大递归深度({context._nested_resolve_max_depth})"
            )

        nested_request = dns.message.make_query(qname, qtype, rdclass=dns.rdataclass.IN)
        nested_context = self._build_context(
            request=nested_request,
            clientaddr=context.clientaddr,
            listener_name=context.listener_name,
            extensions=context.extensions,
            answer_registry_refs=context.answer_registry_refs,
            nested_resolve_chain=context._nested_resolve_chain + (signature,),
        )
        self._logger.debug(
            "发起内部解析 outer_request_id=%s request_id=%s qname=%s qtype=%s depth=%s",
            context.request_id,
            nested_context.request_id,
            qname,
            qtype,
            len(nested_context._nested_resolve_chain),
        )
        result = await self._dispatch_context(nested_context)
        return self._answer_from_nested_result(context, nested_context, result)

    async def resolve_nested_query(
        self,
        qname: str,
        qtype: str,
        clientaddr: Any,
        listener_name: str,
        nested_resolve_chain: tuple[tuple[str, str], ...],
    ) -> dns.resolver.Answer:
        nested_request = dns.message.make_query(qname, qtype, rdclass=dns.rdataclass.IN)
        nested_context = self._build_context(
            request=nested_request,
            clientaddr=clientaddr,
            listener_name=listener_name,
            nested_resolve_chain=nested_resolve_chain,
        )
        self._logger.debug(
            "发起 IPC 内部解析 request_id=%s qname=%s qtype=%s depth=%s",
            nested_context.request_id,
            qname,
            qtype,
            len(nested_context._nested_resolve_chain),
        )
        result = await self._dispatch_context(nested_context)
        return self._answer_from_nested_result(None, nested_context, result)

    def _answer_from_nested_result(
        self,
        outer_context: RequestContext | None,
        nested_context: RequestContext,
        result: UpstreamResult,
    ) -> dns.resolver.Answer:
        outer_request_id = outer_context.request_id if outer_context is not None else "ipc"
        if result.answer is not None:
            self._logger.debug(
                "内部解析成功 outer_request_id=%s request_id=%s upstream=%s duration_ms=%.2f",
                outer_request_id,
                nested_context.request_id,
                result.upstream_name,
                result.duration_ms,
            )
            return result.answer
        if result.error is not None:
            self._logger.debug(
                "内部解析失败 outer_request_id=%s request_id=%s upstream=%s error=%s",
                outer_request_id,
                nested_context.request_id,
                result.upstream_name,
                type(result.error).__name__,
            )
            raise result.error
        question = nested_context.request.question[0]
        raise RuntimeError(
            "内部解析未返回有效答案 "
            f"qname={question.name.to_text().rstrip('.')} "
            f"qtype={dns.rdatatype.to_text(question.rdtype)}"
        )

    def _finalize_context(self, context: RequestContext) -> None:
        if context.final_answer is None and context.final_response is not None:
            context.final_answer = build_answer_from_response(
                context.request, context.final_response
            )
            return

        if context.final_response is None and context.final_answer is not None:
            sync_answer_response(context.final_answer)
            context.final_response = clone_response_for_request(
                context.final_answer.response, context.request
            )
            return

        if context.final_answer is None and context.final_response is None:
            self._logger.error("未生成最终答案 request_id=%s，使用 SERVFAIL", context.request_id)
            context.final_response = make_error_response(context.request, dns.rcode.SERVFAIL)
            context.final_answer = build_answer_from_response(
                context.request, context.final_response
            )
            return

        if context.final_answer is not None and context.final_response is not None:
            sync_answer_response(context.final_answer)
            context.final_response = clone_response_for_request(
                context.final_answer.response, context.request
            )

    async def _observe_context(self, context: RequestContext) -> None:
        try:
            await self._plugin_manager.on_observe(context)
        except Exception:
            self._logger.exception(
                "观测阶段失败 request_id=%s listener=%s",
                context.request_id,
                context.listener_name,
            )

    async def _finish_context(self, context: RequestContext) -> None:
        on_finish = getattr(self._plugin_manager, "on_finish", None)
        if on_finish is None:
            return
        try:
            await on_finish(context)
        except Exception:
            self._logger.exception(
                "finish 阶段失败 request_id=%s listener=%s",
                context.request_id,
                context.listener_name,
            )
