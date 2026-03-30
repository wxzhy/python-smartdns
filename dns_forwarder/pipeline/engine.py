from __future__ import annotations

from typing import Any

import dns.message
import dns.opcode
import dns.rdatatype
import dns.rcode
import dns.resolver

from dns_forwarder.config import AppConfig, RuleConfig
from dns_forwarder.dispatcher import DispatcherRegistry
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult, clone_response_for_request, make_error_response
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

    async def handle_message(
        self,
        request: dns.message.Message,
        client: Any,
        listener_name: str,
    ) -> dns.message.Message | None:
        if request.opcode() != dns.opcode.QUERY or len(request.question) != 1:
            return make_error_response(request, dns.rcode.FORMERR)

        context = RequestContext(
            request=request,
            client=client,
            listener_name=listener_name,
            extensions=self._plugin_manager.build_context_extensions(),
            answer_registry_refs=self._plugin_manager.build_answer_registry(),
        )

        try:
            await self._plugin_manager.on_request(context)
            if context.drop_request:
                return None
            if context.final_response is None:
                context.selected_group = self._match_upstream_group(request)
                group = self._resolver_manager.get_group(context.selected_group)
                strategy = self._dispatcher_registry.get(group.strategy)
                result = await strategy.dispatch(context, group, self._resolver_manager)
                context.upstream_results.append(result)
                await self._plugin_manager.on_upstream_response(context, result)
                if context.final_response is None:
                    if result.answer is not None:
                        context.final_response = clone_response_for_request(result.answer.response, request)
                    elif isinstance(result.error, dns.resolver.NXDOMAIN):
                        context.final_response = make_error_response(request, dns.rcode.NXDOMAIN)

            await self._plugin_manager.on_response(context)
            if context.drop_request:
                return None
            if context.final_response is None:
                return make_error_response(request, dns.rcode.SERVFAIL)
            return clone_response_for_request(context.final_response, request)
        except Exception as exc:
            context.metadata["pipeline_error"] = repr(exc)
            return make_error_response(request, dns.rcode.SERVFAIL)

    def _match_upstream_group(self, request: dns.message.Message) -> str:
        question = request.question[0]
        qname = question.name.to_text().rstrip(".").lower()
        qtype = dns.rdatatype.to_text(question.rdtype).upper()

        for rule in self._config.rules:
            if not rule.enabled:
                continue
            if self._rule_matches(rule, qname, qtype):
                return rule.action.upstream_group

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
