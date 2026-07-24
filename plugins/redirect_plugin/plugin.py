from __future__ import annotations

from copy import deepcopy

import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset

from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline import RequestContext, build_answer_from_response
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

from .models import RedirectPluginConfig, normalize_domain

logger = get_logger("plugins.redirect")


class RedirectPlugin(Plugin):
    name = "redirect-plugin"
    config_model = RedirectPluginConfig
    variables_model = EmptyModel
    request_order = 50
    ui_meta = {  # noqa: RUF012  # read-only frozen-style plugin metadata
        "title": "Redirect Plugin",
        "description": "按域名映射发起内部子查询，并返回源域名 CNAME 加目标域名结果。",
    }

    async def setup(self, registry: PluginRegistry) -> None:
        return None

    async def on_request(self, context: RequestContext) -> None:
        if context.final_answer is not None or context.final_response is not None:
            return

        question = context.request.question[0]
        source_domain = normalize_domain(question.name.to_text())
        target_domain = self.runtime_config.redirects.get(source_domain)
        if target_domain is None:
            return

        qtype = dns.rdatatype.to_text(question.rdtype).upper()
        try:
            redirected_answer = await context.resolve(target_domain, qtype)
        except dns.resolver.NXDOMAIN:
            logger.debug(
                "重定向子查询未命中 request_id=%s qname=%s target=%s qtype=%s",
                context.request_id,
                source_domain,
                target_domain,
                qtype,
            )
            return
        except Exception as exc:
            logger.warning(
                "重定向子查询失败 request_id=%s qname=%s target=%s qtype=%s error=%s",
                context.request_id,
                source_domain,
                target_domain,
                qtype,
                type(exc).__name__,
            )
            return

        if redirected_answer.rrset is None:
            logger.debug(
                "重定向子查询无可用结果 request_id=%s qname=%s target=%s qtype=%s",
                context.request_id,
                source_domain,
                target_domain,
                qtype,
            )
            return

        response = self._build_redirect_response(context.request, target_domain, redirected_answer)
        context.final_answer = build_answer_from_response(context.request, response)
        context.metadata["redirect_target"] = target_domain
        logger.debug(
            "重定向已应用 request_id=%s qname=%s target=%s qtype=%s rrset_size=%s",
            context.request_id,
            source_domain,
            target_domain,
            qtype,
            len(redirected_answer.rrset),
        )

    def _build_redirect_response(
        self,
        request: dns.message.Message,
        target_domain: str,
        redirected_answer: dns.resolver.Answer,
    ) -> dns.message.Message:
        source_response = redirected_answer.response
        response = dns.message.make_response(request)
        response.flags = source_response.flags
        response.set_rcode(source_response.rcode())
        response.answer.append(
            dns.rrset.from_text(
                request.question[0].name.to_text(),
                max(redirected_answer.rrset.ttl, 1),
                "IN",
                "CNAME",
                f"{target_domain}.",
            )
        )
        response.answer.extend(deepcopy(source_response.answer))
        response.authority.extend(deepcopy(source_response.authority))
        response.additional.extend(deepcopy(source_response.additional))
        return response


plugin = RedirectPlugin()
