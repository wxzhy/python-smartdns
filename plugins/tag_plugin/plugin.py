from __future__ import annotations

from typing import TYPE_CHECKING

import dns.rdatatype
import dns.rdtypes.svcbbase
import dns.resolver

from dns_forwarder.core import DOMAINSET_CONTEXT_KEY, IPSET_CONTEXT_KEY, DomainSet, IPSet
from dns_forwarder.logging import format_tags, get_logger
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

if TYPE_CHECKING:
    from dns_forwarder.pipeline import RequestContext, UpstreamResult

logger = get_logger("plugins.tag")


HAS_HINT_TAG = "has_hint"


def get_domainset(context: RequestContext) -> DomainSet:
    domainset = context.extensions[DOMAINSET_CONTEXT_KEY]
    if not isinstance(domainset, DomainSet):
        raise TypeError("core.domainset 类型不正确")
    return domainset


def get_ipset(context: RequestContext) -> IPSet:
    ipset = context.extensions[IPSET_CONTEXT_KEY]
    if not isinstance(ipset, IPSet):
        raise TypeError("core.ipset 类型不正确")
    return ipset


class TagPlugin(Plugin):
    name = "tag-plugin"
    config_model = EmptyModel
    variables_model = EmptyModel
    request_order = -100
    ui_meta = {  # noqa: RUF012  # read-only frozen-style plugin metadata
        "title": "Tag Plugin",
        "description": "基于域名和应答 IP 命中 tag 文件，为请求和上游结果追加标签。",
    }

    async def setup(self, registry: PluginRegistry) -> None:
        return None

    async def on_request(self, context: RequestContext) -> None:
        qname = context.request.question[0].name.to_text().rstrip(".")
        added_tags = get_domainset(context).lookup(qname)
        context.tags.update(added_tags)
        if added_tags:
            logger.debug(
                "请求标签命中 request_id=%s qname=%s added_tags=%s",
                context.request_id,
                qname,
                format_tags(added_tags),
            )

    async def on_upstream_response(self, context: RequestContext, result: UpstreamResult) -> None:
        domainset = get_domainset(context)
        ipset = get_ipset(context)
        before_tags = set(result.tags)
        result.tags.update(context.tags)
        cname_domains: list[str] = []
        for domain in self._extract_cname_chain_domains(result.answer):
            cname_domains.append(domain)
            result.tags.update(domainset.lookup(domain))
        hint_ip_count = 0
        has_hints = False
        if result.answer is None or result.answer.rrset is None:
            self._log_result_tags(
                context, result, before_tags, cname_domains, hint_ip_count, has_hints
            )
            return
        if result.answer.rdtype == dns.rdatatype.HTTPS:
            hint_ips, has_hints = self._extract_https_hints(result.answer)
            hint_ip_count = len(hint_ips)
            if has_hints:
                result.tags.add(HAS_HINT_TAG)
            for ip in hint_ips:
                result.tags.update(ipset.lookup(ip))
            self._log_result_tags(
                context, result, before_tags, cname_domains, hint_ip_count, has_hints
            )
            return
        for ip in self._extract_answer_ips(result.answer):
            result.tags.update(ipset.lookup(ip))
        self._log_result_tags(context, result, before_tags, cname_domains, hint_ip_count, has_hints)

    @staticmethod
    def _log_result_tags(  # noqa: PLR0913  # diagnostic context fields; grouped for one log call
        context: RequestContext,
        result: UpstreamResult,
        before_tags: set[str],
        cname_domains: list[str],
        hint_ip_count: int,
        has_hints: bool,
    ) -> None:
        added_tags = result.tags - before_tags
        if not added_tags and not cname_domains and not has_hints:
            return
        logger.debug(
            "结果标签已更新 request_id=%s upstream=%s added_tags=%s "
            "cname_domains=%s hint_ip_count=%s has_hint=%s",
            context.request_id,
            result.upstream_name,
            format_tags(added_tags),
            cname_domains,
            hint_ip_count,
            has_hints,
        )

    @staticmethod
    def _extract_cname_chain_domains(answer: dns.resolver.Answer | None) -> list[str]:
        if answer is None:
            return []

        chain = getattr(answer, "chaining_result", None)
        if chain is None:
            return []

        domains = [rrset.name.to_text().rstrip(".") for rrset in getattr(chain, "cnames", [])]
        canonical_name = getattr(answer, "canonical_name", None)
        if canonical_name is not None:
            domains.append(canonical_name.to_text().rstrip("."))
        return domains

    @staticmethod
    def _extract_answer_ips(answer: dns.resolver.Answer | None) -> list[str]:
        if answer is None or answer.rrset is None:
            return []
        if answer.rdtype in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return TagPlugin._extract_address_record_ips(answer)
        if answer.rdtype == dns.rdatatype.HTTPS:
            return TagPlugin._extract_https_hints(answer)[0]
        return []

    @staticmethod
    def _extract_address_record_ips(answer: dns.resolver.Answer) -> list[str]:
        addresses: list[str] = []
        for record in answer.rrset:
            address = getattr(record, "address", None)
            if address is None:
                continue
            addresses.append(address)
        return addresses

    @staticmethod
    def _extract_https_hints(answer: dns.resolver.Answer) -> tuple[list[str], bool]:
        addresses: list[str] = []
        has_hints = False
        for record in answer.rrset:
            params = getattr(record, "params", None)
            if params is None:
                continue
            for hint_key in (
                dns.rdtypes.svcbbase.ParamKey.IPV4HINT,
                dns.rdtypes.svcbbase.ParamKey.IPV6HINT,
            ):
                hint_param = params.get(hint_key)
                if hint_param is None:
                    continue
                has_hints = True
                addresses.extend(hint_param.addresses)
        return addresses, has_hints


plugin = TagPlugin()
