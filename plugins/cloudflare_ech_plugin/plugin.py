from __future__ import annotations

from async_lru import alru_cache
import dns.rcode
import dns.rdatatype
import dns.rdtypes.svcbbase
import dns.rrset
import dns.resolver

from dns_forwarder.core import IPSET_CONTEXT_KEY, IPSet
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline import RequestContext, build_answer_from_response
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry
from plugins.tag_plugin import HAS_HINT_TAG

from .models import CloudflareEchPluginConfig


HTTPS_PARAM_KEY = dns.rdtypes.svcbbase.ParamKey
CLOUDFLARE_ECH_DOMAIN = "cloudflare-ech.com"


def get_ipset(context: RequestContext) -> IPSet:
    ipset = context.extensions[IPSET_CONTEXT_KEY]
    if not isinstance(ipset, IPSet):
        raise TypeError("core.ipset 类型不正确")
    return ipset


class CloudflareEchPlugin(Plugin):
    name = "cloudflare-ech-plugin"
    config_model = CloudflareEchPluginConfig
    variables_model = EmptyModel
    response_order = 700
    ui_meta = {
        "title": "Cloudflare ECH Plugin",
        "description": "按 tag 为 HTTPS 响应补充 Cloudflare ECH 参数，并在必要时通过 subquery 判定目标域名。",
    }

    def __init__(self) -> None:
        super().__init__()
        self._logger = get_logger("plugins.cloudflare_ech")
        self._cloudflare_resolvers: dict[object, object] = {}

    async def setup(self, registry: PluginRegistry) -> None:
        if not self.runtime_config.match_tags:
            raise ValueError("cloudflare_ech_plugin 至少需要一个 match_tags")
        return None

    async def on_response(self, context: RequestContext) -> None:
        answer = self._get_https_answer(context)
        if answer is None or self._has_any_ech(answer):
            return

        base_tags = set(context.upstream_results[-1].tags) if context.upstream_results else set(context.tags)
        if self._has_any_tag(base_tags, self.runtime_config.exclude_tags):
            return
        if not self._has_any_tag(base_tags, self.runtime_config.match_tags):
            if HAS_HINT_TAG in base_tags:
                return
            subquery_tags = await self._resolve_address_tags(context, get_ipset(context))
            if self._has_any_tag(subquery_tags, self.runtime_config.exclude_tags):
                return
            if not self._has_any_tag(subquery_tags, self.runtime_config.match_tags):
                return

        ech_bytes = await self._load_cloudflare_ech_for_context(context)
        if ech_bytes is None:
            return
        self._inject_ech(answer, ech_bytes)

    def _get_https_answer(self, context: RequestContext) -> dns.resolver.Answer | None:
        answer = context.final_answer
        if answer is None:
            response = context.final_response
            if response is None or response.rcode() != dns.rcode.NOERROR:
                return None
            answer = build_answer_from_response(context.request, response)
            context.final_answer = answer

        if answer.response.rcode() != dns.rcode.NOERROR:
            return None
        rrset = answer.rrset
        if rrset is None or answer.rdtype != dns.rdatatype.HTTPS or rrset.rdtype != dns.rdatatype.HTTPS:
            return None
        return answer

    @staticmethod
    def _has_any_tag(current_tags: set[str], configured_tags: list[str]) -> bool:
        return bool(current_tags.intersection(configured_tags))

    @staticmethod
    def _has_any_ech(answer: dns.resolver.Answer) -> bool:
        return any(HTTPS_PARAM_KEY.ECH in rdata.params for rdata in answer.rrset)

    async def _resolve_address_tags(self, context: RequestContext, ipset: IPSet) -> set[str]:
        qname = context.request.question[0].name.to_text().rstrip(".")
        try:
            answer = await context.resolve(qname, "A")
        except Exception as exc:
            self._logger.debug(
                "A subquery 失败 request_id=%s qname=%s error=%s",
                context.request_id,
                qname,
                type(exc).__name__,
            )
            return set()

        if answer.rrset is None or answer.rdtype != dns.rdatatype.A:
            return set()

        tags: set[str] = set()
        for record in answer.rrset:
            address = getattr(record, "address", None)
            if address is None:
                continue
            tags.update(ipset.lookup(address))
        return tags

    async def _load_cloudflare_ech_for_context(self, context: RequestContext) -> bytes | None:
        resolve_key = context._resolve_handler
        if resolve_key is None:
            return None
        self._cloudflare_resolvers[resolve_key] = context.resolve
        return await self._load_cloudflare_ech(resolve_key)

    @alru_cache(maxsize=1, ttl=300)
    async def _load_cloudflare_ech(self, resolve_key: object) -> bytes | None:
        resolve = self._cloudflare_resolvers.get(resolve_key)
        if resolve is None:
            return None
        try:
            answer = await resolve(CLOUDFLARE_ECH_DOMAIN, "HTTPS")
        except Exception as exc:
            self._logger.debug("获取 Cloudflare ECH 失败 error=%s", type(exc).__name__)
            return None

        extracted = self._extract_ech_bytes(answer)
        if extracted is None:
            self._logger.debug("Cloudflare ECH 响应未包含可用 ech 参数")
        return extracted

    @staticmethod
    def _extract_ech_bytes(answer: dns.resolver.Answer | None) -> bytes | None:
        if answer is None or answer.rrset is None:
            return None
        if answer.rdtype != dns.rdatatype.HTTPS or answer.rrset.rdtype != dns.rdatatype.HTTPS:
            return None
        for rdata in answer.rrset:
            if getattr(rdata, "priority", 0) == 0:
                continue
            ech_param = rdata.params.get(HTTPS_PARAM_KEY.ECH)
            if ech_param is None:
                continue
            ech_bytes = getattr(ech_param, "ech", None)
            if isinstance(ech_bytes, bytes):
                return ech_bytes
        return None

    def _inject_ech(self, answer: dns.resolver.Answer, ech_bytes: bytes) -> None:
        rrset = answer.rrset
        updated_rdatas = []
        changed = False
        for rdata in rrset:
            if getattr(rdata, "priority", 0) == 0 or HTTPS_PARAM_KEY.ECH in rdata.params:
                updated_rdatas.append(rdata)
                continue
            params = dict(rdata.params)
            params[HTTPS_PARAM_KEY.ECH] = dns.rdtypes.svcbbase.ECHParam(ech_bytes)
            updated_rdatas.append(rdata.replace(params=params))
            changed = True
        if changed:
            answer.rrset = dns.rrset.from_rdata_list(rrset.name, rrset.ttl, updated_rdatas)


plugin = CloudflareEchPlugin()
