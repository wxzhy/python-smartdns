from __future__ import annotations

import dns.rdatatype
import dns.rdtypes.svcbbase
import dns.rrset

from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline import RequestContext, build_answer_from_response
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

logger = get_logger("plugins.https")


HTTPS_PARAM_KEY = dns.rdtypes.svcbbase.ParamKey
H3_ALPN_ID = b"h3"


class HttpsPlugin(Plugin):
    name = "https-plugin"
    config_model = EmptyModel
    variables_model = EmptyModel
    response_order = 800
    ui_meta = {  # noqa: RUF012  # read-only frozen-style plugin metadata
        "title": "HTTPS Plugin",
        "description": "清洗 HTTPS 记录中的 h3 ALPN 与 IPv4/IPv6 hints，保留其余参数不变。",
    }

    async def setup(self, registry: PluginRegistry) -> None:
        return None

    async def on_response(self, context: RequestContext) -> None:
        if context.request.question[0].rdtype != dns.rdatatype.HTTPS:
            return
        answer = context.final_answer
        if answer is None:
            response = context.final_response
            if response is None:
                return
            if response.rcode() != 0:
                return
            answer = build_answer_from_response(context.request, response)
            context.final_answer = answer

        changed_records, removed_h3_ids, removed_hint_params = self._sanitize_https_answer(answer)
        if changed_records:
            question = context.request.question[0]
            logger.debug(
                "HTTPS 记录已清洗 request_id=%s qname=%s changed_records=%s "
                "removed_h3_ids=%s removed_hint_params=%s",
                context.request_id,
                question.name.to_text().rstrip("."),
                changed_records,
                removed_h3_ids,
                removed_hint_params,
            )

    def _sanitize_https_answer(self, answer) -> tuple[int, int, int]:
        rrset = answer.rrset
        if (
            rrset is None
            or answer.rdtype != dns.rdatatype.HTTPS
            or rrset.rdtype != dns.rdatatype.HTTPS
        ):
            return 0, 0, 0

        changed = False
        changed_records = 0
        removed_h3_ids = 0
        removed_hint_params = 0
        sanitized_rdatas = []
        for rdata in rrset:
            sanitized_rdata, removed_h3_count, removed_hint_count = self._sanitize_https_rdata(
                rdata
            )
            changed = changed or sanitized_rdata is not rdata
            if sanitized_rdata is not rdata:
                changed_records += 1
            removed_h3_ids += removed_h3_count
            removed_hint_params += removed_hint_count
            sanitized_rdatas.append(sanitized_rdata)

        if not changed:
            return 0, 0, 0

        answer.rrset = dns.rrset.from_rdata_list(rrset.name, rrset.ttl, sanitized_rdatas)
        return changed_records, removed_h3_ids, removed_hint_params

    def _sanitize_https_rdata(self, rdata):
        params = dict(rdata.params)
        changed = False
        removed_keys: set[dns.rdtypes.svcbbase.ParamKey] = set()
        removed_h3_ids = 0
        removed_hint_params = 0

        alpn = params.get(HTTPS_PARAM_KEY.ALPN)
        if alpn is not None:
            filtered_ids = tuple(item for item in alpn.ids if item != H3_ALPN_ID)
            if filtered_ids != alpn.ids:
                changed = True
                removed_h3_ids = len(alpn.ids) - len(filtered_ids)
                if filtered_ids:
                    params[HTTPS_PARAM_KEY.ALPN] = dns.rdtypes.svcbbase.ALPNParam(filtered_ids)
                else:
                    params.pop(HTTPS_PARAM_KEY.ALPN, None)
                    removed_keys.add(HTTPS_PARAM_KEY.ALPN)
                    if HTTPS_PARAM_KEY.NO_DEFAULT_ALPN in params:
                        params.pop(HTTPS_PARAM_KEY.NO_DEFAULT_ALPN, None)
                        removed_keys.add(HTTPS_PARAM_KEY.NO_DEFAULT_ALPN)

        for hint_key in (HTTPS_PARAM_KEY.IPV4HINT, HTTPS_PARAM_KEY.IPV6HINT):
            if hint_key in params:
                params.pop(hint_key, None)
                removed_keys.add(hint_key)
                changed = True
                removed_hint_params += 1

        mandatory = params.get(HTTPS_PARAM_KEY.MANDATORY)
        if mandatory is not None and removed_keys:
            remaining_keys = tuple(key for key in mandatory.keys if key not in removed_keys)
            if remaining_keys != mandatory.keys:
                changed = True
                if remaining_keys:
                    params[HTTPS_PARAM_KEY.MANDATORY] = dns.rdtypes.svcbbase.MandatoryParam(
                        remaining_keys
                    )
                else:
                    params.pop(HTTPS_PARAM_KEY.MANDATORY, None)

        if not changed:
            return rdata, 0, 0
        return rdata.replace(params=params), removed_h3_ids, removed_hint_params


plugin = HttpsPlugin()
