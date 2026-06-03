from __future__ import annotations

import asyncio
import ipaddress
import time

import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset
from pydantic import BaseModel, Field, field_validator, model_validator

from dns_forwarder.logging import format_tags, get_logger
from dns_forwarder.pipeline import RequestContext, UpstreamResult, sync_answer_rrset_to_response
from dns_forwarder.plugin_api import EmptyModel, Plugin, PluginRegistry

from .models import (
    SPEEDTEST_CONTEXT_KEY,
    SPEEDTEST_SERVICE_KEY,
    SpeedTestContext,
)
from .service import SpeedTestService

logger = get_logger("plugins.speedtest")


ADDRESS_TYPES = {dns.rdatatype.A, dns.rdatatype.AAAA}


class SpeedTestFallbackRuleConfig(BaseModel):
    match_tags: list[str] = Field(default_factory=list, min_length=1)
    exclude_tags: list[str] = Field(default_factory=list)
    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)

    @field_validator("match_tags", "exclude_tags", mode="before")
    @classmethod
    def normalize_tags(cls, value: list[str] | None) -> list[str]:
        return _normalize_tags(value)

    @field_validator("ipv4_addresses", mode="before")
    @classmethod
    def normalize_ipv4_addresses(cls, value: list[str] | None) -> list[str]:
        return _normalize_addresses(value, version=4)

    @field_validator("ipv6_addresses", mode="before")
    @classmethod
    def normalize_ipv6_addresses(cls, value: list[str] | None) -> list[str]:
        return _normalize_addresses(value, version=6)

    @model_validator(mode="after")
    def validate_addresses(self) -> "SpeedTestFallbackRuleConfig":
        if not self.ipv4_addresses and not self.ipv6_addresses:
            raise ValueError("fallback 规则至少需要一个 IPv4 或 IPv6 地址")
        return self


class SpeedTestPluginConfig(BaseModel):
    cache_ttl_seconds: int = Field(default=900, ge=1)
    cache_maxsize: int = Field(default=4096, ge=1)
    max_concurrency: int = Field(default=64, ge=1)
    probe_timeout: float = Field(default=1.5, gt=0)
    ping_count: int = Field(default=1, ge=1, le=10)
    ping_privileged: bool = False
    response_ip_limit: int = Field(default=2, ge=1)
    response_ttl_seconds: int = Field(default=60, ge=1)
    rtt_tolerance_ms: float = Field(default=50.0, ge=0.0)
    rtt_gap_threshold_ms: float = Field(default=20.0, ge=0.0)
    skip_tags: list[str] = Field(default_factory=list)
    fallback_rules: list[SpeedTestFallbackRuleConfig] = Field(default_factory=list)

    @field_validator("skip_tags", mode="before")
    @classmethod
    def normalize_global_tags(cls, value: list[str] | None) -> list[str]:
        return _normalize_tags(value)


def get_speedtest_context(context: RequestContext) -> SpeedTestContext:
    speedtest_context = context.extensions[SPEEDTEST_CONTEXT_KEY]
    if not isinstance(speedtest_context, SpeedTestContext):
        raise TypeError("speedtest.context 类型不正确")
    return speedtest_context


class SpeedTestPlugin(Plugin):
    name = "speedtest-plugin"
    config_model = SpeedTestPluginConfig
    variables_model = EmptyModel
    upstream_response_order = 200
    response_order = 600
    ui_meta = {
        "title": "SpeedTest Plugin",
        "description": "在 upstream_response 阶段对响应 IP 执行 ICMP/TCP(80/443) 并发测速，并写入 speedtest.context。",
    }

    def __init__(self) -> None:
        super().__init__()
        self._service: SpeedTestService | None = None

    async def setup(self, registry: PluginRegistry) -> None:
        self._service = SpeedTestService(
            cache_ttl_seconds=self.runtime_config.cache_ttl_seconds,
            cache_maxsize=self.runtime_config.cache_maxsize,
            max_concurrency=self.runtime_config.max_concurrency,
            probe_timeout=self.runtime_config.probe_timeout,
            ping_count=self.runtime_config.ping_count,
            ping_privileged=self.runtime_config.ping_privileged,
        )
        registry.register_context(SPEEDTEST_SERVICE_KEY, self._service)
        registry.register_context_factory(SPEEDTEST_CONTEXT_KEY, SpeedTestContext)
        logger.debug(
            "测速插件初始化完成 response_ip_limit=%s response_ttl=%s skip_tags=%s fallback_rule_count=%s",
            self.runtime_config.response_ip_limit,
            self.runtime_config.response_ttl_seconds,
            self.runtime_config.skip_tags,
            len(self.runtime_config.fallback_rules),
        )

    async def on_upstream_response(self, context: RequestContext, result: UpstreamResult) -> None:
        if context.request.question[0].rdtype not in ADDRESS_TYPES:
            return
        if self._service is None or result.answer is None:
            return
        if self._has_any_tag(context.tags, self.runtime_config.skip_tags):
            logger.debug(
                "测速跳过 request_id=%s stage=upstream_response reason=skip_tags request_tags=%s",
                context.request_id,
                format_tags(context.tags),
            )
            return

        response_ips = self._extract_unique_ips(result.answer)
        logger.debug(
            "测速收到响应 request_id=%s resolver=%s response_ips=%s",
            context.request_id,
            result.upstream_name,
            response_ips,
        )
        speedtest_context = get_speedtest_context(context)
        await self._measure_new_ips(
            context.request_id,
            speedtest_context,
            response_ips,
            phase="upstream_response",
        )

    @staticmethod
    def _extract_unique_ips(answer: dns.resolver.Answer) -> list[str]:
        if answer.rdtype not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            return []
        if answer.rrset is None:
            return []

        ips: list[str] = []
        seen: set[str] = set()
        for record in answer.rrset:
            address = getattr(record, "address", None)
            if address is None or address in seen:
                continue
            seen.add(address)
            ips.append(address)
        return ips

    async def on_response(self, context: RequestContext) -> None:
        if context.request.question[0].rdtype not in ADDRESS_TYPES:
            return
        if self._has_any_tag(context.tags, self.runtime_config.skip_tags):
            logger.debug(
                "测速跳过 request_id=%s stage=response reason=skip_tags request_tags=%s",
                context.request_id,
                format_tags(context.tags),
            )
            return

        answer = context.final_answer
        if (
            answer is not None
            and answer.rdtype in {dns.rdatatype.A, dns.rdatatype.AAAA}
            and answer.response.rcode() == dns.rcode.NOERROR
        ):
            speedtest_context = get_speedtest_context(context)
            current_ips = self._extract_unique_ips(answer)
            candidate_ips = self._collect_candidate_ips(context, answer)
            if candidate_ips:
                await self._measure_new_ips(
                    context.request_id,
                    speedtest_context,
                    candidate_ips,
                    phase="response",
                )

            measured_results = {
                item.ip: item
                for item in speedtest_context.ip_rtt_results
                if item.best_ms is not None and item.ip in candidate_ips
            }
            if measured_results:
                original_order = {ip: index for index, ip in enumerate(candidate_ips)}
                sorted_items = sorted(
                    measured_results.values(),
                    key=lambda item: (
                        item.best_ms if item.best_ms is not None else float("inf"),
                        original_order[item.ip],
                    ),
                )
                
                # Apply RTT tolerance to filter out slower IPs
                filtered_items = []
                best_ms = None
                for item in sorted_items:
                    if item.best_ms is None:
                        continue
                    if best_ms is None:
                        best_ms = item.best_ms
                    
                    if item.best_ms - best_ms <= self.runtime_config.rtt_tolerance_ms:
                        filtered_items.append(item)
                    else:
                        break
                
                # Fallback to sorted_items if all valid items are filtered out (shouldn't happen)
                if not filtered_items:
                    filtered_items = sorted_items
                
                truncated_items = []
                for i, item in enumerate(filtered_items):
                    if i > 0:
                        prev_item = filtered_items[i - 1]
                        if (
                            item.best_ms is not None
                            and prev_item.best_ms is not None
                            and item.best_ms - prev_item.best_ms > self.runtime_config.rtt_gap_threshold_ms
                        ):
                            logger.debug(
                                "测速相邻 IP RTT 差距过大，进行截断 rtt_gap=%.2fms threshold=%.2fms",
                                item.best_ms - prev_item.best_ms,
                                self.runtime_config.rtt_gap_threshold_ms,
                            )
                            break
                    truncated_items.append(item)

                sorted_ips = [item.ip for item in truncated_items]
                sorted_ips = sorted_ips[: self.runtime_config.response_ip_limit]
                if sorted_ips != current_ips:
                    self._replace_answer_ips(answer, sorted_ips)
                    logger.debug(
                        "测速结果已应用 request_id=%s qtype=%s current_ips=%s candidate_ips=%s selected_ips=%s",
                        context.request_id,
                        dns.rdatatype.to_text(answer.rdtype),
                        current_ips,
                        candidate_ips,
                        sorted_ips,
                    )
            else:
                fallback_ips = self._select_fallback_ips(context.tags, answer.rdtype)
                if fallback_ips:
                    self._replace_answer_ips(answer, fallback_ips)
                    logger.debug(
                        "测速 fallback 已应用 request_id=%s qtype=%s request_tags=%s fallback_ips=%s",
                        context.request_id,
                        dns.rdatatype.to_text(answer.rdtype),
                        format_tags(context.tags),
                        fallback_ips,
                    )
                else:
                    logger.debug(
                        "测速未得到有效结果且无可用 fallback request_id=%s qtype=%s request_tags=%s",
                        context.request_id,
                        dns.rdatatype.to_text(answer.rdtype),
                        format_tags(context.tags),
                    )

    async def _measure_new_ips(
        self,
        request_id: int,
        speedtest_context: SpeedTestContext,
        ips: list[str],
        *,
        phase: str,
    ) -> None:
        if self._service is None or not ips:
            return

        candidate_ips = await speedtest_context.reserve_ips(ips)
        if not candidate_ips:
            logger.debug(
                "测速跳过，所有 IP 已有结果 request_id=%s phase=%s ip_count=%s",
                request_id,
                phase,
                len(ips),
            )
            return
        logger.debug(
            "开始测速 request_id=%s phase=%s candidate_ips=%s",
            request_id,
            phase,
            candidate_ips,
        )

        measurements = await asyncio.gather(
            *(self._service.measure(ip) for ip in candidate_ips),
            return_exceptions=True,
        )
        successful_results = []
        for item in measurements:
            if isinstance(item, Exception):
                continue
            successful_results.append(item)
        await speedtest_context.add_results(successful_results)
        logger.debug(
            "测速完成 request_id=%s phase=%s measured_count=%s success_count=%s",
            request_id,
            phase,
            len(candidate_ips),
            len(successful_results),
        )

    def _replace_answer_ips(self, answer: dns.resolver.Answer, ips: list[str]) -> None:
        ttl = self.runtime_config.response_ttl_seconds
        rrset_name = answer.canonical_name
        if answer.rrset is not None:
            ttl = max(answer.rrset.ttl, ttl)
            rrset_name = answer.rrset.name
        answer.rrset = dns.rrset.from_text_list(
            rrset_name,
            ttl,
            answer.rdclass,
            answer.rdtype,
            ips,
        )
        sync_answer_rrset_to_response(answer)
        answer.expiration = time.time() + ttl

    def _select_fallback_ips(self, tags: set[str], rdtype: dns.rdatatype.RdataType) -> list[str]:
        for rule in self.runtime_config.fallback_rules:
            if self._has_any_tag(tags, rule.exclude_tags):
                continue
            if not self._has_any_tag(tags, rule.match_tags):
                continue
            ips = rule.ipv4_addresses if rdtype == dns.rdatatype.A else rule.ipv6_addresses
            if ips:
                return ips
        return []

    def _collect_candidate_ips(
        self,
        context: RequestContext,
        answer: dns.resolver.Answer,
    ) -> list[str]:
        candidates: list[str] = []
        seen: set[str] = set()

        def add_answer_ips(item: dns.resolver.Answer | None) -> None:
            for ip in self._extract_unique_ips(item) if item is not None else []:
                if ip in seen:
                    continue
                seen.add(ip)
                candidates.append(ip)

        add_answer_ips(answer)
        if not context.upstream_results:
            return candidates

        final_result = context.upstream_results[-1]
        collected_results = sorted(
            final_result.collected_results,
            key=lambda item: (item.duration_ms, item.upstream_name),
        )
        for result in collected_results:
            add_answer_ips(result.answer)
        return candidates

    @staticmethod
    def _has_any_tag(current_tags: set[str], configured_tags: list[str]) -> bool:
        return bool(current_tags.intersection(configured_tags))


def _normalize_tags(value: list[str] | None) -> list[str]:
    if value is None:
        return []
    seen: set[str] = set()
    normalized: list[str] = []
    for item in value:
        tag = str(item).strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        normalized.append(tag)
    return normalized


def _normalize_addresses(value: list[str] | None, *, version: int) -> list[str]:
    if value is None:
        return []
    seen: set[str] = set()
    normalized: list[str] = []
    for item in value:
        address = ipaddress.ip_address(str(item).strip())
        if address.version != version:
            family = "IPv4" if version == 4 else "IPv6"
            raise ValueError(f"fallback 地址必须是 {family}")
        text = address.compressed
        if text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return normalized


plugin = SpeedTestPlugin()
