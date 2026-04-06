from __future__ import annotations

import time

import dns.asyncresolver
import dns.edns
import dns.nameserver
import dns.rdatatype
import dns.resolver

from dns_forwarder.config import UpstreamConfig, UpstreamProtocol
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult

from .base import BaseUpstreamResolver


logger = get_logger("resolver.do53")


class UpstreamResolver(BaseUpstreamResolver):
    protocol = UpstreamProtocol.DO53

    def __init__(self, config: UpstreamConfig) -> None:
        super().__init__(config)
        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.timeout = config.timeout
        self.resolver.lifetime = config.lifetime
        self.resolver.use_search_by_default = False
        self.resolver.search = []
        self.resolver.nameservers = [dns.nameserver.Do53Nameserver(config.host, config.port)]
        if config.ecs is not None:
            self.resolver.use_edns(
                options=[
                    dns.edns.ECSOption(
                        str(config.ecs.subnet.address),
                        srclen=config.ecs.subnet.source_prefix,
                        scopelen=config.ecs.subnet.scope_prefix,
                    )
                ]
            )
            logger.debug(
                "上游启用 ECS request_target=%s ecs=%s",
                config.name,
                config.ecs.subnet.address,
            )

    async def resolve(self, context: RequestContext) -> UpstreamResult:
        question = context.request.question[0]
        started = time.perf_counter()
        logger.debug(
            "发起上游查询 request_id=%s upstream=%s qname=%s qtype=%s tcp=%s",
            context.request_id,
            self.config.name,
            question.name.to_text().rstrip("."),
            dns.rdatatype.to_text(question.rdtype),
            self.config.use_tcp,
        )

        try:
            answer = await self.resolver.resolve(
                question.name,
                rdtype=question.rdtype,
                rdclass=question.rdclass,
                tcp=self.config.use_tcp,
                raise_on_no_answer=False,
            )
            duration_ms = (time.perf_counter() - started) * 1000
            logger.debug(
                "上游查询成功 request_id=%s upstream=%s duration_ms=%.2f rrset_size=%s",
                context.request_id,
                self.config.name,
                duration_ms,
                len(answer),
            )
            return UpstreamResult(
                upstream_name=self.config.name,
                duration_ms=duration_ms,
                answer=answer,
            )
        except dns.resolver.NXDOMAIN as exc:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.info(
                "上游返回 NXDOMAIN request_id=%s upstream=%s duration_ms=%.2f",
                context.request_id,
                self.config.name,
                duration_ms,
            )
            return UpstreamResult(
                upstream_name=self.config.name,
                duration_ms=duration_ms,
                error=exc,
            )
        except Exception as exc:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.warning(
                "上游查询失败 request_id=%s upstream=%s duration_ms=%.2f error=%s",
                context.request_id,
                self.config.name,
                duration_ms,
                type(exc).__name__,
            )
            return UpstreamResult(
                upstream_name=self.config.name,
                duration_ms=duration_ms,
                error=exc,
            )
