from __future__ import annotations

import time

import dns.asyncresolver
import dns.edns
import dns.nameserver
import dns.resolver

from dns_forwarder.config import AppConfig, UpstreamConfig
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult
from dns_forwarder.plugin_api import PluginRegistry


class UpstreamResolver:
    def __init__(self, config: UpstreamConfig) -> None:
        self.config = config
        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.timeout = config.timeout
        self.resolver.lifetime = config.lifetime
        self.resolver.use_search_by_default = False
        self.resolver.search = []
        self.resolver.nameservers = [dns.nameserver.Do53Nameserver(config.host, config.port)]
        if config.edns and config.edns.enabled:
            options: list[dns.edns.Option] = []
            if config.edns.client_subnet is not None:
                options.append(
                    dns.edns.ECSOption(
                        str(config.edns.client_subnet.address),
                        srclen=config.edns.client_subnet.source_prefix,
                        scopelen=config.edns.client_subnet.scope_prefix,
                    )
                )
            self.resolver.use_edns(edns=0, payload=config.edns.payload, options=options or None)

    async def resolve(self, context: RequestContext) -> UpstreamResult:
        question = context.request.question[0]
        started = time.perf_counter()

        try:
            answer = await self.resolver.resolve(
                question.name,
                rdtype=question.rdtype,
                rdclass=question.rdclass,
                tcp=self.config.use_tcp,
                raise_on_no_answer=False,
            )
            return UpstreamResult(
                upstream_name=self.config.name,
                duration_ms=(time.perf_counter() - started) * 1000,
                answer=answer,
            )
        except dns.resolver.NXDOMAIN as exc:
            return UpstreamResult(
                upstream_name=self.config.name,
                duration_ms=(time.perf_counter() - started) * 1000,
                error=exc,
            )
        except Exception as exc:
            return UpstreamResult(
                upstream_name=self.config.name,
                duration_ms=(time.perf_counter() - started) * 1000,
                error=exc,
            )


class ResolverManager:
    def __init__(self, config: AppConfig, plugin_registry: PluginRegistry) -> None:
        self._groups = {group.name: group for group in config.groups}
        self._resolvers = {upstream.name: UpstreamResolver(upstream) for upstream in config.upstreams}
        self._plugin_registry = plugin_registry

    def get_group(self, group_name: str) -> UpstreamGroupConfig:
        return self._groups[group_name]

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        custom_resolver = self._plugin_registry.resolver_registry.get(upstream_name)
        if custom_resolver is not None:
            return await custom_resolver.resolve(context)
        return await self._resolvers[upstream_name].resolve(context)
