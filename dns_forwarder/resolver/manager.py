from __future__ import annotations

from typing import TYPE_CHECKING

from dns_forwarder.logging import get_logger

from .base import BaseUpstreamResolver
from .nameservers import build_nameserver_map
from .upstream import UpstreamResolver

if TYPE_CHECKING:
    import dns.nameserver

    from dns_forwarder.config import AppConfig, UpstreamConfig, UpstreamGroupConfig
    from dns_forwarder.pipeline.context import RequestContext, UpstreamResult
    from dns_forwarder.plugin_api import PluginRegistry

logger = get_logger("resolver.manager")


class ResolverManager:
    def __init__(
        self,
        config: AppConfig,
        plugin_registry: PluginRegistry,
    ) -> None:
        self._groups = {group.name: group for group in config.groups}
        self._plugin_registry = plugin_registry
        self._nameservers = build_nameserver_map(
            config.nameservers,
            config.runtime.bootstrap_resolver,
            config.runtime.fingerprint,
            config.runtime.hosts,
        )
        self._resolvers = {
            upstream.name: self._build_resolver(upstream) for upstream in config.upstreams
        }

    def get_group(self, group_name: str) -> UpstreamGroupConfig:
        return self._groups[group_name]

    def has_group(self, group_name: str) -> bool:
        return group_name in self._groups

    async def resolve(self, upstream_name: str, context: RequestContext) -> UpstreamResult:
        custom_resolver = self._plugin_registry.resolver_registry.get(upstream_name)
        if custom_resolver is not None:
            logger.debug(
                "使用插件 resolver request_id=%s upstream=%s", context.request_id, upstream_name
            )
            return await custom_resolver.resolve(context)
        return await self._resolvers[upstream_name].resolve(context)

    def _build_resolver(self, upstream: UpstreamConfig) -> BaseUpstreamResolver:
        nameservers = [self._nameservers[name] for name in upstream.nameservers]
        logger.debug(
            "装配上游 resolver upstream=%s nameservers=%s rotate=%s",
            upstream.name,
            ",".join(str(nameserver) for nameserver in nameservers),
            len(nameservers) > 1,
        )
        return UpstreamResolver(upstream, nameservers)

    @property
    def nameservers(self) -> dict[str, dns.nameserver.Nameserver]:
        return dict(self._nameservers)


__all__ = [
    "BaseUpstreamResolver",
    "ResolverManager",
    "UpstreamResolver",
]
