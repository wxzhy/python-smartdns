from __future__ import annotations

from collections.abc import Mapping

from dns_forwarder.config import AppConfig, UpstreamConfig, UpstreamGroupConfig, UpstreamProtocol
from dns_forwarder.logging import get_logger
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult
from dns_forwarder.plugin_api import PluginRegistry

from .base import BaseUpstreamResolver
from .do53 import UpstreamResolver


logger = get_logger("resolver.manager")


DEFAULT_RESOLVER_TYPES: dict[UpstreamProtocol, type[BaseUpstreamResolver]] = {
    UpstreamResolver.protocol: UpstreamResolver,
}


class ResolverManager:
    def __init__(
        self,
        config: AppConfig,
        plugin_registry: PluginRegistry,
        resolver_types: Mapping[UpstreamProtocol, type[BaseUpstreamResolver]] | None = None,
    ) -> None:
        self._groups = {group.name: group for group in config.groups}
        self._plugin_registry = plugin_registry
        self._resolver_types = (
            dict(DEFAULT_RESOLVER_TYPES) if resolver_types is None else dict(resolver_types)
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
            logger.debug("使用插件 resolver request_id=%s upstream=%s", context.request_id, upstream_name)
            return await custom_resolver.resolve(context)
        return await self._resolvers[upstream_name].resolve(context)

    def _build_resolver(self, upstream: UpstreamConfig) -> BaseUpstreamResolver:
        resolver_type = self._resolver_types.get(upstream.protocol)
        if resolver_type is None:
            raise ValueError(f"不支持的 upstream protocol: {upstream.protocol}")
        logger.debug(
            "装配上游 resolver upstream=%s protocol=%s implementation=%s",
            upstream.name,
            upstream.protocol.value,
            resolver_type.__name__,
        )
        return resolver_type(upstream)


__all__ = [
    "BaseUpstreamResolver",
    "ResolverManager",
    "UpstreamResolver",
]
