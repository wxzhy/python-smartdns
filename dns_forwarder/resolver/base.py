from __future__ import annotations

from abc import ABC, abstractmethod

from dns_forwarder.config import UpstreamConfig
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult


class BaseUpstreamResolver(ABC):
    def __init__(self, config: UpstreamConfig) -> None:
        self.config = config

    @abstractmethod
    async def resolve(self, context: RequestContext) -> UpstreamResult:
        raise NotImplementedError
