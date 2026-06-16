from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING
import anyio

import dns.resolver

from dns_forwarder.config import DispatchStrategyType, UpstreamGroupConfig
from dns_forwarder.logging import format_tags, get_logger
from dns_forwarder.pipeline.context import RequestContext, UpstreamResult

from .base import DispatchStrategy

if TYPE_CHECKING:
    from dns_forwarder.resolver import ResolverManager

    from .registry import DispatcherRegistry


logger = get_logger("dispatcher.race")


class RaceDispatchStrategy(DispatchStrategy):
    strategy_type = DispatchStrategyType.RACE

    async def dispatch(
        self,
        context: RequestContext,
        group: UpstreamGroupConfig,
        resolver_manager: ResolverManager,
        registry: DispatcherRegistry,
        on_result: Callable[[UpstreamResult], None] | None = None,
    ) -> UpstreamResult:
        send_stream, receive_stream = anyio.create_memory_object_stream(len(group.upstreams))
        failures: list[UpstreamResult] = []
        winner: UpstreamResult | None = None

        async def worker(target_name: str, s_stream: anyio.streams.memory.MemoryObjectSendStream[UpstreamResult]) -> None:
            async with s_stream:
                try:
                    res = await registry.dispatch_target(
                        context,
                        target_name,
                        self.strategy_type,
                        resolver_manager,
                        on_result=on_result,
                    )
                    await s_stream.send(res)
                except Exception:
                    pass

        async def coordinator(tg: anyio.abc.TaskGroup) -> None:
            nonlocal winner
            async with receive_stream:
                async for res in receive_stream:
                    if res.answer is not None:
                        winner = res
                        logger.debug(
                            "并发调度命中 request_id=%s group=%s upstream=%s duration_ms=%.2f tags=%s",
                            context.request_id,
                            group.name,
                            res.upstream_name,
                            res.duration_ms,
                            format_tags(res.tags),
                        )
                        tg.cancel_scope.cancel()
                        break
                    else:
                        logger.debug(
                            "并发调度忽略失败结果 request_id=%s group=%s upstream=%s error=%s tags=%s",
                            context.request_id,
                            group.name,
                            res.upstream_name,
                            self.error_name(res),
                            format_tags(res.tags),
                        )
                        failures.append(res)

        async with anyio.create_task_group() as tg:
            tg.start_soon(coordinator, tg)
            for target_name in group.upstreams:
                tg.start_soon(worker, target_name, send_stream.clone())
            await send_stream.aclose()

        if winner is not None:
            return winner

        fallback = self.pick_failure_result(failures, "所有上游均失败")
        if isinstance(fallback.error, dns.resolver.NXDOMAIN):
            logger.debug(
                "并发调度未命中成功结果，返回 NXDOMAIN request_id=%s group=%s",
                context.request_id,
                group.name,
            )
            return fallback
        logger.warning(
            "并发调度所有上游均失败 request_id=%s group=%s", context.request_id, group.name
        )
        return fallback
