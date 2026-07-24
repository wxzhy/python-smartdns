"""日志门面。

底层统一使用 loguru 渲染输出（彩色、带时间与模块名上下文），对外保持
``configure_logging`` / ``get_logger`` / ``format_tags`` 的简洁 API。

为兼容项目既有的标准 ``logging`` ``%`` 风格格式化（``logger.info("x=%s", v)``），
:func:`get_logger` 返回 :class:`Logger`，它在分发前完成 ``%`` 格式化再交给 loguru，
从而调用点无需改动即可获得 loguru 的彩色输出与结构化能力。

为兼容 pytest ``caplog``，提供 :func:`attach_caplog` 将 loguru 记录转发回标准
``logging`` handler，由 pytest 捕获后即可用 ``caplog.text`` 断言日志文本。
"""

from __future__ import annotations

import contextlib
import logging
import sys
from typing import TYPE_CHECKING, Any

from loguru import logger as _root_logger

if TYPE_CHECKING:
    from collections.abc import Collection

LOGGER_NAME = "dns_forwarder"
_VALID_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"}

# 统一的 stderr sink 输出格式：时间 | 级别 | 模块名 | 消息。
_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{extra[name]}</cyan> - <level>{message}</level>"
)


class Logger:
    """兼容 ``%`` 风格格式化的 loguru 代理记录器。

    方法签名与标准 ``logging.Logger`` 一致（``debug``/``info``/``warning``/
    ``error``/``exception``/``critical``），调用 ``logger.info("x=%s", v)`` 时
    会先做 ``"x=%s" % args`` 格式化，再把已格式化的消息交给绑定的 loguru logger，
    由 loguru 负责彩色输出与上下文渲染。
    """

    __slots__ = ("_bound", "_name")

    def __init__(self, bound: Any, name: str) -> None:
        self._bound = bound
        self._name = name

    def _emit(self, level: str, msg: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        """完成 ``%`` 格式化并交给 loguru。"""
        message = msg % args if args else msg
        # exc_info=True 时附带异常；exception() 也走这里。
        exc_info = kwargs.pop("exc_info", False)
        bound = self._bound
        if exc_info:
            bound = bound.opt(exception=True)
        getattr(bound, level)(message, **kwargs)

    def trace(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._emit("trace", msg, args, kwargs)

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._emit("debug", msg, args, kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._emit("info", msg, args, kwargs)

    def success(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._emit("success", msg, args, kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._emit("warning", msg, args, kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._emit("error", msg, args, kwargs)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._emit("critical", msg, args, kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """记录异常，自动附带当前异常 traceback。"""
        message = msg % args if args else msg
        self._bound.opt(exception=True).error(message, **kwargs)


def _normalize_level(level: str) -> str:
    """校验并归一化日志级别字符串。"""
    normalized = level.upper()
    if normalized not in _VALID_LEVELS:
        raise ValueError(f"未知 log_level: {level}")
    return normalized


_STDERR_SINK_ID: list[int | None] = [None]


def _apply_stderr_sink(level: str) -> None:
    """仅替换 stderr sink 的级别，保留其它 sink（如 caplog 转发）。"""
    if _STDERR_SINK_ID[0] is not None:
        # 该 sink 可能已被外部移除，忽略 ValueError 即可。
        with contextlib.suppress(ValueError):
            _root_logger.remove(_STDERR_SINK_ID[0])
    _STDERR_SINK_ID[0] = _root_logger.add(
        sys.stderr,
        level=level,
        colorize=True,
        format=_FORMAT,
        backtrace=True,
        diagnose=False,
    )


def configure_logging(level: str) -> Logger:
    """配置全局日志级别并返回根 :class:`Logger`。

    每次调用都按给定级别重建 stderr sink，保证级别始终最新。
    """
    _apply_stderr_sink(_normalize_level(level))
    return get_logger()


def get_logger(name: str | None = None) -> Logger:
    """返回带模块名上下文的 :class:`Logger`。

    日志输出会带上 ``name``，便于定位来源模块。
    """
    display = name or LOGGER_NAME
    return Logger(_root_logger.bind(name=display), display)


def attach_caplog(handler: logging.Handler, level: str) -> int:
    """将 loguru 日志转发到标准 ``logging`` handler（供 pytest ``caplog`` 使用）。

    返回 sink id，调用方可通过 :func:`detach_caplog` 移除。
    """
    normalized = _normalize_level(level)

    def _sink(message: Any) -> None:
        # loguru 传给 callable sink 的是已格式化的 Message，原始记录在 .record。
        record = message.record
        py_record = logging.LogRecord(
            name=record["extra"].get("name", LOGGER_NAME),
            level=logging.getLevelName(record["level"].name),
            pathname=record["file"].path,
            lineno=record["line"],
            msg=record["message"],
            args=(),
            exc_info=record["exception"],
            func=record["function"],
        )
        handler.handle(py_record)

    return _root_logger.add(_sink, level=normalized)


def detach_caplog(sink_id: int) -> None:
    """移除 :func:`attach_caplog` 注册的 sink（若已被移除则忽略）。"""
    with contextlib.suppress(ValueError):
        _root_logger.remove(sink_id)


def format_tags(tags: Collection[str] | None) -> str:
    """将 tag 集合格式化为稳定排序的 ``[a,b]`` 字符串，缺失时返回 ``[]``。"""
    if not tags:
        return "[]"
    return "[" + ",".join(sorted(tags)) + "]"
