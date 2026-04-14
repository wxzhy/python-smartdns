from .models import (
    AppConfig,
    BaseNameserverConfig,
    DispatchStrategyType,
    Do53CustomNameserverConfig,
    Do53NameserverConfig,
    DoHCustomNameserverConfig,
    DoHNameserverConfig,
    DoQNameserverConfig,
    DoTNameserverConfig,
    ECSConfig,
    HTTPVersionType,
    ListenerConfig,
    ListenerProtocol,
    NameserverConfig,
    NameserverProtocol,
    PluginConfig,
    RuleActionConfig,
    RuleConfig,
    RuleMatchConfig,
    RuntimeConfig,
    TreeRootConfig,
    UpstreamConfig,
    UpstreamGroupConfig,
    WebUIConfig,
)


def load_config(*args, **kwargs):
    from .loader import load_config as _load_config

    return _load_config(*args, **kwargs)


def parse_config_text(*args, **kwargs):
    from .loader import parse_config_text as _parse_config_text

    return _parse_config_text(*args, **kwargs)


def dump_config_text(*args, **kwargs):
    from .loader import dump_config_text as _dump_config_text

    return _dump_config_text(*args, **kwargs)


def save_config(*args, **kwargs):
    from .loader import save_config as _save_config

    return _save_config(*args, **kwargs)


def build_config_json_schema(*args, **kwargs):
    from .loader import build_config_json_schema as _build_config_json_schema

    return _build_config_json_schema(*args, **kwargs)


__all__ = [
    "AppConfig",
    "BaseNameserverConfig",
    "DispatchStrategyType",
    "Do53NameserverConfig",
    "Do53CustomNameserverConfig",
    "DoHNameserverConfig",
    "DoHCustomNameserverConfig",
    "DoQNameserverConfig",
    "DoTNameserverConfig",
    "ECSConfig",
    "HTTPVersionType",
    "ListenerConfig",
    "ListenerProtocol",
    "NameserverConfig",
    "NameserverProtocol",
    "PluginConfig",
    "RuleActionConfig",
    "RuleConfig",
    "RuleMatchConfig",
    "RuntimeConfig",
    "TreeRootConfig",
    "UpstreamConfig",
    "UpstreamGroupConfig",
    "WebUIConfig",
    "build_config_json_schema",
    "dump_config_text",
    "load_config",
    "parse_config_text",
    "save_config",
]
