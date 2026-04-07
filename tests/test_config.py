from __future__ import annotations

import json
from pathlib import Path

import pytest

from dns_forwarder.config import (
    AppConfig,
    DispatchStrategyType,
    build_config_json_schema,
    dump_config_text,
    parse_config_text,
)
from dns_forwarder.plugin_api import discover_available_plugins


def build_config_dict() -> dict[str, object]:
    return {
        "runtime": {
            "plugin_dirs": ["plugins"],
            "default_upstream_group": "default",
        },
        "listeners": [
            {
                "name": "udp",
                "protocol": "udp",
                "host": "127.0.0.1",
                "port": 5300,
            }
        ],
        "nameservers": [
            {
                "name": "local-ns",
                "protocol": "do53",
                "address": "127.0.0.1",
                "port": 5301,
            }
        ],
        "upstreams": [
            {
                "name": "local",
                "nameservers": ["local-ns"],
            }
        ],
        "groups": [
            {
                "name": "default",
                "strategy": "race",
                "upstreams": ["local"],
            }
        ],
        "rules": [],
        "plugins": [],
        "webui": {
            "enabled": False,
        },
    }


def parse_config_dict(config_dict: dict[str, object]) -> AppConfig:
    return parse_config_text(json.dumps(config_dict, ensure_ascii=False, indent=2))


def test_parse_config_text_success() -> None:
    config = parse_config_dict(build_config_dict())

    assert isinstance(config, AppConfig)
    assert config.runtime.default_upstream_group == "default"
    assert config.listeners[0].protocol.value == "udp"
    assert config.upstreams[0].nameservers == ["local-ns"]


def test_parse_config_text_accepts_all_supported_nameserver_protocols() -> None:
    config_dict = build_config_dict()
    config_dict["nameservers"] = [
        {
            "name": "udp-ns",
            "protocol": "do53",
            "address": "1.1.1.1",
            "port": 53,
        },
        {
            "name": "doh-ns",
            "protocol": "doh",
            "url": "https://cloudflare-dns.com/dns-query",
            "bootstrap_address": "1.1.1.1",
            "verify": True,
            "want_get": False,
            "http_version": "h2",
        },
        {
            "name": "dot-ns",
            "protocol": "dot",
            "address": "9.9.9.9",
            "port": 853,
            "hostname": "dns.quad9.net",
            "verify": True,
        },
        {
            "name": "doq-ns",
            "protocol": "doq",
            "address": "94.140.14.14",
            "port": 853,
            "server_hostname": "unfiltered.adguard-dns.com",
            "verify": True,
        },
    ]
    config_dict["upstreams"] = [
        {
            "name": "mixed",
            "nameservers": ["udp-ns", "doh-ns", "dot-ns", "doq-ns"],
        }
    ]
    config_dict["groups"][0]["upstreams"] = ["mixed"]

    config = parse_config_dict(config_dict)

    assert len(config.nameservers) == 4
    assert config.upstreams[0].nameservers == ["udp-ns", "doh-ns", "dot-ns", "doq-ns"]


def test_parse_config_text_rejects_missing_group_target_reference() -> None:
    config_dict = build_config_dict()
    config_dict["groups"][0]["upstreams"] = ["missing"]

    with pytest.raises(ValueError, match="不存在的 target"):
        parse_config_dict(config_dict)


def test_parse_config_text_rejects_missing_nameserver_reference() -> None:
    config_dict = build_config_dict()
    config_dict["upstreams"][0]["nameservers"] = ["missing-ns"]

    with pytest.raises(ValueError, match="不存在的 nameserver"):
        parse_config_dict(config_dict)


def test_parse_config_text_rejects_duplicate_names() -> None:
    config_dict = build_config_dict()
    config_dict["listeners"].append(
        {
            "name": "udp",
            "protocol": "tcp",
            "host": "127.0.0.1",
            "port": 5300,
        }
    )

    with pytest.raises(ValueError, match="存在重复名称"):
        parse_config_dict(config_dict)


def test_parse_config_text_rejects_invalid_log_level() -> None:
    config_dict = build_config_dict()
    config_dict["runtime"]["log_level"] = "verbose"

    with pytest.raises(ValueError, match="未知 log_level"):
        parse_config_dict(config_dict)


def test_parse_config_text_rejects_unknown_plugin_module() -> None:
    config_dict = build_config_dict()
    config_dict["plugins"] = [
        {
            "name": "missing",
            "module": "missing_plugin",
        }
    ]

    with pytest.raises(ValueError, match="未知插件模块"):
        parse_config_dict(config_dict)


def test_parse_config_text_rejects_legacy_upstream_fields() -> None:
    config_dict = build_config_dict()
    config_dict["upstreams"][0] = {
        "name": "legacy",
        "protocol": "do53",
        "host": "127.0.0.1",
        "port": 5301,
        "nameservers": ["local-ns"],
    }
    config_dict["groups"][0]["upstreams"] = ["legacy"]

    with pytest.raises(ValueError):
        parse_config_dict(config_dict)


def test_parse_config_text_rejects_sequential_dispatcher() -> None:
    config_dict = build_config_dict()
    config_dict["groups"][0]["strategy"] = "sequential"

    with pytest.raises(ValueError):
        parse_config_dict(config_dict)


def test_dump_config_text_outputs_roundtrippable_json() -> None:
    config = parse_config_dict(build_config_dict())

    text = dump_config_text(config)

    assert text.endswith("\n")
    assert parse_config_text(text).runtime.default_upstream_group == "default"


def test_parse_config_text_rejects_empty_webui_credentials() -> None:
    config_dict = build_config_dict()
    config_dict["webui"] = {
        "enabled": True,
        "username": "",
        "password": "change-me",
    }

    with pytest.raises(ValueError):
        parse_config_dict(config_dict)


def test_parse_config_text_materializes_missing_plugins_as_disabled_defaults() -> None:
    config_dict = build_config_dict()
    config_dict["plugins"] = [
        {
            "name": "sample",
            "module": "sample_plugin",
            "enabled": True,
            "config": {
                "domains": ["sample.internal"],
                "answer_name": "sample.static_a",
            },
            "variables": {
                "address": "127.0.0.1",
                "ttl": 30,
            },
        }
    ]

    config = parse_config_dict(config_dict)
    plugins_by_module = {plugin.module: plugin for plugin in config.plugins}

    assert {"sample_plugin", "cache_plugin", "speedtest_plugin"} <= set(plugins_by_module)
    assert plugins_by_module["sample_plugin"].enabled is True
    assert plugins_by_module["cache_plugin"].enabled is False
    assert plugins_by_module["cache_plugin"].config == {"max_size": 100000}
    assert plugins_by_module["cache_plugin"].variables == {}
    assert plugins_by_module["speedtest_plugin"].enabled is False
    assert plugins_by_module["speedtest_plugin"].config["response_ip_limit"] == 2
    assert plugins_by_module["speedtest_plugin"].variables == {}


def test_build_config_json_schema_includes_available_plugin_schemas() -> None:
    plugin_dir = str((Path(__file__).resolve().parents[1] / "plugins").resolve())

    schema = build_config_json_schema([plugin_dir])

    plugin_schema = schema["$defs"]["PluginConfig"]
    options = plugin_schema["oneOf"]
    sample_option = next(item for item in options if item["properties"]["module"]["const"] == "sample_plugin")
    cache_option = next(item for item in options if item["properties"]["module"]["const"] == "cache_plugin")

    assert sample_option["title"] == "Sample Plugin"
    assert "domains" in sample_option["properties"]["config"]["properties"]
    assert "ttl" in sample_option["properties"]["variables"]["properties"]
    assert cache_option["properties"]["enabled"]["default"] is False
    assert cache_option["default"]["enabled"] is False
    assert cache_option["default"]["config"] == {"max_size": 100000}


def test_discover_available_plugins_lists_installed_plugins() -> None:
    plugin_dir = str((Path(__file__).resolve().parents[1] / "plugins").resolve())

    modules = {item.module for item in discover_available_plugins([plugin_dir])}

    assert {"cache_plugin", "sample_plugin", "speedtest_plugin"} <= modules


def test_config_example_json_is_valid() -> None:
    example_path = Path(__file__).resolve().parents[1] / "config.example.json"

    config = parse_config_text(example_path.read_text(encoding="utf-8"))

    assert isinstance(config, AppConfig)
    assert config.runtime.default_upstream_group == "default"
    assert len(config.nameservers) >= 4
    assert any(group.strategy is DispatchStrategyType.RACE for group in config.groups)
    assert any(group.strategy is DispatchStrategyType.WAIT_ALL for group in config.groups)


def test_parse_config_text_accepts_nested_groups_and_new_dispatchers() -> None:
    config_dict = build_config_dict()
    config_dict["nameservers"] = [
        {
            "name": "local-a",
            "protocol": "do53",
            "address": "127.0.0.1",
            "port": 5301,
        },
        {
            "name": "local-b",
            "protocol": "do53",
            "address": "127.0.0.1",
            "port": 5302,
        },
    ]
    config_dict["upstreams"] = [
        {"name": "local-a", "nameservers": ["local-a"]},
        {"name": "local-b", "nameservers": ["local-b"]},
    ]
    config_dict["groups"] = [
        {
            "name": "default",
            "strategy": "race",
            "upstreams": ["ipv4-chain", "local-b"],
        },
        {
            "name": "ipv4-chain",
            "strategy": "wait_all",
            "upstreams": ["local-a"],
        },
    ]

    config = parse_config_dict(config_dict)

    assert config.groups[0].strategy is DispatchStrategyType.RACE
    assert config.groups[1].strategy is DispatchStrategyType.WAIT_ALL
    assert config.groups[0].upstreams == ["ipv4-chain", "local-b"]


def test_parse_config_text_accepts_rule_dispatcher_override_without_group_override() -> None:
    config_dict = build_config_dict()
    config_dict["rules"] = [
        {
            "name": "wait-addresses",
            "enabled": True,
            "match": {
                "exact_domains": [],
                "suffix_domains": ["example.org"],
                "qtypes": ["A"],
            },
            "action": {
                "dispatcher": "wait_all",
            },
        }
    ]

    config = parse_config_dict(config_dict)

    assert config.rules[0].action.upstream_group is None
    assert config.rules[0].action.dispatcher is DispatchStrategyType.WAIT_ALL


def test_parse_config_text_rejects_empty_rule_action() -> None:
    config_dict = build_config_dict()
    config_dict["rules"] = [
        {
            "name": "invalid-action",
            "enabled": True,
            "match": {
                "exact_domains": ["example.org"],
                "suffix_domains": [],
                "qtypes": ["A"],
            },
            "action": {},
        }
    ]

    with pytest.raises(ValueError, match="至少需要 upstream_group 或 dispatcher"):
        parse_config_dict(config_dict)


def test_parse_config_text_rejects_group_upstream_name_conflict() -> None:
    config_dict = build_config_dict()
    config_dict["upstreams"] = [{"name": "shared", "nameservers": ["local-ns"]}]
    config_dict["groups"] = [
        {
            "name": "default",
            "strategy": "race",
            "upstreams": ["shared"],
        },
        {
            "name": "shared",
            "strategy": "wait_all",
            "upstreams": ["default"],
        },
    ]

    with pytest.raises(ValueError, match="名称冲突"):
        parse_config_dict(config_dict)


def test_parse_config_text_rejects_group_cycles() -> None:
    config_dict = build_config_dict()
    config_dict["groups"] = [
        {
            "name": "default",
            "strategy": "race",
            "upstreams": ["nested"],
        },
        {
            "name": "nested",
            "strategy": "wait_all",
            "upstreams": ["default", "local"],
        },
    ]

    with pytest.raises(ValueError, match="group 引用存在循环"):
        parse_config_dict(config_dict)
