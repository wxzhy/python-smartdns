from __future__ import annotations

from pathlib import Path

import pytest

from dns_forwarder.config import AppConfig, build_config_json_schema, dump_config_text, parse_config_text
from dns_forwarder.plugin_api import discover_available_plugins


def test_parse_config_text_success() -> None:
    config = parse_config_text(
        """
{
  "runtime": {
    "plugin_dirs": ["plugins"],
    "default_upstream_group": "default"
  },
  "listeners": [
    {
      "name": "udp",
      "protocol": "udp",
      "host": "127.0.0.1",
      "port": 5300
    }
  ],
  "upstreams": [
    {
      "name": "local",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5301
    }
  ],
  "groups": [
    {
      "name": "default",
      "strategy": "sequential",
      "upstreams": ["local"]
    }
  ],
  "rules": [],
  "plugins": [],
  "webui": {
    "enabled": false
  }
}
        """
    )

    assert isinstance(config, AppConfig)
    assert config.runtime.default_upstream_group == "default"
    assert config.listeners[0].protocol.value == "udp"


def test_parse_config_text_rejects_missing_references() -> None:
    with pytest.raises(ValueError):
        parse_config_text(
            """
{
  "runtime": {
    "plugin_dirs": ["plugins"],
    "default_upstream_group": "default"
  },
  "listeners": [
    {
      "name": "udp",
      "protocol": "udp",
      "host": "127.0.0.1",
      "port": 5300
    }
  ],
  "upstreams": [
    {
      "name": "local",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5301
    }
  ],
  "groups": [
    {
      "name": "default",
      "strategy": "sequential",
      "upstreams": ["missing"]
    }
  ],
  "rules": [],
  "plugins": [],
  "webui": {
    "enabled": false
  }
}
            """
        )


def test_parse_config_text_rejects_duplicate_names() -> None:
    with pytest.raises(ValueError):
        parse_config_text(
            """
{
  "runtime": {
    "plugin_dirs": ["plugins"],
    "default_upstream_group": "default"
  },
  "listeners": [
    {
      "name": "udp",
      "protocol": "udp",
      "host": "127.0.0.1",
      "port": 5300
    },
    {
      "name": "udp",
      "protocol": "tcp",
      "host": "127.0.0.1",
      "port": 5300
    }
  ],
  "upstreams": [
    {
      "name": "local",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5301
    }
  ],
  "groups": [
    {
      "name": "default",
      "strategy": "sequential",
      "upstreams": ["local"]
    }
  ],
  "rules": [],
  "plugins": [],
  "webui": {
    "enabled": false
  }
}
            """
        )


def test_parse_config_text_rejects_invalid_log_level() -> None:
    with pytest.raises(ValueError):
        parse_config_text(
            """
{
  "runtime": {
    "plugin_dirs": ["plugins"],
    "default_upstream_group": "default",
    "log_level": "verbose"
  },
  "listeners": [
    {
      "name": "udp",
      "protocol": "udp",
      "host": "127.0.0.1",
      "port": 5300
    }
  ],
  "upstreams": [
    {
      "name": "local",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5301
    }
  ],
  "groups": [
    {
      "name": "default",
      "strategy": "sequential",
      "upstreams": ["local"]
    }
  ],
  "rules": [],
  "plugins": [],
  "webui": {
    "enabled": false
  }
}
            """
        )


def test_parse_config_text_rejects_unknown_plugin_module() -> None:
    with pytest.raises(ValueError, match="未知插件模块"):
        parse_config_text(
            """
{
  "runtime": {
    "plugin_dirs": ["plugins"],
    "default_upstream_group": "default"
  },
  "listeners": [
    {
      "name": "udp",
      "protocol": "udp",
      "host": "127.0.0.1",
      "port": 5300
    }
  ],
  "upstreams": [
    {
      "name": "local",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5301
    }
  ],
  "groups": [
    {
      "name": "default",
      "strategy": "sequential",
      "upstreams": ["local"]
    }
  ],
  "rules": [],
  "plugins": [
    {
      "name": "missing",
      "module": "missing_plugin"
    }
  ],
  "webui": {
    "enabled": false
  }
}
            """
        )


def test_dump_config_text_outputs_roundtrippable_json() -> None:
    config = parse_config_text(
        """
{
  "runtime": {
    "plugin_dirs": ["plugins"],
    "default_upstream_group": "default"
  },
  "listeners": [
    {
      "name": "udp",
      "protocol": "udp",
      "host": "127.0.0.1",
      "port": 5300
    }
  ],
  "upstreams": [
    {
      "name": "local",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5301
    }
  ],
  "groups": [
    {
      "name": "default",
      "strategy": "sequential",
      "upstreams": ["local"]
    }
  ],
  "rules": [],
  "plugins": [],
  "webui": {
    "enabled": false
  }
}
        """
    )

    text = dump_config_text(config)

    assert text.endswith("\n")
    assert parse_config_text(text).runtime.default_upstream_group == "default"


def test_parse_config_text_rejects_empty_webui_credentials() -> None:
    with pytest.raises(ValueError):
        parse_config_text(
            """
{
  "runtime": {
    "plugin_dirs": ["plugins"],
    "default_upstream_group": "default"
  },
  "listeners": [
    {
      "name": "udp",
      "protocol": "udp",
      "host": "127.0.0.1",
      "port": 5300
    }
  ],
  "upstreams": [
    {
      "name": "local",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5301
    }
  ],
  "groups": [
    {
      "name": "default",
      "strategy": "sequential",
      "upstreams": ["local"]
    }
  ],
  "rules": [],
  "plugins": [],
  "webui": {
    "enabled": true,
    "username": "",
    "password": "change-me"
  }
}
            """
        )


def test_parse_config_text_materializes_missing_plugins_as_disabled_defaults() -> None:
    config = parse_config_text(
        """
{
  "runtime": {
    "plugin_dirs": ["plugins"],
    "default_upstream_group": "default"
  },
  "listeners": [
    {
      "name": "udp",
      "protocol": "udp",
      "host": "127.0.0.1",
      "port": 5300
    }
  ],
  "upstreams": [
    {
      "name": "local",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5301
    }
  ],
  "groups": [
    {
      "name": "default",
      "strategy": "sequential",
      "upstreams": ["local"]
    }
  ],
  "rules": [],
  "plugins": [
    {
      "name": "sample",
      "module": "sample_plugin",
      "enabled": true,
      "config": {
        "domains": ["sample.internal"],
        "answer_name": "sample.static_a"
      },
      "variables": {
        "address": "127.0.0.1",
        "ttl": 30
      }
    }
  ],
  "webui": {
    "enabled": false
  }
}
        """
    )

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
