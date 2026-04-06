from __future__ import annotations

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


def test_config_example_json_is_valid() -> None:
    example_path = Path(__file__).resolve().parents[1] / "config.example.json"

    config = parse_config_text(example_path.read_text(encoding="utf-8"))

    assert isinstance(config, AppConfig)
    assert config.runtime.default_upstream_group == "default"
    assert any(group.strategy is DispatchStrategyType.RACE for group in config.groups)
    assert any(group.strategy is DispatchStrategyType.WAIT_ALL for group in config.groups)


def test_parse_config_text_accepts_nested_groups_and_new_dispatchers() -> None:
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
      "name": "local-a",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5301
    },
    {
      "name": "local-b",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5302
    }
  ],
  "groups": [
    {
      "name": "default",
      "strategy": "race",
      "upstreams": ["ipv4-chain", "local-b"]
    },
    {
      "name": "ipv4-chain",
      "strategy": "wait_all",
      "upstreams": ["local-a"]
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

    assert config.groups[0].strategy is DispatchStrategyType.RACE
    assert config.groups[1].strategy is DispatchStrategyType.WAIT_ALL
    assert config.groups[0].upstreams == ["ipv4-chain", "local-b"]


def test_parse_config_text_accepts_rule_dispatcher_override_without_group_override() -> None:
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
      "strategy": "race",
      "upstreams": ["local"]
    }
  ],
  "rules": [
    {
      "name": "wait-addresses",
      "enabled": true,
      "match": {
        "exact_domains": [],
        "suffix_domains": ["example.org"],
        "qtypes": ["A"]
      },
      "action": {
        "dispatcher": "wait_all"
      }
    }
  ],
  "plugins": [],
  "webui": {
    "enabled": false
  }
}
        """
    )

    assert config.rules[0].action.upstream_group is None
    assert config.rules[0].action.dispatcher is DispatchStrategyType.WAIT_ALL


def test_parse_config_text_rejects_empty_rule_action() -> None:
    with pytest.raises(ValueError, match="至少需要 upstream_group 或 dispatcher"):
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
      "strategy": "race",
      "upstreams": ["local"]
    }
  ],
  "rules": [
    {
      "name": "invalid-action",
      "enabled": true,
      "match": {
        "exact_domains": ["example.org"],
        "suffix_domains": [],
        "qtypes": ["A"]
      },
      "action": {}
    }
  ],
  "plugins": [],
  "webui": {
    "enabled": false
  }
}
            """
        )


def test_parse_config_text_rejects_group_upstream_name_conflict() -> None:
    with pytest.raises(ValueError, match="名称冲突"):
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
      "name": "shared",
      "protocol": "do53",
      "host": "127.0.0.1",
      "port": 5301
    }
  ],
  "groups": [
    {
      "name": "default",
      "strategy": "sequential",
      "upstreams": ["shared"]
    },
    {
      "name": "shared",
      "strategy": "wait_all",
      "upstreams": ["default"]
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


def test_parse_config_text_rejects_group_cycles() -> None:
    with pytest.raises(ValueError, match="group 引用存在循环"):
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
      "upstreams": ["nested"]
    },
    {
      "name": "nested",
      "strategy": "wait_all",
      "upstreams": ["default", "local"]
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
