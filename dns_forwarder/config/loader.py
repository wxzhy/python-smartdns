from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from pydantic_settings import SettingsConfigDict

from dns_forwarder.plugin_api import (
    discover_available_plugins,
    materialize_plugin_configs,
    namespace_json_schema,
    validate_plugin_configs,
)

from .models import AppConfig


def _build_settings_class(config_path: Path) -> type[AppConfig]:
    base_config = dict(AppConfig.model_config)
    base_config.update(
        json_file=str(config_path),
        json_file_encoding="utf-8",
    )

    class FileAppConfig(AppConfig):
        model_config = SettingsConfigDict(**base_config)

    return FileAppConfig


def load_config(config_path: str | Path) -> AppConfig:
    path = Path(config_path)
    settings_cls = _build_settings_class(path)
    config = settings_cls()
    validate_plugin_configs(config.plugins, config.runtime.plugin_dirs)
    config.plugins = materialize_plugin_configs(config.plugins, config.runtime.plugin_dirs)
    return config


def parse_config_text(config_text: str) -> AppConfig:
    raw: Any = json.loads(config_text)
    if not isinstance(raw, dict):
        raise ValueError("配置根节点必须是 object")
    config = AppConfig.model_validate(raw)
    validate_plugin_configs(config.plugins, config.runtime.plugin_dirs)
    config.plugins = materialize_plugin_configs(config.plugins, config.runtime.plugin_dirs)
    return config


def dump_config_text(config: AppConfig) -> str:
    config = config.model_copy(deep=True)
    config.plugins = materialize_plugin_configs(config.plugins, config.runtime.plugin_dirs)
    return (
        json.dumps(
            config.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )


def save_config(config: AppConfig, config_path: str | Path) -> None:
    Path(config_path).write_text(dump_config_text(config), encoding="utf-8")


def build_config_json_schema(plugin_dirs: list[str]) -> dict[str, Any]:
    schema = deepcopy(AppConfig.model_json_schema())
    definitions = schema.setdefault("$defs", {})
    plugin_options = []

    for entry in discover_available_plugins(plugin_dirs):
        config_schema, config_defs = namespace_json_schema(
            entry.config_model.model_json_schema(),
            f"{entry.module}.config",
        )
        variables_schema, variables_defs = namespace_json_schema(
            entry.variables_model.model_json_schema(),
            f"{entry.module}.variables",
        )
        definitions.update(config_defs)
        definitions.update(variables_defs)
        plugin_options.append(
            {
                "title": entry.ui_meta.get("title") or entry.plugin_name,
                "description": entry.ui_meta.get("description", ""),
                "type": "object",
                "properties": {
                    "name": {
                        "title": "Name",
                        "type": "string",
                    },
                    "module": {
                        "title": "Module",
                        "type": "string",
                        "const": entry.module,
                        "default": entry.module,
                    },
                    "enabled": {
                        "title": "Enabled",
                        "type": "boolean",
                        "default": False,
                    },
                    "config": config_schema,
                    "variables": variables_schema,
                },
                "required": ["name", "module"],
                "default": entry.build_default_plugin_config().model_dump(mode="json"),
                "additionalProperties": False,
            }
        )

    plugin_schema = definitions.get("PluginConfig")
    if plugin_options:
        definitions["PluginConfig"] = {
            "title": "PluginConfig",
            "oneOf": plugin_options,
        }
    elif plugin_schema is not None:
        definitions["PluginConfig"] = plugin_schema

    return schema
