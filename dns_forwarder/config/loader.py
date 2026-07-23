from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

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


class _InlineTextAppConfig(AppConfig):
    """仅用于 ``parse_config_text``，不合并磁盘上的 ``config.json``。

    ``AppConfig`` 默认会读取工作目录下的 ``config.json`` 作为 settings 源，
    但文本校验应只针对传入的文本，故这里丢弃 ``JsonConfigSettingsSource``，
    并移除 json 相关 model_config 键以避免「未使用配置键」告警。
    """

    # 覆盖父类 model_config：显式清除 json 相关键，避免未使用配置键告警。
    model_config = SettingsConfigDict(
        extra="forbid",
        env_prefix="DNS_FORWARDER_",
        env_nested_delimiter="__",
        json_file=None,
        json_file_encoding=None,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # 排除 JsonConfigSettingsSource，仅保留 init / env / dotenv / secret 源。
        return (init_settings, env_settings, dotenv_settings, file_secret_settings)


def load_config(config_path: str | Path) -> AppConfig:
    """从 JSON 配置文件加载并校验配置，物化插件配置后返回。"""
    path = Path(config_path)
    settings_cls = _build_settings_class(path)
    config = settings_cls()
    validate_plugin_configs(config.plugins, config.runtime.plugin_dirs)
    config.plugins = materialize_plugin_configs(config.plugins, config.runtime.plugin_dirs)
    return config


def parse_config_text(config_text: str) -> AppConfig:
    """解析配置文本为 :class:`AppConfig`，不合并磁盘上的 ``config.json``。"""
    raw: Any = json.loads(config_text)
    if not isinstance(raw, dict):
        raise ValueError("配置根节点必须是 object")
    config = _InlineTextAppConfig.model_validate(raw)
    validate_plugin_configs(config.plugins, config.runtime.plugin_dirs)
    config.plugins = materialize_plugin_configs(config.plugins, config.runtime.plugin_dirs)
    return config


def dump_config_text(config: AppConfig) -> str:
    """将配置序列化为格式化的 JSON 文本（保留中文，缩进 2 空格）。"""
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
    """将配置以 UTF-8 写入文件。"""
    Path(config_path).write_text(dump_config_text(config), encoding="utf-8")


def build_config_json_schema(plugin_dirs: list[str]) -> dict[str, Any]:
    """构建包含插件配置项的完整 JSON Schema，供 WebUI 校验/编辑器使用。"""
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
