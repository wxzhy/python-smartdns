from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from dns_forwarder.config.models import PluginConfig

from .base import Plugin, PluginManager


@dataclass(frozen=True, slots=True)
class PluginCatalogEntry:
    module: str
    plugin_name: str
    ui_meta: dict[str, Any]
    config_model: type[BaseModel]
    variables_model: type[BaseModel]

    def describe(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "plugin_name": self.plugin_name,
            "ui_meta": self.ui_meta,
            "config_schema": self.config_model.model_json_schema(),
            "variables_schema": self.variables_model.model_json_schema(),
            "default_config": self.build_default_plugin_config().model_dump(mode="json"),
        }

    def build_default_plugin_config(self, existing_names: set[str] | None = None) -> PluginConfig:
        used_names = set() if existing_names is None else set(existing_names)
        plugin_name = self._build_unique_name(used_names)
        return PluginConfig(
            name=plugin_name,
            module=self.module,
            enabled=False,
            config=self.config_model().model_dump(mode="json"),
            variables=self.variables_model().model_dump(mode="json"),
        )

    def _build_unique_name(self, existing_names: set[str]) -> str:
        candidate = self.module
        if candidate not in existing_names:
            return candidate
        suffix = 2
        while f"{candidate}-{suffix}" in existing_names:
            suffix += 1
        return f"{candidate}-{suffix}"


def discover_available_plugins(plugin_dirs: list[str]) -> list[PluginCatalogEntry]:
    entries: list[PluginCatalogEntry] = []
    seen_modules: set[str] = set()

    for module_name in _iter_plugin_module_names(plugin_dirs):
        if module_name in seen_modules:
            continue
        plugin = _load_plugin(module_name, plugin_dirs)
        seen_modules.add(module_name)
        entries.append(
            PluginCatalogEntry(
                module=module_name,
                plugin_name=plugin.name,
                ui_meta=dict(plugin.ui_meta),
                config_model=plugin.config_model,
                variables_model=plugin.variables_model,
            )
        )

    return entries


def validate_plugin_configs(plugin_configs: list[PluginConfig], plugin_dirs: list[str]) -> None:
    available_plugins = {entry.module: entry for entry in discover_available_plugins(plugin_dirs)}
    for plugin_config in plugin_configs:
        entry = available_plugins.get(plugin_config.module)
        if entry is None:
            raise ValueError(f"未知插件模块: {plugin_config.module}")
        entry.config_model.model_validate(plugin_config.config)
        entry.variables_model.model_validate(plugin_config.variables)


def materialize_plugin_configs(plugin_configs: list[PluginConfig], plugin_dirs: list[str]) -> list[PluginConfig]:
    available_plugins = discover_available_plugins(plugin_dirs)
    materialized = [plugin.model_copy(deep=True) for plugin in plugin_configs]
    configured_modules = {plugin.module for plugin in materialized}
    used_names = {plugin.name for plugin in materialized}

    for entry in available_plugins:
        if entry.module in configured_modules:
            continue
        default_plugin = entry.build_default_plugin_config(used_names)
        materialized.append(default_plugin)
        configured_modules.add(entry.module)
        used_names.add(default_plugin.name)

    return materialized


def namespace_json_schema(schema: dict[str, Any], prefix: str) -> tuple[dict[str, Any], dict[str, Any]]:
    namespaced_schema = deepcopy(schema)
    definitions = namespaced_schema.pop("$defs", {})
    _rewrite_schema_refs(namespaced_schema, prefix)

    namespaced_definitions: dict[str, Any] = {}
    for name, definition in definitions.items():
        key = f"{prefix}.{name}"
        definition_copy = deepcopy(definition)
        _rewrite_schema_refs(definition_copy, prefix)
        namespaced_definitions[key] = definition_copy

    return namespaced_schema, namespaced_definitions


def _rewrite_schema_refs(value: Any, prefix: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref" and isinstance(item, str) and item.startswith("#/$defs/"):
                ref_name = item.removeprefix("#/$defs/")
                value[key] = f"#/$defs/{prefix}.{ref_name}"
                continue
            _rewrite_schema_refs(item, prefix)
        return

    if isinstance(value, list):
        for item in value:
            _rewrite_schema_refs(item, prefix)


def _iter_plugin_module_names(plugin_dirs: list[str]) -> list[str]:
    modules: list[str] = []
    for plugin_dir in plugin_dirs:
        base = Path(plugin_dir)
        if not base.exists() or not base.is_dir():
            continue

        for child in sorted(base.iterdir(), key=lambda item: item.name):
            if child.name == "__pycache__" or child.name.startswith("_"):
                continue
            if child.is_dir() and (child / "__init__.py").exists():
                modules.append(child.name)
                continue
            if child.is_file() and child.suffix == ".py" and child.stem != "__init__":
                modules.append(child.stem)

    return modules


def _load_plugin(module_name: str, plugin_dirs: list[str]) -> Plugin:
    module = PluginManager._load_module(module_name, plugin_dirs)
    plugin = getattr(module, "plugin", None)
    if not isinstance(plugin, Plugin):
        raise TypeError(f"插件 {module_name} 未导出 plugin 实例")
    return plugin
