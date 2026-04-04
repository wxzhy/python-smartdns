from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, Callable

from pydantic import BaseModel

from dns_forwarder.config.models import PluginConfig

if TYPE_CHECKING:
    import dns.message

    from dns_forwarder.pipeline.context import RequestContext, UpstreamResult


class EmptyModel(BaseModel):
    """默认的空插件配置模型。"""


AnswerBuilder = Callable[["RequestContext"], "dns.message.Message"]
ContextFactory = Callable[[], Any]


@dataclass(frozen=True, slots=True)
class ContextRegistration:
    value: Any = None
    factory: ContextFactory | None = None

    def build(self) -> Any:
        if self.factory is not None:
            return self.factory()
        return self.value


@dataclass(slots=True)
class PluginRegistry:
    context_registry: dict[str, ContextRegistration] = field(default_factory=dict)
    resolver_registry: dict[str, Any] = field(default_factory=dict)
    answer_registry: dict[str, AnswerBuilder] = field(default_factory=dict)

    def register_context(self, name: str, value: Any) -> None:
        self._register(self.context_registry, name, ContextRegistration(value=value))

    def register_context_factory(self, name: str, factory: ContextFactory) -> None:
        self._register(self.context_registry, name, ContextRegistration(factory=factory))

    def register_resolver(self, name: str, value: Any) -> None:
        self._register(self.resolver_registry, name, value)

    def register_answer(self, name: str, builder: AnswerBuilder) -> None:
        self._register(self.answer_registry, name, builder)

    @staticmethod
    def _register(bucket: dict[str, Any], name: str, value: Any) -> None:
        if name in bucket:
            raise ValueError(f"重复注册对象: {name}")
        bucket[name] = value


class Plugin:
    name = "plugin"
    config_model: type[BaseModel] = EmptyModel
    variables_model: type[BaseModel] = EmptyModel
    ui_meta: dict[str, Any] = {}
    request_order: int = 0
    upstream_response_order: int = 0
    response_order: int = 0
    runtime_config: BaseModel = EmptyModel()
    runtime_variables: BaseModel = EmptyModel()

    def bind(self, config: BaseModel, variables: BaseModel) -> None:
        self.runtime_config = config
        self.runtime_variables = variables

    async def setup(self, registry: PluginRegistry) -> None:
        return None

    async def on_request(self, context: "RequestContext") -> None:
        return None

    async def on_upstream_response(self, context: "RequestContext", result: "UpstreamResult") -> None:
        return None

    async def on_response(self, context: "RequestContext") -> None:
        return None


@dataclass(slots=True)
class LoadedPlugin:
    instance: Plugin
    config: BaseModel
    variables: BaseModel
    raw_config: PluginConfig


class PluginManager:
    def __init__(self, loaded_plugins: list[LoadedPlugin], registry: PluginRegistry) -> None:
        self.loaded_plugins = loaded_plugins
        self.registry = registry

    @classmethod
    async def build(cls, plugin_configs: list[PluginConfig], plugin_dirs: list[str]) -> "PluginManager":
        registry = PluginRegistry()
        loaded: list[LoadedPlugin] = []

        for plugin_config in plugin_configs:
            if not plugin_config.enabled:
                continue
            module = cls._load_module(plugin_config.module, plugin_dirs)
            plugin = getattr(module, "plugin", None)
            if not isinstance(plugin, Plugin):
                raise TypeError(f"插件 {plugin_config.name} 未导出 plugin 实例")

            config_model = plugin.config_model.model_validate(plugin_config.config)
            variables_model = plugin.variables_model.model_validate(plugin_config.variables)
            plugin.bind(config_model, variables_model)
            loaded_plugin = LoadedPlugin(
                instance=plugin,
                config=config_model,
                variables=variables_model,
                raw_config=plugin_config,
            )
            await plugin.setup(registry)
            loaded.append(loaded_plugin)

        return cls(loaded, registry)

    @staticmethod
    def _load_module(module_name: str, plugin_dirs: list[str]) -> ModuleType:
        module_path = PluginManager._find_module_path(module_name, plugin_dirs)
        normalized_name = module_name.replace("\\", ".").replace("/", ".").strip(".")
        unique_name = f"dns_forwarder.plugins.{normalized_name}_{abs(hash(module_path))}"
        spec = importlib.util.spec_from_file_location(unique_name, module_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"无法加载插件模块: {module_name}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[unique_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(unique_name, None)
            raise
        return module

    @staticmethod
    def _find_module_path(module_name: str, plugin_dirs: list[str]) -> Path:
        candidate_name = module_name if module_name.endswith(".py") else f"{module_name}.py"
        for plugin_dir in plugin_dirs:
            base = Path(plugin_dir)
            direct = base / candidate_name
            package_init = base / module_name / "__init__.py"
            if direct.exists():
                return direct
            if package_init.exists():
                return package_init
        raise FileNotFoundError(f"未找到插件模块: {module_name}")

    def build_context_extensions(self) -> dict[str, Any]:
        return {
            name: registration.build() for name, registration in self.registry.context_registry.items()
        }

    def build_answer_registry(self) -> dict[str, AnswerBuilder]:
        return dict(self.registry.answer_registry)

    def _ordered_plugins(self, order_attr: str) -> list[LoadedPlugin]:
        return sorted(self.loaded_plugins, key=lambda item: getattr(item.instance, order_attr))

    async def on_request(self, context: "RequestContext") -> None:
        for plugin in self._ordered_plugins("request_order"):
            context.metadata.setdefault("plugin_order", []).append(plugin.instance.name)
            await plugin.instance.on_request(context)

    async def on_upstream_response(self, context: "RequestContext", result: "UpstreamResult") -> None:
        for plugin in self._ordered_plugins("upstream_response_order"):
            await plugin.instance.on_upstream_response(context, result)

    async def on_response(self, context: "RequestContext") -> None:
        for plugin in self._ordered_plugins("response_order"):
            await plugin.instance.on_response(context)

    def describe(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for plugin in self.loaded_plugins:
            result.append(
                {
                    "name": plugin.raw_config.name,
                    "module": plugin.raw_config.module,
                    "plugin_name": plugin.instance.name,
                    "ui_meta": plugin.instance.ui_meta,
                    "config_schema": plugin.config.model_json_schema(),
                    "variables_schema": plugin.variables.model_json_schema(),
                }
            )
        return result
