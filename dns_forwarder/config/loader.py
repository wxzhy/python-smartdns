from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import SettingsConfigDict

from .models import AppConfig


def _build_settings_class(config_path: Path) -> type[AppConfig]:
    base_config = dict(AppConfig.model_config)
    base_config.update(
        yaml_file=str(config_path),
        yaml_file_encoding="utf-8",
    )

    class FileAppConfig(AppConfig):
        model_config = SettingsConfigDict(**base_config)

    return FileAppConfig


def load_config(config_path: str | Path) -> AppConfig:
    path = Path(config_path)
    settings_cls = _build_settings_class(path)
    return settings_cls()


def parse_config_text(config_text: str) -> AppConfig:
    raw: Any = yaml.safe_load(config_text) or {}
    if not isinstance(raw, dict):
        raise ValueError("配置根节点必须是 mapping")
    return AppConfig.model_validate(raw)


def dump_config_text(config: AppConfig) -> str:
    return yaml.safe_dump(
        config.model_dump(mode="json"),
        allow_unicode=True,
        sort_keys=False,
    )


def save_config(config: AppConfig, config_path: str | Path) -> None:
    Path(config_path).write_text(dump_config_text(config), encoding="utf-8")
