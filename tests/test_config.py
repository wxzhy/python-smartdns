from __future__ import annotations

from pathlib import Path

import pytest

from dns_forwarder.config import AppConfig, parse_config_text


def test_parse_config_text_success() -> None:
    config = parse_config_text(
        """
runtime:
  plugin_dirs: ["plugins"]
  default_upstream_group: default
listeners:
  - name: udp
    protocol: udp
    host: 127.0.0.1
    port: 5300
upstreams:
  - name: local
    protocol: do53
    host: 127.0.0.1
    port: 5301
groups:
  - name: default
    strategy: sequential
    upstreams: [local]
rules: []
plugins: []
webui:
  enabled: false
        """
    )

    assert isinstance(config, AppConfig)
    assert config.runtime.default_upstream_group == "default"
    assert config.listeners[0].protocol.value == "udp"


def test_parse_config_text_rejects_missing_references() -> None:
    with pytest.raises(ValueError):
        parse_config_text(
            """
runtime:
  plugin_dirs: ["plugins"]
  default_upstream_group: default
listeners:
  - name: udp
    protocol: udp
    host: 127.0.0.1
    port: 5300
upstreams:
  - name: local
    protocol: do53
    host: 127.0.0.1
    port: 5301
groups:
  - name: default
    strategy: sequential
    upstreams: [missing]
rules: []
plugins: []
webui:
  enabled: false
            """
        )


def test_parse_config_text_rejects_duplicate_names() -> None:
    with pytest.raises(ValueError):
        parse_config_text(
            """
runtime:
  plugin_dirs: ["plugins"]
  default_upstream_group: default
listeners:
  - name: udp
    protocol: udp
    host: 127.0.0.1
    port: 5300
  - name: udp
    protocol: tcp
    host: 127.0.0.1
    port: 5300
upstreams:
  - name: local
    protocol: do53
    host: 127.0.0.1
    port: 5301
groups:
  - name: default
    strategy: sequential
    upstreams: [local]
rules: []
plugins: []
webui:
  enabled: false
            """
        )


def test_parse_config_text_rejects_invalid_log_level() -> None:
    with pytest.raises(ValueError):
        parse_config_text(
            """
runtime:
  plugin_dirs: ["plugins"]
  default_upstream_group: default
  log_level: verbose
listeners:
  - name: udp
    protocol: udp
    host: 127.0.0.1
    port: 5300
upstreams:
  - name: local
    protocol: do53
    host: 127.0.0.1
    port: 5301
groups:
  - name: default
    strategy: sequential
    upstreams: [local]
rules: []
plugins: []
webui:
  enabled: false
            """
        )
