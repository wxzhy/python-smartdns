from __future__ import annotations

from pathlib import Path

import dns.message
from httpx import ASGITransport, AsyncClient
import yaml

from dns_forwarder.core.runtime import RuntimeManager
from dns_forwarder.webui import ManagedUvicornServer, create_webui_app


def write_config(path: Path, *, upstream_port: int = 5301, webui_enabled: bool = False, webui_port: int = 8080) -> None:
    plugin_dir = str((Path(__file__).resolve().parents[1] / "plugins").resolve())
    data = {
        "runtime": {
            "plugin_dirs": [plugin_dir],
            "default_upstream_group": "default",
            "loop_policy": "asyncio",
        },
        "listeners": [
            {
                "name": "udp",
                "protocol": "udp",
                "host": "127.0.0.1",
                "port": 0,
                "enabled": True,
            }
        ],
        "upstreams": [
            {
                "name": "local",
                "protocol": "do53",
                "host": "127.0.0.1",
                "port": upstream_port,
                "timeout": 0.2,
                "lifetime": 0.5,
                "use_tcp": False,
            }
        ],
        "groups": [
            {
                "name": "default",
                "strategy": "sequential",
                "upstreams": ["local"],
            }
        ],
        "rules": [],
        "plugins": [
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
        ],
        "webui": {
            "enabled": webui_enabled,
            "host": "127.0.0.1",
            "port": webui_port,
            "reload_endpoint": "/admin/reload",
        },
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


async def test_sample_plugin_short_circuits_request(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    manager = RuntimeManager(config_path)
    await manager.load()

    response = await manager.process_query(
        dns.message.make_query("sample.internal", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )

    assert response is not None
    assert response.answer[0][0].address == "127.0.0.1"


async def test_webui_save_and_reload_success(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    manager = RuntimeManager(config_path)
    await manager.load()
    app = create_webui_app(manager)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        editor = await client.get("/config")
        assert editor.status_code == 200

        current_text = config_path.read_text(encoding="utf-8").replace("address: 127.0.0.1", "address: 127.0.0.2", 1)
        saved = await client.post("/config", data={"config_text": current_text})
        assert saved.status_code == 200
        assert "配置已保存" in saved.text

        reloaded = await client.post("/admin/reload", follow_redirects=False)
        assert reloaded.status_code == 303

    response = await manager.process_query(
        dns.message.make_query("sample.internal", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )
    assert response.answer[0][0].address == "127.0.0.2"


async def test_webui_reload_failure_keeps_old_runtime(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    write_config(config_path)
    manager = RuntimeManager(config_path)
    await manager.start()
    app = create_webui_app(manager)

    changed_text = config_path.read_text(encoding="utf-8").replace("port: 0", "port: 5305", 1)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        saved = await client.post("/config", data={"config_text": changed_text})
        assert saved.status_code == 200
        failed = await client.post("/admin/reload")
        assert failed.status_code == 400
        assert "需要重启进程" in failed.text

    response = await manager.process_query(
        dns.message.make_query("sample.internal", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )
    assert response.answer[0][0].address == "127.0.0.1"
    await manager.stop()


def test_webui_server_uses_current_event_loop() -> None:
    server = ManagedUvicornServer(create_webui_app(RuntimeManager(Path("config.yaml"))), "127.0.0.1", 8080)
    assert server._config.loop == "none"
