from __future__ import annotations

import asyncio
import sys
import json
import base64
from pathlib import Path

import dns.message
from httpx import ASGITransport, AsyncClient

from dns_forwarder.core.runtime import RuntimeManager, main
from dns_forwarder.webui import ManagedUvicornServer, WEBUI_RELOAD_ENDPOINT, create_webui_app


def _basic_auth_headers(username: str = "admin", password: str = "change-me") -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def write_config(
    path: Path,
    *,
    upstream_port: int = 5301,
    webui_enabled: bool = False,
    doh_enabled: bool = False,
    webui_port: int = 8080,
) -> None:
    plugin_dir = str((Path(__file__).resolve().parents[1] / "plugins").resolve())
    data = {
        "runtime": {
            "plugin_dirs": [plugin_dir],
            "default_upstream_group": "default",
            "loop_policy": "asyncio",
            "log_level": "INFO",
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
        "nameservers": [
            {
                "name": "local-ns",
                "protocol": "do53",
                "address": "127.0.0.1",
                "port": upstream_port,
            }
        ],
        "upstreams": [
            {
                "name": "local",
                "nameservers": ["local-ns"],
                "timeout": 0.2,
                "lifetime": 0.5,
                "use_tcp": False,
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
            "doh_enabled": doh_enabled,
            "host": "127.0.0.1",
            "port": webui_port,
            "username": "admin",
            "password": "change-me",
        },
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


async def test_sample_plugin_short_circuits_request(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
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


async def test_webui_save_and_reload_success(tmp_path: Path, capture_dns_logs, caplog) -> None:
    capture_dns_logs("INFO")
    config_path = tmp_path / "config.json"
    write_config(config_path, webui_enabled=True)
    manager = RuntimeManager(config_path)
    await manager.load()
    app = create_webui_app(manager)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        editor = await client.get("/config", headers=_basic_auth_headers())
        assert editor.status_code == 200

        current_data = json.loads(config_path.read_text(encoding="utf-8"))
        current_data["plugins"][0]["variables"]["address"] = "127.0.0.2"
        current_text = json.dumps(current_data, ensure_ascii=False, indent=2) + "\n"
        saved = await client.post("/config", data={"config_text": current_text}, headers=_basic_auth_headers())
        assert saved.status_code == 200
        assert "配置已保存" in saved.text
        assert "jsoneditor.min.js" in saved.text
        assert '"oneOf"' in saved.text

        reloaded = await client.post(WEBUI_RELOAD_ENDPOINT, follow_redirects=False, headers=_basic_auth_headers())
        assert reloaded.status_code == 303
        assert "保存配置成功" in caplog.text
        assert "手动 reload 完成" in caplog.text

    response = await manager.process_query(
        dns.message.make_query("sample.internal", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )
    assert response.answer[0][0].address == "127.0.0.2"


async def test_webui_reload_failure_keeps_old_runtime(tmp_path: Path, capture_dns_logs, caplog) -> None:
    capture_dns_logs("INFO")
    config_path = tmp_path / "config.json"
    write_config(config_path, webui_enabled=True)
    manager = RuntimeManager(config_path)
    await manager.start()
    app = create_webui_app(manager)

    changed_text = config_path.read_text(encoding="utf-8").replace('"port": 0', '"port": 5305', 1)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        saved = await client.post("/config", data={"config_text": changed_text}, headers=_basic_auth_headers())
        assert saved.status_code == 200
        failed = await client.post(WEBUI_RELOAD_ENDPOINT, headers=_basic_auth_headers())
        assert failed.status_code == 400
        assert "需要重启进程" in failed.text
        assert "手动 reload 失败" in caplog.text
        assert "reload 失败" in caplog.text

    response = await manager.process_query(
        dns.message.make_query("sample.internal", "A"),
        ("127.0.0.1", 10000),
        "udp",
    )
    assert response.answer[0][0].address == "127.0.0.1"
    await manager.stop()


async def test_webui_requires_basic_auth(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    write_config(config_path, webui_enabled=True)
    manager = RuntimeManager(config_path)
    await manager.load()
    app = create_webui_app(manager)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        unauthorized = await client.get("/config")
        forbidden = await client.get("/config", headers=_basic_auth_headers(password="wrong-password"))
        authorized = await client.get("/config", headers=_basic_auth_headers())

    assert unauthorized.status_code == 401
    assert unauthorized.headers["www-authenticate"] == "Basic"
    assert forbidden.status_code == 401
    assert authorized.status_code == 200


def test_webui_server_uses_current_event_loop() -> None:
    manager = RuntimeManager(Path("config.json"))
    asyncio.run(manager.load())
    server = ManagedUvicornServer(create_webui_app(manager), "127.0.0.1", 8080)
    assert server._config.loop == "none"


def test_check_config_logs_instead_of_print(
    tmp_path: Path,
    monkeypatch,
    capsys,
    capture_dns_logs,
    caplog,
) -> None:
    capture_dns_logs("INFO")
    config_path = tmp_path / "config.json"
    write_config(config_path)
    monkeypatch.setattr(sys, "argv", ["main.py", "--config", str(config_path), "check-config"])

    main()

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "config ok:" in caplog.text
