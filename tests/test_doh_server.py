from __future__ import annotations

import base64
import json
from pathlib import Path

import dns.message
from httpx import ASGITransport, AsyncClient

from dns_forwarder.core.runtime import RuntimeManager
from dns_forwarder.server.doh import DOH_DNS_QUERY_PATH, DOH_MEDIA_TYPE
from dns_forwarder.webui import create_webui_app


def write_config(path: Path) -> None:
    plugin_dir = str((Path(__file__).resolve().parents[1] / "plugins").resolve())
    data = {
        "runtime": {
            "plugin_dirs": [plugin_dir],
            "default_upstream_group": "default",
            "loop_policy": "asyncio",
            "log_level": "INFO",
        },
        "listeners": [],
        "nameservers": [
            {
                "name": "local-ns",
                "protocol": "do53",
                "address": "127.0.0.1",
                "port": 5301,
            }
        ],
        "upstreams": [
            {
                "name": "local",
                "nameservers": ["local-ns"],
            }
        ],
        "groups": [
            {
                "name": "default",
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
            "enabled": False,
            "doh_enabled": True,
            "host": "127.0.0.1",
            "port": 0,
        },
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _encode_doh_query(message: dns.message.Message) -> str:
    return base64.urlsafe_b64encode(message.to_wire()).rstrip(b"=").decode("ascii")


async def test_doh_get_supports_base64url_query_and_dns_message_response(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    write_config(config_path)
    manager = RuntimeManager(config_path)
    await manager.load()
    app = create_webui_app(manager)
    query = dns.message.make_query("sample.internal", "A")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(
            DOH_DNS_QUERY_PATH,
            params={"dns": _encode_doh_query(query)},
            headers={"Accept": DOH_MEDIA_TYPE},
        )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(DOH_MEDIA_TYPE)
    assert response.headers["cache-control"] == "max-age=30"
    message = dns.message.from_wire(response.content)
    assert message.answer[0][0].address == "127.0.0.1"


async def test_doh_post_supports_application_dns_message_body(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    write_config(config_path)
    manager = RuntimeManager(config_path)
    await manager.load()
    app = create_webui_app(manager)
    query = dns.message.make_query("sample.internal", "A")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            DOH_DNS_QUERY_PATH,
            content=query.to_wire(),
            headers={
                "Content-Type": DOH_MEDIA_TYPE,
                "Accept": DOH_MEDIA_TYPE,
            },
        )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(DOH_MEDIA_TYPE)
    assert "cache-control" not in response.headers
    message = dns.message.from_wire(response.content)
    assert message.answer[0][0].address == "127.0.0.1"


async def test_doh_rejects_unacceptable_accept_header(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    write_config(config_path)
    manager = RuntimeManager(config_path)
    await manager.load()
    app = create_webui_app(manager)
    query = dns.message.make_query("sample.internal", "A")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(
            DOH_DNS_QUERY_PATH,
            params={"dns": _encode_doh_query(query)},
            headers={"Accept": "application/json"},
        )

    assert response.status_code == 406


async def test_doh_rejects_invalid_post_media_type(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    write_config(config_path)
    manager = RuntimeManager(config_path)
    await manager.load()
    app = create_webui_app(manager)
    query = dns.message.make_query("sample.internal", "A")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            DOH_DNS_QUERY_PATH,
            content=query.to_wire(),
            headers={"Content-Type": "application/octet-stream"},
        )

    assert response.status_code == 415


async def test_doh_rejects_invalid_base64url_query(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    write_config(config_path)
    manager = RuntimeManager(config_path)
    await manager.load()
    app = create_webui_app(manager)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(DOH_DNS_QUERY_PATH, params={"dns": "not-valid@@"})

    assert response.status_code == 400


async def test_doh_endpoint_does_not_require_webui_basic_auth(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    write_config(config_path)
    manager = RuntimeManager(config_path)
    await manager.load()
    query = dns.message.make_query("sample.internal", "A")

    config_data = json.loads(config_path.read_text(encoding="utf-8"))
    config_data["webui"]["enabled"] = True
    config_path.write_text(
        json.dumps(config_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    await manager.reload()
    app = create_webui_app(manager)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        config_response = await client.get("/config")
        doh_response = await client.get(
            DOH_DNS_QUERY_PATH,
            params={"dns": _encode_doh_query(query)},
            headers={"Accept": DOH_MEDIA_TYPE},
        )

    assert config_response.status_code == 401
    assert doh_response.status_code == 200


async def test_runtime_can_start_shared_http_server_for_doh(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    write_config(config_path)
    manager = RuntimeManager(config_path)

    await manager.start()
    try:
        assert manager._webui_server is not None
        host, port = manager._webui_server.bound_address()
        assert host
        assert port > 0
    finally:
        await manager.stop()
