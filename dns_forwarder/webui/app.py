from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated
from typing import TYPE_CHECKING

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import uvicorn

from dns_forwarder.config import dump_config_text, parse_config_text, save_config
from dns_forwarder.logging import get_logger

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
logger = get_logger("webui.app")

if TYPE_CHECKING:
    from dns_forwarder.core.runtime import RuntimeManager


def create_webui_app(runtime_manager: "RuntimeManager") -> FastAPI:
    app = FastAPI(title="dns-forwarder webui", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return TEMPLATES.TemplateResponse(
            request=request,
            name="index.html",
            context=runtime_manager.get_status(),
        )

    @app.get("/config", response_class=HTMLResponse)
    async def config_editor(request: Request) -> HTMLResponse:
        state = runtime_manager.get_state()
        return TEMPLATES.TemplateResponse(
            request=request,
            name="config.html",
            context=runtime_manager.get_status()
            | {
                "config_text": dump_config_text(state.config),
                "message": "",
                "error": "",
            },
        )

    @app.post("/config", response_class=HTMLResponse)
    async def save_config_view(
        request: Request,
        config_text: Annotated[str, Form()],
    ) -> HTMLResponse:
        try:
            config = parse_config_text(config_text)
            save_config(config, runtime_manager.config_path)
            logger.info("保存配置成功 path=%s", runtime_manager.config_path)
        except Exception as exc:
            logger.warning("保存配置失败 path=%s error=%s", runtime_manager.config_path, exc)
            return TEMPLATES.TemplateResponse(
                request=request,
                name="config.html",
                context=runtime_manager.get_status()
                | {
                    "config_text": config_text,
                    "message": "",
                    "error": str(exc),
                },
                status_code=400,
            )

        return TEMPLATES.TemplateResponse(
            request=request,
            name="config.html",
            context=runtime_manager.get_status()
            | {
                "config_text": config_text,
                "message": "配置已保存，请手动 reload 使其生效。",
                "error": "",
            },
        )

    @app.post(runtime_manager.reload_endpoint, response_model=None)
    async def manual_reload(request: Request):
        try:
            logger.info("收到手动 reload 请求 path=%s", runtime_manager.config_path)
            await runtime_manager.reload()
        except Exception as exc:
            logger.error("手动 reload 失败 path=%s error=%s", runtime_manager.config_path, exc)
            return TEMPLATES.TemplateResponse(
                request=request,
                name="index.html",
                context=runtime_manager.get_status() | {"error": str(exc)},
                status_code=400,
            )
        logger.info("手动 reload 完成 path=%s", runtime_manager.config_path)
        return RedirectResponse(url="/", status_code=303)

    return app


class ManagedUvicornServer:
    def __init__(self, app: FastAPI, host: str, port: int) -> None:
        self._config = uvicorn.Config(
            app=app, host=host, port=port, log_level="info", loop="none"
        )
        self._server = uvicorn.Server(self._config)
        self._server.install_signal_handlers = lambda: None
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._server.serve())
        while not self._server.started:
            await asyncio.sleep(0.01)
        logger.info("webui server 就绪 address=%s:%s", self._config.host, self._config.port)

    async def stop(self) -> None:
        self._server.should_exit = True
        if self._task is not None:
            await self._task
            self._task = None
            logger.info("webui server 已停止 address=%s:%s", self._config.host, self._config.port)
