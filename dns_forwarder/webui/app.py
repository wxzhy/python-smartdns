from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from dns_forwarder.config import (
    build_config_json_schema,
    dump_config_text,
    parse_config_text,
    save_config,
)
from dns_forwarder.logging import get_logger
from dns_forwarder.plugin_api import discover_available_plugins
from dns_forwarder.server.doh import register_doh_routes

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
logger = get_logger("webui.app")
JSONEDITOR_JS_URL = "https://cdn.jsdelivr.net/npm/jsoneditor@10.4.2/dist/jsoneditor.min.js"
JSONEDITOR_CSS_URL = "https://cdn.jsdelivr.net/npm/jsoneditor@10.4.2/dist/jsoneditor.min.css"
WEBUI_RELOAD_ENDPOINT = "/admin/reload"
QUERY_LOG_PAGE_SIZE = 100

if TYPE_CHECKING:
    from dns_forwarder.core.runtime import RuntimeManager
    from plugins.query_log_plugin import QueryLogStore


@dataclass(frozen=True, slots=True)
class ConfigEditorView:
    """配置编辑器视图所需的数据集合。"""

    config_text: str
    available_plugins: list
    plugin_dirs: list[str]
    editor_mode: str
    message: str
    error: str


def _build_config_context(
    runtime_manager: RuntimeManager,
    *,
    view: ConfigEditorView,
) -> dict:
    """构造配置编辑器页面的模板上下文。"""
    return runtime_manager.get_status() | {
        "config_text": view.config_text,
        "config_schema": build_config_json_schema(view.plugin_dirs),
        "available_plugins": [item.describe() for item in view.available_plugins],
        "editor_mode": view.editor_mode,
        "config_filename": runtime_manager.config_path.name,
        "jsoneditor_js_url": JSONEDITOR_JS_URL,
        "jsoneditor_css_url": JSONEDITOR_CSS_URL,
        "message": view.message,
        "error": view.error,
    }


def _authorize_webui(
    runtime_manager: RuntimeManager,
    security: HTTPBasic,
):
    def authorize_webui(
        # FastAPI 的依赖注入惯用法：在参数默认值中调用 Depends。
        credentials: HTTPBasicCredentials = Depends(security),  # noqa: B008
    ) -> None:
        webui_config = runtime_manager.get_state().config.webui
        expected_username = webui_config.username.encode("utf-8")
        expected_password = webui_config.password.encode("utf-8")
        current_username = credentials.username.encode("utf-8")
        current_password = credentials.password.encode("utf-8")
        is_valid = secrets.compare_digest(
            current_username, expected_username
        ) and secrets.compare_digest(
            current_password,
            expected_password,
        )
        if is_valid:
            return
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    return authorize_webui


def create_webui_app(runtime_manager: RuntimeManager) -> FastAPI:
    security = HTTPBasic()
    authorize_webui = _authorize_webui(runtime_manager, security)

    app = FastAPI(title="dns-forwarder http", docs_url=None, redoc_url=None)

    def get_query_log_store() -> QueryLogStore | None:
        return runtime_manager.get_query_log_store()

    def get_query_log_store_or_503() -> QueryLogStore:
        store = get_query_log_store()
        if store is None:
            raise HTTPException(status_code=503, detail="query log plugin is not enabled")
        return store

    if runtime_manager.get_state().config.webui.enabled:

        @app.get("/", response_class=HTMLResponse, dependencies=[Depends(authorize_webui)])
        async def index(request: Request) -> HTMLResponse:
            return TEMPLATES.TemplateResponse(
                request=request,
                name="index.html",
                context=runtime_manager.get_status(),
            )

        @app.get("/queries", response_class=HTMLResponse, dependencies=[Depends(authorize_webui)])
        async def query_logs_view(request: Request) -> HTMLResponse:
            store = get_query_log_store()
            return TEMPLATES.TemplateResponse(
                request=request,
                name="queries.html",
                context=runtime_manager.get_status()
                | {
                    "query_log_enabled": store is not None,
                    "query_logs_api_url": "/api/query-logs",
                    "query_logs_stream_url": "/api/query-logs/stream",
                    "page_size": QUERY_LOG_PAGE_SIZE,
                },
            )

        @app.get("/config", response_class=HTMLResponse, dependencies=[Depends(authorize_webui)])
        async def config_editor(request: Request) -> HTMLResponse:
            state = runtime_manager.get_state()
            available_plugins = discover_available_plugins(state.config.runtime.plugin_dirs)
            return TEMPLATES.TemplateResponse(
                request=request,
                name="config.html",
                context=_build_config_context(
                    runtime_manager,
                    view=ConfigEditorView(
                        config_text=dump_config_text(state.config),
                        available_plugins=available_plugins,
                        plugin_dirs=state.config.runtime.plugin_dirs,
                        editor_mode="tree",
                        message="",
                        error="",
                    ),
                ),
            )

        @app.post("/config", response_class=HTMLResponse, dependencies=[Depends(authorize_webui)])
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
                state = runtime_manager.get_state()
                available_plugins = discover_available_plugins(state.config.runtime.plugin_dirs)
                return TEMPLATES.TemplateResponse(
                    request=request,
                    name="config.html",
                    context=_build_config_context(
                        runtime_manager,
                        view=ConfigEditorView(
                            config_text=config_text,
                            available_plugins=available_plugins,
                            plugin_dirs=state.config.runtime.plugin_dirs,
                            editor_mode="code",
                            message="",
                            error=str(exc),
                        ),
                    ),
                    status_code=400,
                )

            available_plugins = discover_available_plugins(config.runtime.plugin_dirs)
            return TEMPLATES.TemplateResponse(
                request=request,
                name="config.html",
                context=_build_config_context(
                    runtime_manager,
                    view=ConfigEditorView(
                        config_text=dump_config_text(config),
                        available_plugins=available_plugins,
                        plugin_dirs=config.runtime.plugin_dirs,
                        editor_mode="tree",
                        message="配置已保存，请手动 reload 使其生效。",
                        error="",
                    ),
                ),
            )

        @app.post(
            WEBUI_RELOAD_ENDPOINT, response_model=None, dependencies=[Depends(authorize_webui)]
        )
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

        @app.get("/api/query-logs", dependencies=[Depends(authorize_webui)])
        async def query_logs_api(
            limit: Annotated[int, Query(ge=1)] = QUERY_LOG_PAGE_SIZE,
        ) -> JSONResponse:
            store = get_query_log_store_or_503()
            items = await store.list_recent(min(limit, store.max_entries))
            return JSONResponse([item.model_dump(mode="json") for item in items])

        @app.get("/api/query-logs/stream", dependencies=[Depends(authorize_webui)])
        async def query_logs_stream(
            request: Request,
            after_id: Annotated[int | None, Query(ge=0)] = None,
        ) -> StreamingResponse:
            store = get_query_log_store_or_503()

            async def event_stream():
                async for item in store.subscribe(after_id):
                    if await request.is_disconnected():
                        break
                    if item is None:
                        yield ": ping\n\n"
                        continue
                    payload = json.dumps(item.model_dump(mode="json"), ensure_ascii=False)
                    yield f"id: {item.id}\nevent: query\ndata: {payload}\n\n"

            return StreamingResponse(
                event_stream(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-store",
                    "X-Accel-Buffering": "no",
                },
            )

    if runtime_manager.get_state().config.webui.doh_enabled:
        register_doh_routes(app, runtime_manager, listener_name="doh")

    return app


class ManagedUvicornServer:
    def __init__(self, app: FastAPI, host: str, port: int) -> None:
        self._config = uvicorn.Config(
            app=app,
            host=host,
            port=port,
            log_level="info",
            loop="none",
        )
        self._server = uvicorn.Server(self._config)
        self._server.install_signal_handlers = lambda: None
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._server.serve())
        # uvicorn 未暴露就绪事件，这里轮询其内部 started 标志。
        while not self._server.started:  # noqa: ASYNC110
            await asyncio.sleep(0.01)
        logger.info("HTTP server 就绪 address=%s:%s", *self.bound_address())

    async def stop(self) -> None:
        address = self.bound_address()
        self._server.should_exit = True
        if self._task is not None:
            await self._task
            self._task = None
            logger.info("HTTP server 已停止 address=%s:%s", *address)

    def bound_address(self) -> tuple[str, int]:
        servers = getattr(self._server, "servers", None)
        if servers:
            sockets = servers[0].sockets
            if sockets:
                sockname = sockets[0].getsockname()
                return sockname[0], sockname[1]
        return self._config.host or "127.0.0.1", self._config.port
