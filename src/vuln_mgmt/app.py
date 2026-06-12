from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from vuln_mgmt.core.config import load_settings
from vuln_mgmt.core.container import (
    AppContainer,
    build_memory_container,
    build_sqlalchemy_container,
)
from vuln_mgmt.core.logging import configure_logging
from vuln_mgmt.core.telemetry import instrument_fastapi
from vuln_mgmt.infrastructure.clients.nvd import NvdClientConfig
from vuln_mgmt.routers.assets import router as assets_router
from vuln_mgmt.routers.dashboard import router as dashboard_router
from vuln_mgmt.routers.health import router as health_router
from vuln_mgmt.routers.remediations import router as remediations_router
from vuln_mgmt.routers.vulnerabilities import router as vulnerabilities_router
from vuln_mgmt.services.demo import seed_demo_data

UI_DIR = Path(__file__).resolve().parent / "ui"


async def _build_default_container(settings: Any) -> AppContainer:
    if settings.database_url.startswith("postgresql"):
        return await build_sqlalchemy_container(
            database_url=settings.database_url,
            nvd_config=NvdClientConfig(
                base_url=settings.nvd_api_base_url,
                api_key=settings.nvd_api_key,
                timeout_seconds=settings.request_timeout_seconds,
            ),
            auto_create_schema=settings.auto_create_schema,
        )
    return build_memory_container()


def create_app(settings: Any | None = None, container: AppContainer | None = None) -> FastAPI:
    runtime_settings = settings or load_settings()
    configure_logging(runtime_settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = runtime_settings
        if container is None:
            app.state.container = await _build_default_container(runtime_settings)
        else:
            app.state.container = container
        await app.state.container.startup()
        await seed_demo_data(app.state.container)
        try:
            yield
        finally:
            await app.state.container.shutdown()

    app = FastAPI(title=runtime_settings.app_name, lifespan=lifespan)
    app.state.settings = runtime_settings
    if container is not None:
        app.state.container = container
    app.mount("/ui", StaticFiles(directory=UI_DIR), name="ui")
    app.include_router(health_router)
    app.include_router(dashboard_router)
    app.include_router(assets_router)
    app.include_router(vulnerabilities_router)
    app.include_router(remediations_router)
    instrument_fastapi(app)
    return app
