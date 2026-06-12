from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from vuln_mgmt.app import create_app
from vuln_mgmt.core.config import load_settings
from vuln_mgmt.core.container import build_memory_container


@pytest.fixture
def test_app():
    settings = load_settings({"database_url": "memory://tests"})
    return create_app(settings=settings, container=build_memory_container())


@pytest.fixture
async def api_client(test_app) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client

