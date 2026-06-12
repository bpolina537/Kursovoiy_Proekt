from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_and_readiness(api_client: AsyncClient) -> None:
    health = await api_client.get("/health")
    ready = await api_client.get("/ready")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_dashboard_is_available(api_client: AsyncClient) -> None:
    response = await api_client.get("/")

    assert response.status_code == 200
    assert "Платформа управления уязвимостями" in response.text


@pytest.mark.asyncio
async def test_create_asset_validation_error(api_client: AsyncClient) -> None:
    response = await api_client.post("/assets", json={"name": "x"})

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_vulnerability_and_assessment_flow(api_client: AsyncClient) -> None:
    asset_response = await api_client.post(
        "/assets",
        json={
            "name": "CRM",
            "vendor": "Acme",
            "product": "crm",
            "version": "1.0.0",
            "environment": "production",
            "owner": "IT",
            "criticality": 5,
        },
    )
    assert asset_response.status_code == 201
    asset_id = asset_response.json()["id"]

    vulnerability_response = await api_client.post(
        "/vulnerabilities",
        json={
            "cve_id": "CVE-2024-11111",
            "title": "Remote code execution",
            "description": "Unauthenticated remote code execution in CRM component",
            "cvss_score": 9.8,
            "severity": "critical",
            "affected_vendor": "Acme",
            "affected_product": "crm",
            "fixed_version": "1.1.0",
            "published_at": datetime.now(timezone.utc).isoformat(),
            "exploit_available": True,
        },
    )
    assert vulnerability_response.status_code == 201
    vulnerability_id = vulnerability_response.json()["id"]

    remediation_response = await api_client.post(
        "/remediations",
        json={
            "asset_id": asset_id,
            "vulnerability_id": vulnerability_id,
            "status": "open",
            "note": "registered by SOC",
        },
    )
    assert remediation_response.status_code == 201

    report_response = await api_client.get(f"/assets/{asset_id}/assessment")
    report = report_response.json()

    assert report_response.status_code == 200
    assert report["risk_level"] == "critical"
    assert report["findings"][0]["remediation_status"] == "open"


@pytest.mark.asyncio
async def test_remediations_list_is_available(api_client: AsyncClient) -> None:
    response = await api_client.get("/remediations")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_update_missing_remediation_returns_404(api_client: AsyncClient) -> None:
    response = await api_client.patch(
        "/remediations/missing",
        json={"status": "mitigated", "note": "patched"},
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_create_remediation_requires_existing_records(api_client: AsyncClient) -> None:
    response = await api_client.post(
        "/remediations",
        json={
            "asset_id": "missing-asset",
            "vulnerability_id": "missing-vulnerability",
            "status": "open",
        },
    )

    assert response.status_code == 404
