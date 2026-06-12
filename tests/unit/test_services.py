from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vuln_mgmt.domain.entities import Vulnerability
from vuln_mgmt.infrastructure.repositories.memory import (
    InMemoryAssetRepository,
    InMemoryRemediationRepository,
    InMemoryVulnerabilityRepository,
)
from vuln_mgmt.schemas.assets import AssetCreate
from vuln_mgmt.schemas.remediations import RemediationCreate
from vuln_mgmt.schemas.vulnerabilities import VulnerabilityImportRequest
from vuln_mgmt.services.assets import AssetService
from vuln_mgmt.services.assessment import AssessmentService
from vuln_mgmt.services.remediations import RemediationService
from vuln_mgmt.services.vulnerabilities import VulnerabilityService


class FakeNvdClient:
    async def fetch_vulnerability(self, cve_id: str) -> dict[str, object]:
        return {"id": cve_id}

    @staticmethod
    def to_domain_entity(
        payload: dict[str, object],
        *,
        cve_id: str,
        affected_vendor: str,
        affected_product: str,
        fixed_version: str | None,
    ) -> Vulnerability:
        return Vulnerability(
            id="vuln-1",
            cve_id=cve_id,
            title=cve_id,
            description="Remote code execution",
            cvss_score=9.8,
            severity="critical",
            affected_vendor=affected_vendor,
            affected_product=affected_product,
            fixed_version=fixed_version,
            published_at=datetime.now(timezone.utc),
            exploit_available=True,
        )


@pytest.mark.asyncio
async def test_asset_service_creates_timezone_aware_asset() -> None:
    repository = InMemoryAssetRepository()
    service = AssetService(repository)

    asset = await service.create_asset(
        AssetCreate(
            name="CRM",
            vendor="Acme",
            product="crm",
            version="1.0.0",
            environment="production",
            owner="IT",
            criticality=5,
        )
    )

    assert asset.id
    assert asset.created_at.tzinfo is not None


@pytest.mark.asyncio
async def test_nvd_import_uses_repository_cache() -> None:
    repository = InMemoryVulnerabilityRepository()
    service = VulnerabilityService(repository, FakeNvdClient())
    request = VulnerabilityImportRequest(
        cve_id="CVE-2024-12345",
        affected_vendor="Acme",
        affected_product="crm",
        fixed_version="1.1.0",
    )

    first = await service.import_from_nvd(request)
    second = await service.import_from_nvd(request)

    assert first.id == second.id
    assert len(await repository.list_all()) == 1


@pytest.mark.asyncio
async def test_assessment_ignores_mitigated_version() -> None:
    asset_repository = InMemoryAssetRepository()
    vulnerability_repository = InMemoryVulnerabilityRepository()
    remediation_repository = InMemoryRemediationRepository()
    asset_service = AssetService(asset_repository)
    vulnerability_service = VulnerabilityService(vulnerability_repository, FakeNvdClient())
    remediation_service = RemediationService(
        remediation_repository,
        asset_repository,
        vulnerability_repository,
    )
    assessment_service = AssessmentService(
        asset_repository,
        vulnerability_repository,
        remediation_repository,
    )

    asset = await asset_service.create_asset(
        AssetCreate(
            name="CRM",
            vendor="Acme",
            product="crm",
            version="1.0.0",
            environment="production",
            owner="IT",
            criticality=5,
        )
    )
    vulnerability = await vulnerability_service.import_from_nvd(
        VulnerabilityImportRequest(
            cve_id="CVE-2024-12345",
            affected_vendor="Acme",
            affected_product="crm",
            fixed_version="1.1.0",
        )
    )
    await remediation_service.create_remediation(
        RemediationCreate(
            asset_id=asset.id,
            vulnerability_id=vulnerability.id,
            status="in_progress",
            note="patch planned",
        )
    )

    report = await assessment_service.build_asset_report(asset.id)

    assert report is not None
    assert report.findings[0].remediation_status == "in_progress"
    assert report.overall_score > 0
