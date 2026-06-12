from __future__ import annotations

from uuid import uuid4

from vuln_mgmt.domain.entities import Vulnerability
from vuln_mgmt.infrastructure.clients.nvd import NvdClient
from vuln_mgmt.infrastructure.repositories.base import VulnerabilityRepository
from vuln_mgmt.schemas.vulnerabilities import VulnerabilityCreate, VulnerabilityImportRequest


class VulnerabilityService:
    def __init__(
        self,
        repository: VulnerabilityRepository,
        nvd_client: NvdClient | None = None,
    ) -> None:
        self._repository = repository
        self._nvd_client = nvd_client

    async def create_vulnerability(self, payload: VulnerabilityCreate) -> Vulnerability:
        vulnerability = Vulnerability(
            id=str(uuid4()),
            cve_id=payload.cve_id,
            title=payload.title,
            description=payload.description,
            cvss_score=payload.cvss_score,
            severity=payload.severity,
            affected_vendor=payload.affected_vendor,
            affected_product=payload.affected_product,
            fixed_version=payload.fixed_version,
            published_at=payload.published_at,
            exploit_available=payload.exploit_available,
        )
        return await self._repository.create(vulnerability)

    async def import_from_nvd(self, payload: VulnerabilityImportRequest) -> Vulnerability:
        if self._nvd_client is None:
            raise RuntimeError("NVD client is not configured")
        existing = await self._repository.get_by_cve_id(payload.cve_id)
        if existing is not None:
            return existing
        raw_payload = await self._nvd_client.fetch_vulnerability(payload.cve_id)
        vulnerability = self._nvd_client.to_domain_entity(
            raw_payload,
            cve_id=payload.cve_id,
            affected_vendor=payload.affected_vendor,
            affected_product=payload.affected_product,
            fixed_version=payload.fixed_version,
        )
        return await self._repository.create(vulnerability)

    async def list_vulnerabilities(self) -> list[Vulnerability]:
        return list(await self._repository.list_all())

    async def get_vulnerability(self, vulnerability_id: str) -> Vulnerability | None:
        return await self._repository.get_by_id(vulnerability_id)
