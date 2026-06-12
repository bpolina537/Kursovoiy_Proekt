from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from vuln_mgmt.domain.errors import EntityNotFoundError
from vuln_mgmt.domain.entities import Remediation
from vuln_mgmt.infrastructure.repositories.base import (
    AssetRepository,
    RemediationRepository,
    VulnerabilityRepository,
)
from vuln_mgmt.schemas.remediations import RemediationCreate, RemediationStatusUpdate


class RemediationService:
    def __init__(
        self,
        repository: RemediationRepository,
        asset_repository: AssetRepository | None = None,
        vulnerability_repository: VulnerabilityRepository | None = None,
    ) -> None:
        self._repository = repository
        self._asset_repository = asset_repository
        self._vulnerability_repository = vulnerability_repository

    async def create_remediation(self, payload: RemediationCreate) -> Remediation:
        if self._asset_repository is not None:
            asset = await self._asset_repository.get_by_id(payload.asset_id)
            if asset is None:
                raise EntityNotFoundError("Asset not found")
        if self._vulnerability_repository is not None:
            vulnerability = await self._vulnerability_repository.get_by_id(payload.vulnerability_id)
            if vulnerability is None:
                raise EntityNotFoundError("Vulnerability not found")
        remediation = Remediation(
            id=str(uuid4()),
            asset_id=payload.asset_id,
            vulnerability_id=payload.vulnerability_id,
            status=payload.status,
            note=payload.note,
            due_date=payload.due_date,
            updated_at=datetime.now(timezone.utc),
        )
        return await self._repository.create(remediation)

    async def update_status(
        self,
        remediation_id: str,
        payload: RemediationStatusUpdate,
    ) -> Remediation | None:
        return await self._repository.update_status(remediation_id, payload.status, payload.note)

    async def list_for_asset(self, asset_id: str) -> list[Remediation]:
        return list(await self._repository.list_by_asset_id(asset_id))

    async def get_by_id(self, remediation_id: str) -> Remediation | None:
        return await self._repository.get_by_id(remediation_id)

    async def list_remediations(self) -> list[Remediation]:
        return list(await self._repository.list_all())
