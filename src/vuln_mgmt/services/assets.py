from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from vuln_mgmt.domain.entities import Asset
from vuln_mgmt.infrastructure.repositories.base import AssetRepository
from vuln_mgmt.schemas.assets import AssetCreate


class AssetService:
    def __init__(self, repository: AssetRepository) -> None:
        self._repository = repository

    async def create_asset(self, payload: AssetCreate) -> Asset:
        asset = Asset(
            id=str(uuid4()),
            name=payload.name,
            vendor=payload.vendor,
            product=payload.product,
            version=payload.version,
            environment=payload.environment,
            owner=payload.owner,
            criticality=payload.criticality,
            created_at=datetime.now(timezone.utc),
        )
        return await self._repository.create(asset)

    async def list_assets(self) -> list[Asset]:
        return list(await self._repository.list_all())

    async def get_asset(self, asset_id: str) -> Asset | None:
        return await self._repository.get_by_id(asset_id)

