from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from datetime import datetime, timezone

from vuln_mgmt.domain.entities import Asset, Remediation, Vulnerability


class InMemoryAssetRepository:
    def __init__(self) -> None:
        self._items: dict[str, Asset] = {}

    async def create(self, asset: Asset) -> Asset:
        self._items[asset.id] = asset
        return deepcopy(asset)

    async def list_all(self) -> Sequence[Asset]:
        return [deepcopy(item) for item in self._items.values()]

    async def get_by_id(self, asset_id: str) -> Asset | None:
        item = self._items.get(asset_id)
        return deepcopy(item) if item is not None else None


class InMemoryVulnerabilityRepository:
    def __init__(self) -> None:
        self._items: dict[str, Vulnerability] = {}
        self._by_cve: dict[str, str] = {}

    async def create(self, vulnerability: Vulnerability) -> Vulnerability:
        self._items[vulnerability.id] = vulnerability
        self._by_cve[vulnerability.cve_id] = vulnerability.id
        return deepcopy(vulnerability)

    async def get_by_id(self, vulnerability_id: str) -> Vulnerability | None:
        item = self._items.get(vulnerability_id)
        return deepcopy(item) if item is not None else None

    async def get_by_cve_id(self, cve_id: str) -> Vulnerability | None:
        item_id = self._by_cve.get(cve_id)
        if item_id is None:
            return None
        return await self.get_by_id(item_id)

    async def list_all(self) -> Sequence[Vulnerability]:
        return [deepcopy(item) for item in self._items.values()]


class InMemoryRemediationRepository:
    def __init__(self) -> None:
        self._items: dict[str, Remediation] = {}

    async def create(self, remediation: Remediation) -> Remediation:
        self._items[remediation.id] = remediation
        return deepcopy(remediation)

    async def update_status(
        self,
        remediation_id: str,
        status: str,
        note: str,
    ) -> Remediation | None:
        remediation = self._items.get(remediation_id)
        if remediation is None:
            return None
        updated = Remediation(
            id=remediation.id,
            asset_id=remediation.asset_id,
            vulnerability_id=remediation.vulnerability_id,
            status=status,
            note=note,
            due_date=remediation.due_date,
            updated_at=datetime.now(timezone.utc),
        )
        self._items[remediation_id] = updated
        return deepcopy(updated)

    async def list_by_asset_id(self, asset_id: str) -> Sequence[Remediation]:
        return [deepcopy(item) for item in self._items.values() if item.asset_id == asset_id]

    async def get_by_id(self, remediation_id: str) -> Remediation | None:
        item = self._items.get(remediation_id)
        return deepcopy(item) if item is not None else None

    async def list_all(self) -> Sequence[Remediation]:
        return [deepcopy(item) for item in self._items.values()]


class InMemoryHealthProbe:
    async def ping(self) -> bool:
        return True
