from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from vuln_mgmt.domain.entities import Asset, Remediation, Vulnerability


class AssetRepository(Protocol):
    async def create(self, asset: Asset) -> Asset: ...

    async def list_all(self) -> Sequence[Asset]: ...

    async def get_by_id(self, asset_id: str) -> Asset | None: ...


class VulnerabilityRepository(Protocol):
    async def create(self, vulnerability: Vulnerability) -> Vulnerability: ...

    async def get_by_id(self, vulnerability_id: str) -> Vulnerability | None: ...

    async def get_by_cve_id(self, cve_id: str) -> Vulnerability | None: ...

    async def list_all(self) -> Sequence[Vulnerability]: ...


class RemediationRepository(Protocol):
    async def create(self, remediation: Remediation) -> Remediation: ...

    async def update_status(
        self,
        remediation_id: str,
        status: str,
        note: str,
    ) -> Remediation | None: ...

    async def list_by_asset_id(self, asset_id: str) -> Sequence[Remediation]: ...

    async def get_by_id(self, remediation_id: str) -> Remediation | None: ...

    async def list_all(self) -> Sequence[Remediation]: ...


class HealthProbe(Protocol):
    async def ping(self) -> bool: ...
