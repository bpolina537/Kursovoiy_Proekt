from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from vuln_mgmt.domain.entities import Asset, Remediation, Vulnerability
from vuln_mgmt.infrastructure.db.models import AssetORM, RemediationORM, VulnerabilityORM


def _asset_to_entity(row: AssetORM) -> Asset:
    return Asset(
        id=row.id,
        name=row.name,
        vendor=row.vendor,
        product=row.product,
        version=row.version,
        environment=row.environment,
        owner=row.owner,
        criticality=row.criticality,
        created_at=row.created_at,
    )


def _vulnerability_to_entity(row: VulnerabilityORM) -> Vulnerability:
    return Vulnerability(
        id=row.id,
        cve_id=row.cve_id,
        title=row.title,
        description=row.description,
        cvss_score=row.cvss_score,
        severity=row.severity,
        affected_vendor=row.affected_vendor,
        affected_product=row.affected_product,
        fixed_version=row.fixed_version,
        published_at=row.published_at,
        exploit_available=row.exploit_available,
    )


def _remediation_to_entity(row: RemediationORM) -> Remediation:
    return Remediation(
        id=row.id,
        asset_id=row.asset_id,
        vulnerability_id=row.vulnerability_id,
        status=row.status,
        note=row.note,
        due_date=row.due_date,
        updated_at=row.updated_at,
    )


class SqlAlchemyAssetRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(self, asset: Asset) -> Asset:
        async with self._session_factory() as session:
            async with session.begin():
                row = AssetORM(
                    id=asset.id,
                    name=asset.name,
                    vendor=asset.vendor,
                    product=asset.product,
                    version=asset.version,
                    environment=asset.environment,
                    owner=asset.owner,
                    criticality=asset.criticality,
                    created_at=asset.created_at,
                )
                session.add(row)
                await session.flush()
                return _asset_to_entity(row)

    async def list_all(self) -> Sequence[Asset]:
        async with self._session_factory() as session:
            result = await session.execute(select(AssetORM).order_by(AssetORM.created_at.desc()))
            return [_asset_to_entity(row) for row in result.scalars().all()]

    async def get_by_id(self, asset_id: str) -> Asset | None:
        async with self._session_factory() as session:
            row = await session.get(AssetORM, asset_id)
            return _asset_to_entity(row) if row is not None else None


class SqlAlchemyVulnerabilityRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(self, vulnerability: Vulnerability) -> Vulnerability:
        async with self._session_factory() as session:
            async with session.begin():
                existing = await session.scalar(
                    select(VulnerabilityORM).where(VulnerabilityORM.cve_id == vulnerability.cve_id)
                )
                if existing is not None:
                    existing.title = vulnerability.title
                    existing.description = vulnerability.description
                    existing.cvss_score = vulnerability.cvss_score
                    existing.severity = vulnerability.severity
                    existing.affected_vendor = vulnerability.affected_vendor
                    existing.affected_product = vulnerability.affected_product
                    existing.fixed_version = vulnerability.fixed_version
                    existing.published_at = vulnerability.published_at
                    existing.exploit_available = vulnerability.exploit_available
                    await session.flush()
                    return _vulnerability_to_entity(existing)
                row = VulnerabilityORM(
                    id=vulnerability.id,
                    cve_id=vulnerability.cve_id,
                    title=vulnerability.title,
                    description=vulnerability.description,
                    cvss_score=vulnerability.cvss_score,
                    severity=vulnerability.severity,
                    affected_vendor=vulnerability.affected_vendor,
                    affected_product=vulnerability.affected_product,
                    fixed_version=vulnerability.fixed_version,
                    published_at=vulnerability.published_at,
                    exploit_available=vulnerability.exploit_available,
                )
                session.add(row)
                await session.flush()
                return _vulnerability_to_entity(row)

    async def get_by_id(self, vulnerability_id: str) -> Vulnerability | None:
        async with self._session_factory() as session:
            row = await session.get(VulnerabilityORM, vulnerability_id)
            return _vulnerability_to_entity(row) if row is not None else None

    async def get_by_cve_id(self, cve_id: str) -> Vulnerability | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(VulnerabilityORM).where(VulnerabilityORM.cve_id == cve_id)
            )
            return _vulnerability_to_entity(row) if row is not None else None

    async def list_all(self) -> Sequence[Vulnerability]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(VulnerabilityORM).order_by(VulnerabilityORM.published_at.desc())
            )
            return [_vulnerability_to_entity(row) for row in result.scalars().all()]


class SqlAlchemyRemediationRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(self, remediation: Remediation) -> Remediation:
        async with self._session_factory() as session:
            async with session.begin():
                row = RemediationORM(
                    id=remediation.id,
                    asset_id=remediation.asset_id,
                    vulnerability_id=remediation.vulnerability_id,
                    status=remediation.status,
                    note=remediation.note,
                    due_date=remediation.due_date,
                    updated_at=remediation.updated_at,
                )
                session.add(row)
                await session.flush()
                return _remediation_to_entity(row)

    async def update_status(
        self,
        remediation_id: str,
        status: str,
        note: str,
    ) -> Remediation | None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(RemediationORM, remediation_id)
                if row is None:
                    return None
                row.status = status
                row.note = note
                row.updated_at = datetime.now(timezone.utc)
                await session.flush()
                return _remediation_to_entity(row)

    async def list_by_asset_id(self, asset_id: str) -> Sequence[Remediation]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(RemediationORM)
                .where(RemediationORM.asset_id == asset_id)
                .order_by(RemediationORM.updated_at.desc())
            )
            return [_remediation_to_entity(row) for row in result.scalars().all()]

    async def get_by_id(self, remediation_id: str) -> Remediation | None:
        async with self._session_factory() as session:
            row = await session.get(RemediationORM, remediation_id)
            return _remediation_to_entity(row) if row is not None else None


class SqlAlchemyHealthProbe:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def ping(self) -> bool:
        async with self._session_factory() as session:
            await session.execute(select(1))
            return True
