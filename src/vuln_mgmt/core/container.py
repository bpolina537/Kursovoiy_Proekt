from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncEngine

from vuln_mgmt.core.database import create_engine, create_session_factory, init_db
from vuln_mgmt.core.telemetry import TelemetryHandle, configure_telemetry
from vuln_mgmt.infrastructure.clients.nvd import NvdClient, NvdClientConfig
from vuln_mgmt.infrastructure.repositories.memory import (
    InMemoryAssetRepository,
    InMemoryHealthProbe,
    InMemoryRemediationRepository,
    InMemoryVulnerabilityRepository,
)
from vuln_mgmt.infrastructure.repositories.sqlalchemy import (
    SqlAlchemyAssetRepository,
    SqlAlchemyHealthProbe,
    SqlAlchemyRemediationRepository,
    SqlAlchemyVulnerabilityRepository,
)
from vuln_mgmt.services.assets import AssetService
from vuln_mgmt.services.assessment import AssessmentService
from vuln_mgmt.services.health import HealthService
from vuln_mgmt.services.remediations import RemediationService
from vuln_mgmt.services.vulnerabilities import VulnerabilityService


@dataclass(slots=True)
class AppContainer:
    asset_service: AssetService
    vulnerability_service: VulnerabilityService
    remediation_service: RemediationService
    assessment_service: AssessmentService
    health_service: HealthService
    telemetry: TelemetryHandle
    nvd_client: NvdClient | None = None
    engine: AsyncEngine | None = None

    async def startup(self) -> None:
        if self.nvd_client is not None:
            await self.nvd_client.start()

    async def shutdown(self) -> None:
        if self.nvd_client is not None:
            await self.nvd_client.close()
        if self.engine is not None:
            from vuln_mgmt.core.database import dispose_engine

            await dispose_engine(self.engine)
        await self.telemetry.shutdown()


def build_memory_container() -> AppContainer:
    asset_repository = InMemoryAssetRepository()
    vulnerability_repository = InMemoryVulnerabilityRepository()
    remediation_repository = InMemoryRemediationRepository()
    telemetry = configure_telemetry("vuln-mgmt")
    return AppContainer(
        asset_service=AssetService(asset_repository),
        vulnerability_service=VulnerabilityService(vulnerability_repository),
        remediation_service=RemediationService(
            remediation_repository,
            asset_repository,
            vulnerability_repository,
        ),
        assessment_service=AssessmentService(
            asset_repository,
            vulnerability_repository,
            remediation_repository,
        ),
        health_service=HealthService(InMemoryHealthProbe()),
        telemetry=telemetry,
    )


async def build_sqlalchemy_container(
    database_url: str,
    nvd_config: NvdClientConfig,
    auto_create_schema: bool,
) -> AppContainer:
    engine = create_engine(database_url)
    session_factory = create_session_factory(engine)
    if auto_create_schema:
        await init_db(engine)
    asset_repository = SqlAlchemyAssetRepository(session_factory)
    vulnerability_repository = SqlAlchemyVulnerabilityRepository(session_factory)
    remediation_repository = SqlAlchemyRemediationRepository(session_factory)
    nvd_client = NvdClient(nvd_config)
    telemetry = configure_telemetry("vuln-mgmt")
    return AppContainer(
        asset_service=AssetService(asset_repository),
        vulnerability_service=VulnerabilityService(vulnerability_repository, nvd_client),
        remediation_service=RemediationService(
            remediation_repository,
            asset_repository,
            vulnerability_repository,
        ),
        assessment_service=AssessmentService(
            asset_repository,
            vulnerability_repository,
            remediation_repository,
        ),
        health_service=HealthService(SqlAlchemyHealthProbe(session_factory)),
        telemetry=telemetry,
        nvd_client=nvd_client,
        engine=engine,
    )
