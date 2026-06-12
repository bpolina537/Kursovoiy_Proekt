from __future__ import annotations

from datetime import datetime, timezone

from vuln_mgmt.core.container import AppContainer
from vuln_mgmt.schemas.assets import AssetCreate
from vuln_mgmt.schemas.remediations import RemediationCreate
from vuln_mgmt.schemas.vulnerabilities import VulnerabilityCreate


async def seed_demo_data(container: AppContainer) -> None:
    assets = await container.asset_service.list_assets()
    vulnerabilities = await container.vulnerability_service.list_vulnerabilities()
    if assets or vulnerabilities:
        return

    crm = await container.asset_service.create_asset(
        AssetCreate(
            name="CRM Portal",
            vendor="Acme",
            product="crm",
            version="1.0.0",
            environment="production",
            owner="IT Security",
            criticality=5,
        )
    )
    billing = await container.asset_service.create_asset(
        AssetCreate(
            name="Billing API",
            vendor="Acme",
            product="billing-api",
            version="2.4.1",
            environment="staging",
            owner="Platform Team",
            criticality=4,
        )
    )

    crm_vulnerability = await container.vulnerability_service.create_vulnerability(
        VulnerabilityCreate(
            cve_id="CVE-2024-11111",
            title="Remote code execution in CRM component",
            description=(
                "Уязвимость позволяет выполнить произвольный код в компоненте CRM "
                "при обработке специально подготовленного запроса."
            ),
            cvss_score=9.8,
            severity="critical",
            affected_vendor="Acme",
            affected_product="crm",
            fixed_version="1.1.0",
            published_at=datetime(2024, 1, 10, 10, 0, tzinfo=timezone.utc),
            exploit_available=True,
        )
    )
    await container.vulnerability_service.create_vulnerability(
        VulnerabilityCreate(
            cve_id="CVE-2024-22222",
            title="Authentication bypass in Billing API",
            description=(
                "Некорректная проверка прав доступа может привести к обходу "
                "аутентификации для части служебных методов."
            ),
            cvss_score=8.1,
            severity="high",
            affected_vendor="Acme",
            affected_product="billing-api",
            fixed_version="2.5.0",
            published_at=datetime(2024, 2, 5, 9, 30, tzinfo=timezone.utc),
            exploit_available=False,
        )
    )
    await container.vulnerability_service.create_vulnerability(
        VulnerabilityCreate(
            cve_id="CVE-2024-33333",
            title="Information disclosure in legacy module",
            description="Уязвимость раскрытия служебной информации в устаревшем модуле.",
            cvss_score=5.6,
            severity="medium",
            affected_vendor="LegacySoft",
            affected_product="legacy-module",
            fixed_version="3.2.0",
            published_at=datetime(2024, 3, 14, 12, 15, tzinfo=timezone.utc),
            exploit_available=False,
        )
    )

    await container.remediation_service.create_remediation(
        RemediationCreate(
            asset_id=crm.id,
            vulnerability_id=crm_vulnerability.id,
            status="in_progress",
            note="Патч 1.1.0 запланирован к установке после резервного копирования.",
        )
    )
