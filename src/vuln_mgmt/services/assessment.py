from __future__ import annotations

from vuln_mgmt.domain.entities import AssessmentFinding, AssetAssessmentReport
from vuln_mgmt.domain.risk import calculate_priority_score, classify_risk, is_version_affected
from vuln_mgmt.infrastructure.repositories.base import (
    AssetRepository,
    RemediationRepository,
    VulnerabilityRepository,
)


class AssessmentService:
    def __init__(
        self,
        asset_repository: AssetRepository,
        vulnerability_repository: VulnerabilityRepository,
        remediation_repository: RemediationRepository,
    ) -> None:
        self._asset_repository = asset_repository
        self._vulnerability_repository = vulnerability_repository
        self._remediation_repository = remediation_repository

    async def build_asset_report(self, asset_id: str) -> AssetAssessmentReport | None:
        asset = await self._asset_repository.get_by_id(asset_id)
        if asset is None:
            return None
        vulnerabilities = await self._vulnerability_repository.list_all()
        remediations = await self._remediation_repository.list_by_asset_id(asset_id)
        remediation_index = {item.vulnerability_id: item for item in remediations}

        findings: list[AssessmentFinding] = []
        for vulnerability in vulnerabilities:
            if vulnerability.affected_vendor.lower() != asset.vendor.lower():
                continue
            if vulnerability.affected_product.lower() != asset.product.lower():
                continue
            if not is_version_affected(asset.version, vulnerability.fixed_version):
                continue
            score = calculate_priority_score(
                vulnerability.cvss_score,
                asset.environment,
                asset.criticality,
                vulnerability.exploit_available,
            )
            findings.append(
                AssessmentFinding(
                    vulnerability=vulnerability,
                    remediation_status=(
                        remediation_index[vulnerability.id].status
                        if vulnerability.id in remediation_index
                        else None
                    ),
                    priority_score=score,
                    risk_level=classify_risk(score),
                    match_reason="vendor/product/version match",
                )
            )

        overall_score = round(
            max((finding.priority_score for finding in findings), default=0.0),
            2,
        )
        risk_level = classify_risk(overall_score)
        return AssetAssessmentReport(
            asset=asset,
            overall_score=overall_score,
            risk_level=risk_level,
            findings=sorted(findings, key=lambda item: item.priority_score, reverse=True),
        )
