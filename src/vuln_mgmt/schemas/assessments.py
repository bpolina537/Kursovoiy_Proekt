from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from vuln_mgmt.schemas.assets import AssetRead
from vuln_mgmt.schemas.vulnerabilities import VulnerabilityRead


class AssessmentFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    vulnerability: VulnerabilityRead
    remediation_status: str | None
    priority_score: float
    risk_level: str
    match_reason: str


class AssetAssessmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset: AssetRead
    overall_score: float
    risk_level: str
    findings: list[AssessmentFindingRead]

