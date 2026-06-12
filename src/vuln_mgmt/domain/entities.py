from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime


@dataclass(slots=True, frozen=True)
class Asset:
    id: str
    name: str
    vendor: str
    product: str
    version: str
    environment: str
    owner: str
    criticality: int
    created_at: datetime


@dataclass(slots=True, frozen=True)
class Vulnerability:
    id: str
    cve_id: str
    title: str
    description: str
    cvss_score: float
    severity: str
    affected_vendor: str
    affected_product: str
    fixed_version: str | None
    published_at: datetime
    exploit_available: bool


@dataclass(slots=True, frozen=True)
class Remediation:
    id: str
    asset_id: str
    vulnerability_id: str
    status: str
    note: str
    due_date: date | None
    updated_at: datetime


@dataclass(slots=True, frozen=True)
class AssessmentFinding:
    vulnerability: Vulnerability
    remediation_status: str | None
    priority_score: float
    risk_level: str
    match_reason: str


@dataclass(slots=True, frozen=True)
class AssetAssessmentReport:
    asset: Asset
    overall_score: float
    risk_level: str
    findings: list[AssessmentFinding]

