from __future__ import annotations

from fastapi import Request

from vuln_mgmt.core.container import AppContainer
from vuln_mgmt.services.assets import AssetService
from vuln_mgmt.services.assessment import AssessmentService
from vuln_mgmt.services.health import HealthService
from vuln_mgmt.services.remediations import RemediationService
from vuln_mgmt.services.vulnerabilities import VulnerabilityService


def get_container(request: Request) -> AppContainer:
    return request.app.state.container


def get_asset_service(request: Request) -> AssetService:
    return get_container(request).asset_service


def get_vulnerability_service(request: Request) -> VulnerabilityService:
    return get_container(request).vulnerability_service


def get_remediation_service(request: Request) -> RemediationService:
    return get_container(request).remediation_service


def get_assessment_service(request: Request) -> AssessmentService:
    return get_container(request).assessment_service


def get_health_service(request: Request) -> HealthService:
    return get_container(request).health_service

