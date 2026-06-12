from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from vuln_mgmt.core.dependencies import get_vulnerability_service
from vuln_mgmt.schemas.vulnerabilities import (
    VulnerabilityCreate,
    VulnerabilityImportRequest,
    VulnerabilityRead,
)
from vuln_mgmt.services.vulnerabilities import VulnerabilityService

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.post("", response_model=VulnerabilityRead, status_code=status.HTTP_201_CREATED)
async def create_vulnerability(
    payload: VulnerabilityCreate,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> VulnerabilityRead:
    vulnerability = await service.create_vulnerability(payload)
    return VulnerabilityRead.model_validate(vulnerability)


@router.post("/import", response_model=VulnerabilityRead, status_code=status.HTTP_201_CREATED)
async def import_vulnerability(
    payload: VulnerabilityImportRequest,
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> VulnerabilityRead:
    try:
        vulnerability = await service.import_from_nvd(payload)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    return VulnerabilityRead.model_validate(vulnerability)


@router.get("", response_model=list[VulnerabilityRead])
async def list_vulnerabilities(
    service: VulnerabilityService = Depends(get_vulnerability_service),
) -> list[VulnerabilityRead]:
    vulnerabilities = await service.list_vulnerabilities()
    return [VulnerabilityRead.model_validate(item) for item in vulnerabilities]
