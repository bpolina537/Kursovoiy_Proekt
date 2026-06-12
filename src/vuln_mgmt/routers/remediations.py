from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from vuln_mgmt.core.dependencies import get_remediation_service
from vuln_mgmt.domain.errors import EntityNotFoundError
from vuln_mgmt.schemas.remediations import (
    RemediationCreate,
    RemediationRead,
    RemediationStatusUpdate,
)
from vuln_mgmt.services.remediations import RemediationService

router = APIRouter(prefix="/remediations", tags=["remediations"])


@router.post("", response_model=RemediationRead, status_code=status.HTTP_201_CREATED)
async def create_remediation(
    payload: RemediationCreate,
    service: RemediationService = Depends(get_remediation_service),
) -> RemediationRead:
    try:
        remediation = await service.create_remediation(payload)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return RemediationRead.model_validate(remediation)


@router.patch("/{remediation_id}", response_model=RemediationRead)
async def update_remediation(
    remediation_id: str,
    payload: RemediationStatusUpdate,
    service: RemediationService = Depends(get_remediation_service),
) -> RemediationRead:
    remediation = await service.update_status(remediation_id, payload)
    if remediation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation not found")
    return RemediationRead.model_validate(remediation)


@router.get("", response_model=list[RemediationRead])
async def list_remediations(
    service: RemediationService = Depends(get_remediation_service),
) -> list[RemediationRead]:
    remediations = await service.list_remediations()
    return [RemediationRead.model_validate(item) for item in remediations]
