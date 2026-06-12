from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from vuln_mgmt.core.dependencies import get_asset_service, get_assessment_service
from vuln_mgmt.schemas.assessments import AssetAssessmentRead
from vuln_mgmt.schemas.assets import AssetCreate, AssetRead
from vuln_mgmt.services.assets import AssetService
from vuln_mgmt.services.assessment import AssessmentService

router = APIRouter(prefix="/assets", tags=["assets"])


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    service: AssetService = Depends(get_asset_service),
) -> AssetRead:
    asset = await service.create_asset(payload)
    return AssetRead.model_validate(asset)


@router.get("", response_model=list[AssetRead])
async def list_assets(service: AssetService = Depends(get_asset_service)) -> list[AssetRead]:
    assets = await service.list_assets()
    return [AssetRead.model_validate(item) for item in assets]


@router.get("/{asset_id}", response_model=AssetRead)
async def get_asset(asset_id: str, service: AssetService = Depends(get_asset_service)) -> AssetRead:
    asset = await service.get_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return AssetRead.model_validate(asset)


@router.get("/{asset_id}/assessment", response_model=AssetAssessmentRead)
async def get_assessment(
    asset_id: str,
    service: AssessmentService = Depends(get_assessment_service),
) -> AssetAssessmentRead:
    report = await service.build_asset_report(asset_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return AssetAssessmentRead.model_validate(report)
