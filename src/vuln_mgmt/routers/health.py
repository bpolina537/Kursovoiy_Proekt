from __future__ import annotations

from fastapi import APIRouter, Depends

from vuln_mgmt.core.dependencies import get_health_service
from vuln_mgmt.schemas.health import HealthRead
from vuln_mgmt.services.health import HealthService

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthRead)
async def health_check() -> HealthRead:
    return HealthRead(status="ok")


@router.get("/ready", response_model=HealthRead)
async def readiness_check(service: HealthService = Depends(get_health_service)) -> HealthRead:
    status = "ok" if await service.is_ready() else "degraded"
    return HealthRead(status=status)

