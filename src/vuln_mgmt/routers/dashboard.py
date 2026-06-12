from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(tags=["dashboard"])
_UI_DIR = Path(__file__).resolve().parents[1] / "ui"


@router.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(_UI_DIR / "index.html", media_type="text/html")
