from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class RemediationCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    asset_id: Annotated[str, Field(min_length=1)]
    vulnerability_id: Annotated[str, Field(min_length=1)]
    status: Literal["open", "in_progress", "mitigated", "accepted"] = "open"
    note: Annotated[str, Field(max_length=500)] = ""
    due_date: date | None = None


class RemediationStatusUpdate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    status: Literal["open", "in_progress", "mitigated", "accepted"]
    note: Annotated[str, Field(max_length=500)] = ""


class RemediationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    vulnerability_id: str
    status: str
    note: str
    due_date: date | None
    updated_at: datetime

