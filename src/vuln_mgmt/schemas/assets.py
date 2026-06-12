from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class AssetCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: Annotated[str, Field(min_length=2, max_length=120)]
    vendor: Annotated[str, Field(min_length=1, max_length=120)]
    product: Annotated[str, Field(min_length=1, max_length=120)]
    version: Annotated[str, Field(min_length=1, max_length=64)]
    environment: Literal["development", "staging", "production"]
    owner: Annotated[str, Field(min_length=2, max_length=120)]
    criticality: Annotated[int, Field(ge=1, le=5)] = 3


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    vendor: str
    product: str
    version: str
    environment: str
    owner: str
    criticality: int
    created_at: datetime

