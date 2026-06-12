from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class VulnerabilityCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cve_id: Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]
    title: Annotated[str, Field(min_length=3, max_length=200)]
    description: Annotated[str, Field(min_length=3, max_length=5000)]
    cvss_score: Annotated[float, Field(ge=0.0, le=10.0)]
    severity: Annotated[str, Field(pattern=r"^(low|medium|high|critical)$")]
    affected_vendor: Annotated[str, Field(min_length=1, max_length=120)]
    affected_product: Annotated[str, Field(min_length=1, max_length=120)]
    fixed_version: Annotated[str | None, Field(max_length=64)] = None
    published_at: datetime
    exploit_available: bool = False


class VulnerabilityImportRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cve_id: Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]
    affected_vendor: Annotated[str, Field(min_length=1, max_length=120)]
    affected_product: Annotated[str, Field(min_length=1, max_length=120)]
    fixed_version: Annotated[str | None, Field(max_length=64)] = None


class VulnerabilityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

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
