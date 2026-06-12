from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Settings(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    app_name: str = Field(default="Vulnerability Management Platform", min_length=1)
    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"
    database_url: str = Field(
        default="postgresql+asyncpg://vuln:vuln@db:5432/vuln_mgmt",
        min_length=1,
    )
    nvd_api_base_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        min_length=1,
    )
    nvd_api_key: str | None = None
    auto_create_schema: bool = True
    request_timeout_seconds: float = Field(default=10.0, gt=0.0)


def load_settings(source: dict[str, Any] | None = None) -> Settings:
    import os

    env_file_data = _read_env_file(Path(".env"))
    data = {
        "app_name": env_file_data.get(
            "APP_NAME",
            os.getenv("APP_NAME", "Vulnerability Management Platform"),
        ),
        "environment": env_file_data.get(
            "APP_ENVIRONMENT",
            os.getenv("APP_ENVIRONMENT", "development"),
        ),
        "log_level": env_file_data.get("LOG_LEVEL", os.getenv("LOG_LEVEL", "INFO")),
        "database_url": env_file_data.get(
            "DATABASE_URL",
            os.getenv(
                "DATABASE_URL",
                "postgresql+asyncpg://vuln:vuln@localhost:5432/vuln_mgmt",
            ),
        ),
        "nvd_api_base_url": env_file_data.get(
            "NVD_API_BASE_URL",
            os.getenv(
                "NVD_API_BASE_URL",
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
            ),
        ),
        "nvd_api_key": env_file_data.get("NVD_API_KEY", os.getenv("NVD_API_KEY", "")) or None,
        "auto_create_schema": _to_bool(
            env_file_data.get("AUTO_CREATE_SCHEMA", os.getenv("AUTO_CREATE_SCHEMA", "true"))
        ),
        "request_timeout_seconds": float(
            env_file_data.get(
                "REQUEST_TIMEOUT_SECONDS",
                os.getenv("REQUEST_TIMEOUT_SECONDS", "10"),
            )
        ),
    }
    if source:
        data.update(source)
    return Settings.model_validate(data)


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _to_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
