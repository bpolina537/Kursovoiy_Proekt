from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from vuln_mgmt.domain.entities import Vulnerability


@dataclass(slots=True)
class NvdClientConfig:
    base_url: str
    api_key: str | None
    timeout_seconds: float
    retries: int = 2


class NvdClient:
    def __init__(self, config: NvdClientConfig) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        headers = {}
        if self._config.api_key:
            headers["apiKey"] = self._config.api_key
        self._client = httpx.AsyncClient(
            base_url=self._config.base_url,
            timeout=httpx.Timeout(self._config.timeout_seconds),
            headers=headers,
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch_vulnerability(self, cve_id: str) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("NVD client is not started")
        params = {"cveId": cve_id}
        last_error: Exception | None = None
        for attempt in range(self._config.retries + 1):
            try:
                response = await self._client.get("", params=params)
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
                if attempt >= self._config.retries:
                    break
        raise RuntimeError(f"Unable to fetch NVD data for {cve_id}") from last_error

    @staticmethod
    def to_domain_entity(
        payload: dict[str, Any],
        *,
        cve_id: str,
        affected_vendor: str,
        affected_product: str,
        fixed_version: str | None,
    ) -> Vulnerability:
        vulns = payload.get("vulnerabilities") or []
        cve = vulns[0].get("cve", {}) if vulns else {}
        descriptions = cve.get("descriptions") or []
        description = next(
            (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
            "",
        )
        metrics = cve.get("metrics") or {}
        cvss_entries = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        cvss_data = cvss_entries[0].get("cvssData", {}) if cvss_entries else {}
        base_score = float(cvss_data.get("baseScore", 0.0))
        severity = str(cvss_data.get("baseSeverity", "low")).lower()
        published_at_raw = cve.get("published") or datetime.now(timezone.utc).isoformat()
        published_at = datetime.fromisoformat(published_at_raw.replace("Z", "+00:00"))
        title = cve.get("id", cve_id)
        exploit_available = bool(cve.get("vulnStatus") == "Analyzed")
        return Vulnerability(
            id=cve_id,
            cve_id=cve_id,
            title=title,
            description=description or title,
            cvss_score=base_score,
            severity=severity,
            affected_vendor=affected_vendor,
            affected_product=affected_product,
            fixed_version=fixed_version,
            published_at=published_at,
            exploit_available=exploit_available,
        )
