from __future__ import annotations

from vuln_mgmt.infrastructure.repositories.base import HealthProbe


class HealthService:
    def __init__(self, probe: HealthProbe) -> None:
        self._probe = probe

    async def is_ready(self) -> bool:
        return await self._probe.ping()

