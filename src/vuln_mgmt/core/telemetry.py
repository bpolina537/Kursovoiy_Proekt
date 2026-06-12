from __future__ import annotations

from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class TelemetryHandle:
    tracer: Any | None = None
    shutdown_handler: Any | None = None

    def span(self, name: str) -> AbstractContextManager[Any]:
        if self.tracer is None:
            return nullcontext()
        return self.tracer.start_as_current_span(name)

    async def shutdown(self) -> None:
        if self.shutdown_handler is not None:
            maybe_result = self.shutdown_handler()
            if hasattr(maybe_result, "__await__"):
                await maybe_result


def configure_telemetry(service_name: str) -> TelemetryHandle:
    _ = service_name
    return TelemetryHandle()


def instrument_fastapi(app: Any) -> None:
    _ = app
    return
