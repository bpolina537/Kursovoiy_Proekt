from __future__ import annotations

from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from io import StringIO
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
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    except ImportError:
        return TelemetryHandle()

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter(out=StringIO())))
    trace.set_tracer_provider(provider)
    return TelemetryHandle(
        tracer=trace.get_tracer(service_name),
        shutdown_handler=provider.shutdown,
    )


def instrument_fastapi(app: Any) -> None:
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        return
    FastAPIInstrumentor.instrument_app(app)
