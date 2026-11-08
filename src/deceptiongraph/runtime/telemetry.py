"""Observability for the live loop: OpenTelemetry traces, Prometheus metrics.

Every event the mediator handles becomes a trace::

    mediator.handle            event.type, actor, host, triggered, stage
      +-- mediator.profile     stage, sophistication, objective
      +-- mediator.adapt       decoys added / retired
      +-- mediator.incident    incident id, severity

and moves these Prometheus series (served at the API's ``/metrics``):

=====================================  ======================================
``dg_events_total{type}``              events handled
``dg_deception_triggers_total{type}``  decoys touched / used / exfiltrated
``dg_alerts_total{severity}``          incident updates, by severity
``dg_stage_transitions_total{stage}``  attackers entering each kill-chain stage
``dg_adaptations_total``               re-plans that changed the deployment
``dg_live_decoys``                     decoys currently deployed
``dg_open_incidents``                  incidents not yet closed
``dg_mediator_handle_seconds``         time to handle one event
=====================================  ======================================

Both libraries are optional (the ``observability`` extra). Without them every
call here is a no-op, so the mediator never branches on what is installed.

Tracing export is chosen by ``DG_OTEL_EXPORTER``: ``none`` (default),
``console``, or ``otlp`` (to ``DG_OTEL_ENDPOINT``, default
``http://localhost:4318/v1/traces`` - Jaeger, Tempo or any collector).
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator

SERVICE_NAME = "deceptiongraph"


class _NoSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        return None


class Telemetry:
    """Traces and metrics for one process. Build with :func:`get_telemetry`."""

    def __init__(self, tracer: Any = None, registry: Any = None, enabled: bool = True) -> None:
        self.enabled = enabled
        self.tracer = tracer if enabled else None
        self.registry = registry if enabled else None
        self._metrics: dict[str, Any] = {}
        if self.registry is not None:
            self._build_metrics()

    @classmethod
    def disabled(cls) -> "Telemetry":
        """Records nothing. The experiment runner uses this: ten thousand
        simulated intrusions are not production traffic."""
        return cls(enabled=False)

    # -- tracing -------------------------------------------------------------

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[Any]:
        if self.tracer is None:
            yield _NoSpan()
            return
        with self.tracer.start_as_current_span(name) as span:
            for key, value in attributes.items():
                if value is not None:
                    span.set_attribute(key, value)
            yield span

    # -- metrics -------------------------------------------------------------

    def _build_metrics(self) -> None:
        from prometheus_client import Counter, Gauge, Histogram

        r = self.registry
        self._metrics = {
            "events": Counter("dg_events", "Events handled by the mediator", ["type"], registry=r),
            "triggers": Counter("dg_deception_triggers", "Decoys that fired", ["type"],
                                registry=r),
            "alerts": Counter("dg_alerts", "Incident updates raised", ["severity"], registry=r),
            "stages": Counter("dg_stage_transitions", "Attackers entering a kill-chain stage",
                              ["stage"], registry=r),
            "adaptations": Counter("dg_adaptations", "Re-plans that changed the deployment",
                                   registry=r),
            "live_decoys": Gauge("dg_live_decoys", "Decoys currently deployed", registry=r),
            "open_incidents": Gauge("dg_open_incidents", "Incidents not yet closed", registry=r),
            "latency": Histogram("dg_mediator_handle_seconds", "Time to handle one event",
                                 buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
                                 registry=r),
        }

    def record(self, reaction: Any, seconds: float, live_decoys: int, open_incidents: int,
               new_stage: str | None = None) -> None:
        """Fold one handled event into the metrics."""
        if not self._metrics:
            return
        m = self._metrics
        event_type = reaction.event.type.value
        m["events"].labels(type=event_type).inc()
        if reaction.triggered:
            m["triggers"].labels(type=event_type).inc()
        if reaction.incident is not None:
            m["alerts"].labels(severity=reaction.incident.severity.value).inc()
        if new_stage is not None:
            m["stages"].labels(stage=new_stage).inc()
        if reaction.adaptation is not None and reaction.adaptation.changed:
            m["adaptations"].inc()
        m["live_decoys"].set(live_decoys)
        m["open_incidents"].set(open_incidents)
        m["latency"].observe(seconds)

    def exposition(self) -> tuple[bytes, str]:
        """Prometheus text format, for a ``/metrics`` endpoint."""
        if self.registry is None:
            return b"# observability extra not installed or telemetry disabled\n", "text/plain"
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        return generate_latest(self.registry), CONTENT_TYPE_LATEST


_DEFAULT: Telemetry | None = None


def get_telemetry() -> Telemetry:
    """The process-wide telemetry, configured from the environment on first use."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = _from_environment()
    return _DEFAULT


def reset_telemetry(telemetry: Telemetry | None = None) -> None:
    """Replace the process-wide telemetry (tests use this)."""
    global _DEFAULT
    _DEFAULT = telemetry


def _from_environment() -> Telemetry:
    registry = tracer = None
    try:
        from prometheus_client import CollectorRegistry

        registry = CollectorRegistry()
    except ImportError:
        pass
    try:
        tracer = _tracer(os.environ.get("DG_OTEL_EXPORTER", "none").lower())
    except ImportError:
        tracer = None
    return Telemetry(tracer=tracer, registry=registry)


def _tracer(exporter: str):
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    if exporter in ("", "none", "off"):
        return trace.get_tracer(SERVICE_NAME)  # no-op unless the host app set a provider
    provider = TracerProvider(resource=Resource.create({"service.name": SERVICE_NAME}))
    if exporter == "console":
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    elif exporter == "otlp":
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        endpoint = os.environ.get("DG_OTEL_ENDPOINT", "http://localhost:4318/v1/traces")
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    else:
        raise ValueError(f"DG_OTEL_EXPORTER must be none, console or otlp, got {exporter!r}")
    return provider.get_tracer(SERVICE_NAME)
