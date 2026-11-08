"""Traces and metrics on the mediator."""

from __future__ import annotations

import pytest

pytest.importorskip("opentelemetry.sdk")
pytest.importorskip("prometheus_client")

from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)
from prometheus_client import CollectorRegistry  # noqa: E402

from deceptiongraph.deception.engine import DeceptionEngine  # noqa: E402
from deceptiongraph.runtime.events import Event, EventType  # noqa: E402
from deceptiongraph.runtime.mediator import SecurityMediator  # noqa: E402
from deceptiongraph.runtime.telemetry import (  # noqa: E402
    Telemetry,
    get_telemetry,
    reset_telemetry,
)


@pytest.fixture
def telemetry():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    t = Telemetry(tracer=provider.get_tracer("test"), registry=CollectorRegistry())
    t.exporter = exporter
    return t


@pytest.fixture
def mediator(enterprise_repo, telemetry):
    engine = DeceptionEngine(enterprise_repo)
    return SecurityMediator(enterprise_repo, deception=engine,
                            deployment=engine.deploy(budget=3), telemetry=telemetry)


def trigger(mediator):
    asset = mediator.live_assets[0]
    return mediator.handle(Event(type=EventType.DECOY_AUTHENTICATED, host_id=asset.host_id,
                                 actor_id="apt-1", asset_id=asset.id, token=asset.marker.token))


def value(registry, name, labels=None):
    return registry.get_sample_value(name, labels or {})


class TestTraces:
    def test_one_trace_per_event_with_a_span_per_step(self, mediator, telemetry):
        trigger(mediator)
        spans = {s.name: s for s in telemetry.exporter.get_finished_spans()}
        assert {"mediator.handle", "mediator.profile", "mediator.adapt",
                "mediator.incident"} <= set(spans)
        root = spans["mediator.handle"]
        assert root.attributes["event.type"] == "DECOY_AUTHENTICATED"
        assert root.attributes["actor.id"] == "apt-1"
        assert root.attributes["event.triggered"] is True
        assert "attacker.stage" in root.attributes
        for child in ("mediator.profile", "mediator.adapt", "mediator.incident"):
            assert spans[child].parent.span_id == root.context.span_id
        assert spans["mediator.incident"].attributes["incident.id"] == "INC-0001"

    def test_an_event_without_attacker_signal_still_traces(self, mediator, telemetry):
        mediator.handle(Event(type=EventType.ALERT_RAISED, actor_id="system"))
        names = [s.name for s in telemetry.exporter.get_finished_spans()]
        assert "mediator.handle" in names and "mediator.incident" not in names


class TestMetrics:
    def test_counters_move(self, mediator, telemetry):
        trigger(mediator)
        r = telemetry.registry
        assert value(r, "dg_events_total", {"type": "DECOY_AUTHENTICATED"}) == 1
        assert value(r, "dg_deception_triggers_total", {"type": "DECOY_AUTHENTICATED"}) == 1
        assert sum(value(r, "dg_alerts_total", {"severity": s}) or 0
                   for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")) == 1
        assert value(r, "dg_open_incidents") == 1
        assert value(r, "dg_live_decoys") == len(mediator.live_assets)
        assert value(r, "dg_mediator_handle_seconds_count") == 1

    def test_exposition_is_prometheus_text(self, mediator, telemetry):
        trigger(mediator)
        body, content_type = telemetry.exposition()
        assert b"dg_events_total" in body and "text/plain" in content_type

    def test_disabled_records_nothing(self, enterprise_repo):
        quiet = Telemetry.disabled()
        engine = DeceptionEngine(enterprise_repo)
        mediator = SecurityMediator(enterprise_repo, deception=engine,
                                    deployment=engine.deploy(budget=2), telemetry=quiet)
        trigger(mediator)  # must not raise
        assert quiet.registry is None
        assert b"disabled" in quiet.exposition()[0]


def test_api_serves_metrics(telemetry):
    from fastapi.testclient import TestClient

    from deceptiongraph.api.app import create_app
    from deceptiongraph.config import Settings

    from conftest import DATA_DIR

    reset_telemetry(telemetry)
    try:
        client = TestClient(create_app(Settings(network_path=DATA_DIR / "enterprise.yaml")))
        asset = client.post("/deception/deploy", json={"budget": 2}).json()["assets"][0]
        client.post("/events", json={"type": "DECOY_TOUCHED", "token": asset["token"],
                                      "actor_id": "apt-1"})
        response = client.get("/metrics")
        assert response.status_code == 200
        assert 'dg_events_total{type="DECOY_TOUCHED"} 1.0' in response.text
    finally:
        reset_telemetry(None)
    assert get_telemetry() is not telemetry


def test_experiments_stay_out_of_the_metrics(telemetry):
    from deceptiongraph.experiments.runner import ExperimentRunner

    from conftest import DATA_DIR

    reset_telemetry(telemetry)
    try:
        ExperimentRunner(DATA_DIR / "enterprise.yaml", trials=3).run(budget=1, arms=("adaptive",))
        assert value(telemetry.registry, "dg_mediator_handle_seconds_count") in (None, 0.0)
    finally:
        reset_telemetry(None)
