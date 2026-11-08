"""The API's use of the storage backends, without any servers.

PostgreSQL is stood in for by a SQLite file (the schema is portable - the
integration suite runs the same code on real PostgreSQL). Neo4j and Redis
paths are checked for their "not configured" and "unreachable" behaviour.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from deceptiongraph.api.app import create_app
from deceptiongraph.config import PostgresSettings, RedisSettings, Settings

NETWORK = Path(__file__).resolve().parents[1] / "data" / "networks" / "enterprise.yaml"


@pytest.fixture
def memory_client():
    return TestClient(create_app(Settings(network_path=NETWORK)))


@pytest.fixture
def recorded(tmp_path):
    url = f"sqlite+pysqlite:///{(tmp_path / 'record.db').as_posix()}"
    app = create_app(Settings(network_path=NETWORK, postgres=PostgresSettings(url=url)))
    yield TestClient(app)
    app.state.backends.close()


class TestWithoutBackends:
    def test_health_reports_each_backend(self, memory_client):
        status = memory_client.get("/health").json()["backends"]["status"]
        assert status == {"neo4j": "not configured", "postgresql": "not configured",
                          "redis": "not configured"}

    def test_history_needs_a_database(self, memory_client):
        response = memory_client.get("/history/alerts")
        assert response.status_code == 503
        assert "DG_DATABASE_URL" in response.json()["detail"]

    def test_server_side_paths_need_neo4j(self, memory_client):
        response = memory_client.get("/graph/paths/web01")
        assert response.status_code == 503
        assert "DG_NEO4J_URI" in response.json()["detail"]

    def test_ml_strategy_without_a_model_is_a_422(self, memory_client, monkeypatch, tmp_path):
        pytest.importorskip("sklearn")
        monkeypatch.setenv("DG_ML_TARGET_MODEL", str(tmp_path / "missing.joblib"))
        response = memory_client.post("/deception/deploy", json={"strategy": "ml"})
        assert response.status_code == 422
        assert "dgraph lanl train" in response.json()["detail"]

    def test_ml_is_listed_as_a_strategy(self, memory_client):
        assert "ml" in memory_client.get("/health").json()["strategies"]

    def test_a_token_alone_locates_the_attacker(self, memory_client):
        """A sensor that only knows the canary token still yields a located event."""
        asset = memory_client.post("/deception/deploy", json={"budget": 2}).json()["assets"][0]
        reaction = memory_client.post("/events", json={
            "type": "DECOY_AUTHENTICATED", "actor_id": "apt-1", "token": asset["token"]}).json()
        assert reaction["event"]["host_id"] == asset["host_id"]
        assert asset["host_id"] in reaction["profile"]["hosts_seen"]


class TestRecording:
    def test_a_session_opens_when_a_network_loads(self, recorded):
        recorded.get("/network")
        assert recorded.get("/history/counts").json()["sessions"] == 1

    def test_deployments_events_and_incidents_are_recorded(self, recorded):
        deployment = recorded.post("/deception/deploy", json={"budget": 3}).json()
        token = deployment["assets"][0]["token"]
        reaction = recorded.post("/events", json={
            "type": "DECOY_AUTHENTICATED", "actor_id": "apt-1", "token": token}).json()
        assert "persistence_error" not in reaction

        counts = recorded.get("/history/counts").json()
        assert counts["decoys"] >= 3
        assert counts["events"] >= 2  # the trigger and the alert it raised
        assert counts["alerts"] == 1
        alert = recorded.get("/history/alerts").json()["alerts"][0]
        assert alert["actor_id"] == "apt-1"
        assert alert["severity"] in {"HIGH", "CRITICAL"}

    def test_events_are_not_recorded_twice(self, recorded):
        recorded.post("/deception/deploy", json={"budget": 2})
        recorded.post("/events", json={"type": "SCAN_OBSERVED", "actor_id": "a"})
        first = recorded.get("/history/counts").json()["events"]
        recorded.post("/events", json={"type": "SCAN_OBSERVED", "actor_id": "a"})
        assert recorded.get("/history/counts").json()["events"] == first + 1

    def test_experiments_feed_the_leaderboard(self, recorded):
        body = recorded.post("/experiments", json={
            "budget": 1, "trials": 3, "arms": ["random", "attack-path"]}).json()
        assert body["experiment_id"] == 1
        board = recorded.get("/history/leaderboard").json()["strategies"]
        assert {row["strategy"] for row in board} == {"random", "attack-path"}


def test_an_unreachable_backend_is_reported_not_fatal():
    settings = Settings(network_path=NETWORK, redis=RedisSettings(url="redis://127.0.0.1:1/0"))
    client = TestClient(create_app(settings))
    status = client.get("/health").json()["backends"]["status"]
    assert status["redis"].startswith("down")
    assert client.get("/analysis").status_code == 200  # carries on without the cache
