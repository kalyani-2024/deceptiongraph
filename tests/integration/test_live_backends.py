"""Integration tests against real Neo4j, PostgreSQL and Redis servers.

Skipped unless the servers are configured, so a plain ``pytest`` still needs
nothing. To run them:

    scripts/integration.ps1       # Windows: starts containers, runs, tears down
    scripts/integration.sh        # same, POSIX shell

or point these at servers of your own:

    DG_TEST_NEO4J_URI=bolt://localhost:17687  DG_TEST_NEO4J_PASSWORD=...
    DG_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:15432/db
    DG_TEST_REDIS_URL=redis://localhost:16379/15

The fake-driver tests in ``tests/test_storage.py`` prove the right statements
are issued; these prove the statements do the right thing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from deceptiongraph.analysis.attack_graph import AttackGraphEngine
from deceptiongraph.analysis.risk import RiskEngine
from deceptiongraph.config import Neo4jSettings, PostgresSettings, RedisSettings, Settings
from deceptiongraph.deception.engine import DeceptionEngine
from deceptiongraph.graph.loader import load_network
from deceptiongraph.graph.repository import InMemoryGraphRepository
from deceptiongraph.runtime.events import Event, EventType
from deceptiongraph.runtime.incidents import IncidentManager

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
NETWORKS = ROOT / "data" / "networks"

NEO4J_URI = os.environ.get("DG_TEST_NEO4J_URI")
DATABASE_URL = os.environ.get("DG_TEST_DATABASE_URL")
REDIS_URL = os.environ.get("DG_TEST_REDIS_URL")

needs_neo4j = pytest.mark.skipif(not NEO4J_URI, reason="DG_TEST_NEO4J_URI not set")
needs_postgres = pytest.mark.skipif(not DATABASE_URL, reason="DG_TEST_DATABASE_URL not set")
needs_redis = pytest.mark.skipif(not REDIS_URL, reason="DG_TEST_REDIS_URL not set")


def neo4j_settings() -> Neo4jSettings:
    return Neo4jSettings(
        uri=NEO4J_URI,
        user=os.environ.get("DG_TEST_NEO4J_USER", "neo4j"),
        password=os.environ.get("DG_TEST_NEO4J_PASSWORD", "integration-test"),
    )


# -- Neo4j -----------------------------------------------------------------


@pytest.fixture
def neo4j():
    from deceptiongraph.storage.neo4j_repository import Neo4jGraphRepository

    repository = Neo4jGraphRepository.connect(neo4j_settings())
    with repository.driver.session(database=repository.database) as session:
        session.run("MATCH (n) DETACH DELETE n").consume()
    yield repository
    repository.close()


def fresh(repository, network: str):
    """A second repository on the same database, with nothing cached."""
    from deceptiongraph.storage.neo4j_repository import Neo4jGraphRepository

    return Neo4jGraphRepository(repository.driver, database=repository.database, network=network)


def assert_same_model(a, b) -> None:
    assert a.name == b.name
    assert list(a.hosts) == list(b.hosts)
    for host_id, host in a.hosts.items():
        other = b.hosts[host_id]
        for attr in ("name", "ip", "os", "exposure", "criticality", "is_crown_jewel",
                     "patch_level", "tags"):
            assert getattr(host, attr) == getattr(other, attr), (host_id, attr)
        assert host.services == other.services, host_id
        assert host.credentials == other.credentials, host_id
    assert a.users == b.users
    assert a.connections == b.connections


@needs_neo4j
class TestNeo4j:
    @pytest.mark.parametrize("name", ["enterprise.yaml", "campus.yaml"])
    def test_a_network_round_trips_exactly(self, neo4j, name):
        original = load_network(NETWORKS / name)
        neo4j.save(original)
        reloaded = fresh(neo4j, original.name).reload()
        assert_same_model(original, reloaded)

    @pytest.mark.parametrize("name", ["enterprise.yaml", "campus.yaml"])
    def test_analysis_from_neo4j_matches_memory(self, neo4j, name):
        original = load_network(NETWORKS / name)
        neo4j.save(original)
        stored = fresh(neo4j, original.name)
        stored.reload()

        memory = InMemoryGraphRepository(load_network(NETWORKS / name))
        a, b = AttackGraphEngine(memory), AttackGraphEngine(stored)
        assert a.most_dangerous_path().nodes == b.most_dangerous_path().nodes
        assert a.most_dangerous_path().probability == pytest.approx(
            b.most_dangerous_path().probability)
        assert a.choke_points() == b.choke_points()

        ranked_a = [(r.host_id, round(r.score, 9)) for r in RiskEngine(memory).rank_assets()]
        ranked_b = [(r.host_id, round(r.score, 9)) for r in RiskEngine(stored).rank_assets()]
        assert ranked_a == ranked_b
        # The Composite (department/subnet tree) survives too.
        assert (memory.model.root.calculate_risk().value
                == pytest.approx(stored.model.root.calculate_risk().value))

    def test_networks_live_side_by_side(self, neo4j):
        enterprise = load_network(NETWORKS / "enterprise.yaml")
        campus = load_network(NETWORKS / "campus.yaml")
        neo4j.save(enterprise)
        fresh(neo4j, None).save(campus)
        neo4j.save(enterprise)  # re-saving one must not touch the other

        assert set(neo4j.networks()) == {enterprise.name, campus.name}
        assert_same_model(campus, fresh(neo4j, campus.name).reload())
        assert_same_model(enterprise, fresh(neo4j, enterprise.name).reload())

    def test_unknown_network_is_a_clear_error(self, neo4j):
        with pytest.raises(LookupError, match="not in the database"):
            fresh(neo4j, "no-such-network").reload()

    def test_server_side_paths_reach_the_crown_jewel(self, neo4j):
        model = load_network(NETWORKS / "enterprise.yaml")
        neo4j.save(model)
        paths = neo4j.paths_to_crown_jewel("web01", limit=20)
        assert paths
        assert all(p["hosts"][0] == "web01" and p["hosts"][-1] == "db01" for p in paths)
        assert ["web01", "api02", "db01"] in [p["hosts"] for p in paths]

    def test_a_real_data_twin_round_trips(self, neo4j, tmp_path):
        """Hundreds of credentials: exercises the batched writes."""
        sys.path.insert(0, str(ROOT / "tests"))
        from lanl_fixture import write_fixture

        from deceptiongraph.datasets.lanl import prepare

        auth, redteam = write_fixture(tmp_path / "raw")
        prepare(auth, redteam, tmp_path / "prep", negative_rate=1.0)
        twin = load_network(tmp_path / "prep" / "network.yaml")
        neo4j.save(twin)
        assert_same_model(twin, fresh(neo4j, twin.name).reload())

    def test_backends_write_networks_through_to_neo4j(self, neo4j):
        from deceptiongraph.storage.backends import Backends
        from deceptiongraph.storage.neo4j_repository import Neo4jGraphRepository

        backends = Backends.from_settings(Settings(neo4j=neo4j_settings()))
        try:
            assert backends.status()["neo4j"] == "live"
            repository = backends.graph_repository(load_network(NETWORKS / "enterprise.yaml"))
            assert isinstance(repository, Neo4jGraphRepository)
            assert "acme-enterprise" in neo4j.networks()
        finally:
            backends.close()


# -- PostgreSQL --------------------------------------------------------------


@pytest.fixture
def store():
    from deceptiongraph.storage.relational import RelationalStore

    relational = RelationalStore(DATABASE_URL, create=False)
    relational.drop_schema()
    relational.create_schema()
    yield relational
    relational.drop_schema()
    relational.close()


@needs_postgres
class TestPostgres:
    def test_it_really_is_postgres(self, store):
        assert store.engine.dialect.name == "postgresql"
        assert store.ping()

    def test_the_full_record_round_trips(self, store):
        repo = InMemoryGraphRepository(load_network(NETWORKS / "enterprise.yaml"))
        deployment = DeceptionEngine(repo).deploy(budget=3)
        session_id = store.open_session("acme", "attack-path", 3, 0.35)
        assert store.record_decoys(session_id, deployment.assets) == 3

        manager = IncidentManager()
        events = [
            Event(type=EventType.DECOY_TOUCHED, actor_id="apt-1", host_id="web01",
                  metadata={"note": "naïve ünïcode", "nested": {"k": [1, 2]}}),
            Event(type=EventType.EXFIL_OBSERVED, actor_id="apt-1", host_id="db01"),
        ]
        for event in events:
            manager.on_event(event)
        store.record_events(session_id, events)
        store.record_incidents(session_id, manager.incidents)

        assert store.counts() == {"sessions": 1, "decoys": 3, "events": 2, "alerts": 1,
                                  "experiments": 0}
        stored_events = store.events(session_id)
        assert stored_events[1]["metadata"] == {"note": "naïve ünïcode", "nested": {"k": [1, 2]}}
        assert stored_events[0]["at"].endswith("+00:00")  # timezone survived
        alert = store.alerts(session_id)[0]
        assert alert["severity"] == "CRITICAL" and alert["hosts"] == ["web01", "db01"]
        token = deployment.assets[0].marker.token
        assert store.decoy_by_token(token)["host_id"] == deployment.assets[0].host_id

    def test_two_sessions_do_not_overwrite_each_other(self, store):
        """IDs restart per process: INC-0001 and decoy serial 1 come round again."""
        for run in range(2):
            repo = InMemoryGraphRepository(load_network(NETWORKS / "enterprise.yaml"))
            deployment = DeceptionEngine(repo).deploy(budget=2)
            manager = IncidentManager()
            manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id=f"actor-{run}"))
            session_id = store.open_session("acme", "attack-path", 2)
            store.record_decoys(session_id, deployment.assets)
            store.record_incidents(session_id, manager.incidents)

        assert store.counts()["decoys"] == 4
        alerts = store.alerts()
        assert len(alerts) == 2
        assert {a["id"] for a in alerts} == {"INC-0001"}
        assert {a["actor_id"] for a in alerts} == {"actor-0", "actor-1"}

    def test_experiments_and_the_leaderboard(self, store):
        from deceptiongraph.experiments.runner import ExperimentRunner

        runner = ExperimentRunner(NETWORKS / "enterprise.yaml", trials=5, seed=1)
        store.record_experiment(runner.run(budget=1, arms=("random", "attack-path")))
        store.record_experiment(runner.run(budget=2, arms=("random", "attack-path")))
        board = store.strategy_leaderboard()
        assert {row["strategy"] for row in board} == {"random", "attack-path"}
        assert all(row["experiments"] == 2 for row in board)


# -- Redis -------------------------------------------------------------------


@pytest.fixture
def redis_cache():
    from deceptiongraph.storage.cache import RedisCache

    cache = RedisCache.connect(RedisSettings(url=REDIS_URL, ttl_seconds=60))
    cache.client.flushdb()
    yield cache
    cache.client.flushdb()


@needs_redis
class TestRedis:
    def test_round_trip_and_ttl(self, redis_cache):
        assert redis_cache.ping()
        redis_cache.set("analysis:x", {"risk": 0.35, "path": ["a", "b"]})
        assert redis_cache.get("analysis:x") == {"risk": 0.35, "path": ["a", "b"]}
        assert 0 < redis_cache.client.ttl("dg:analysis:x") <= 60

    def test_invalidate_and_corruption(self, redis_cache):
        redis_cache.set("k", 1)
        redis_cache.invalidate("k")
        assert redis_cache.get("k") is None
        redis_cache.client.set("dg:bad", b"{not json")
        assert redis_cache.get("bad") is None
        assert redis_cache.client.exists("dg:bad") == 0


# -- the API with every backend live -------------------------------------------


@needs_neo4j
@needs_postgres
@needs_redis
def test_api_end_to_end_with_every_backend(neo4j, store, redis_cache):
    from fastapi.testclient import TestClient

    from deceptiongraph.api.app import create_app

    settings = Settings(
        network_path=NETWORKS / "enterprise.yaml",
        neo4j=neo4j_settings(),
        postgres=PostgresSettings(url=DATABASE_URL),
        redis=RedisSettings(url=REDIS_URL),
    )
    app = create_app(settings)
    client = TestClient(app)
    try:
        health = client.get("/health").json()
        assert health["backends"]["status"] == {
            "neo4j": "live", "postgresql": "live", "redis": "live"}

        first = client.get("/analysis").json()
        assert redis_cache.client.keys("dg:analysis:*")
        assert client.get("/analysis").json() == first  # served from Redis

        assert "acme-enterprise" in neo4j.networks()
        paths = client.get("/graph/paths/web01").json()["paths"]
        assert ["web01", "api02", "db01"] in [p["hosts"] for p in paths]

        deployment = client.post("/deception/deploy", json={"budget": 3}).json()
        token = deployment["assets"][0]["token"]
        reaction = client.post("/events", json={
            "type": "DECOY_AUTHENTICATED", "actor_id": "apt-1", "token": token}).json()
        assert reaction["triggered"] and "persistence_error" not in reaction

        counts = client.get("/history/counts").json()
        assert counts["sessions"] == 1 and counts["decoys"] >= 3
        assert counts["events"] >= 2  # the trigger plus the alert it raised
        alerts = client.get("/history/alerts").json()["alerts"]
        assert alerts and alerts[0]["actor_id"] == "apt-1"

        experiment = client.post("/experiments", json={"budget": 1, "trials": 5,
                                                       "arms": ["random", "attack-path"]})
        assert experiment.json()["experiment_id"] == 1
        board = client.get("/history/leaderboard").json()["strategies"]
        assert {row["strategy"] for row in board} == {"random", "attack-path"}
    finally:
        app.state.backends.close()
