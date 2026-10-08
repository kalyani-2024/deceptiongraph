"""Storage tests.

Scope, stated plainly: the relational store runs against in-memory SQLite, and
the Neo4j repository and Redis cache run against fakes defined here. None of
the three has been exercised against a real server. These tests prove the
schema builds, the queries are well formed and the mappings round-trip - not
that the adapters work against PostgreSQL, Neo4j or Redis.
"""

from __future__ import annotations

import pytest

from deceptiongraph.config import Neo4jSettings, PostgresSettings, RedisSettings, Settings
from deceptiongraph.deception.engine import DeceptionEngine
from deceptiongraph.graph.repository import InMemoryGraphRepository
from deceptiongraph.runtime.events import Event, EventType
from deceptiongraph.runtime.incidents import IncidentManager
from deceptiongraph.storage.cache import NullCache, RedisCache, build_cache, model_fingerprint
from deceptiongraph.storage.neo4j_repository import Neo4jGraphRepository, build_graph_repository
from deceptiongraph.storage.relational import RelationalStore


# -- fakes -----------------------------------------------------------------


class FakeRedis:
    """The three commands RedisCache actually uses."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.expiries: dict[str, int | None] = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value, ex=None):
        self.store[key] = value
        self.expiries[key] = ex

    def delete(self, key):
        self.store.pop(key, None)


class FakeNeo4jSession:
    """Records every statement, so the Cypher can be asserted on."""

    def __init__(self, recorder: list, responses: dict | None = None) -> None:
        self.recorder = recorder
        self.responses = responses or {}

    def run(self, query, **params):
        self.recorder.append((query.strip(), params))
        for marker, rows in self.responses.items():
            if marker in query:
                return list(rows)
        return []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeNeo4jDriver:
    def __init__(self, responses: dict | None = None) -> None:
        self.statements: list = []
        self.responses = responses or {}
        self.closed = False

    def session(self, database=None):
        return FakeNeo4jSession(self.statements, self.responses)

    def close(self):
        self.closed = True


# -- config ----------------------------------------------------------------


class TestSettings:
    def test_defaults_need_no_services(self):
        settings = Settings()
        assert not settings.neo4j.enabled
        assert not settings.postgres.enabled
        assert not settings.redis.enabled
        assert settings.describe()["graph_backend"] == "in-memory"

    def test_reads_the_environment(self, monkeypatch):
        monkeypatch.setenv("DG_NEO4J_URI", "bolt://localhost:7687")
        monkeypatch.setenv("DG_DATABASE_URL", "postgresql+psycopg://u:p@localhost/db")
        monkeypatch.setenv("DG_REDIS_URL", "redis://localhost:6379/0")
        monkeypatch.setenv("DG_BUDGET", "7")

        settings = Settings.from_env()
        assert settings.neo4j.enabled and settings.postgres.enabled and settings.redis.enabled
        assert settings.default_budget == 7
        assert settings.describe()["graph_backend"] == "neo4j"

    def test_a_non_numeric_integer_is_rejected(self, monkeypatch):
        monkeypatch.setenv("DG_BUDGET", "lots")
        with pytest.raises(ValueError, match="must be an integer"):
            Settings.from_env()

    def test_booleans_accept_the_usual_spellings(self, monkeypatch):
        for raw in ("1", "true", "YES", "on"):
            monkeypatch.setenv("DG_SQL_ECHO", raw)
            assert PostgresSettings.from_env().echo is True
        monkeypatch.setenv("DG_SQL_ECHO", "no")
        assert PostgresSettings.from_env().echo is False


# -- cache -----------------------------------------------------------------


class TestCache:
    def test_null_cache_is_always_a_miss(self):
        cache = NullCache()
        cache.set("k", {"a": 1})
        assert cache.get("k") is None
        assert cache.enabled is False

    def test_build_cache_defaults_to_null(self):
        assert isinstance(build_cache(Settings()), NullCache)

    def test_redis_cache_round_trips(self):
        cache = RedisCache(FakeRedis(), ttl_seconds=60)
        cache.set("analysis", {"risk": 0.35})
        assert cache.get("analysis") == {"risk": 0.35}

    def test_ttl_is_applied(self):
        client = FakeRedis()
        RedisCache(client, ttl_seconds=90).set("k", 1)
        assert client.expiries["dg:k"] == 90

    def test_explicit_ttl_overrides_the_default(self):
        client = FakeRedis()
        RedisCache(client, ttl_seconds=90).set("k", 1, ttl=5)
        assert client.expiries["dg:k"] == 5

    def test_invalidate_removes_the_entry(self):
        cache = RedisCache(FakeRedis())
        cache.set("k", 1)
        cache.invalidate("k")
        assert cache.get("k") is None

    def test_corrupt_entries_are_a_miss_not_a_crash(self):
        client = FakeRedis()
        client.set("dg:k", "{not json")
        cache = RedisCache(client)
        assert cache.get("k") is None
        assert "dg:k" not in client.store  # and it was evicted

    def test_unconfigured_redis_refuses_to_connect(self):
        with pytest.raises(RuntimeError, match="Redis is not configured"):
            RedisCache.connect(RedisSettings())


class TestFingerprint:
    def test_is_stable_for_the_same_model(self, enterprise_model):
        assert model_fingerprint(enterprise_model) == model_fingerprint(enterprise_model)

    def test_differs_between_networks(self, enterprise_model, linear_model):
        assert model_fingerprint(enterprise_model) != model_fingerprint(linear_model)

    def test_changes_when_patching_changes(self, enterprise_model):
        before = model_fingerprint(enterprise_model)
        enterprise_model.hosts["web01"].patch_level = 0.95
        assert model_fingerprint(enterprise_model) != before

    def test_changes_when_segmentation_changes(self, enterprise_model):
        from deceptiongraph.graph.model import Connection

        before = model_fingerprint(enterprise_model)
        enterprise_model.connections.append(
            Connection(source="bak01", target="adm01", filtered=0.1)
        )
        assert model_fingerprint(enterprise_model) != before


# -- relational ------------------------------------------------------------


@pytest.fixture
def store():
    return RelationalStore("sqlite+pysqlite:///:memory:")


class TestRelationalStore:
    def test_schema_builds(self, store):
        assert store.counts() == {
            "sessions": 0, "decoys": 0, "events": 0, "alerts": 0, "experiments": 0
        }

    def test_from_settings_is_none_without_a_url(self):
        assert RelationalStore.from_settings(Settings()) is None

    def test_records_a_session(self, store):
        session_id = store.open_session("acme", "attack-path", 3, 0.35)
        assert session_id == 1
        assert store.counts()["sessions"] == 1

    def test_records_decoys_and_resolves_tokens(self, store, enterprise_repo):
        deployment = DeceptionEngine(enterprise_repo).deploy(budget=3)
        session_id = store.open_session("acme", "attack-path", 3)
        assert store.record_decoys(session_id, deployment.assets) == 3

        token = deployment.assets[0].marker.token
        found = store.decoy_by_token(token)
        assert found["host_id"] == deployment.assets[0].host_id
        assert store.decoy_by_token("nope") is None

    def test_re_recording_a_decoy_updates_its_state(self, store, enterprise_repo):
        from deceptiongraph.deception.assets import DeceptionState

        deployment = DeceptionEngine(enterprise_repo).deploy(budget=1)
        session_id = store.open_session("acme", "attack-path", 1)
        store.record_decoys(session_id, deployment.assets)
        deployment.assets[0].state = DeceptionState.BURNED
        store.record_decoys(session_id, deployment.assets)

        assert store.counts()["decoys"] == 1
        assert store.decoys(session_id)[0]["state"] == "BURNED"

    def test_records_events(self, store):
        session_id = store.open_session("acme", "attack-path", 3)
        events = [
            Event(type=EventType.HOST_COMPROMISED, host_id="web01", actor_id="a1"),
            Event(type=EventType.DECOY_TOUCHED, host_id="api02", actor_id="a1",
                  metadata={"is_crown_jewel": False}),
        ]
        assert store.record_events(session_id, events) == 2
        rows = store.events(session_id)
        assert rows[0]["type"] == "DECOY_TOUCHED"  # newest first
        assert rows[0]["metadata"] == {"is_crown_jewel": False}

    def test_records_and_updates_incidents(self, store):
        manager = IncidentManager()
        manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id="a1", host_id="web01"))
        session_id = store.open_session("acme", "attack-path", 3)
        store.record_incidents(session_id, manager.incidents)

        manager.on_event(Event(type=EventType.EXFIL_OBSERVED, actor_id="a1", host_id="db01"))
        store.record_incidents(session_id, manager.incidents)

        alerts = store.alerts(session_id)
        assert len(alerts) == 1  # updated, not duplicated
        assert alerts[0]["severity"] == "CRITICAL"
        assert alerts[0]["hosts"] == ["web01", "db01"]

    def test_alerts_filter_by_severity(self, store):
        manager = IncidentManager()
        manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id="a1"))
        manager.on_event(Event(type=EventType.EXFIL_OBSERVED, actor_id="a2"))
        session_id = store.open_session("acme", "attack-path", 3)
        store.record_incidents(session_id, manager.incidents)

        assert len(store.alerts(severity="CRITICAL")) == 1
        assert len(store.alerts(severity="INFO")) == 0

    def test_records_an_experiment_and_its_arms(self, store, enterprise_repo):
        from deceptiongraph.experiments.runner import ExperimentRunner

        report = ExperimentRunner(enterprise_repo, trials=5, seed=1).run(
            budget=1, arms=("random", "attack-path")
        )
        experiment_id = store.record_experiment(report)
        assert experiment_id == 1
        assert store.counts()["experiments"] == 1

        leaderboard = store.strategy_leaderboard()
        assert {row["strategy"] for row in leaderboard} == {"random", "attack-path"}
        assert all(row["experiments"] == 1 for row in leaderboard)

    def test_leaderboard_averages_across_experiments(self, store, enterprise_repo):
        from deceptiongraph.experiments.runner import ExperimentRunner

        runner = ExperimentRunner(enterprise_repo, trials=5, seed=1)
        for _ in range(2):
            store.record_experiment(runner.run(budget=1, arms=("attack-path",)))
        row = store.strategy_leaderboard()[0]
        assert row["experiments"] == 2

    def test_event_limit_is_applied(self, store):
        session_id = store.open_session("acme", "attack-path", 3)
        store.record_events(
            session_id, [Event(type=EventType.SCAN_OBSERVED) for _ in range(10)]
        )
        assert len(store.events(session_id, limit=4)) == 4

    def test_schema_can_be_dropped(self, store):
        store.drop_schema()
        store.create_schema()
        assert store.counts()["sessions"] == 0


# -- neo4j -----------------------------------------------------------------


class TestNeo4jRepository:
    def test_save_writes_every_entity_type(self, enterprise_model):
        driver = FakeNeo4jDriver()
        Neo4jGraphRepository(driver).save(enterprise_model)
        statements = " ".join(q for q, _ in driver.statements)

        for marker in ("MERGE (h:Host", "MERGE (s:Service", "MERGE (v:Vulnerability",
                       "MERGE (c:Credential", "MERGE (u:User", "GRANTS_ACCESS",
                       "LOGS_INTO", "CONNECTS_TO"):
            assert marker in statements

    def test_existing_data_is_cleared_first(self, enterprise_model):
        driver = FakeNeo4jDriver()
        Neo4jGraphRepository(driver).save(enterprise_model)
        assert "DETACH DELETE" in driver.statements[0][0]

    def test_the_synthetic_internet_node_is_not_persisted(self, enterprise_model):
        driver = FakeNeo4jDriver()
        Neo4jGraphRepository(driver).save(enterprise_model)
        connection_params = [
            params for query, params in driver.statements if "CONNECTS_TO" in query
        ]
        assert connection_params
        assert all("INTERNET" not in (p.get("source"), p.get("target"))
                   for p in connection_params)

    def test_queries_are_served_from_the_projection_after_save(self, enterprise_model):
        repo = Neo4jGraphRepository(FakeNeo4jDriver())
        repo.save(enterprise_model)
        assert repo.host("db01").is_crown_jewel is True
        assert repo.model.name == "acme-enterprise"
        assert set(repo.neighbours("web01")) == {"api02", "bak01"}
        assert repo.asset_graph().number_of_nodes() > 0
        assert repo.connectivity_graph().number_of_nodes() > 0

    def test_analysis_runs_against_the_neo4j_repository(self, enterprise_model):
        from deceptiongraph.analysis.attack_graph import AttackGraphEngine

        repo = Neo4jGraphRepository(FakeNeo4jDriver())
        repo.save(enterprise_model)
        path = AttackGraphEngine(repo).most_dangerous_path()
        assert path.nodes == ("INTERNET", "web01", "api02", "db01")

    def test_reload_maps_rows_back_into_a_model(self):
        host_row = {
            "h": {"id": "web01", "name": "Web", "exposure": "INTERNET",
                  "criticality": 0.4, "is_crown_jewel": False, "patch_level": 0.3,
                  "ip": "1.2.3.4", "os": "linux", "tags": ["dmz"]},
            "services": [
                {
                    "service": {"id": "web01:nginx:443", "name": "nginx", "port": 443,
                                "protocol": "tcp", "version": "1.18"},
                    "vuln": {"cve_id": "CVE-1", "cvss": 9.4, "exploitability": 0.7,
                             "privilege_gained": "SERVICE", "description": "x"},
                }
            ],
            "credentials": [
                {
                    "credential": {"id": "c1", "username": "svc", "kind": "password",
                                   "privilege": "USER", "strength": 0.3},
                    "grants": "web01",
                }
            ],
        }
        conn_row = {"source": "web01", "target": "web01", "protocol": "tcp",
                    "ports": [443], "filtered": 0.0}
        driver = FakeNeo4jDriver(
            responses={"MATCH (h:Host)": [host_row], "CONNECTS_TO]->(b:Host)": [conn_row]}
        )
        model = Neo4jGraphRepository(driver).reload()

        host = model.hosts["web01"]
        assert host.name == "Web"
        assert host.services[0].vulnerabilities[0].cve_id == "CVE-1"
        assert host.credentials[0].grants_access == ("web01",)

    def test_crown_jewel_query_is_parameterised(self):
        driver = FakeNeo4jDriver()
        Neo4jGraphRepository(driver).paths_to_crown_jewel("web01", limit=5)
        query, params = driver.statements[0]
        assert params == {"start": "web01", "limit": 5}
        assert "is_crown_jewel: true" in query

    def test_close_closes_the_driver(self):
        driver = FakeNeo4jDriver()
        Neo4jGraphRepository(driver).close()
        assert driver.closed is True

    def test_unconfigured_neo4j_refuses_to_connect(self):
        with pytest.raises(RuntimeError, match="Neo4j is not configured"):
            Neo4jGraphRepository.connect(Neo4jSettings())

    def test_backend_selection_defaults_to_memory(self):
        assert isinstance(build_graph_repository(Settings()), InMemoryGraphRepository)
