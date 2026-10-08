"""Tests for the HTTP API and the agent tool surface."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from deceptiongraph.agent.tools import DeceptionGraphTools, tool_schemas
from deceptiongraph.api.app import create_app
from deceptiongraph.config import Settings

NETWORK = Path(__file__).resolve().parents[1] / "data" / "networks" / "enterprise.yaml"


@pytest.fixture
def client():
    return TestClient(create_app(Settings(network_path=NETWORK)))


@pytest.fixture
def tools():
    return DeceptionGraphTools(NETWORK)


class TestApiMeta:
    def test_health_names_the_live_backends(self, client):
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert body["backends"]["graph_backend"] == "in-memory"
        assert "attack-path" in body["strategies"]

    def test_network_summary(self, client):
        body = client.get("/network").json()
        assert body["hosts"] == 5
        assert body["crown_jewels"] == ["db01"]

    def test_a_missing_network_is_a_404(self, client):
        assert client.get("/network", params={"network": "nope.yaml"}).status_code == 404

    def test_report_covers_analysis(self, client):
        body = client.get("/report").json()
        assert body["network"] == "acme-enterprise"
        assert body["recommendations"]


class TestApiAnalysis:
    def test_analysis_returns_the_worst_path_and_chokes(self, client):
        body = client.get("/analysis").json()
        assert body["most_dangerous_path"]["nodes"] == ["INTERNET", "web01", "api02", "db01"]
        assert body["choke_points"]["api02"] == 1.0

    def test_paths_for_a_host(self, client):
        body = client.get("/paths/db01").json()
        assert len(body["paths"]) == 1
        assert body["paths"][0]["nodes"][-1] == "db01"

    def test_paths_can_enumerate(self, client):
        body = client.get("/paths/db01", params={"all_paths": True, "limit": 3}).json()
        assert 1 < len(body["paths"]) <= 3

    def test_unknown_host_is_a_404(self, client):
        assert client.get("/paths/ghost").status_code == 404
        assert client.get("/predict/ghost").status_code == 404

    def test_prediction(self, client):
        body = client.get("/predict/web01").json()
        assert body["objective"] == "db01"
        assert body["next_hops"][0]["target"] == "api02"


class TestApiDeception:
    def test_deploy_and_read_back(self, client):
        deployed = client.post("/deception/deploy", json={"budget": 3}).json()
        assert len(deployed["assets"]) == 3
        assert client.get("/deception").json()["coverage"]["decoys_used"] == 3

    def test_reading_before_deploying_is_a_404(self, client):
        assert client.get("/deception").status_code == 404

    def test_invalid_budget_is_rejected_by_the_schema(self, client):
        assert client.post("/deception/deploy", json={"budget": 0}).status_code == 422

    def test_unknown_strategy_is_rejected(self, client):
        response = client.post("/deception/deploy", json={"budget": 2, "strategy": "vibes"})
        assert response.status_code == 422

    def test_compare_covers_every_strategy(self, client):
        body = client.get("/deception/compare", params={"budget": 2}).json()
        assert {r["strategy"] for r in body["results"]} == {
            "random", "risk", "centrality", "attack-path"
        }


class TestApiRuntime:
    def test_reporting_an_event_deploys_the_default_posture_first(self, client):
        body = client.post(
            "/events",
            json={"type": "HOST_COMPROMISED", "host_id": "web01", "actor_id": "a1"},
        ).json()
        assert body["profile"]["stage"] == "INITIAL_ACCESS"

    def test_a_token_resolves_to_its_decoy(self, client):
        deployed = client.post("/deception/deploy", json={"budget": 3}).json()
        asset = deployed["assets"][1]
        body = client.post(
            "/events",
            json={
                "type": "DECOY_AUTHENTICATED", "actor_id": "apt-1",
                "host_id": asset["host_id"], "token": asset["token"],
            },
        ).json()
        assert body["triggered"] is True
        assert body["incident"]["severity"] in {"HIGH", "CRITICAL"}
        assert body["profile"]["objective"] == "db01"

    def test_an_unknown_token_is_a_404(self, client):
        client.post("/deception/deploy", json={"budget": 2})
        response = client.post(
            "/events", json={"type": "DECOY_TOUCHED", "token": "not-a-token"}
        )
        assert response.status_code == 404

    def test_an_invalid_event_type_is_rejected(self, client):
        assert client.post("/events", json={"type": "TELEPORT"}).status_code == 422

    def test_status_requires_an_active_loop(self, client):
        assert client.get("/status").status_code == 404
        client.post("/events", json={"type": "HOST_COMPROMISED", "host_id": "web01"})
        assert client.get("/status").status_code == 200

    def test_incidents_and_timeline_are_empty_before_any_event(self, client):
        assert client.get("/incidents").json()["incidents"] == []
        assert client.get("/timeline").json()["events"] == []

    def test_incidents_and_timeline_fill_in(self, client):
        deployed = client.post("/deception/deploy", json={"budget": 3}).json()
        asset = deployed["assets"][1]
        client.post(
            "/events",
            json={"type": "DECOY_AUTHENTICATED", "actor_id": "apt-1",
                  "host_id": asset["host_id"], "token": asset["token"]},
        )
        assert client.get("/incidents").json()["incidents"]
        assert client.get("/timeline").json()["events"]

    def test_redeploying_resets_the_loop(self, client):
        client.post("/events", json={"type": "HOST_COMPROMISED", "host_id": "web01"})
        client.post("/deception/deploy", json={"budget": 2})
        assert client.get("/status").status_code == 404


class TestApiExperiments:
    def test_runs_a_small_experiment(self, client):
        body = client.post(
            "/experiments",
            json={"budget": 1, "trials": 10, "seed": 1, "arms": ["random", "attack-path"]},
        ).json()
        assert {a["label"] for a in body["arms"]} == {"random", "attack-path"}
        assert body["verdict"]

    def test_unknown_arms_are_rejected(self, client):
        response = client.post(
            "/experiments", json={"budget": 1, "trials": 5, "arms": ["telepathy"]}
        )
        assert response.status_code == 422

    def test_trial_bounds_are_enforced(self, client):
        assert client.post("/experiments", json={"trials": 0}).status_code == 422
        assert client.post("/experiments", json={"trials": 99999}).status_code == 422


class TestAgentTools:
    def test_every_tool_has_a_schema(self, tools):
        for tool in tools.tools():
            schema = tool.schema()
            assert schema["name"] and schema["description"]
            assert schema["inputSchema"]["type"] == "object"

    def test_mutating_tools_are_flagged(self, tools):
        mutating = {t.name for t in tools.tools() if t.mutates}
        assert mutating == {"deploy_deception", "report_event"}
        assert mutating.isdisjoint({t.name for t in tools.read_only_tools()})

    def test_read_only_schemas_exclude_the_mutators(self):
        names = {s["name"] for s in tool_schemas(NETWORK, read_only=True)}
        assert "deploy_deception" not in names
        assert "analyse_network" in names

    def test_analyse_network(self, tools):
        result = tools.call("analyse_network")
        assert result["most_dangerous_path"]["route"].endswith("db01")
        assert result["choke_points"]["api02"] == 1.0
        assert len(result["top_assets"]) == 5

    def test_find_attack_paths(self, tools):
        result = tools.call("find_attack_paths", {"host_id": "db01"})
        assert result["path_count"] == 1
        assert result["paths"][0]["steps"]

    def test_predict_movement(self, tools):
        result = tools.call("predict_movement", {"host_id": "web01"})
        assert result["objective"] == "db01"
        assert result["next_hops"][0]["target"] == "api02"

    def test_compare_strategies(self, tools):
        result = tools.call("compare_strategies", {"budget": 2})
        assert len(result["results"]) == 4

    def test_deploy_then_report_then_status(self, tools):
        deployed = tools.call("deploy_deception", {"budget": 3})
        assert len(deployed["decoys"]) == 3

        reported = tools.call(
            "report_event",
            {"type": "DECOY_AUTHENTICATED", "actor_id": "apt-x",
             "token": deployed["decoys"][1]["token"], "detail": "read fake creds"},
        )
        assert reported["deception_triggered"] is True
        assert reported["stage"] == "LATERAL_MOVEMENT"
        assert "DECEPTION TRIGGERED" in reported["narrative"]

        status = tools.call("get_status")
        assert status["runtime_active"] is True
        assert status["triggers"] == 1

    def test_status_before_any_event(self, tools):
        assert tools.call("get_status")["runtime_active"] is False

    def test_errors_come_back_as_data(self, tools):
        assert "error" in tools.call("find_attack_paths", {"host_id": "ghost"})
        assert "error" in tools.call("predict_movement", {"host_id": "ghost"})
        assert "error" in tools.call("report_event", {"type": "TELEPORT"})
        assert "error" in tools.call("deploy_deception", {"strategy": "vibes"})
        assert "error" in tools.call("deploy_deception", {"budget": 0})
        assert "error" in tools.call("nonexistent_tool")

    def test_a_raising_handler_is_caught(self, tools):
        from deceptiongraph.agent.tools import Tool

        def explode():
            raise RuntimeError("database on fire")

        tool = Tool(name="boom", description="d", parameters={}, handler=explode)
        assert tool()["error"] == "RuntimeError: database on fire"

    def test_unknown_host_errors_list_the_valid_ones(self, tools):
        result = tools.call("find_attack_paths", {"host_id": "ghost"})
        assert "db01" in result["known_hosts"]

    def test_unknown_token_is_an_error(self, tools):
        tools.call("deploy_deception", {"budget": 2})
        assert "error" in tools.call(
            "report_event", {"type": "DECOY_TOUCHED", "token": "nope"}
        )

    def test_by_name_lookup(self, tools):
        assert tools.by_name("analyse_network") is not None
        assert tools.by_name("nope") is None
