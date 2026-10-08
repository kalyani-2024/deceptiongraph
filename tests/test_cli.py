from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from deceptiongraph.cli.main import app

NETWORK = Path(__file__).resolve().parents[1] / "data" / "networks" / "enterprise.yaml"


@pytest.fixture
def runner():
    return CliRunner()


def run(runner: CliRunner, *args: str):
    return runner.invoke(app, list(args))


class TestDiscover:
    def test_reports_the_inventory(self, runner):
        result = run(runner, "discover", str(NETWORK))
        assert result.exit_code == 0
        assert "Discovered assets" in result.stdout
        assert "web01" in result.stdout

    def test_missing_file_fails_cleanly(self, runner, tmp_path):
        result = run(runner, "discover", str(tmp_path / "nope.yaml"))
        assert result.exit_code == 1
        assert "error" in result.stdout.lower()

    def test_invalid_file_fails_cleanly(self, runner, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("hosts:\n  - name: no-id\n", encoding="utf-8")
        result = run(runner, "discover", str(bad))
        assert result.exit_code == 1
        assert "error" in result.stdout.lower()


class TestPaths:
    def test_shows_the_most_dangerous_path(self, runner):
        result = run(runner, "paths", str(NETWORK))
        assert result.exit_code == 0
        assert "Most dangerous attack path" in result.stdout
        assert "Choke points" in result.stdout

    def test_targets_a_named_host(self, runner):
        result = run(runner, "paths", str(NETWORK), "--target", "db01", "--all", "--top", "3")
        assert result.exit_code == 0
        assert "db01" in result.stdout

    def test_unknown_target_fails(self, runner):
        result = run(runner, "paths", str(NETWORK), "--target", "ghost")
        assert result.exit_code == 1


class TestRisk:
    def test_prints_a_report(self, runner):
        result = run(runner, "risk", str(NETWORK))
        assert result.exit_code == 0
        assert "Network risk" in result.stdout

    def test_json_output_is_parseable(self, runner):
        result = run(runner, "risk", str(NETWORK), "--json")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["name"] == "acme-enterprise"
        assert len(data["assets"]) == 5


class TestPredict:
    def test_predicts_the_next_move(self, runner):
        result = run(runner, "predict", str(NETWORK), "--from", "web01")
        assert result.exit_code == 0
        assert "api02" in result.stdout

    def test_json_output_names_the_objective(self, runner):
        result = run(runner, "predict", str(NETWORK), "--from", "web01", "--json")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["objective"] == "db01"
        assert data["trajectory"]["nodes"][0] == "web01"

    def test_unknown_host_fails(self, runner):
        assert run(runner, "predict", str(NETWORK), "--from", "ghost").exit_code == 1

    def test_dead_end_is_reported(self, runner):
        result = run(runner, "predict", str(NETWORK), "--from", "bak01")
        assert result.exit_code == 0


class TestDeceive:
    def test_recommends_placements(self, runner):
        result = run(runner, "deceive", str(NETWORK))
        assert result.exit_code == 0
        assert "Recommended deception placement" in result.stdout
        assert "web01" in result.stdout
        assert "Deception coverage" in result.stdout

    @pytest.mark.parametrize("strategy", ["random", "risk", "centrality", "attack-path"])
    def test_every_strategy_runs(self, runner, strategy):
        result = run(runner, "deceive", str(NETWORK), "--strategy", strategy, "--budget", "2")
        assert result.exit_code == 0

    def test_json_output_is_parseable(self, runner):
        result = run(runner, "deceive", str(NETWORK), "--budget", "2", "--json")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["strategy"] == "attack-path"
        assert len(data["assets"]) == 2
        assert data["coverage"]["decoys_used"] == 2

    def test_unknown_strategy_fails(self, runner):
        assert run(runner, "deceive", str(NETWORK), "--strategy", "vibes").exit_code == 1

    def test_zero_budget_fails(self, runner):
        assert run(runner, "deceive", str(NETWORK), "--budget", "0").exit_code == 1


class TestCompare:
    def test_ranks_the_strategies(self, runner):
        result = run(runner, "compare", str(NETWORK), "--budget", "2")
        assert result.exit_code == 0
        for name in ("random", "risk", "centrality", "attack-path"):
            assert name in result.stdout

    def test_json_output_lists_every_strategy(self, runner):
        result = run(runner, "compare", str(NETWORK), "--budget", "2", "--json")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert {d["strategy"] for d in data} == {"random", "risk", "centrality", "attack-path"}

    def test_seed_makes_the_run_reproducible(self, runner):
        args = ("compare", str(NETWORK), "--budget", "2", "--seed", "5", "--json")
        first = json.loads(run(runner, *args).stdout)
        second = json.loads(run(runner, *args).stdout)
        assert [d["hosts"] for d in first] == [d["hosts"] for d in second]

    def test_zero_budget_fails(self, runner):
        assert run(runner, "compare", str(NETWORK), "--budget", "0").exit_code == 1


class TestReport:
    def test_prints_recommendations(self, runner):
        result = run(runner, "report", str(NETWORK), "--budget", "2")
        assert result.exit_code == 0
        assert "Security report" in result.stdout

    def test_writes_a_json_file(self, runner, tmp_path):
        out = tmp_path / "nested" / "report.json"
        result = run(runner, "report", str(NETWORK), "--budget", "2", "--out", str(out))
        assert result.exit_code == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["network"] == "acme-enterprise"
        assert data["deception"]["coverage"]["decoys_used"] == 2
        assert data["recommendations"]

    def test_unknown_strategy_fails(self, runner):
        assert run(runner, "report", str(NETWORK), "--strategy", "vibes").exit_code == 1


class TestSimulate:
    def test_runs_an_adaptive_attack(self, runner):
        result = run(runner, "simulate", str(NETWORK), "--runs", "4", "--seed", "3")
        assert result.exit_code == 0
        assert "Standing deception" in result.stdout
        assert "Posture after the attack" in result.stdout

    def test_static_mode_skips_the_loop(self, runner):
        result = run(runner, "simulate", str(NETWORK), "--static", "--seed", "3")
        assert result.exit_code == 0
        assert "Posture after the attack" not in result.stdout

    def test_json_output_is_parseable(self, runner):
        result = run(
            runner, "simulate", str(NETWORK), "--runs", "3", "--seed", "5", "--json"
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data["runs"]) == 3
        assert data["status"] is not None

    def test_the_seed_makes_it_repeatable(self, runner):
        args = ("simulate", str(NETWORK), "--runs", "5", "--seed", "42", "--json")
        first = json.loads(run(runner, *args).stdout)
        second = json.loads(run(runner, *args).stdout)
        assert [r["path"] for r in first["runs"]] == [r["path"] for r in second["runs"]]

    def test_invalid_arguments_fail(self, runner):
        assert run(runner, "simulate", str(NETWORK), "--runs", "0").exit_code == 1
        assert run(runner, "simulate", str(NETWORK), "--strategy", "vibes").exit_code == 1


class TestExperiment:
    def test_reports_a_verdict(self, runner):
        result = run(
            runner, "experiment", str(NETWORK), "--budget", "2", "--trials", "20"
        )
        assert result.exit_code == 0
        assert "Verdict" in result.stdout
        assert "random" in result.stdout

    def test_sweep_covers_several_budgets(self, runner):
        result = run(runner, "experiment", str(NETWORK), "--trials", "5", "--sweep")
        assert result.exit_code == 0
        assert result.stdout.count("Verdict") >= 2

    def test_writes_a_json_report(self, runner, tmp_path):
        out = tmp_path / "nested" / "experiment.json"
        result = run(
            runner, "experiment", str(NETWORK), "--budget", "1", "--trials", "10",
            "--out", str(out),
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["trials"] == 10
        assert data["arms"]

    def test_invalid_arguments_fail(self, runner):
        assert run(runner, "experiment", str(NETWORK), "--trials", "0").exit_code == 1
        assert run(runner, "experiment", str(NETWORK), "--budget", "0").exit_code == 1


class TestExport:
    @pytest.mark.parametrize("kind", ["attack", "assets", "connectivity"])
    def test_writes_node_link_json(self, runner, tmp_path, kind):
        out = tmp_path / "sub" / f"{kind}.json"
        result = run(runner, "export", str(NETWORK), "--out", str(out), "--kind", kind)
        assert result.exit_code == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["nodes"] and data["links"]
        assert all("step" not in link for link in data["links"])

    def test_unknown_kind_fails(self, runner, tmp_path):
        result = run(runner, "export", str(NETWORK), "--out", str(tmp_path / "x.json"),
                     "--kind", "galaxy")
        assert result.exit_code == 1
