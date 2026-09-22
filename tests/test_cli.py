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
