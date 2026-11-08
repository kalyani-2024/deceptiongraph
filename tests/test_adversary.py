"""Attacker models: naive, cautious, learning."""

from __future__ import annotations

import random
from dataclasses import replace

import pytest

from deceptiongraph.deception.assets import DeceptionKind
from deceptiongraph.deception.engine import DeceptionEngine
from deceptiongraph.experiments.runner import ExperimentRunner
from deceptiongraph.graph.loader import load_network
from deceptiongraph.graph.repository import InMemoryGraphRepository
from deceptiongraph.runtime.adversary import (
    CautiousAdversary,
    NaiveAdversary,
    adversary_for,
)
from deceptiongraph.runtime.simulator import AttackSimulator

from conftest import DATA_DIR

CAMPUS = DATA_DIR / "campus.yaml"


def tuned(asset, believability=None, fidelity=None):
    """The same decoy with a different lure or sensor quality (both are immutable)."""
    if believability is not None:
        asset.lure = replace(asset.lure, believability=believability)
    if fidelity is not None:
        asset.sensor = replace(asset.sensor, fidelity=fidelity)
    return asset


@pytest.fixture
def decoys(enterprise_repo):
    return list(DeceptionEngine(enterprise_repo).deploy(budget=3).assets)


class TestNaive:
    def test_reproduces_the_original_simulator_exactly(self, enterprise_repo, decoys):
        """Same seed, same results as before attacker models existed."""
        explicit = AttackSimulator(enterprise_repo, assets=decoys, seed=11,
                                   adversary=NaiveAdversary()).run_many(40)
        default = AttackSimulator(enterprise_repo, assets=decoys, seed=11).run_many(40)
        assert [r.as_dict() for r in explicit] == [r.as_dict() for r in default]
        assert all(r.decoys_spotted == 0 for r in default)


class TestCautious:
    def test_an_unconvincing_decoy_is_spotted_and_raises_wariness(self, decoys):
        decoy = tuned(decoys[0], believability=0.0)  # obviously fake
        attacker = CautiousAdversary(skill=1.0)
        attacker.begin_campaign()
        result = attacker.encounter([decoy], decoy.host_id, random.Random(0))
        assert result.fired is None and result.spotted == [decoy]
        assert attacker.wariness[decoy.kind] == pytest.approx(0.5)
        others = [k for k in DeceptionKind if k is not decoy.kind]
        assert all(attacker.wariness[k] == pytest.approx(0.125) for k in others)

    def test_a_perfect_decoy_is_never_spotted(self, decoys):
        decoy = tuned(decoys[0], believability=1.0, fidelity=1.0)
        attacker = CautiousAdversary(skill=1.0)
        attacker.begin_campaign()
        result = attacker.encounter([decoy], decoy.host_id, random.Random(0))
        assert result.fired is decoy and not result.spotted

    def test_wariness_resets_between_campaigns_unless_it_learns(self, decoys):
        decoy = tuned(decoys[0], believability=0.0)
        for learns, expect_wary in ((False, False), (True, True)):
            attacker = CautiousAdversary(skill=1.0, learns=learns)
            attacker.begin_campaign()
            attacker.encounter([decoy], decoy.host_id, random.Random(0))
            attacker.end_campaign(None)
            attacker.begin_campaign()
            assert bool(attacker.wariness.get(decoy.kind, 0.0)) is expect_wary

    def test_learned_wariness_has_a_ceiling(self, decoys):
        attacker = CautiousAdversary(learns=True, max_wariness=0.7)
        for _ in range(500):
            attacker.end_campaign(decoys[0])
        attacker.begin_campaign()
        assert attacker.wariness[decoys[0].kind] <= 0.7

    def test_parameters_are_validated(self):
        with pytest.raises(ValueError, match="skill"):
            CautiousAdversary(skill=1.5)
        with pytest.raises(ValueError, match="unknown adversary"):
            adversary_for("psychic")


class TestAgainstTheExperiment:
    @pytest.fixture(scope="class")
    def rates(self):
        out = {}
        for name in ("naive", "cautious", "learning"):
            report = ExperimentRunner(CAMPUS, trials=150, seed=7, adversary=name).run(
                budget=3, arms=("attack-path",), include_runs=True)
            out[name] = report.arms[0]
        return out

    def test_a_smarter_attacker_is_caught_less(self, rates):
        naive = rates["naive"].metrics.detection_rate
        cautious = rates["cautious"].metrics.detection_rate
        learning = rates["learning"].metrics.detection_rate
        assert naive >= cautious >= learning
        assert learning < naive

    def test_only_smarter_attackers_spot_decoys(self, rates):
        assert sum(r.decoys_spotted for r in rates["naive"].runs) == 0
        assert sum(r.decoys_spotted for r in rates["cautious"].runs) > 0

    def test_the_report_names_the_adversary(self):
        report = ExperimentRunner(CAMPUS, trials=3, adversary="cautious").run(
            budget=1, arms=("random",))
        assert report.as_dict()["adversary"] == "cautious"

    def test_compare_adversaries(self):
        from deceptiongraph.experiments.adversaries import compare_adversaries

        rows = compare_adversaries(CAMPUS, trials=30, arms=("random", "attack-path"))
        assert {r.strategy for r in rows} == {"random", "attack-path"}
        for row in rows:
            assert 0.0 <= row.learning <= 1.0
            assert row.as_dict()["retained"] == pytest.approx(row.retained, abs=1e-4)


def test_cli_adversary(tmp_path):
    from typer.testing import CliRunner

    from deceptiongraph.cli.main import app

    result = CliRunner().invoke(app, ["adversary", str(CAMPUS), "-t", "12",
                                      "-o", str(tmp_path / "a.json")])
    assert result.exit_code == 0, result.output
    assert "Learning" in result.output and (tmp_path / "a.json").exists()
    result = CliRunner().invoke(app, ["experiment", str(CAMPUS), "-t", "5", "-a", "psychic"])
    assert result.exit_code == 1
