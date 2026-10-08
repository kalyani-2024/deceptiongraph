"""Experiment harness tests.

Trial counts here are small on purpose - these test the harness, not the
security result. The headline numbers in the README come from 1000-trial runs,
which are far too slow for a test suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deceptiongraph.deception.engine import DeceptionEngine
from deceptiongraph.experiments.metrics import Metrics, false_alerts_per_day, summarise
from deceptiongraph.experiments.runner import DEFAULT_ARMS, ExperimentRunner
from deceptiongraph.runtime.simulator import AttackSimulator

CAMPUS = Path(__file__).resolve().parents[1] / "data" / "networks" / "campus.yaml"


def metrics(label="x", rate=0.5, n=100, hops=2.0, decoys=3, false_alerts=0.1, coverage=1.0):
    """Build a Metrics directly, for the comparison logic."""
    return Metrics(
        label=label, trials=n, attempted_runs=n, detections=int(rate * n),
        objective_reached=0, detection_rate=rate, detection_rate_given_progress=rate,
        detection_ci95=1.96 * ((rate * (1 - rate) / n) ** 0.5),
        mean_time_to_detection=hops, mean_path_length=2.0, decoys_used=decoys,
        false_alerts_per_day=false_alerts, critical_asset_coverage=coverage,
    )


class TestMetrics:
    def test_summarise_counts_outcomes(self, enterprise_repo):
        engine = DeceptionEngine(enterprise_repo)
        deployment = engine.deploy(budget=3)
        runs = AttackSimulator(
            enterprise_repo, assets=list(deployment.assets), seed=3
        ).run_many(40)

        result = summarise("test", runs, deployment.assets, critical_asset_coverage=1.0)
        assert result.trials == 40
        assert result.detections == sum(1 for r in runs if r.detected)
        assert 0.0 <= result.detection_rate <= 1.0
        assert result.decoys_used == 3

    def test_zero_runs_is_rejected(self):
        with pytest.raises(ValueError, match="cannot summarise zero runs"):
            summarise("x", [], [], 0.0)

    def test_confidence_interval_narrows_with_more_trials(self):
        assert metrics(n=1000).detection_ci95 < metrics(n=50).detection_ci95

    def test_a_certain_outcome_has_no_interval(self):
        assert metrics(rate=0.0).detection_ci95 == 0.0
        assert metrics(rate=1.0).detection_ci95 == 0.0

    def test_beats_requires_non_overlapping_intervals(self):
        strong, weak = metrics(rate=0.9, n=500), metrics(rate=0.1, n=500)
        assert strong.beats(weak)
        assert not weak.beats(strong)

    def test_a_marginal_lead_is_not_a_win(self):
        assert not metrics(rate=0.52, n=100).beats(metrics(rate=0.50, n=100))

    def test_false_alerts_add_across_sensors(self, enterprise_repo):
        deployment = DeceptionEngine(enterprise_repo).deploy(budget=3)
        expected = sum(a.sensor.false_alert_rate for a in deployment.assets)
        assert false_alerts_per_day(deployment.assets) == pytest.approx(expected)

    def test_honeyfiles_are_noisier_than_decoy_hosts(self):
        from deceptiongraph.deception.factory import DocumentDecoyFactory, NetworkDecoyFactory

        assert DocumentDecoyFactory.false_alert_rate > NetworkDecoyFactory.false_alert_rate

    def test_detection_rate_given_progress_excludes_stillborn_runs(self, enterprise_repo):
        engine = DeceptionEngine(enterprise_repo)
        deployment = engine.deploy(budget=3)
        runs = AttackSimulator(
            enterprise_repo, assets=list(deployment.assets), seed=11
        ).run_many(40)
        result = summarise("x", runs, deployment.assets, 1.0)
        if result.attempted_runs < result.trials:
            assert result.detection_rate_given_progress >= result.detection_rate

    def test_overrides_are_honoured(self, enterprise_repo):
        runs = AttackSimulator(enterprise_repo, seed=1).run_many(5)
        result = summarise("x", runs, (), 0.5, decoys_used=7, false_alerts=1.25)
        assert result.decoys_used == 7
        assert result.false_alerts_per_day == 1.25

    def test_serialises(self):
        data = metrics().as_dict()
        assert data["label"] == "x"
        assert "detection_ci95" in data


class TestExperimentRunner:
    @pytest.fixture(scope="class")
    @classmethod
    def report(cls):
        """One small experiment, shared across this class - it is the slow part."""
        return ExperimentRunner(CAMPUS, trials=40, seed=99).run(budget=2)

    def test_every_arm_runs(self, report):
        assert {a.label for a in report.arms} == set(DEFAULT_ARMS)

    def test_each_arm_ran_the_full_trial_count(self, report):
        assert all(a.metrics.trials == 40 for a in report.arms)

    def test_ranking_is_by_detection_rate(self, report):
        rates = [a.metrics.detection_rate for a in report.ranked]
        assert rates == sorted(rates, reverse=True)
        assert report.best is report.ranked[0]

    def test_the_control_group_is_present(self, report):
        assert report.control is not None
        assert report.control.label == "random"

    def test_winners_must_clear_the_interval(self, report):
        control = report.control
        for arm in report.significant_winners():
            assert arm.metrics.detection_rate_low > control.metrics.detection_rate_high

    def test_verdict_is_honest_either_way(self, report):
        verdict = report.verdict()
        assert "random" in verdict
        if report.significant_winners():
            assert "beat random" in verdict
        else:
            assert "no strategy beat random" in verdict

    def test_table_has_a_header_and_a_row_per_arm(self, report):
        rows = report.table()
        assert rows[0][0] == "Strategy"
        assert len(rows) == len(report.arms) + 1

    def test_serialises_without_runs_by_default(self, report):
        data = report.as_dict()
        assert data["network"] == "campus"
        assert "verdict" in data
        assert "runs" not in data["arms"][0]

    def test_runs_can_be_included(self):
        report = ExperimentRunner(CAMPUS, trials=5, seed=1).run(
            budget=1, arms=("attack-path",), include_runs=True
        )
        assert len(report.arms[0].runs) == 5
        assert len(report.as_dict(include_runs=True)["arms"][0]["runs"]) == 5

    def test_arms_are_isolated_from_each_other(self):
        """The adaptive arm mutates its network; the next arm must not see it."""
        report = ExperimentRunner(CAMPUS, trials=10, seed=4).run(
            budget=2, arms=("adaptive", "attack-path")
        )
        static = next(a for a in report.arms if a.label == "attack-path")
        assert static.metrics.decoys_used == 2

    def test_the_adaptive_arm_reports_live_decoys_not_cumulative(self):
        report = ExperimentRunner(CAMPUS, trials=10, seed=4).run(
            budget=2, arms=("adaptive",)
        )
        # Ceiling is budget * 3; a cumulative count over 10 campaigns would blow past it.
        assert report.arms[0].metrics.decoys_used <= 6

    def test_identical_seeds_reproduce_the_experiment(self):
        first = ExperimentRunner(CAMPUS, trials=20, seed=7).run(budget=2, arms=("random",))
        second = ExperimentRunner(CAMPUS, trials=20, seed=7).run(budget=2, arms=("random",))
        assert first.arms[0].metrics.detection_rate == second.arms[0].metrics.detection_rate
        assert first.arms[0].hosts == second.arms[0].hosts

    def test_sweep_covers_every_budget(self):
        reports = ExperimentRunner(CAMPUS, trials=5, seed=1).sweep(
            budgets=(1, 2), arms=("attack-path",)
        )
        assert [r.budget for r in reports] == [1, 2]

    def test_a_bigger_budget_never_detects_less(self):
        runner = ExperimentRunner(CAMPUS, trials=60, seed=21)
        small = runner.run(budget=1, arms=("attack-path",)).arms[0]
        large = runner.run(budget=5, arms=("attack-path",)).arms[0]
        assert large.metrics.detection_rate >= small.metrics.detection_rate

    def test_invalid_inputs_are_rejected(self):
        with pytest.raises(ValueError, match="budget must be at least 1"):
            ExperimentRunner(CAMPUS, trials=5).run(budget=0)
        with pytest.raises(ValueError, match="trials must be at least 1"):
            ExperimentRunner(CAMPUS, trials=0).run(budget=1)

    def test_accepts_a_repository(self, enterprise_repo):
        report = ExperimentRunner(enterprise_repo, trials=5, seed=1).run(
            budget=1, arms=("attack-path",)
        )
        assert report.network == "acme-enterprise"
