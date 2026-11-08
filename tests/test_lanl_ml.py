"""Real-dataset adapter and the ML models.

Runs against the small LANL-format fixture in ``lanl_fixture.py``. These tests
check the pipeline - parsing, causality of the features, leakage guards,
persistence, the strategy and the replay - not the security result, which only
the real dataset can give.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from deceptiongraph.datasets.lanl import (
    AUTH_FEATURES,
    AuthFeaturizer,
    LanlAssetDiscovery,
    load_redteam_csv,
    parse_auth_line,
    prepare,
    read_auth,
    read_redteam,
)
from deceptiongraph.graph.loader import load_network
from deceptiongraph.graph.repository import InMemoryGraphRepository

from lanl_fixture import ATTACKER, DCS, write_fixture

sklearn = pytest.importorskip("sklearn")


@pytest.fixture(scope="module")
def raw_files(tmp_path_factory):
    return write_fixture(tmp_path_factory.mktemp("lanl-raw"))


@pytest.fixture(scope="module")
def prepared(raw_files, tmp_path_factory):
    out = tmp_path_factory.mktemp("lanl-prepared")
    summary = prepare(raw_files[0], raw_files[1], out, negative_rate=1.0, max_hosts=60)
    return out, summary


@pytest.fixture(scope="module")
def trained(prepared, tmp_path_factory):
    from deceptiongraph.deception.placement import PlacementContext
    from deceptiongraph.ml.data import load_features, split_by_time
    from deceptiongraph.ml.detector import LateralMovementDetector
    from deceptiongraph.ml.targets import TargetRanker

    out, _ = prepared
    table = load_features(out)
    train, test, split = split_by_time(table)
    detector = LateralMovementDetector.fit(train, seed=3, max_iter=60)
    detector.info["split_time"] = split
    repository = InMemoryGraphRepository(load_network(out / "network.yaml"))
    targets = {e.dst for e in load_redteam_csv(out / "redteam.csv") if e.time < split}
    ranker = TargetRanker.fit(PlacementContext.build(repository), targets)
    ranker.info["split_time"] = split
    return {"table": table, "train": train, "test": test, "split": split,
            "detector": detector, "ranker": ranker, "repository": repository}


# -- parsing ---------------------------------------------------------------


class TestParsing:
    def test_an_auth_line_parses(self):
        event = parse_auth_line("151648,U748@DOM1,U748@DOM1,C17693,C728,NTLM,Network,LogOn,Success")
        assert event.time == 151648 and event.user == "U748"
        assert event.src == "C17693" and event.dst == "C728"
        assert event.success and event.is_human and event.is_remote and event.is_lateral_logon

    def test_machine_accounts_and_local_logons_are_not_lateral(self):
        machine = parse_auth_line("1,C625$@DOM1,U147@DOM1,C625,C586,Negotiate,Batch,LogOn,Success")
        local = parse_auth_line("1,U5@DOM1,U5@DOM1,C9,C9,Kerberos,Interactive,LogOn,Success")
        assert not machine.is_lateral_logon
        assert not local.is_lateral_logon

    def test_malformed_lines_are_skipped(self):
        assert parse_auth_line("not,a,line") is None
        assert parse_auth_line("x,U1@D,U1@D,C1,C2,NTLM,Network,LogOn,Success") is None

    def test_read_auth_respects_the_window(self, raw_files):
        events = list(read_auth(raw_files[0], start=86_400, until=2 * 86_400))
        assert events and all(86_400 <= e.time < 2 * 86_400 for e in events)

    def test_redteam_strips_the_domain_and_sorts(self, raw_files):
        events = read_redteam(raw_files[1])
        assert events
        assert all("@" not in e.user and e.src == ATTACKER for e in events)
        assert [e.time for e in events] == sorted(e.time for e in events)

    def test_missing_files_say_so(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="dataset file not found"):
            list(read_auth(tmp_path / "nope.txt.gz"))


# -- features --------------------------------------------------------------


class TestFeaturizer:
    def col(self, name):
        return AUTH_FEATURES.index(name)

    def test_first_time_flags_switch_off_after_the_first_logon(self):
        f = AuthFeaturizer()
        first = f.step("U1", "C1", "C2", "Kerberos", "Network", 100)
        second = f.step("U1", "C1", "C2", "Kerberos", "Network", 200)
        for name in ("new_user_dst", "new_user_src", "new_pair"):
            assert first[self.col(name)] == 1.0
            assert second[self.col(name)] == 0.0

    def test_features_only_see_the_past(self):
        f = AuthFeaturizer()
        before = f.features("U1", "C1", "C2", "NTLM", "Network", 0)
        assert before[self.col("dst_user_count")] == 0.0
        f.update("U1", "C1", "C2")
        f.update("U2", "C3", "C2")
        after = f.features("U3", "C4", "C2", "NTLM", "Network", 0)
        assert after[self.col("dst_user_count")] == pytest.approx(np.log1p(2))
        assert after[self.col("auth_ntlm")] == 1.0

    def test_failures_are_counted_per_user(self):
        f = AuthFeaturizer()
        f.observe_failure("U1")
        f.observe_failure("U1")
        vector = f.features("U1", "C1", "C2", "Kerberos", "Network", 0)
        assert vector[self.col("user_fail_count")] == pytest.approx(np.log1p(2))


# -- prepare and the twin --------------------------------------------------


class TestPrepare:
    def test_every_redteam_event_is_matched_and_labelled(self, prepared):
        _, summary = prepared
        assert summary.redteam_events > 0
        assert summary.redteam_matched == summary.redteam_events
        assert summary.positive_rows == summary.redteam_events

    def test_outputs_are_written(self, prepared):
        out, _ = prepared
        for name in ("network.yaml", "auth_features.csv.gz", "redteam.csv", "hosts.csv",
                     "meta.json"):
            assert (out / name).exists(), name
        meta = json.loads((out / "meta.json").read_text())
        assert meta["features"] == list(AUTH_FEATURES)
        assert "Kent" in meta["citation"]

    def test_the_twin_is_an_ordinary_network_file(self, prepared):
        model = load_network(prepared[0] / "network.yaml")
        assert len(model.hosts) == prepared[1].twin_hosts
        assert set(DCS) <= set(model.crown_jewels)  # the most-used servers
        assert len(model.crown_jewels) == 3
        assert model.entry_points  # workstations are the phishing foothold

    def test_the_attacker_does_not_leak_into_the_twin(self, prepared):
        """The red team's machine is only ever seen doing red-team logons."""
        model = load_network(prepared[0] / "network.yaml")
        assert ATTACKER not in model.hosts
        redteam = load_redteam_csv(prepared[0] / "redteam.csv")
        triples = {(e.user, e.src, e.dst) for e in redteam}
        for host in model.hosts.values():
            for credential in host.credentials:
                for target in credential.grants_access:
                    assert (credential.username, host.id, target) not in triples

    def test_analysis_runs_on_the_twin(self, prepared):
        from deceptiongraph.facade import SecurityFacade

        security = SecurityFacade(prepared[0] / "network.yaml")
        analysis = security.analyse_network()
        assert analysis.crown_jewel_paths
        deployment = security.deploy_deception(budget=3)
        assert len(deployment.assets) == 3

    def test_the_adapter_builds_the_same_twin(self, raw_files, prepared):
        direct = LanlAssetDiscovery(raw_files[0], raw_files[1], max_hosts=60).discover()
        written = load_network(prepared[0] / "network.yaml")
        assert set(direct.hosts) == set(written.hosts)
        assert direct.crown_jewels == written.crown_jewels

    def test_negative_sampling_sets_weights(self, raw_files, tmp_path):
        summary = prepare(raw_files[0], raw_files[1], tmp_path, negative_rate=0.5, seed=1)
        from deceptiongraph.ml.data import load_features

        table = load_features(tmp_path)
        assert set(np.unique(table.weight[table.y == 0])) == {2.0}
        assert set(np.unique(table.weight[table.y == 1])) == {1.0}
        assert summary.negative_rows < summary.lateral_logons - summary.positive_rows

    def test_a_bad_negative_rate_is_rejected(self, raw_files, tmp_path):
        with pytest.raises(ValueError, match="negative_rate"):
            prepare(raw_files[0], raw_files[1], tmp_path, negative_rate=0.0)


# -- detector --------------------------------------------------------------


class TestDetector:
    def test_split_is_by_time(self, trained):
        assert trained["train"].time.max() < trained["split"] <= trained["test"].time.min()
        assert trained["train"].positives > 0 and trained["test"].positives > 0

    def test_it_separates_the_fixture_attacker(self, trained):
        metrics = trained["detector"].evaluate(trained["test"])
        positive_rate = trained["test"].positives / len(trained["test"])
        assert metrics.average_precision > positive_rate
        assert metrics.roc_auc > 0.8

    def test_save_and_load_round_trip(self, trained, tmp_path):
        from deceptiongraph.ml.detector import LateralMovementDetector

        path = trained["detector"].save(tmp_path / "d.joblib")
        loaded = LateralMovementDetector.load(path)
        X = trained["test"].X[:20]
        assert np.allclose(loaded.score(X), trained["detector"].score(X))
        assert loaded.threshold == trained["detector"].threshold
        assert (tmp_path / "d.json").exists()

    def test_loading_the_wrong_file_is_an_error(self, trained, tmp_path):
        from deceptiongraph.ml.detector import LateralMovementDetector

        path = trained["ranker"].save(tmp_path / "r.joblib")
        with pytest.raises(ValueError, match="not a lateral-movement detector"):
            LateralMovementDetector.load(path)

    def test_threshold_for_fpr(self):
        from deceptiongraph.ml.detector import threshold_for_fpr

        scores = np.array([0.9, 0.8, 0.7, 0.6, 0.95])
        y = np.array([0, 0, 0, 0, 1])
        weight = np.ones(5)
        t = threshold_for_fpr(scores, y, weight, target_fpr=0.25)
        flagged_negatives = ((scores >= t) & (y == 0)).sum()
        assert flagged_negatives == 1  # 1 of 4 negatives = 25%

    def test_weighted_metrics_scale_sampled_negatives(self):
        from deceptiongraph.ml.detector import evaluate_scores

        y = np.array([1, 0, 0])
        scores = np.array([0.9, 0.95, 0.1])
        metrics = evaluate_scores(y, scores, np.array([1.0, 100.0, 100.0]),
                                  threshold=0.5, days=1.0)
        assert metrics.negatives_weighted == 200.0
        assert metrics.false_alerts_per_day == 100.0
        assert metrics.precision_at_threshold == pytest.approx(1 / 101)

    def test_rule_baseline_is_bounded(self, trained):
        from deceptiongraph.ml.detector import rule_scores

        scores = rule_scores(trained["test"])
        assert scores.min() >= 0.0 and scores.max() <= 1.0

    def test_permutation_importance_names_every_feature(self, trained):
        importance = trained["detector"].feature_importance(trained["test"], repeats=1)
        assert set(importance) == set(AUTH_FEATURES)


# -- target ranker and the ml strategy --------------------------------------


class TestTargetRanker:
    def test_host_features_cover_every_host(self, trained):
        from deceptiongraph.deception.placement import PlacementContext
        from deceptiongraph.ml.targets import HOST_FEATURES, host_features

        repository = trained["repository"]
        ids, X = host_features(PlacementContext.build(repository))
        assert ids == sorted(repository.model.hosts)
        assert X.shape == (len(ids), len(HOST_FEATURES))
        assert np.isfinite(X).all()

    def test_scores_are_probabilities(self, trained):
        from deceptiongraph.deception.placement import PlacementContext

        scores = trained["ranker"].scores(PlacementContext.build(trained["repository"]))
        assert scores and all(0.0 <= p <= 1.0 for p in scores.values())

    def test_ml_placement_plans_a_full_budget(self, trained):
        from deceptiongraph.deception.engine import DeceptionEngine
        from deceptiongraph.ml.targets import MLPlacement

        engine = DeceptionEngine(trained["repository"])
        deployment = engine.deploy(budget=4, strategy=MLPlacement(trained["ranker"]))
        assert deployment.strategy == "ml" and len(deployment.assets) == 4
        assert all("P(targeted)" in a.rationale for a in deployment.assets)

    def test_ml_strategy_by_name_loads_the_model_from_the_environment(
        self, trained, tmp_path, monkeypatch
    ):
        from deceptiongraph.deception.engine import DeceptionEngine
        from deceptiongraph.deception.placement import strategy_for

        path = trained["ranker"].save(tmp_path / "ranker.joblib")
        monkeypatch.setenv("DG_ML_TARGET_MODEL", str(path))
        deployment = DeceptionEngine(trained["repository"]).deploy(budget=2, strategy="ml")
        assert deployment.strategy == "ml"
        assert strategy_for("ML").name == "ml"

    def test_a_missing_model_is_a_clear_error(self, trained, tmp_path, monkeypatch):
        from deceptiongraph.deception.engine import DeceptionEngine

        monkeypatch.setenv("DG_ML_TARGET_MODEL", str(tmp_path / "missing.joblib"))
        with pytest.raises(FileNotFoundError, match="dgraph lanl train"):
            DeceptionEngine(trained["repository"]).deploy(budget=2, strategy="ml")

    def test_no_positives_is_rejected(self, trained):
        from deceptiongraph.deception.placement import PlacementContext
        from deceptiongraph.ml.targets import TargetRanker

        with pytest.raises(ValueError, match="none of the targeted hosts"):
            TargetRanker.fit(PlacementContext.build(trained["repository"]), {"nowhere"})


# -- evaluation against the red team ----------------------------------------


class TestRedTeamEvaluation:
    def test_score_placement_by_hand(self):
        from deceptiongraph.datasets.lanl import RedTeamEvent
        from deceptiongraph.ml.evaluation import score_placement

        events = [RedTeamEvent(0, "U1", "X", "A"), RedTeamEvent(3600, "U1", "X", "B"),
                  RedTeamEvent(7200, "U2", "X", "B"), RedTeamEvent(9000, "U2", "X", "C")]
        result = score_placement({"B"}, events, {"A", "B", "C"})
        assert result["target_hit_rate"] == pytest.approx(1 / 3)
        assert result["event_coverage"] == 0.5
        assert result["events_before_detection"] == 1.0
        assert result["hours_to_detection"] == 1.0

    def test_undetected_has_no_timing(self):
        from deceptiongraph.datasets.lanl import RedTeamEvent
        from deceptiongraph.ml.evaluation import score_placement

        result = score_placement({"Z"}, [RedTeamEvent(0, "U1", "X", "A")], {"A"})
        assert result["hours_to_detection"] is None
        assert result["target_hit_rate"] == 0.0

    def test_every_strategy_is_evaluated(self, trained, prepared):
        from deceptiongraph.deception.placement import STRATEGIES, RandomPlacement
        from deceptiongraph.ml.evaluation import evaluate_on_redteam
        from deceptiongraph.ml.targets import MLPlacement

        strategies = {"random": RandomPlacement()}
        strategies.update({n: c() for n, c in STRATEGIES.items() if n != "random"})
        strategies["ml"] = MLPlacement(trained["ranker"])
        events = [e for e in load_redteam_csv(prepared[0] / "redteam.csv")
                  if e.time >= trained["split"]]
        outcomes = evaluate_on_redteam(trained["repository"], events, strategies,
                                       budgets=(2, 4), random_trials=5)
        assert {(o.strategy, o.budget) for o in outcomes} == {
            (s, b) for s in strategies for b in (2, 4)
        }
        random_arm = next(o for o in outcomes if o.strategy == "random")
        assert random_arm.trials == 5
        assert all(0.0 <= o.target_hit_rate <= 1.0 for o in outcomes)


# -- sensor and replay -----------------------------------------------------


class TestSensorAndReplay:
    def test_a_flagged_logon_reaches_the_mediator(self, trained):
        from deceptiongraph.datasets.lanl import AuthEvent
        from deceptiongraph.deception.engine import DeceptionEngine
        from deceptiongraph.ml.detector import LateralMovementDetector
        from deceptiongraph.ml.sensor import MLDetectionSensor
        from deceptiongraph.runtime.events import EventType
        from deceptiongraph.runtime.mediator import SecurityMediator

        repository = trained["repository"]
        engine = DeceptionEngine(repository)
        mediator = SecurityMediator(repository, deception=engine,
                                    deployment=engine.deploy(budget=2))
        trigger_happy = LateralMovementDetector(
            model=trained["detector"].model, threshold=0.0, features=AUTH_FEATURES
        )
        sensor = MLDetectionSensor(trigger_happy, mediator=mediator)
        target = sorted(repository.model.hosts)[0]
        p, reaction = sensor.observe(AuthEvent(10, "U1@DOM1", "U1@DOM1", ATTACKER, target,
                                               "NTLM", "Network", "LogOn", True))
        assert reaction is not None
        assert reaction.event.type is EventType.HOST_COMPROMISED
        assert reaction.event.actor_id == f"src:{ATTACKER}"
        assert reaction.incident is not None
        assert sensor.alerts == 1

    def test_failures_and_local_logons_are_not_scored(self, trained):
        from deceptiongraph.datasets.lanl import AuthEvent
        from deceptiongraph.ml.sensor import MLDetectionSensor

        sensor = MLDetectionSensor(trained["detector"])
        sensor.observe(AuthEvent(1, "U1@D", "U1@D", "C1", "C2", "NTLM", "Network", "LogOn", False))
        sensor.observe(AuthEvent(2, "U1@D", "U1@D", "C1", "C1", "NTLM", "Network", "LogOn", True))
        assert sensor.scored == 0

    def test_replay_runs_the_held_out_period(self, trained, prepared):
        from deceptiongraph.ml.sensor import replay
        from deceptiongraph.ml.targets import MLPlacement

        summary = replay(prepared[0], trained["detector"],
                         strategy=MLPlacement(trained["ranker"]), budget=3,
                         start_time=trained["split"], table=trained["table"])
        assert summary.rows == len(trained["test"])
        assert summary.redteam_rows == trained["test"].positives
        assert summary.ml_alerts == summary.ml_true_alerts + summary.ml_false_alerts
        assert summary.ml_true_alerts > 0
        assert summary.incidents >= 1
        assert summary.as_dict()["strategy"] == "ml"


# -- CLI -------------------------------------------------------------------


def test_cli_pipeline(raw_files, tmp_path):
    from typer.testing import CliRunner

    from deceptiongraph.cli.main import app

    runner = CliRunner()
    out, models = tmp_path / "prep", tmp_path / "models"

    result = runner.invoke(app, ["lanl", "prepare", "--auth", str(raw_files[0]),
                                 "--redteam", str(raw_files[1]), "--out", str(out),
                                 "--negative-rate", "1.0"])
    assert result.exit_code == 0, result.output
    assert "Red-team events matched" in result.output

    result = runner.invoke(app, ["lanl", "train", str(out), "--models", str(models)])
    assert result.exit_code == 0, result.output
    assert (models / "detector.joblib").exists()
    report = json.loads((models / "training_report.json").read_text())
    assert "rule_baseline" in report and "average_precision" in report["detector"]["test"]

    result = runner.invoke(app, ["lanl", "evaluate", str(out), "--models", str(models),
                                 "-b", "2", "--random-trials", "3",
                                 "-o", str(tmp_path / "eval.json")])
    assert result.exit_code == 0, result.output
    assert {r["strategy"] for r in json.loads((tmp_path / "eval.json").read_text())} >= {
        "random", "attack-path", "ml"}

    result = runner.invoke(app, ["lanl", "replay", str(out), "--models", str(models),
                                 "-s", "ml", "-b", "2"])
    assert result.exit_code == 0, result.output
    assert "Replay: ml" in result.output

    # The twin is an ordinary network: the existing commands take it as-is.
    result = runner.invoke(app, ["deceive", str(out / "network.yaml"), "-b", "2"])
    assert result.exit_code == 0, result.output


def test_cli_prepare_reports_missing_files(tmp_path):
    from typer.testing import CliRunner

    from deceptiongraph.cli.main import app

    result = CliRunner().invoke(app, ["lanl", "prepare", "--auth", str(tmp_path / "a.gz"),
                                      "--redteam", str(tmp_path / "r.gz")])
    assert result.exit_code == 1
    assert "csr.lanl.gov" in result.output
