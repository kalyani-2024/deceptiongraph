from __future__ import annotations

from pathlib import Path

import pytest

from deceptiongraph.deception.placement import RiskBasedPlacement
from deceptiongraph.facade import SecurityFacade
from deceptiongraph.graph.repository import InMemoryGraphRepository

NETWORK = Path(__file__).resolve().parents[1] / "data" / "networks" / "enterprise.yaml"


class TestConstruction:
    def test_accepts_a_path(self):
        assert SecurityFacade(NETWORK).model.name == "acme-enterprise"

    def test_accepts_a_string(self):
        assert SecurityFacade(str(NETWORK)).model.name == "acme-enterprise"

    def test_accepts_a_model(self, enterprise_model):
        assert SecurityFacade(enterprise_model).model is enterprise_model

    def test_accepts_a_repository(self, enterprise_repo):
        assert SecurityFacade(enterprise_repo).repository is enterprise_repo

    def test_subsystems_stay_reachable(self, enterprise_repo):
        facade = SecurityFacade(enterprise_repo)
        assert facade.attack is not None
        assert facade.risk.engine is facade.attack
        assert facade.predictor.engine is facade.attack


class TestAnalyseNetwork:
    def test_reports_the_worst_path_and_choke_points(self, enterprise_repo):
        analysis = SecurityFacade(enterprise_repo).analyse_network()
        assert analysis.most_dangerous_path.target == "db01"
        assert analysis.choke_points["api02"] == pytest.approx(1.0)
        assert analysis.summary["hosts"] == 5
        assert "db01" in analysis.crown_jewel_paths

    def test_result_is_cached_until_refreshed(self, enterprise_repo):
        facade = SecurityFacade(enterprise_repo)
        assert facade.analyse_network() is facade.analyse_network()
        assert facade.analyse_network(refresh=True) is not None

    def test_serialises(self, enterprise_repo):
        data = SecurityFacade(enterprise_repo).analyse_network().as_dict()
        assert data["most_dangerous_path"]["nodes"][0] == "INTERNET"
        assert data["risk"]["assets"]


class TestDeployDeception:
    def test_deploys_and_remembers(self, enterprise_repo):
        facade = SecurityFacade(enterprise_repo)
        assert facade.deployment is None
        deployment = facade.deploy_deception(budget=2)
        assert facade.deployment is deployment
        assert len(deployment.assets) == 2

    def test_strategy_can_be_set_at_construction(self, enterprise_repo):
        facade = SecurityFacade(enterprise_repo, strategy=RiskBasedPlacement())
        assert facade.deploy_deception(budget=1).strategy == "risk"

    def test_strategy_can_be_overridden_per_call(self, enterprise_repo):
        facade = SecurityFacade(enterprise_repo)
        assert facade.deploy_deception(budget=1, strategy="centrality").strategy == "centrality"

    def test_comparison_covers_every_strategy(self, enterprise_repo):
        results = SecurityFacade(enterprise_repo).compare_strategies(budget=2)
        assert {d.strategy for d in results} == {"random", "risk", "centrality", "attack-path"}


class TestGenerateReport:
    def test_report_runs_analysis_without_deploying(self, enterprise_repo):
        facade = SecurityFacade(enterprise_repo)
        report = facade.generate_report()
        assert report["network"] == "acme-enterprise"
        assert report["analysis"] is not None
        assert report["deception"] is None
        assert facade.deployment is None

    def test_report_includes_deception_once_deployed(self, enterprise_repo):
        facade = SecurityFacade(enterprise_repo)
        facade.deploy_deception(budget=2)
        report = facade.generate_report()
        assert report["deception"]["coverage"]["decoys_used"] == 2

    def test_report_is_json_serialisable(self, enterprise_repo):
        import json

        facade = SecurityFacade(enterprise_repo)
        facade.deploy_deception(budget=2)
        assert json.loads(json.dumps(facade.generate_report(), default=str))


class TestRecommendations:
    def test_names_the_worst_path_and_choke_points(self, enterprise_repo):
        advice = " ".join(SecurityFacade(enterprise_repo).recommend())
        assert "Most dangerous path" in advice
        assert "api02" in advice

    def test_prompts_for_deception_when_none_is_deployed(self, enterprise_repo):
        advice = " ".join(SecurityFacade(enterprise_repo).recommend())
        assert "No deception deployed yet" in advice

    def test_describes_the_deployment_once_present(self, enterprise_repo):
        facade = SecurityFacade(enterprise_repo)
        facade.deploy_deception(budget=3)
        advice = " ".join(facade.recommend())
        assert "Current deployment" in advice
        assert "No deception deployed yet" not in advice


class TestPrediction:
    def test_exposes_next_moves_and_trajectory(self, enterprise_repo):
        facade = SecurityFacade(enterprise_repo)
        assert facade.next_moves("web01")[0].target == "api02"
        assert facade.predict_from("web01").nodes == ("web01", "api02", "db01")


class TestEmptyNetwork:
    def test_a_network_with_no_hosts_does_not_crash(self):
        from deceptiongraph.graph.loader import build_model

        facade = SecurityFacade(InMemoryGraphRepository(build_model({"name": "empty"})))
        analysis = facade.analyse_network()
        assert analysis.most_dangerous_path is None
        assert analysis.choke_points == {}
        assert facade.deploy_deception(budget=3).assets == ()
        assert facade.generate_report()["deception"]["coverage"]["decoys_used"] == 0
