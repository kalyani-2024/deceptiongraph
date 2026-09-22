"""Analysis tests.

The ``linear`` fixture is INTERNET -> web -> app -> db with hand-chosen
probabilities, so expected numbers below are arithmetic rather than golden
values copied out of a run:

    INTERNET -> web   perimeter entry, web surface 1.0            p = 1.00
    web      -> app   exploit 1.0 OR credential reuse 1.0         p = 1.00
    app      -> db    exploit, db surface 0.5                     p = 0.50

so P(reach db) = 0.5 and, with db criticality 1.0, path risk = 0.5.
"""

from __future__ import annotations

import pytest

from deceptiongraph.analysis.attack_graph import AttackGraphEngine
from deceptiongraph.analysis.prediction import PathPredictor
from deceptiongraph.analysis.risk import RiskEngine
from deceptiongraph.domain.enums import AttackVector
from deceptiongraph.graph.loader import build_model
from deceptiongraph.graph.model import INTERNET
from deceptiongraph.graph.repository import InMemoryGraphRepository


@pytest.fixture
def linear_engine(linear_repo):
    return AttackGraphEngine(linear_repo)


class TestAttackGraphConstruction:
    def test_perimeter_entry_is_the_only_edge_from_the_internet(self, linear_engine):
        graph = linear_engine.graph()
        assert list(graph.successors(INTERNET)) == ["web"]
        assert graph[INTERNET]["web"]["vector"] == AttackVector.PERIMETER_ENTRY.value

    def test_edge_probability_is_traversal_times_surface(self, linear_engine):
        graph = linear_engine.graph()
        assert graph["app"]["db"]["probability"] == pytest.approx(0.5)

    def test_parallel_vectors_combine_with_noisy_or(self):
        # exploit p=0.5 alongside a credential with reuse p=0.5 -> 0.75
        model = build_model({
            "hosts": [
                {"id": "a", "credentials": [
                    {"username": "u", "strength": 0.5, "grants_access": ["b"]}
                ]},
                {"id": "b", "patch_level": 0.0, "services": [
                    {"name": "x", "port": 1, "vulnerabilities": [
                        {"cve": "C", "cvss": 10.0, "exploitability": 0.5}
                    ]}
                ]},
            ],
            "connections": [{"from": "a", "to": "b"}],
        })
        graph = AttackGraphEngine(InMemoryGraphRepository(model)).graph()
        assert graph["a"]["b"]["probability"] == pytest.approx(0.75)

    def test_credential_without_a_network_route_is_penalised(self):
        model = build_model({
            "hosts": [
                {"id": "a", "credentials": [
                    {"username": "u", "strength": 0.0, "grants_access": ["b"]}
                ]},
                {"id": "b"},
            ],
        })
        graph = AttackGraphEngine(InMemoryGraphRepository(model)).graph()
        assert graph["a"]["b"]["probability"] == pytest.approx(0.5)
        assert graph["a"]["b"]["vector"] == AttackVector.CREDENTIAL_REUSE.value

    def test_a_shared_session_creates_edges_both_ways(self):
        model = build_model({
            "hosts": [{"id": "a", "patch_level": 0.0}, {"id": "b", "patch_level": 0.0}],
            "users": [{"username": "dba", "logs_into": ["a", "b"]}],
        })
        graph = AttackGraphEngine(InMemoryGraphRepository(model)).graph()
        assert graph.has_edge("a", "b") and graph.has_edge("b", "a")
        assert graph["a"]["b"]["vector"] == AttackVector.TRUSTED_SESSION.value
        assert graph["a"]["b"]["probability"] == pytest.approx(0.35)

    def test_a_hardened_unreachable_host_gets_no_inbound_edge(self, linear_engine):
        assert list(linear_engine.graph().predecessors("island")) == []

    def test_reachability_excludes_the_island(self, linear_engine):
        assert linear_engine.reachable_from(INTERNET) == ("app", "db", "web")


class TestAttackPaths:
    def test_best_path_multiplies_step_probabilities(self, linear_engine):
        path = linear_engine.best_path("db")
        assert path.nodes == (INTERNET, "web", "app", "db")
        assert path.probability == pytest.approx(0.5)
        assert path.impact == pytest.approx(1.0)
        assert path.risk == pytest.approx(0.5)
        assert path.length == 3

    def test_no_path_to_an_unreachable_host(self, linear_engine):
        assert linear_engine.best_path("island") is None

    def test_unknown_endpoints_yield_nothing(self, linear_engine):
        assert linear_engine.best_path("ghost") is None
        assert linear_engine.paths("ghost") == []
        assert linear_engine.paths("db", source="db") == []

    def test_most_dangerous_path_targets_the_crown_jewel(self, linear_engine):
        assert linear_engine.most_dangerous_path().target == "db"

    def test_enumeration_is_ordered_by_risk(self, enterprise_repo):
        engine = AttackGraphEngine(enterprise_repo)
        found = engine.paths("db01")
        assert len(found) > 1
        assert found == sorted(found, key=lambda p: (p.risk, -p.length), reverse=True)

    def test_best_path_matches_the_best_enumerated_path(self, enterprise_repo):
        engine = AttackGraphEngine(enterprise_repo)
        best = engine.best_path("db01")
        enumerated = engine.paths("db01")[0]
        assert best.probability == pytest.approx(enumerated.probability)

    def test_reference_network_follows_the_briefs_route(self, enterprise_repo):
        path = AttackGraphEngine(enterprise_repo).most_dangerous_path()
        assert path.nodes == (INTERNET, "web01", "api02", "db01")

    def test_choke_points_cover_every_route_to_a_jewel(self, enterprise_repo):
        chokes = AttackGraphEngine(enterprise_repo).choke_points()
        assert chokes["api02"] == pytest.approx(1.0)
        assert "db01" not in chokes  # the target itself is not a choke point

    def test_path_serialises(self, linear_engine):
        data = linear_engine.best_path("db").as_dict()
        assert data["nodes"] == [INTERNET, "web", "app", "db"]
        assert len(data["steps"]) == 3
        assert data["steps"][0]["vector"] == AttackVector.PERIMETER_ENTRY.value


class TestRiskEngine:
    def test_asset_risk_blends_path_and_intrinsic_risk(self, linear_repo):
        risk = RiskEngine(linear_repo).asset_risk("db")
        assert risk.compromise_probability == pytest.approx(0.5)
        assert risk.path_risk == pytest.approx(0.5)
        # db intrinsic: surface 0.5 * (0.6 + 0.4) = 0.5, crown jewel premium 1.15
        assert risk.intrinsic == pytest.approx(0.575)
        assert risk.score == pytest.approx(0.65 * 0.5 + 0.35 * 0.575)
        assert risk.hops_from_internet == 3

    def test_unreachable_asset_has_no_path_risk_but_stays_listed(self, linear_repo):
        risk = RiskEngine(linear_repo).asset_risk("island")
        assert risk.compromise_probability == 0.0
        assert risk.path_risk == 0.0
        assert risk.hops_from_internet is None
        assert risk.reachable is False

    def test_unknown_host_is_rejected(self, linear_repo):
        with pytest.raises(KeyError, match="unknown host"):
            RiskEngine(linear_repo).asset_risk("ghost")

    def test_crown_jewel_exposure_is_the_chance_of_reaching_any_jewel(self, linear_repo):
        assert RiskEngine(linear_repo).crown_jewel_exposure() == pytest.approx(0.5)

    def test_exposure_is_zero_without_crown_jewels(self):
        model = build_model({"hosts": [{"id": "a"}]})
        assert RiskEngine(InMemoryGraphRepository(model)).crown_jewel_exposure() == 0.0

    def test_ranking_is_descending_and_complete(self, enterprise_repo):
        assets = RiskEngine(enterprise_repo).rank_assets()
        assert len(assets) == 5
        assert [a.score for a in assets] == sorted((a.score for a in assets), reverse=True)

    def test_network_report_serialises(self, linear_repo):
        report = RiskEngine(linear_repo).network_risk()
        data = report.as_dict()
        assert data["crown_jewel_exposure"] == pytest.approx(0.5)
        assert data["worst_asset"] == report.assets[0].host_id
        assert data["intrinsic"] is not None
        assert 0.0 <= report.score <= 1.0


class TestPathPredictor:
    def test_next_hops_form_a_distribution(self, enterprise_repo):
        hops = PathPredictor(enterprise_repo).next_hops("web01")
        assert sum(h.probability for h in hops) == pytest.approx(1.0)
        assert [h.probability for h in hops] == sorted(
            (h.probability for h in hops), reverse=True
        )

    def test_the_route_to_the_jewel_beats_the_dead_end(self, enterprise_repo):
        hops = PathPredictor(enterprise_repo).next_hops("web01")
        assert hops[0].target == "api02"
        assert hops[0].leads_to_crown_jewel is True

    def test_visited_hosts_are_not_revisited(self, enterprise_repo):
        hops = PathPredictor(enterprise_repo).next_hops("web01", visited=("api02",))
        assert "api02" not in {h.target for h in hops}

    def test_a_dead_end_has_no_next_hop(self, linear_repo):
        predictor = PathPredictor(linear_repo)
        assert predictor.next_hops("db") == ()
        assert predictor.most_likely_next("db") is None

    def test_unknown_node_is_rejected(self, linear_repo):
        with pytest.raises(KeyError, match="unknown node"):
            PathPredictor(linear_repo).next_hops("ghost")

    def test_trajectory_stops_at_the_crown_jewel(self, enterprise_repo):
        trajectory = PathPredictor(enterprise_repo).predict_trajectory("web01", depth=5)
        assert trajectory.nodes == ("web01", "api02", "db01")
        assert 0.0 < trajectory.confidence <= 1.0

    def test_trajectory_respects_the_depth_limit(self, enterprise_repo):
        assert len(PathPredictor(enterprise_repo).predict_trajectory("web01", depth=1).hops) == 1

    def test_objective_is_the_highest_payoff_target(self, enterprise_repo):
        assert PathPredictor(enterprise_repo).objective("web01") == "db01"

    def test_objective_is_unknown_from_a_dead_end(self, linear_repo):
        assert PathPredictor(linear_repo).objective("db") is None

    def test_hop_serialises(self, enterprise_repo):
        hop = PathPredictor(enterprise_repo).most_likely_next("web01")
        data = hop.as_dict()
        assert data["target"] == "api02"
        assert 0.0 <= data["probability"] <= 1.0
