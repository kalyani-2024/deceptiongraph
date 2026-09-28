"""Deception layer tests.

Coverage numbers are checked against the ``linear`` fixture
(INTERNET -> web -> app -> db, step probabilities 1.0, 1.0, 0.5), so expected
values are arithmetic rather than golden values from a previous run.
"""

from __future__ import annotations

import pytest

from deceptiongraph.deception.assets import (
    DeceptionAsset,
    DeceptionKind,
    DeceptionState,
    Lure,
    Marker,
    Sensor,
)
from deceptiongraph.deception.coverage import detection_by_host, intercept
from deceptiongraph.deception.engine import DeceptionEngine
from deceptiongraph.deception.factory import (
    CredentialDecoyFactory,
    DocumentDecoyFactory,
    NetworkDecoyFactory,
    factory_for,
)
from deceptiongraph.deception.placement import (
    AttackPathPlacement,
    CentralityBasedPlacement,
    PlacementContext,
    RandomPlacement,
    RiskBasedPlacement,
    strategy_for,
    suggest_kind,
)
from deceptiongraph.domain.entities import Credential, Host, Service


@pytest.fixture
def host():
    return Host(id="api02", name="API Server", criticality=0.6)


@pytest.fixture
def jewel():
    return Host(
        id="db01", name="Production Database", criticality=0.95, is_crown_jewel=True,
        services=[Service(id="s", name="postgresql", port=5432)],
    )


class TestAssets:
    def test_detection_needs_both_the_bait_and_the_sensor(self):
        asset = _asset(believability=0.8, fidelity=0.5)
        assert asset.detection_probability == pytest.approx(0.4)

    def test_believability_must_be_a_probability(self):
        with pytest.raises(ValueError, match="believability"):
            Lure(id="l", kind=DeceptionKind.DOCUMENT, name="x", host_id="h", believability=1.4)

    def test_fidelity_must_be_a_probability(self):
        with pytest.raises(ValueError, match="fidelity"):
            Sensor(id="s", kind=DeceptionKind.DOCUMENT, lure_id="l", watches="", fidelity=-0.1)

    def test_assets_start_staged_and_deploy(self):
        asset = _asset()
        assert asset.state is DeceptionState.STAGED
        asset.deploy()
        assert asset.state is DeceptionState.DEPLOYED

    def test_markers_are_unique(self):
        assert Marker.mint("credential") != Marker.mint("credential")


class TestAbstractFactory:
    @pytest.mark.parametrize(
        "factory_cls,kind",
        [
            (CredentialDecoyFactory, DeceptionKind.CREDENTIAL),
            (NetworkDecoyFactory, DeceptionKind.NETWORK),
            (DocumentDecoyFactory, DeceptionKind.DOCUMENT),
        ],
    )
    def test_each_family_builds_a_matched_set(self, factory_cls, kind, host, jewel):
        asset = factory_cls().create(host, jewel)
        assert asset.kind is kind
        assert asset.lure.kind is asset.sensor.kind is asset.marker.kind is kind
        assert asset.sensor.lure_id == asset.lure.id
        assert asset.marker.lure_id == asset.lure.id
        assert asset.host_id == host.id
        assert asset.sensor.watches

    def test_a_decoy_imitating_a_crown_jewel_is_more_believable(self, host, jewel):
        factory = CredentialDecoyFactory()
        plain = factory.create(host)
        mimicking = factory.create(host, jewel)
        assert mimicking.lure.believability > plain.lure.believability
        assert mimicking.protects == "db01"

    def test_credential_decoy_names_the_asset_it_guards(self, host, jewel):
        asset = CredentialDecoyFactory().create(host, jewel)
        assert asset.lure.name == "fake_production_database_password.txt"
        assert "production_database" in asset.lure.payload["username"]

    def test_credential_path_follows_the_host_os(self, jewel):
        windows = Host(id="adm01", name="Admin", os="windows-11")
        asset = CredentialDecoyFactory().create(windows, jewel)
        assert "ProgramData" in asset.lure.payload["path"]

    def test_network_decoy_copies_the_service_it_imitates(self, host, jewel):
        asset = NetworkDecoyFactory().create(host, jewel)
        assert asset.lure.payload["port"] == 5432
        assert asset.lure.payload["service"] == "postgresql"
        assert asset.lure.name == "db01-replica"

    def test_document_decoy_is_a_file(self, host, jewel):
        asset = DocumentDecoyFactory().create(host, jewel)
        assert asset.lure.name.endswith(".xlsx")
        assert asset.lure.payload["path"].startswith("/srv/backups/")

    def test_ids_are_unique_within_a_factory(self, host):
        factory = DocumentDecoyFactory()
        assert factory.create(host).id != factory.create(host).id

    def test_factory_lookup_by_kind(self):
        assert isinstance(factory_for(DeceptionKind.NETWORK), NetworkDecoyFactory)

    def test_unknown_kind_is_rejected(self):
        with pytest.raises(ValueError, match="unknown deception kind"):
            factory_for("HONEYPOT")


class TestPlacementStrategies:
    def test_every_strategy_is_registered_and_named(self):
        for name in ("random", "risk", "centrality", "attack-path"):
            strategy = strategy_for(name)
            assert strategy.name == name
            assert strategy.description

    def test_unknown_strategy_is_rejected(self):
        with pytest.raises(ValueError, match="unknown placement strategy"):
            strategy_for("vibes")

    def test_budget_is_respected(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        assert len(RiskBasedPlacement().plan(context, budget=2)) == 2

    def test_zero_budget_places_nothing(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        assert AttackPathPlacement().plan(context, budget=0) == ()

    def test_negative_budget_is_rejected(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        with pytest.raises(ValueError, match="budget must not be negative"):
            AttackPathPlacement().plan(context, budget=-1)

    def test_unreachable_hosts_are_not_candidates(self, linear_repo):
        context = PlacementContext.build(linear_repo)
        assert "island" not in {h.id for h in context.candidate_hosts()}

    def test_attack_path_strategy_picks_the_choke_points(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        chosen = {p.host_id for p in AttackPathPlacement().plan(context, budget=2)}
        assert chosen == {"web01", "api02"}

    def test_attack_path_prefers_earlier_interception(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        scores = AttackPathPlacement().score_hosts(context)
        assert scores["web01"] > scores["api02"] > scores["db01"]

    def test_risk_strategy_follows_the_risk_ranking(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        placements = RiskBasedPlacement().plan(context, budget=3)
        ranked = [a.host_id for a in context.risk.rank_assets()][:3]
        assert [p.host_id for p in placements] == ranked

    def test_centrality_strategy_scores_the_middle_of_the_graph(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        scores = CentralityBasedPlacement().score_hosts(context)
        assert scores["api02"] > 0.0

    def test_random_placement_is_reproducible_with_a_seed(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        first = RandomPlacement(seed=7).plan(context, budget=3)
        second = RandomPlacement(seed=7).plan(context, budget=3)
        assert [p.host_id for p in first] == [p.host_id for p in second]

    def test_placements_carry_a_rationale(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        for placement in AttackPathPlacement().plan(context, budget=2):
            assert placement.rationale

    def test_kind_suggestion_follows_what_the_attacker_would_seek(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        # api02 stores a credential that unlocks the database
        assert suggest_kind("api02", context) is DeceptionKind.CREDENTIAL
        # bak01 stores none but can reach onward
        assert suggest_kind("bak01", context) is DeceptionKind.NETWORK

    def test_unknown_host_falls_back_to_a_document(self, enterprise_repo):
        context = PlacementContext.build(enterprise_repo)
        assert suggest_kind("ghost", context) is DeceptionKind.DOCUMENT


class TestCoverage:
    def test_decoys_on_one_host_combine_with_noisy_or(self):
        assets = [_asset(believability=1.0, fidelity=0.5, host="h"),
                  _asset(believability=1.0, fidelity=0.5, host="h")]
        assert detection_by_host(assets)["h"] == pytest.approx(0.75)

    def test_interception_walks_the_path(self, linear_repo):
        from deceptiongraph.analysis.attack_graph import AttackGraphEngine

        path = AttackGraphEngine(linear_repo).best_path("db")
        # A perfect decoy on the first hop: attacker arrives with p=1.0.
        result = intercept(path, {"web": 1.0})
        assert result.detection_probability == pytest.approx(1.0)
        assert result.mean_hops_to_detection == pytest.approx(1.0)
        assert result.undetected_arrival == pytest.approx(0.0)

    def test_detection_is_terminal(self, linear_repo):
        from deceptiongraph.analysis.attack_graph import AttackGraphEngine

        path = AttackGraphEngine(linear_repo).best_path("db")
        # Half the attackers are caught at web; the rest carry on to db (p=0.5).
        result = intercept(path, {"web": 0.5, "db": 1.0})
        assert result.detection_probability == pytest.approx(0.5 + 0.5 * 0.5)
        assert result.undetected_arrival == pytest.approx(0.0)

    def test_no_decoys_means_no_detection(self, linear_repo):
        from deceptiongraph.analysis.attack_graph import AttackGraphEngine

        path = AttackGraphEngine(linear_repo).best_path("db")
        result = intercept(path, {})
        assert result.detection_probability == 0.0
        assert result.mean_hops_to_detection is None
        assert result.undetected_arrival == pytest.approx(0.5)


class TestDeceptionEngine:
    def test_deploy_builds_and_activates_assets(self, enterprise_repo):
        deployment = DeceptionEngine(enterprise_repo).deploy(budget=3)
        assert len(deployment.assets) == 3
        assert all(a.state is DeceptionState.DEPLOYED for a in deployment.assets)
        assert deployment.coverage.decoys_used == 3

    def test_planning_does_not_build_anything(self, enterprise_repo):
        placements = DeceptionEngine(enterprise_repo).plan(budget=2)
        assert len(placements) == 2
        assert all(p.rationale for p in placements)

    def test_default_strategy_is_attack_path(self, enterprise_repo):
        assert DeceptionEngine(enterprise_repo).deploy(budget=1).strategy == "attack-path"

    def test_strategy_can_be_named_or_passed(self, enterprise_repo):
        engine = DeceptionEngine(enterprise_repo, strategy="risk")
        assert engine.deploy(budget=1).strategy == "risk"
        assert engine.deploy(budget=1, strategy=RandomPlacement(seed=1)).strategy == "random"

    def test_decoys_raise_detection_above_nothing(self, enterprise_repo):
        engine = DeceptionEngine(enterprise_repo)
        assert engine.evaluate([]).detection_probability == 0.0
        assert engine.deploy(budget=3).coverage.detection_probability > 0.0

    def test_more_decoys_never_detect_less(self, enterprise_repo):
        engine = DeceptionEngine(enterprise_repo)
        scores = [
            engine.deploy(budget=b).coverage.detection_probability for b in (1, 2, 3)
        ]
        assert scores == sorted(scores)

    def test_tokens_resolve_back_to_their_decoy(self, enterprise_repo):
        deployment = DeceptionEngine(enterprise_repo).deploy(budget=2)
        token = deployment.assets[0].marker.token
        assert deployment.asset_by_token(token) is deployment.assets[0]
        assert deployment.asset_by_token("not-a-token") is None

    def test_attack_path_beats_random_on_the_reference_network(self, enterprise_repo):
        results = DeceptionEngine(enterprise_repo).compare(budget=2, seed=1337)
        by_name = {d.strategy: d.coverage.detection_probability for d in results}
        assert by_name["attack-path"] > by_name["random"]

    def test_comparison_is_ordered_and_reproducible(self, enterprise_repo):
        engine = DeceptionEngine(enterprise_repo)
        first = engine.compare(budget=2, seed=99)
        second = engine.compare(budget=2, seed=99)
        probabilities = [d.coverage.detection_probability for d in first]
        assert probabilities == sorted(probabilities, reverse=True)
        assert [d.strategy for d in first] == [d.strategy for d in second]
        assert [list(d.hosts) for d in first] == [list(d.hosts) for d in second]

    def test_crown_jewel_coverage_is_reported(self, enterprise_repo):
        coverage = DeceptionEngine(enterprise_repo).deploy(budget=3).coverage
        assert coverage.critical_asset_coverage == pytest.approx(1.0)
        assert 0.0 <= coverage.host_coverage <= 1.0

    def test_deployment_serialises(self, enterprise_repo):
        data = DeceptionEngine(enterprise_repo).deploy(budget=2).as_dict()
        assert data["strategy"] == "attack-path"
        assert len(data["assets"]) == 2
        assert data["coverage"]["decoys_used"] == 2
        assert data["placements"][0]["rationale"]

    def test_recommendations_read_like_the_brief(self, enterprise_repo):
        lines = DeceptionEngine(enterprise_repo).deploy(budget=2).recommendations()
        assert lines[0].startswith("[1] ")
        assert "on web01" in lines[0]

    def test_a_network_without_crown_jewels_still_deploys(self):
        from deceptiongraph.graph.loader import build_model
        from deceptiongraph.graph.repository import InMemoryGraphRepository

        model = build_model({
            "hosts": [
                {"id": "a", "exposure": "INTERNET", "patch_level": 0.0, "services": [
                    {"name": "http", "port": 80, "vulnerabilities": [
                        {"cve": "C1", "cvss": 10.0, "exploitability": 1.0}]}
                ]},
                {"id": "b", "patch_level": 0.0, "services": [
                    {"name": "ssh", "port": 22, "vulnerabilities": [
                        {"cve": "C2", "cvss": 10.0, "exploitability": 1.0}]}
                ]},
            ],
            "connections": [{"from": "a", "to": "b"}],
        })
        deployment = DeceptionEngine(InMemoryGraphRepository(model)).deploy(budget=1)
        assert len(deployment.assets) == 1
        assert deployment.coverage.critical_asset_coverage == 0.0


def _asset(believability: float = 0.5, fidelity: float = 0.9, host: str = "h") -> DeceptionAsset:
    lure = Lure(id="l", kind=DeceptionKind.DOCUMENT, name="bait.xlsx", host_id=host,
                believability=believability)
    sensor = Sensor(id="s", kind=DeceptionKind.DOCUMENT, lure_id="l", watches="open",
                    fidelity=fidelity)
    marker = Marker(id="m", kind=DeceptionKind.DOCUMENT, lure_id="l", token="tok")
    return DeceptionAsset(id="a", kind=DeceptionKind.DOCUMENT, host_id=host,
                          lure=lure, sensor=sensor, marker=marker)
