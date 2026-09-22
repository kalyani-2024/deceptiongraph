from __future__ import annotations

import pytest

from deceptiongraph.domain.enums import NodeType, RelationType
from deceptiongraph.graph.builder import GraphBuilder
from deceptiongraph.graph.loader import build_model
from deceptiongraph.graph.model import INTERNET, Connection, NetworkModel
from deceptiongraph.graph.repository import GraphRepository, InMemoryGraphRepository


class TestLoader:
    def test_loads_the_reference_network(self, enterprise_model):
        summary = enterprise_model.summary()
        assert summary["hosts"] == 5
        assert summary["crown_jewels"] == ["db01"]
        assert summary["entry_points"] == ["web01"]

    def test_builds_the_declared_hierarchy(self, enterprise_model):
        root = enterprise_model.root
        assert root is not None
        assert root.node_type is NodeType.ORGANISATION
        assert {c.id for c in root.children} == {"dept:engineering", "dept:operations"}
        assert {h.id for h in root.hosts()} == set(enterprise_model.hosts)

    def test_falls_back_to_exposure_buckets_without_hierarchy(self, linear_model):
        root = linear_model.root
        assert root is not None
        assert {c.node_type for c in root.children} == {NodeType.SUBNET}
        assert {h.id for h in root.hosts()} == set(linear_model.hosts)

    def test_generates_stable_ids_for_nested_entities(self):
        model = build_model({
            "hosts": [{
                "id": "h", "services": [{"name": "http", "port": 80}],
                "credentials": [{"username": "svc"}],
            }]
        })
        host = model.hosts["h"]
        assert host.services[0].id == "h:http:80"
        assert host.credentials[0].id == "h:cred:svc"

    def test_rejects_a_credential_pointing_at_an_unknown_host(self):
        with pytest.raises(ValueError, match="unknown host ghost"):
            build_model({
                "hosts": [{"id": "h", "credentials": [
                    {"username": "u", "grants_access": ["ghost"]}
                ]}]
            })

    def test_rejects_a_user_on_an_unknown_host(self):
        with pytest.raises(ValueError, match="logs into unknown host"):
            build_model({"hosts": [{"id": "h"}], "users": [
                {"username": "u", "logs_into": ["ghost"]}
            ]})

    def test_rejects_a_connection_to_an_unknown_host(self):
        with pytest.raises(ValueError, match="unknown host"):
            build_model({"hosts": [{"id": "h"}], "connections": [
                {"from": "h", "to": "ghost"}
            ]})

    def test_rejects_a_host_without_an_id(self):
        with pytest.raises(ValueError, match="missing required field 'id'"):
            build_model({"hosts": [{"name": "nameless"}]})

    def test_rejects_an_unknown_enum_value(self):
        with pytest.raises(ValueError, match="invalid exposure"):
            build_model({"hosts": [{"id": "h", "exposure": "OUTER_SPACE"}]})

    def test_rejects_an_unknown_hierarchy_type(self):
        with pytest.raises(ValueError, match="unknown hierarchy node type"):
            build_model({"hosts": [{"id": "h"}],
                         "hierarchy": {"type": "galaxy", "hosts": ["h"]}})

    def test_rejects_a_hierarchy_referencing_an_unknown_host(self):
        with pytest.raises(ValueError, match="hierarchy references unknown host"):
            build_model({"hosts": [{"id": "h"}],
                         "hierarchy": {"type": "subnet", "hosts": ["ghost"]}})


class TestNetworkModel:
    def test_rejects_duplicate_host_ids(self):
        with pytest.raises(ValueError, match="duplicate host id"):
            build_model({"hosts": [{"id": "h"}, {"id": "h"}]})

    def test_connection_filtering_must_be_a_probability(self):
        with pytest.raises(ValueError, match="filtered"):
            Connection(source="a", target="b", filtered=1.5)

    def test_internet_exposed_hosts_are_entry_points_without_a_declared_link(self):
        model = build_model({"hosts": [{"id": "h", "exposure": "INTERNET"}]})
        assert model.entry_points == ("h",)


class TestGraphBuilder:
    def test_asset_graph_carries_the_neo4j_labels(self, enterprise_model):
        graph = GraphBuilder(enterprise_model).build()
        relations = {data["relation"] for _, _, data in graph.edges(data=True)}
        assert {
            RelationType.RUNS.value,
            RelationType.HAS_VULNERABILITY.value,
            RelationType.STORES.value,
            RelationType.GRANTS_ACCESS.value,
            RelationType.LOGS_INTO.value,
            RelationType.CONNECTS_TO.value,
        } <= relations

        node_types = {data["node_type"] for _, data in graph.nodes(data=True)}
        assert {
            NodeType.HOST.value, NodeType.SERVICE.value,
            NodeType.VULNERABILITY.value, NodeType.CREDENTIAL.value, NodeType.USER.value,
        } <= node_types

    def test_credential_edge_points_at_the_host_it_unlocks(self, enterprise_model):
        graph = GraphBuilder(enterprise_model).build()
        credential = enterprise_model.hosts["api02"].credentials[0]
        assert graph.has_edge(credential.id, "db01")
        assert graph.has_edge("api02", credential.id)

    def test_connectivity_view_holds_only_hosts(self, enterprise_model):
        graph = GraphBuilder(enterprise_model).build_connectivity()
        assert set(graph.nodes) == set(enterprise_model.hosts) | {INTERNET}
        assert graph.has_edge(INTERNET, "web01")

    def test_connectivity_keeps_the_most_permissive_parallel_link(self):
        model = build_model({
            "hosts": [{"id": "a"}, {"id": "b"}],
            "connections": [
                {"from": "a", "to": "b", "filtered": 0.9},
                {"from": "a", "to": "b", "filtered": 0.1},
            ],
        })
        graph = GraphBuilder(model).build_connectivity()
        assert graph["a"]["b"]["traversal_probability"] == pytest.approx(0.9)

    def test_internet_exposure_implies_an_edge_from_the_internet(self):
        model = build_model({"hosts": [{"id": "h", "exposure": "INTERNET"}]})
        assert GraphBuilder(model).build_connectivity().has_edge(INTERNET, "h")


class TestRepository:
    def test_in_memory_repository_satisfies_the_protocol(self, enterprise_repo):
        assert isinstance(enterprise_repo, GraphRepository)

    def test_exposes_hosts_graphs_and_neighbours(self, enterprise_repo):
        assert enterprise_repo.host("db01").is_crown_jewel is True
        assert enterprise_repo.host("ghost") is None
        assert len(tuple(enterprise_repo.hosts())) == 5
        assert set(enterprise_repo.neighbours("web01")) == {"api02", "bak01"}
        assert enterprise_repo.neighbours("ghost") == ()

    def test_refuses_queries_before_a_network_is_loaded(self):
        repo = InMemoryGraphRepository()
        with pytest.raises(RuntimeError, match="no network loaded"):
            repo.asset_graph()
        with pytest.raises(RuntimeError, match="no network loaded"):
            repo.connectivity_graph()

    def test_saving_supplies_a_default_hierarchy(self):
        model = NetworkModel(name="bare")
        assert model.root is None
        InMemoryGraphRepository(model)
        assert model.root is not None
        assert model.root.node_type is NodeType.ORGANISATION
