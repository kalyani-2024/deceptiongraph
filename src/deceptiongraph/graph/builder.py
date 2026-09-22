"""Graph Builder: turns a :class:`NetworkModel` into a labelled property graph.

The graph is a ``networkx.MultiDiGraph`` whose node/edge labels match the Neo4j
schema planned for stage 2, so the Cypher translation is mechanical:

    USER       -[:LOGS_INTO]->        HOST
    HOST       -[:CONNECTS_TO]->      HOST
    HOST       -[:RUNS]->             SERVICE
    HOST       -[:STORES]->           CREDENTIAL
    CREDENTIAL -[:GRANTS_ACCESS]->    HOST
    SERVICE    -[:HAS_VULNERABILITY]->VULNERABILITY
"""

from __future__ import annotations

import networkx as nx

from ..domain.enums import Exposure, NodeType, RelationType
from .model import INTERNET, NetworkModel


class GraphBuilder:
    """Builds the asset graph and the host-level connectivity projection."""

    def __init__(self, model: NetworkModel) -> None:
        self.model = model

    def build(self) -> nx.MultiDiGraph:
        graph = nx.MultiDiGraph(name=self.model.name)
        self._add_internet(graph)
        self._add_hosts(graph)
        self._add_users(graph)
        self._add_connections(graph)
        return graph

    def build_connectivity(self) -> nx.DiGraph:
        """Host-only view: who can talk to whom, including the internet source.

        Parallel connections collapse to the most permissive one, since an
        attacker only needs the easiest route.
        """
        graph = nx.DiGraph(name=f"{self.model.name}:connectivity")
        graph.add_node(INTERNET, node_type=NodeType.HOST.value, label=INTERNET, synthetic=True)
        for host in self.model.hosts.values():
            graph.add_node(
                host.id,
                node_type=NodeType.HOST.value,
                label=host.name,
                exposure=host.exposure.value,
                criticality=host.criticality,
                is_crown_jewel=host.is_crown_jewel,
                attack_surface=host.attack_surface,
            )

        for connection in self._effective_connections():
            probability = connection.traversal_probability
            if graph.has_edge(connection.source, connection.target):
                existing = graph[connection.source][connection.target]
                if existing["traversal_probability"] >= probability:
                    continue
            graph.add_edge(
                connection.source,
                connection.target,
                relation=RelationType.CONNECTS_TO.value,
                protocol=connection.protocol,
                ports=list(connection.ports),
                filtered=connection.filtered,
                traversal_probability=probability,
            )
        return graph

    # -- internals ---------------------------------------------------------

    def _effective_connections(self):
        """Declared connections plus implied internet edges to exposed hosts."""
        seen = {(c.source, c.target) for c in self.model.connections}
        yield from self.model.connections
        from .model import Connection

        for host in self.model.hosts.values():
            if host.exposure is Exposure.INTERNET and (INTERNET, host.id) not in seen:
                yield Connection(source=INTERNET, target=host.id, filtered=0.0)

    def _add_internet(self, graph: nx.MultiDiGraph) -> None:
        graph.add_node(INTERNET, node_type=NodeType.HOST.value, label=INTERNET, synthetic=True)

    def _add_hosts(self, graph: nx.MultiDiGraph) -> None:
        for host in self.model.hosts.values():
            graph.add_node(
                host.id,
                node_type=NodeType.HOST.value,
                label=host.name,
                ip=host.ip,
                os=host.os,
                exposure=host.exposure.value,
                criticality=host.criticality,
                is_crown_jewel=host.is_crown_jewel,
                patch_level=host.patch_level,
                attack_surface=host.attack_surface,
                tags=list(host.tags),
            )

            for service in host.services:
                graph.add_node(
                    service.id,
                    node_type=NodeType.SERVICE.value,
                    label=service.name,
                    port=service.port,
                    protocol=service.protocol,
                    version=service.version,
                )
                graph.add_edge(host.id, service.id, key=RelationType.RUNS.value,
                               relation=RelationType.RUNS.value)

                for vuln in service.vulnerabilities:
                    graph.add_node(
                        vuln.cve_id,
                        node_type=NodeType.VULNERABILITY.value,
                        label=vuln.cve_id,
                        cvss=vuln.cvss,
                        exploitability=vuln.exploitability,
                        privilege_gained=vuln.privilege_gained.value,
                        description=vuln.description,
                    )
                    graph.add_edge(
                        service.id,
                        vuln.cve_id,
                        key=RelationType.HAS_VULNERABILITY.value,
                        relation=RelationType.HAS_VULNERABILITY.value,
                    )

            for credential in host.credentials:
                graph.add_node(
                    credential.id,
                    node_type=NodeType.CREDENTIAL.value,
                    label=credential.username,
                    kind=credential.kind,
                    privilege=credential.privilege.value,
                    strength=credential.strength,
                )
                graph.add_edge(host.id, credential.id, key=RelationType.STORES.value,
                               relation=RelationType.STORES.value)
                for target in credential.grants_access:
                    if target not in self.model.hosts:
                        raise ValueError(
                            f"credential {credential.id} grants access to unknown host {target}"
                        )
                    graph.add_edge(
                        credential.id,
                        target,
                        key=RelationType.GRANTS_ACCESS.value,
                        relation=RelationType.GRANTS_ACCESS.value,
                        privilege=credential.privilege.value,
                    )

    def _add_users(self, graph: nx.MultiDiGraph) -> None:
        for user in self.model.users.values():
            graph.add_node(
                user.id,
                node_type=NodeType.USER.value,
                label=user.username,
                role=user.role,
                privilege=user.privilege.value,
            )
            for host_id in user.logs_into:
                if host_id not in self.model.hosts:
                    raise ValueError(f"user {user.id} logs into unknown host {host_id}")
                graph.add_edge(
                    user.id,
                    host_id,
                    key=RelationType.LOGS_INTO.value,
                    relation=RelationType.LOGS_INTO.value,
                    privilege=user.privilege.value,
                )

    def _add_connections(self, graph: nx.MultiDiGraph) -> None:
        for connection in self._effective_connections():
            graph.add_edge(
                connection.source,
                connection.target,
                key=f"{RelationType.CONNECTS_TO.value}:{connection.protocol}",
                relation=RelationType.CONNECTS_TO.value,
                protocol=connection.protocol,
                ports=list(connection.ports),
                filtered=connection.filtered,
                traversal_probability=connection.traversal_probability,
            )
