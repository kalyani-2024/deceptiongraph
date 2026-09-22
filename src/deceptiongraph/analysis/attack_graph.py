"""Attack graph engine.

The asset graph says what *exists*. The attack graph says what an attacker can
*do*: one directed edge per host-to-host transition an attacker could make,
weighted by how likely that transition succeeds.

Three vectors produce edges:

``PERIMETER_ENTRY``
    The internet reaching an exposed host through its vulnerable services.
``NETWORK_EXPLOIT``
    A foothold host reaching a neighbour and exploiting one of its services.
``CREDENTIAL_REUSE``
    A credential stored on the foothold that unlocks another host directly.
``TRUSTED_SESSION``
    A user (or service account) with active sessions on both hosts, letting the
    attacker ride the trust rather than break anything.

Where several vectors connect the same pair of hosts, their probabilities
combine with a noisy-OR: the attacker only needs one of them to work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import islice

import networkx as nx

from ..domain.entities import Host
from ..domain.enums import AttackVector, Privilege
from ..graph.model import INTERNET, NetworkModel
from ..graph.repository import GraphRepository

UNROUTED_CREDENTIAL_PENALTY = 0.5
"""A credential whose target has no discovered network path is still usable, but
only if the attacker finds a route, so its probability is halved."""

SESSION_HIJACK_BASE = 0.35
"""Base chance of stealing a live session/token shared between two hosts."""

MAX_PATHS = 2000
"""Safety cap on simple-path enumeration for dense networks."""


@dataclass(frozen=True, slots=True)
class AttackStep:
    """One hop of an attack path."""

    source: str
    target: str
    vector: AttackVector
    probability: float
    privilege_gained: Privilege
    detail: str = ""

    def describe(self) -> str:
        return f"{self.source} -> {self.target} via {self.vector.value} (p={self.probability:.2f})"


@dataclass(frozen=True, slots=True)
class AttackPath:
    """A full route from the attacker's origin to a target host."""

    steps: tuple[AttackStep, ...]
    probability: float
    impact: float
    risk: float

    @property
    def nodes(self) -> tuple[str, ...]:
        if not self.steps:
            return ()
        return (self.steps[0].source,) + tuple(s.target for s in self.steps)

    @property
    def source(self) -> str:
        return self.steps[0].source if self.steps else ""

    @property
    def target(self) -> str:
        return self.steps[-1].target if self.steps else ""

    @property
    def length(self) -> int:
        return len(self.steps)

    def describe(self) -> str:
        return " -> ".join(self.nodes)

    def as_dict(self) -> dict:
        return {
            "nodes": list(self.nodes),
            "length": self.length,
            "probability": round(self.probability, 4),
            "impact": round(self.impact, 4),
            "risk": round(self.risk, 4),
            "steps": [
                {
                    "source": s.source,
                    "target": s.target,
                    "vector": s.vector.value,
                    "probability": round(s.probability, 4),
                    "privilege_gained": s.privilege_gained.value,
                    "detail": s.detail,
                }
                for s in self.steps
            ],
        }


@dataclass(slots=True)
class _EdgeVectors:
    """Accumulates the vectors found between one pair of hosts."""

    steps: list[AttackStep] = field(default_factory=list)

    def add(self, step: AttackStep) -> None:
        if step.probability > 0.0:
            self.steps.append(step)

    def collapse(self) -> AttackStep | None:
        if not self.steps:
            return None
        best = max(self.steps, key=lambda s: s.probability)
        combined = _noisy_or(s.probability for s in self.steps)
        detail = "; ".join(sorted({s.detail for s in self.steps if s.detail}))
        return AttackStep(
            source=best.source,
            target=best.target,
            vector=best.vector,
            probability=combined,
            privilege_gained=max(
                (s.privilege_gained for s in self.steps), key=lambda p: p.level
            ),
            detail=detail,
        )


class AttackGraphEngine:
    """Derives and queries the attack graph for a network."""

    def __init__(self, repository: GraphRepository) -> None:
        self.repository = repository
        self._graph: nx.DiGraph | None = None

    @property
    def model(self) -> NetworkModel:
        return self.repository.model  # type: ignore[attr-defined]

    def graph(self) -> nx.DiGraph:
        """The attack graph, built once and cached."""
        if self._graph is None:
            self._graph = self.build()
        return self._graph

    def build(self) -> nx.DiGraph:
        model = self.model
        connectivity = self.repository.connectivity_graph()
        pairs: dict[tuple[str, str], _EdgeVectors] = {}

        def bucket(source: str, target: str) -> _EdgeVectors:
            return pairs.setdefault((source, target), _EdgeVectors())

        # 1. Network-reachable exploitation (and perimeter entry from INTERNET).
        for source, target, data in connectivity.edges(data=True):
            if source == target:
                continue
            host = model.hosts.get(target)
            if host is None:
                continue
            traversal = float(data.get("traversal_probability", 1.0))
            probability = traversal * host.attack_surface
            vector = (
                AttackVector.PERIMETER_ENTRY if source == INTERNET else AttackVector.NETWORK_EXPLOIT
            )
            bucket(source, target).add(
                AttackStep(
                    source=source,
                    target=target,
                    vector=vector,
                    probability=probability,
                    privilege_gained=host.max_privilege_gained,
                    detail=_exploit_detail(host),
                )
            )

        # 2. Credential reuse from the host that stores the secret.
        for host in model.hosts.values():
            for credential in host.credentials:
                for target_id in credential.grants_access:
                    if target_id == host.id:
                        continue
                    target = model.hosts.get(target_id)
                    if target is None:
                        continue
                    probability = credential.reuse_probability
                    if not connectivity.has_edge(host.id, target_id):
                        probability *= UNROUTED_CREDENTIAL_PENALTY
                    bucket(host.id, target_id).add(
                        AttackStep(
                            source=host.id,
                            target=target_id,
                            vector=AttackVector.CREDENTIAL_REUSE,
                            probability=probability,
                            privilege_gained=credential.privilege,
                            detail=f"credential {credential.username} ({credential.kind})",
                        )
                    )

        # 3. Shared sessions: a principal logged into both hosts.
        for user in model.users.values():
            reachable = [h for h in user.logs_into if h in model.hosts]
            for source in reachable:
                for target in reachable:
                    if source == target:
                        continue
                    target_host = model.hosts[target]
                    probability = SESSION_HIJACK_BASE * (1.0 - 0.5 * target_host.patch_level)
                    bucket(source, target).add(
                        AttackStep(
                            source=source,
                            target=target,
                            vector=AttackVector.TRUSTED_SESSION,
                            probability=probability,
                            privilege_gained=user.privilege,
                            detail=f"session of {user.username} ({user.role})",
                        )
                    )

        graph = nx.DiGraph(name=f"{model.name}:attack")
        graph.add_node(INTERNET, label=INTERNET, criticality=0.0, synthetic=True)
        for host in model.hosts.values():
            graph.add_node(
                host.id,
                label=host.name,
                criticality=host.criticality,
                is_crown_jewel=host.is_crown_jewel,
                exposure=host.exposure.value,
                attack_surface=host.attack_surface,
            )

        for (source, target), vectors in pairs.items():
            step = vectors.collapse()
            if step is None:
                continue
            graph.add_edge(
                source,
                target,
                step=step,
                vector=step.vector.value,
                probability=step.probability,
                privilege_gained=step.privilege_gained.value,
                detail=step.detail,
                weight=_to_cost(step.probability),
            )
        return graph

    # -- queries -----------------------------------------------------------

    def reachable_from(self, source: str = INTERNET) -> tuple[str, ...]:
        graph = self.graph()
        if source not in graph:
            return ()
        return tuple(sorted(nx.descendants(graph, source)))

    def paths(
        self,
        target: str,
        source: str = INTERNET,
        cutoff: int | None = None,
        limit: int = MAX_PATHS,
    ) -> list[AttackPath]:
        """Every simple attack path from ``source`` to ``target``, best first."""
        graph = self.graph()
        if source not in graph or target not in graph or source == target:
            return []
        raw = nx.all_simple_paths(graph, source, target, cutoff=cutoff)
        paths = [self._to_attack_path(graph, nodes) for nodes in islice(raw, limit)]
        paths.sort(key=lambda p: (p.risk, -p.length), reverse=True)
        return paths

    def best_path(self, target: str, source: str = INTERNET) -> AttackPath | None:
        """The single most likely route, found without enumerating every path.

        Edge costs are ``-log(p)``, so the shortest weighted path is the one with
        the highest success probability.
        """
        graph = self.graph()
        if source not in graph or target not in graph or source == target:
            return None
        try:
            nodes = nx.shortest_path(graph, source, target, weight="weight")
        except nx.NetworkXNoPath:
            return None
        return self._to_attack_path(graph, nodes)

    def most_dangerous_path(self, source: str = INTERNET) -> AttackPath | None:
        """Highest-risk route to any host, crown jewels weighted by criticality.

        Ties break towards the costlier target: when two routes carry the same
        risk, the one that loses more of the business is the one to report.
        """
        candidates = [
            path
            for host_id in self.model.hosts
            if (path := self.best_path(host_id, source=source)) is not None
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda p: (p.risk, p.impact, p.length))

    def paths_to_crown_jewels(self, source: str = INTERNET) -> dict[str, AttackPath]:
        result: dict[str, AttackPath] = {}
        for host_id in self.model.crown_jewels:
            path = self.best_path(host_id, source=source)
            if path is not None:
                result[host_id] = path
        return result

    def choke_points(self, source: str = INTERNET) -> dict[str, float]:
        """How often each host appears on the best route to a crown jewel.

        A host on every route is where deception pays off most; stage 2's
        placement strategies consume this directly.
        """
        paths = self.paths_to_crown_jewels(source)
        if not paths:
            return {}
        counts: dict[str, float] = {}
        for path in paths.values():
            for node in path.nodes:
                if node in (source, path.target):
                    continue
                counts[node] = counts.get(node, 0.0) + 1.0
        return {node: count / len(paths) for node, count in sorted(counts.items())}

    # -- internals ---------------------------------------------------------

    def _to_attack_path(self, graph: nx.DiGraph, nodes: list[str] | tuple[str, ...]) -> AttackPath:
        steps: list[AttackStep] = []
        probability = 1.0
        for source, target in zip(nodes, nodes[1:]):
            step: AttackStep = graph[source][target]["step"]
            steps.append(step)
            probability *= step.probability
        target_host: Host | None = self.model.hosts.get(nodes[-1])
        impact = target_host.criticality if target_host else 0.0
        return AttackPath(
            steps=tuple(steps),
            probability=probability,
            impact=impact,
            risk=probability * impact,
        )


def _exploit_detail(host: Host) -> str:
    cves = [v.cve_id for s in host.services for v in s.vulnerabilities]
    if not cves:
        return "no known vulnerability"
    return "exploit " + ", ".join(sorted(cves)[:3])


def _to_cost(probability: float) -> float:
    """Turn a success probability into an additive shortest-path cost."""
    import math

    p = max(1e-9, min(1.0, probability))
    return -math.log(p)


def _noisy_or(probabilities) -> float:
    miss = 1.0
    for p in probabilities:
        miss *= 1.0 - max(0.0, min(1.0, p))
    return 1.0 - miss
