"""Strategy pattern over deception placement.

    DeceptionPlacementStrategy
              |
              +--- RandomPlacement          the control group
              +--- RiskBasedPlacement       guard what is most at risk
              +--- CentralityBasedPlacement guard where traffic concentrates
              +--- AttackPathPlacement      guard where the attacker must pass

All four answer the same question - *given a budget of N decoys, which hosts?* -
so stage 5 can swap one for another and measure the difference. `RandomPlacement`
exists to be beaten: a strategy that cannot outperform random placement is not
worth its complexity.

A strategy ranks hosts and says *why*. Choosing the kind of decoy for a host is
a separate decision (see :func:`suggest_kind`), because it depends on what the
attacker would plausibly look for there rather than on the ranking method.
"""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass

import networkx as nx

from ..analysis.attack_graph import AttackGraphEngine
from ..analysis.prediction import PathPredictor
from ..analysis.risk import RiskEngine
from ..domain.entities import Host
from ..graph.model import INTERNET
from ..graph.repository import GraphRepository
from .assets import DeceptionKind


@dataclass(slots=True)
class PlacementContext:
    """Everything the strategies are allowed to look at.

    Built once and shared, so comparing strategies compares the strategies and
    not how many times each recomputed the attack graph.
    """

    repository: GraphRepository
    attack: AttackGraphEngine
    risk: RiskEngine
    predictor: PathPredictor
    source: str = INTERNET

    @classmethod
    def build(cls, repository: GraphRepository, source: str = INTERNET) -> "PlacementContext":
        attack = AttackGraphEngine(repository)
        return cls(
            repository=repository,
            attack=attack,
            risk=RiskEngine(repository, attack),
            predictor=PathPredictor(repository, attack),
            source=source,
        )

    @property
    def model(self):
        return self.repository.model

    def candidate_hosts(self) -> tuple[Host, ...]:
        """Hosts worth considering: the ones an attacker can actually reach.

        Placing a decoy somewhere unreachable protects nothing.
        """
        reachable = set(self.attack.reachable_from(self.source))
        hosts = [h for h in self.model.hosts.values() if h.id in reachable]
        return tuple(hosts or self.model.hosts.values())


@dataclass(frozen=True, slots=True)
class Placement:
    """One decision: put a decoy of this kind on this host, for this reason."""

    host_id: str
    kind: DeceptionKind
    score: float
    rationale: str
    mimics: str | None = None

    def as_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "kind": self.kind.value,
            "score": round(self.score, 4),
            "rationale": self.rationale,
            "mimics": self.mimics,
        }


class DeceptionPlacementStrategy(ABC):
    """Strategy role: rank hosts by how much a decoy there would be worth."""

    name: str = "abstract"
    description: str = ""

    @abstractmethod
    def score_hosts(self, context: PlacementContext) -> dict[str, float]:
        """Score every candidate host. Higher is a better place for a decoy."""

    def explain(self, host_id: str, score: float, context: PlacementContext) -> str:
        return f"{self.name} score {score:.2f}"

    def plan(self, context: PlacementContext, budget: int) -> tuple[Placement, ...]:
        """Turn scores into the top ``budget`` placements."""
        if budget < 0:
            raise ValueError(f"budget must not be negative, got {budget}")
        if budget == 0:
            return ()

        scores = self.score_hosts(context)
        ranked = sorted(scores.items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
        placements = []
        for host_id, score in ranked[:budget]:
            if score <= 0.0:
                continue
            mimics = _mimic_target(host_id, context)
            placements.append(
                Placement(
                    host_id=host_id,
                    kind=suggest_kind(host_id, context),
                    score=score,
                    rationale=self.explain(host_id, score, context),
                    mimics=mimics.id if mimics else None,
                )
            )
        return tuple(placements)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


class RandomPlacement(DeceptionPlacementStrategy):
    """Uniformly random placement - the baseline every other strategy must beat."""

    name = "random"
    description = "Uniform random choice of reachable hosts (control group)."

    def __init__(self, seed: int | None = None) -> None:
        self.seed = seed
        self._rng = random.Random(seed)

    def score_hosts(self, context: PlacementContext) -> dict[str, float]:
        hosts = context.candidate_hosts()
        # Scores are random but non-zero, so ranking is a shuffle.
        return {h.id: self._rng.uniform(0.01, 1.0) for h in hosts}

    def explain(self, host_id: str, score: float, context: PlacementContext) -> str:
        return "selected at random (baseline)"


class RiskBasedPlacement(DeceptionPlacementStrategy):
    """Place decoys on the hosts that carry the most risk."""

    name = "risk"
    description = "Rank by blended asset risk: reachability x criticality."

    def score_hosts(self, context: PlacementContext) -> dict[str, float]:
        scores = {}
        for host in context.candidate_hosts():
            scores[host.id] = context.risk.asset_risk(host.id, source=context.source).score
        return scores

    def explain(self, host_id: str, score: float, context: PlacementContext) -> str:
        asset = context.risk.asset_risk(host_id, source=context.source)
        return (
            f"asset risk {score:.2f} "
            f"(P(compromise)={asset.compromise_probability:.2f}, "
            f"criticality={asset.criticality:.2f})"
        )


class CentralityBasedPlacement(DeceptionPlacementStrategy):
    """Place decoys where attack traffic concentrates.

    Betweenness centrality over the attack graph, weighted by ``-log(p)`` edge
    costs so 'between' means *on the likely routes*, not merely on some route.
    """

    name = "centrality"
    description = "Rank by betweenness centrality on the weighted attack graph."

    def score_hosts(self, context: PlacementContext) -> dict[str, float]:
        graph = context.attack.graph()
        if graph.number_of_edges() == 0:
            return {h.id: 0.0 for h in context.candidate_hosts()}

        centrality = nx.betweenness_centrality(graph, weight="weight", normalized=True)
        candidates = {h.id for h in context.candidate_hosts()}
        scores = {h: c for h, c in centrality.items() if h in candidates}

        # Every score being zero (a pure chain, where nothing is 'between')
        # would make the ranking arbitrary, so fall back to in-degree.
        if scores and max(scores.values()) == 0.0:
            return {h: float(graph.in_degree(h)) for h in scores}
        return scores

    def explain(self, host_id: str, score: float, context: PlacementContext) -> str:
        return f"betweenness centrality {score:.2f} - attack routes converge here"


class AttackPathPlacement(DeceptionPlacementStrategy):
    """Place decoys on the choke points of the best routes to crown jewels.

    This is the strategy the whole attack-graph engine exists to enable: score a
    host by the share of crown-jewel routes it sits on, weighted by how risky
    those routes are and how early the host appears. Catching an intruder on the
    first hop is worth more than catching them on the doorstep of the database.
    """

    name = "attack-path"
    description = "Rank by choke-point coverage of the highest-risk attack paths."

    def score_hosts(self, context: PlacementContext) -> dict[str, float]:
        candidates = {h.id for h in context.candidate_hosts()}
        scores = {host_id: 0.0 for host_id in candidates}

        paths = context.attack.paths_to_crown_jewels(source=context.source)
        if not paths:
            # No crown jewels declared: fall back to the single worst path.
            worst = context.attack.most_dangerous_path(source=context.source)
            if worst is None:
                return scores
            paths = {worst.target: worst}

        for path in paths.values():
            hops = max(1, path.length)
            for index, node in enumerate(path.nodes):
                if node not in candidates or node == context.source:
                    continue
                # Earlier interception is worth more: the attacker has done less
                # by the time the alert fires.
                earliness = 1.0 - (index - 1) / (2 * hops)
                scores[node] = scores.get(node, 0.0) + path.risk * earliness

        # The target itself still counts, but a decoy there catches the attacker
        # only once they have already arrived.
        for path in paths.values():
            if path.target in scores:
                scores[path.target] *= 0.6
        return scores

    def explain(self, host_id: str, score: float, context: PlacementContext) -> str:
        chokes = context.attack.choke_points(source=context.source)
        coverage = chokes.get(host_id)
        if coverage:
            return f"sits on {coverage:.0%} of crown-jewel routes (weighted {score:.2f})"
        return f"on a high-risk attack path (weighted {score:.2f})"


STRATEGIES: dict[str, type[DeceptionPlacementStrategy]] = {
    RandomPlacement.name: RandomPlacement,
    RiskBasedPlacement.name: RiskBasedPlacement,
    CentralityBasedPlacement.name: CentralityBasedPlacement,
    AttackPathPlacement.name: AttackPathPlacement,
}


def strategy_for(name: str) -> DeceptionPlacementStrategy:
    """Look up a strategy by name, as the CLI and experiments do."""
    try:
        return STRATEGIES[name.lower()]()
    except KeyError as exc:
        allowed = ", ".join(sorted(STRATEGIES))
        raise ValueError(f"unknown placement strategy {name!r} (expected one of: {allowed})") from exc


def suggest_kind(host_id: str, context: PlacementContext) -> DeceptionKind:
    """Pick the deception family that fits what an attacker would seek here.

    - A host whose stored credentials unlock somewhere valuable is a place the
      attacker will go looking for more credentials, so plant a fake one.
    - A host with onward network moves is a place they will scan, so stand up a
      decoy service beside it.
    - Otherwise they are looking for data, so leave a document.
    """
    model = context.model
    host = model.hosts.get(host_id)
    if host is None:
        return DeceptionKind.DOCUMENT

    if host.credentials:
        return DeceptionKind.CREDENTIAL

    graph = context.attack.graph()
    onward = [n for n in graph.successors(host_id)] if host_id in graph else []
    if onward:
        return DeceptionKind.NETWORK

    return DeceptionKind.DOCUMENT


def _mimic_target(host_id: str, context: PlacementContext) -> Host | None:
    """The real asset a decoy on this host should imitate.

    The attacker's own likely next move, which is exactly what they expect to
    find evidence of. Falls back to the most valuable thing reachable onward.
    """
    model = context.model
    try:
        hop = context.predictor.most_likely_next(host_id)
    except KeyError:
        hop = None
    if hop is not None and hop.target in model.hosts:
        return model.hosts[hop.target]

    objective = context.predictor.objective(host_id)
    if objective and objective in model.hosts:
        return model.hosts[objective]

    jewels = model.crown_jewels
    if jewels:
        return model.hosts[jewels[0]]
    return None
