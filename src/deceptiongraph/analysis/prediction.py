"""Path prediction.

Answers the question the deception engine depends on: *if someone owns this
node, where do they go next?*

A neighbour is attractive for two reasons at once — the hop itself is easy, and
the neighbour leads somewhere worth going. So each candidate is scored as

    score(next) = P(hop) x value(next)

where ``value`` is the best risk-weighted payoff reachable onward from that
neighbour, never less than the neighbour's own business value. Scores are then
normalised across the available moves to give a distribution.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.enums import AttackVector
from ..graph.model import INTERNET
from ..graph.repository import GraphRepository
from .attack_graph import AttackGraphEngine


@dataclass(frozen=True, slots=True)
class NextHop:
    """One candidate move, with the reasoning behind its score."""

    target: str
    name: str
    probability: float
    """Normalised likelihood the attacker picks this move."""
    hop_probability: float
    """Raw chance this specific transition succeeds."""
    onward_value: float
    """Best risk-weighted payoff reachable through this neighbour."""
    vector: AttackVector
    detail: str
    leads_to_crown_jewel: bool

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "name": self.name,
            "probability": round(self.probability, 4),
            "hop_probability": round(self.hop_probability, 4),
            "onward_value": round(self.onward_value, 4),
            "vector": self.vector.value,
            "detail": self.detail,
            "leads_to_crown_jewel": self.leads_to_crown_jewel,
        }


@dataclass(frozen=True, slots=True)
class Trajectory:
    """A predicted multi-hop continuation from a foothold."""

    start: str
    hops: tuple[NextHop, ...]

    @property
    def nodes(self) -> tuple[str, ...]:
        return (self.start,) + tuple(h.target for h in self.hops)

    @property
    def confidence(self) -> float:
        """Joint likelihood of the attacker taking exactly this sequence."""
        value = 1.0
        for hop in self.hops:
            value *= hop.probability
        return value

    def describe(self) -> str:
        return " -> ".join(self.nodes)

    def as_dict(self) -> dict:
        return {
            "start": self.start,
            "nodes": list(self.nodes),
            "confidence": round(self.confidence, 4),
            "hops": [h.as_dict() for h in self.hops],
        }


class PathPredictor:
    """Predicts attacker movement over the attack graph."""

    def __init__(self, repository: GraphRepository, engine: AttackGraphEngine | None = None) -> None:
        self.repository = repository
        self.engine = engine or AttackGraphEngine(repository)
        self._value_cache: dict[str, float] = {}

    @property
    def model(self):
        return self.repository.model  # type: ignore[attr-defined]

    def next_hops(
        self, current: str, visited: tuple[str, ...] = (), limit: int | None = None
    ) -> tuple[NextHop, ...]:
        """Ranked distribution over the attacker's next move from ``current``."""
        graph = self.engine.graph()
        if current not in graph:
            raise KeyError(f"unknown node: {current}")

        seen = set(visited) | {current}
        candidates = []
        for target in graph.successors(current):
            if target in seen or target == INTERNET:
                continue
            edge = graph[current][target]
            hop_probability = float(edge["probability"])
            onward = self._value(target)
            score = hop_probability * onward
            if score <= 0.0:
                continue
            candidates.append((target, hop_probability, onward, score, edge))

        total = sum(c[3] for c in candidates)
        if total <= 0.0:
            return ()

        jewels = set(self.model.crown_jewels)
        hops = [
            NextHop(
                target=target,
                name=self.model.hosts[target].name if target in self.model.hosts else target,
                probability=score / total,
                hop_probability=hop_probability,
                onward_value=onward,
                vector=edge["step"].vector,
                detail=edge.get("detail", ""),
                leads_to_crown_jewel=target in jewels or self._reaches_jewel(target),
            )
            for target, hop_probability, onward, score, edge in candidates
        ]
        hops.sort(key=lambda h: h.probability, reverse=True)
        return tuple(hops[:limit]) if limit else tuple(hops)

    def most_likely_next(self, current: str, visited: tuple[str, ...] = ()) -> NextHop | None:
        hops = self.next_hops(current, visited=visited)
        return hops[0] if hops else None

    def predict_trajectory(self, start: str, depth: int = 4) -> Trajectory:
        """Greedy roll-out of the most likely moves, ``depth`` hops deep."""
        hops: list[NextHop] = []
        current = start
        visited: list[str] = [start]
        for _ in range(depth):
            hop = self.most_likely_next(current, visited=tuple(visited))
            if hop is None:
                break
            hops.append(hop)
            visited.append(hop.target)
            current = hop.target
            if hop.target in self.model.crown_jewels:
                break
        return Trajectory(start=start, hops=tuple(hops))

    def objective(self, start: str) -> str | None:
        """The asset the attacker is most plausibly heading towards."""
        best: tuple[float, str] | None = None
        for host_id, host in self.model.hosts.items():
            if host_id == start:
                continue
            path = self.engine.best_path(host_id, source=start)
            if path is None:
                continue
            payoff = path.probability * host.criticality
            if best is None or payoff > best[0]:
                best = (payoff, host_id)
        return best[1] if best else None

    # -- internals ---------------------------------------------------------

    def _value(self, node: str) -> float:
        """Best risk-weighted payoff reachable from ``node``, inclusive.

        Cached per predictor: the roll-out asks for the same nodes repeatedly.
        """
        cached = self._value_cache.get(node)
        if cached is not None:
            return cached
        value = self._compute_value(node)
        self._value_cache[node] = value
        return value

    def _compute_value(self, node: str) -> float:
        host = self.model.hosts.get(node)
        own = host.criticality if host else 0.0
        best = own
        for target_id, target in self.model.hosts.items():
            if target_id == node:
                continue
            path = self.engine.best_path(target_id, source=node)
            if path is None:
                continue
            best = max(best, path.probability * target.criticality)
        return best

    def _reaches_jewel(self, node: str) -> bool:
        jewels = set(self.model.crown_jewels)
        if not jewels:
            return False
        return bool(jewels & set(self.engine.reachable_from(node)))
