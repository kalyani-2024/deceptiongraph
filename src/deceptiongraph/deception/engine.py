"""The deception engine.

Puts the two patterns together: a Strategy decides *where* decoys go, an
Abstract Factory decides *what* goes there, and the engine owns the resulting
deployment and its scorecard.

    strategy.plan(context, budget)  ->  placements
    factory.create(host, mimics)    ->  deception assets
    coverage.intercept(path, ...)   ->  what that buys you
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..analysis.attack_graph import AttackPath
from ..graph.model import INTERNET
from ..graph.repository import GraphRepository
from .assets import DeceptionAsset, DeceptionKind, DeceptionState
from .coverage import Coverage, PathInterception, detection_by_host, intercept
from .factory import DeceptionFactory, factory_for
from .placement import (
    DeceptionPlacementStrategy,
    Placement,
    PlacementContext,
    RandomPlacement,
    strategy_for,
)


@dataclass(slots=True)
class Deployment:
    """A set of deployed decoys and what it is worth."""

    strategy: str
    budget: int
    placements: tuple[Placement, ...]
    assets: tuple[DeceptionAsset, ...]
    coverage: Coverage

    @property
    def hosts(self) -> tuple[str, ...]:
        seen: list[str] = []
        for asset in self.assets:
            if asset.host_id not in seen:
                seen.append(asset.host_id)
        return tuple(seen)

    def by_kind(self, kind: DeceptionKind) -> tuple[DeceptionAsset, ...]:
        return tuple(a for a in self.assets if a.kind is kind)

    def asset_by_token(self, token: str) -> DeceptionAsset | None:
        """Look up the decoy a canary token belongs to.

        Stage 3's event pipeline resolves alerts through this.
        """
        return next((a for a in self.assets if a.marker.token == token), None)

    def recommendations(self) -> tuple[str, ...]:
        """The deployment as the brief prints it, one line per decoy."""
        lines = []
        for index, asset in enumerate(self.assets, start=1):
            target = f" (mimics {asset.protects})" if asset.protects else ""
            lines.append(f"[{index}] {asset.describe()}{target}")
        return tuple(lines)

    def as_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "budget": self.budget,
            "hosts": list(self.hosts),
            "placements": [p.as_dict() for p in self.placements],
            "assets": [a.as_dict() for a in self.assets],
            "coverage": self.coverage.as_dict(),
        }


class DeceptionEngine:
    """Plans, builds and scores deception deployments."""

    def __init__(
        self,
        repository: GraphRepository,
        strategy: DeceptionPlacementStrategy | str | None = None,
        source: str = INTERNET,
    ) -> None:
        self.repository = repository
        self.context = PlacementContext.build(repository, source=source)
        self.strategy = _resolve_strategy(strategy)
        self._factories: dict[DeceptionKind, DeceptionFactory] = {}

    # -- planning ----------------------------------------------------------

    def plan(
        self, budget: int = 3, strategy: DeceptionPlacementStrategy | str | None = None
    ) -> tuple[Placement, ...]:
        """Where decoys should go, without building anything."""
        chosen = _resolve_strategy(strategy) if strategy is not None else self.strategy
        return chosen.plan(self.context, budget)

    def deploy(
        self,
        budget: int = 3,
        strategy: DeceptionPlacementStrategy | str | None = None,
        activate: bool = True,
    ) -> Deployment:
        """Plan, build and score a full deployment."""
        chosen = _resolve_strategy(strategy) if strategy is not None else self.strategy
        placements = chosen.plan(self.context, budget)
        assets = tuple(self._build(p) for p in placements)
        if activate:
            for asset in assets:
                asset.deploy()
        return Deployment(
            strategy=chosen.name,
            budget=budget,
            placements=placements,
            assets=assets,
            coverage=self.evaluate(assets, strategy_name=chosen.name),
        )

    def compare(
        self,
        budget: int = 3,
        strategies: tuple[str, ...] | None = None,
        seed: int | None = 1337,
    ) -> tuple[Deployment, ...]:
        """Run several strategies over the same network, best coverage first.

        This is the experiment the brief asks for: random against centrality
        against attack-path placement, on identical inputs and budget.

        The random baseline is seeded so a comparison repeats. Pass ``seed=None``
        to let it vary, which is what averaging over many runs needs.
        """
        names = strategies or ("random", "risk", "centrality", "attack-path")
        results = [
            self.deploy(budget=budget, strategy=self._seeded(name, seed), activate=False)
            for name in names
        ]
        results.sort(
            key=lambda d: (
                d.coverage.detection_probability,
                -(d.coverage.mean_hops_to_detection or 99.0),
            ),
            reverse=True,
        )
        return tuple(results)

    @staticmethod
    def _seeded(
        strategy: DeceptionPlacementStrategy | str, seed: int | None
    ) -> DeceptionPlacementStrategy:
        """Resolve a strategy, seeding it when it has a random component."""
        resolved = _resolve_strategy(strategy)
        if seed is not None and isinstance(resolved, RandomPlacement):
            return RandomPlacement(seed=seed)
        return resolved

    # -- scoring -----------------------------------------------------------

    def evaluate(
        self,
        assets: tuple[DeceptionAsset, ...] | list[DeceptionAsset],
        strategy_name: str = "ad-hoc",
    ) -> Coverage:
        """Score an arbitrary set of decoys against the attack graph."""
        detection = detection_by_host(assets)
        paths = self._paths_to_defend()

        interceptions = tuple(intercept(path, detection) for path in paths)
        headline = self._headline(interceptions)

        jewels = self.context.model.crown_jewels
        if jewels:
            covered = sum(1 for i in interceptions if i.target in jewels and i.covered_hops)
            critical_coverage = covered / len(jewels)
            residual = self._residual_risk(interceptions, jewels)
        else:
            critical_coverage = 0.0
            residual = self._residual_risk(interceptions, ())

        reachable = self.context.candidate_hosts()
        decoyed = {a.host_id for a in assets}
        host_coverage = len(decoyed & {h.id for h in reachable}) / len(reachable) if reachable else 0.0

        return Coverage(
            strategy=strategy_name,
            decoys_used=len(assets),
            detection_probability=headline[0],
            mean_hops_to_detection=headline[1],
            critical_asset_coverage=critical_coverage,
            host_coverage=host_coverage,
            undetected_crown_jewel_risk=residual,
            interceptions=interceptions,
        )

    # -- internals ---------------------------------------------------------

    def build_asset(self, placement: Placement) -> DeceptionAsset:
        """Build a single decoy from a placement decision.

        Public because the adaptation engine places decoys one at a time, in
        response to a live actor, rather than planning a whole deployment.
        """
        return self._build(placement)

    def _build(self, placement: Placement) -> DeceptionAsset:
        host = self.repository.host(placement.host_id)
        if host is None:
            raise KeyError(f"cannot place a decoy on unknown host: {placement.host_id}")
        mimics = (
            self.repository.host(placement.mimics) if placement.mimics else None
        )
        return self._factory(placement.kind).create(host, mimics, rationale=placement.rationale)

    def _factory(self, kind: DeceptionKind) -> DeceptionFactory:
        """One factory instance per family, so decoy serial numbers stay unique."""
        if kind not in self._factories:
            self._factories[kind] = factory_for(kind)
        return self._factories[kind]

    def _paths_to_defend(self) -> tuple[AttackPath, ...]:
        """The routes worth measuring against: one per crown jewel."""
        paths = self.context.attack.paths_to_crown_jewels(source=self.context.source)
        if paths:
            return tuple(paths.values())
        worst = self.context.attack.most_dangerous_path(source=self.context.source)
        return (worst,) if worst else ()

    def _headline(
        self, interceptions: tuple[PathInterception, ...]
    ) -> tuple[float, float | None]:
        """Detection probability and timing for the single worst path.

        The worst path is the one the deployment has to stop, so it sets the
        headline number rather than an average across easier routes.
        """
        if not interceptions:
            return 0.0, None
        worst = max(interceptions, key=lambda i: i.undetected_arrival)
        return worst.detection_probability, worst.mean_hops_to_detection

    def _residual_risk(
        self, interceptions: tuple[PathInterception, ...], jewels: tuple[str, ...]
    ) -> float:
        """Risk that survives the deployment: undetected arrival x impact."""
        model = self.context.model
        worst = 0.0
        for interception in interceptions:
            host = model.hosts.get(interception.target)
            if host is None:
                continue
            if jewels and interception.target not in jewels:
                continue
            worst = max(worst, interception.undetected_arrival * host.criticality)
        return worst


def _resolve_strategy(
    strategy: DeceptionPlacementStrategy | str | None,
) -> DeceptionPlacementStrategy:
    if strategy is None:
        from .placement import AttackPathPlacement

        return AttackPathPlacement()
    if isinstance(strategy, str):
        return strategy_for(strategy)
    return strategy
