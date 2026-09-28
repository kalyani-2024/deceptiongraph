"""Facade over the whole system.

Analysing a network touches the loader, the graph builder, the repository, the
attack graph engine, the risk engine, the path predictor, the placement
strategies and the decoy factories. Almost no caller wants to assemble that by
hand, so:

    security = SecurityFacade("data/networks/enterprise.yaml")
    security.analyse_network()
    security.deploy_deception(budget=3)
    security.generate_report()

The subsystems stay public for anyone who does need them - a Facade is a
convenience, not a wall. Stage 3's mediator will sit behind this same surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .analysis.attack_graph import AttackGraphEngine, AttackPath
from .analysis.prediction import NextHop, PathPredictor, Trajectory
from .analysis.risk import NetworkRisk, RiskEngine
from .deception.engine import DeceptionEngine, Deployment
from .deception.placement import DeceptionPlacementStrategy
from .graph.loader import load_network
from .graph.model import INTERNET, NetworkModel
from .graph.repository import GraphRepository, InMemoryGraphRepository


@dataclass(frozen=True, slots=True)
class NetworkAnalysis:
    """What the analysis stage concluded about a network."""

    summary: dict
    risk: NetworkRisk
    most_dangerous_path: AttackPath | None
    crown_jewel_paths: dict[str, AttackPath]
    choke_points: dict[str, float]

    def as_dict(self) -> dict:
        return {
            "summary": self.summary,
            "risk": self.risk.as_dict(),
            "most_dangerous_path": (
                self.most_dangerous_path.as_dict() if self.most_dangerous_path else None
            ),
            "crown_jewel_paths": {k: v.as_dict() for k, v in self.crown_jewel_paths.items()},
            "choke_points": {k: round(v, 4) for k, v in self.choke_points.items()},
        }


class SecurityFacade:
    """One object that answers the three questions the system exists to answer."""

    def __init__(
        self,
        network: str | Path | NetworkModel | GraphRepository,
        strategy: DeceptionPlacementStrategy | str | None = None,
        source: str = INTERNET,
    ) -> None:
        self.repository = _as_repository(network)
        self.source = source

        self.attack = AttackGraphEngine(self.repository)
        self.risk = RiskEngine(self.repository, self.attack)
        self.predictor = PathPredictor(self.repository, self.attack)
        self.deception = DeceptionEngine(self.repository, strategy=strategy, source=source)

        self._analysis: NetworkAnalysis | None = None
        self._deployment: Deployment | None = None

    @property
    def model(self) -> NetworkModel:
        return self.repository.model

    @property
    def deployment(self) -> Deployment | None:
        """The last deployment, if `deploy_deception` has been called."""
        return self._deployment

    # -- the three headline operations -------------------------------------

    def analyse_network(self, refresh: bool = False) -> NetworkAnalysis:
        """Build the attack graph and score the network. Cached by default."""
        if self._analysis is None or refresh:
            self._analysis = NetworkAnalysis(
                summary=self.model.summary(),
                risk=self.risk.network_risk(source=self.source),
                most_dangerous_path=self.attack.most_dangerous_path(source=self.source),
                crown_jewel_paths=self.attack.paths_to_crown_jewels(source=self.source),
                choke_points=self.attack.choke_points(source=self.source),
            )
        return self._analysis

    def deploy_deception(
        self,
        budget: int = 3,
        strategy: DeceptionPlacementStrategy | str | None = None,
    ) -> Deployment:
        """Choose decoy placements, build the assets and score the result."""
        self._deployment = self.deception.deploy(budget=budget, strategy=strategy)
        return self._deployment

    def generate_report(self) -> dict:
        """Everything known so far, as plain data.

        Analysis runs if it has not already. Deception is reported only if it
        was deployed - the report describes what happened, it does not quietly
        deploy decoys as a side effect of asking for a summary.
        """
        analysis = self.analyse_network()
        report = {
            "network": self.model.name,
            "analysis": analysis.as_dict(),
            "deception": self._deployment.as_dict() if self._deployment else None,
            "recommendations": list(self.recommend()),
        }
        return report

    # -- convenience -------------------------------------------------------

    def compare_strategies(
        self, budget: int = 3, strategies: tuple[str, ...] | None = None
    ) -> tuple[Deployment, ...]:
        """Run the placement strategies head to head on this network."""
        return self.deception.compare(budget=budget, strategies=strategies)

    def predict_from(self, host_id: str, depth: int = 4) -> Trajectory:
        return self.predictor.predict_trajectory(host_id, depth=depth)

    def next_moves(self, host_id: str) -> tuple[NextHop, ...]:
        return self.predictor.next_hops(host_id)

    def recommend(self) -> tuple[str, ...]:
        """Plain-language advice from the current analysis and deployment."""
        analysis = self.analyse_network()
        advice: list[str] = []

        worst = analysis.most_dangerous_path
        if worst is not None and worst.risk > 0.0:
            advice.append(
                f"Most dangerous path is {worst.describe()} "
                f"(risk {worst.risk:.2f}); break it by hardening "
                f"{worst.steps[0].target if worst.steps else 'the entry point'}."
            )

        for host_id, coverage in sorted(
            analysis.choke_points.items(), key=lambda kv: kv[1], reverse=True
        )[:2]:
            advice.append(
                f"{host_id} sits on {coverage:.0%} of crown-jewel routes - "
                f"a decoy there covers the most ground."
            )

        if self._deployment is not None:
            coverage = self._deployment.coverage
            advice.append(
                f"Current deployment ({coverage.strategy}, {coverage.decoys_used} decoys) "
                f"detects the worst path with probability {coverage.detection_probability:.2f}"
                + (
                    f", typically after {coverage.mean_hops_to_detection:.1f} hops."
                    if coverage.mean_hops_to_detection is not None
                    else "."
                )
            )
            if coverage.critical_asset_coverage < 1.0:
                advice.append(
                    f"Only {coverage.critical_asset_coverage:.0%} of crown jewels have a "
                    f"decoy on their best route - raise the budget to close the gap."
                )
        else:
            advice.append("No deception deployed yet; call deploy_deception() to place decoys.")

        return tuple(advice)


def _as_repository(
    network: str | Path | NetworkModel | GraphRepository,
) -> GraphRepository:
    if isinstance(network, (str, Path)):
        return InMemoryGraphRepository(load_network(network))
    if isinstance(network, NetworkModel):
        return InMemoryGraphRepository(network)
    return network
