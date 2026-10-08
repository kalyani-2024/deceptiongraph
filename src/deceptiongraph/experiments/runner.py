"""Experiment runner: the placement strategies measured head to head.

One arm of the experiment is one strategy at one budget. For each arm the
runner builds a fresh deployment, runs `trials` independent simulated attacks
against it, and reduces them to a :class:`Metrics` scorecard.

Three things keep the comparison honest:

*Identical conditions.* Every arm gets the same network, the same budget and
the same seed sequence, so the attacker rolls the same dice against each
deployment. Differences come from where the decoys are, not from luck.

*A control group.* `random` placement is always included. A strategy that
cannot beat random placement outside the confidence interval has not been
shown to work, however sophisticated its reasoning.

*An adaptive arm.* `adaptive` starts from the same attack-path deployment but
runs the full mediator loop, moving decoys as the profile develops. It is the
only arm that answers whether adaptation earns its complexity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..deception.assets import DeceptionAsset
from ..deception.engine import DeceptionEngine
from ..deception.placement import RandomPlacement, strategy_for
from ..graph.loader import load_network
from ..graph.model import NetworkModel
from ..graph.repository import GraphRepository, InMemoryGraphRepository
from ..runtime.mediator import SecurityMediator
from ..runtime.simulator import AttackSimulator, SimulationResult
from .metrics import Metrics, summarise

DEFAULT_ARMS = ("random", "risk", "centrality", "attack-path", "adaptive")


@dataclass(slots=True)
class ArmResult:
    """One strategy's results: the scorecard plus the runs behind it."""

    label: str
    budget: int
    metrics: Metrics
    hosts: tuple[str, ...]
    runs: tuple[SimulationResult, ...] = field(default_factory=tuple)

    def as_dict(self, include_runs: bool = False) -> dict:
        data = {
            "label": self.label,
            "budget": self.budget,
            "hosts": list(self.hosts),
            "metrics": self.metrics.as_dict(),
        }
        if include_runs:
            data["runs"] = [r.as_dict() for r in self.runs]
        return data


@dataclass(slots=True)
class ExperimentReport:
    """All arms of one experiment, ranked."""

    network: str
    budget: int
    trials: int
    seed: int
    arms: tuple[ArmResult, ...]

    @property
    def ranked(self) -> tuple[ArmResult, ...]:
        return tuple(
            sorted(
                self.arms,
                key=lambda a: (
                    a.metrics.detection_rate,
                    -(a.metrics.mean_time_to_detection or 99.0),
                ),
                reverse=True,
            )
        )

    @property
    def best(self) -> ArmResult | None:
        ranked = self.ranked
        return ranked[0] if ranked else None

    @property
    def control(self) -> ArmResult | None:
        return next((a for a in self.arms if a.label == "random"), None)

    def significant_winners(self) -> tuple[ArmResult, ...]:
        """Arms that beat the random control outside the confidence interval."""
        control = self.control
        if control is None:
            return ()
        return tuple(
            a for a in self.arms
            if a.label != "random" and a.metrics.beats(control.metrics)
        )

    def verdict(self) -> str:
        """One honest sentence about what the experiment showed."""
        control = self.control
        best = self.best
        if best is None or control is None:
            return "No arms were run."
        winners = self.significant_winners()
        if not winners:
            return (
                f"At {self.trials} trials no strategy beat random placement outside "
                f"the 95% interval; the best was {best.label} at "
                f"{best.metrics.detection_rate:.2f} "
                f"(+/-{best.metrics.detection_ci95:.2f}) against random's "
                f"{control.metrics.detection_rate:.2f}. More trials or a tighter "
                f"budget would be needed to separate them."
            )
        names = ", ".join(a.label for a in sorted(
            winners, key=lambda a: a.metrics.detection_rate, reverse=True))
        return (
            f"{names} beat random placement outside the 95% interval. Best was "
            f"{best.label}: detection {best.metrics.detection_rate:.2f} "
            f"(+/-{best.metrics.detection_ci95:.2f}) against random's "
            f"{control.metrics.detection_rate:.2f}, "
            f"detected after {best.metrics.mean_time_to_detection:.1f} hops."
            if best.metrics.mean_time_to_detection is not None
            else f"{names} beat random placement outside the 95% interval."
        )

    def as_dict(self, include_runs: bool = False) -> dict:
        return {
            "network": self.network,
            "budget": self.budget,
            "trials": self.trials,
            "seed": self.seed,
            "verdict": self.verdict(),
            "significant_winners": [a.label for a in self.significant_winners()],
            "arms": [a.as_dict(include_runs) for a in self.ranked],
        }

    def table(self) -> tuple[tuple[str, ...], ...]:
        """Rows for plain-text or Rich rendering, header first."""
        header = (
            "Strategy", "Detect", "+/-95%", "Hops", "Path", "Decoys", "False/day", "Jewels",
        )
        rows = [header]
        for arm in self.ranked:
            m = arm.metrics
            rows.append((
                arm.label,
                f"{m.detection_rate:.2f}",
                f"{m.detection_ci95:.2f}",
                "-" if m.mean_time_to_detection is None else f"{m.mean_time_to_detection:.2f}",
                f"{m.mean_path_length:.2f}",
                str(m.decoys_used),
                f"{m.false_alerts_per_day:.2f}",
                f"{m.critical_asset_coverage:.0%}",
            ))
        return tuple(rows)


class ExperimentRunner:
    """Runs the placement experiment over one network."""

    def __init__(
        self,
        network: str | Path | NetworkModel | GraphRepository,
        trials: int = 200,
        seed: int = 2024,
        max_steps: int = 12,
    ) -> None:
        self.network = network
        self.trials = trials
        self.seed = seed
        self.max_steps = max_steps

    def run(
        self,
        budget: int = 3,
        arms: tuple[str, ...] = DEFAULT_ARMS,
        include_runs: bool = False,
    ) -> ExperimentReport:
        """Run every arm at one budget."""
        if self.trials < 1:
            raise ValueError(f"trials must be at least 1, got {self.trials}")
        if budget < 1:
            raise ValueError(f"budget must be at least 1, got {budget}")

        results = []
        for arm in arms:
            results.append(self._run_arm(arm, budget, include_runs))

        name = _network_name(self.network)
        return ExperimentReport(
            network=name, budget=budget, trials=self.trials, seed=self.seed,
            arms=tuple(results),
        )

    def sweep(
        self, budgets: tuple[int, ...] = (1, 2, 3, 5), arms: tuple[str, ...] = DEFAULT_ARMS
    ) -> tuple[ExperimentReport, ...]:
        """The same experiment at several budgets.

        Where strategies converge is itself a finding: past the point where the
        budget covers every choke point, the clever strategies stop mattering.
        """
        return tuple(self.run(budget=b, arms=arms) for b in budgets)

    # -- internals ---------------------------------------------------------

    def _run_arm(self, arm: str, budget: int, include_runs: bool) -> ArmResult:
        """One arm: `trials` independent campaigns against this strategy.

        Every arm sees the same dice on trial *i* (both are seeded
        ``seed + i``), which makes this a paired comparison: arms differ by
        where their decoys are, not by which attacks they happened to face.

        The adaptive arm rebuilds its defence per trial, because one trial is
        one campaign. Letting a single mediator face all 200 attackers in
        sequence would measure something else entirely - a defence that has
        already seen 199 intrusions - and would not be comparable to the
        static arms.
        """
        if arm == "adaptive":
            return self._run_adaptive_arm(arm, budget, include_runs)

        repository = self._fresh_repository()
        engine = DeceptionEngine(repository)
        strategy = (
            RandomPlacement(seed=self.seed) if arm == "random" else strategy_for(arm)
        )
        deployment = engine.deploy(budget=budget, strategy=strategy)

        runs = []
        for index in range(self.trials):
            simulator = AttackSimulator(
                repository,
                assets=list(deployment.assets),
                seed=self.seed + index,
                max_steps=self.max_steps,
            )
            runs.append(simulator.run(actor_id=f"{arm}-actor-{index + 1}"))

        metrics = summarise(
            label=arm, results=runs, assets=deployment.assets,
            critical_asset_coverage=deployment.coverage.critical_asset_coverage,
        )
        return ArmResult(
            label=arm, budget=budget, metrics=metrics,
            hosts=tuple(sorted({a.host_id for a in deployment.assets})),
            runs=tuple(runs) if include_runs else (),
        )

    def _run_adaptive_arm(self, arm: str, budget: int, include_runs: bool) -> ArmResult:
        """The adaptive arm: a fresh defence per campaign, adapting mid-attack."""
        runs = []
        live_counts: list[int] = []
        false_rates: list[float] = []
        coverages: list[float] = []
        hosts: set[str] = set()

        for index in range(self.trials):
            repository = self._fresh_repository()
            engine = DeceptionEngine(repository)
            deployment = engine.deploy(budget=budget, strategy=strategy_for("attack-path"))
            mediator = SecurityMediator(
                repository, deception=engine, deployment=deployment,
                max_total_decoys=budget * 3,
            )
            simulator = AttackSimulator(
                repository, mediator=mediator,
                seed=self.seed + index, max_steps=self.max_steps,
            )
            runs.append(simulator.run(actor_id=f"{arm}-actor-{index + 1}"))

            live = mediator.adaptation.active
            live_counts.append(len(live))
            false_rates.append(sum(a.sensor.false_alert_rate for a in live))
            coverages.append(mediator.adaptation.coverage().critical_asset_coverage)
            hosts.update(a.host_id for a in live)

        metrics = summarise(
            label=arm, results=runs, assets=(),
            critical_asset_coverage=sum(coverages) / len(coverages),
            decoys_used=round(sum(live_counts) / len(live_counts)),
            false_alerts=sum(false_rates) / len(false_rates),
        )
        return ArmResult(
            label=arm, budget=budget, metrics=metrics,
            hosts=tuple(sorted(hosts)),
            runs=tuple(runs) if include_runs else (),
        )

    def _fresh_repository(self) -> GraphRepository:
        """A new repository per arm, so one arm's adaptation cannot leak into the next."""
        source = self.network
        if isinstance(source, (str, Path)):
            return InMemoryGraphRepository(load_network(source))
        if isinstance(source, NetworkModel):
            return InMemoryGraphRepository(load_network_copy(source))
        return InMemoryGraphRepository(load_network_copy(source.model))


def load_network_copy(model: NetworkModel) -> NetworkModel:
    """Deep-ish copy of a model, so arms cannot mutate each other's hosts."""
    import copy

    return copy.deepcopy(model)


def _network_name(network) -> str:
    if isinstance(network, (str, Path)):
        return Path(network).stem
    if isinstance(network, NetworkModel):
        return network.name
    return getattr(getattr(network, "model", None), "name", "network")
