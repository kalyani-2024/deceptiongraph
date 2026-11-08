"""Sensitivity analysis: do the conclusions survive different guesses?

Several of the model's probabilities are judgement calls (see the README's
modelling caveats). If the headline result - which strategy wins - flipped
when one of them moved by a quarter, the result would be about the guess,
not the strategies. This varies each one in turn, holds the others at their
defaults, reruns the experiment on identical seeds, and reports:

* each strategy's detection rate across the range,
* whether the winner changes, and
* how far the ranking of strategies moves (Kendall's tau against the default).

Parameters varied:

``session_hijack_base`` (0.35)
    Chance of riding a shared session between two hosts.
``unrouted_credential_penalty`` (0.5)
    Discount on a stolen credential with no known network route.
``path_weight`` (0.65)
    Risk blend: reachability against intrinsic softness.
``patch_damping`` (0.7)
    How much full patching cuts exploitability.
``adversary_skill`` (0.6)
    How readily the cautious attacker spots an unconvincing decoy (only
    meaningful with ``adversary="cautious"`` or ``"learning"``).
"""

from __future__ import annotations

import itertools
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from .runner import DEFAULT_ARMS, ExperimentRunner


@dataclass(frozen=True, slots=True)
class Parameter:
    name: str
    module: str
    attribute: str
    default: float
    description: str


PARAMETERS: dict[str, Parameter] = {p.name: p for p in (
    Parameter("session_hijack_base", "deceptiongraph.analysis.attack_graph",
              "SESSION_HIJACK_BASE", 0.35, "P(riding a shared session)"),
    Parameter("unrouted_credential_penalty", "deceptiongraph.analysis.attack_graph",
              "UNROUTED_CREDENTIAL_PENALTY", 0.5, "discount on a credential with no route"),
    Parameter("path_weight", "deceptiongraph.analysis.risk", "PATH_WEIGHT", 0.65,
              "risk blend towards reachability"),
    Parameter("patch_damping", "deceptiongraph.domain.entities", "PATCH_DAMPING", 0.7,
              "exploitability cut by full patching"),
    Parameter("adversary_skill", "deceptiongraph.runtime.adversary", "DEFAULT_SKILL", 0.6,
              "cautious attacker's eye for a fake"),
)}

DEFAULT_MULTIPLIERS = (0.5, 0.75, 1.0, 1.25, 1.5)


@contextmanager
def override(name: str, value: float) -> Iterator[None]:
    """Temporarily set one model parameter. Restored even on error."""
    import importlib

    parameter = PARAMETERS[name]
    module = importlib.import_module(parameter.module)
    original = getattr(module, parameter.attribute)
    setattr(module, parameter.attribute, value)
    try:
        yield
    finally:
        setattr(module, parameter.attribute, original)


@dataclass(slots=True)
class SensitivityResult:
    parameter: str
    description: str
    values: list[float]
    detection: dict[str, list[float]] = field(default_factory=dict)
    """strategy -> detection rate at each value."""
    winners: list[str] = field(default_factory=list)
    tau: list[float] = field(default_factory=list)
    """Kendall's tau of the strategy ranking at each value against the default."""

    @property
    def winner_stable(self) -> bool:
        return len(set(self.winners)) == 1

    @property
    def min_tau(self) -> float:
        return min(self.tau) if self.tau else 1.0

    def spread(self, strategy: str) -> float:
        rates = self.detection.get(strategy, [])
        return max(rates) - min(rates) if rates else 0.0

    def as_dict(self) -> dict:
        return {
            "parameter": self.parameter, "description": self.description,
            "values": self.values,
            "detection": {k: [round(v, 4) for v in vs] for k, vs in self.detection.items()},
            "winners": self.winners, "winner_stable": self.winner_stable,
            "kendall_tau": [round(t, 4) for t in self.tau], "min_tau": round(self.min_tau, 4),
        }


def kendall_tau(a: list[str], b: list[str]) -> float:
    """Rank agreement of two orderings of the same items: 1 same, -1 reversed."""
    position = {item: i for i, item in enumerate(b)}
    concordant = discordant = 0
    for x, y in itertools.combinations(a, 2):
        if position[x] < position[y]:
            concordant += 1
        else:
            discordant += 1
    total = concordant + discordant
    return (concordant - discordant) / total if total else 1.0


def run_sensitivity(
    network,
    parameters: tuple[str, ...] | None = None,
    multipliers: tuple[float, ...] = DEFAULT_MULTIPLIERS,
    budget: int = 3,
    trials: int = 100,
    seed: int = 2024,
    arms: tuple[str, ...] = DEFAULT_ARMS,
    adversary: str = "naive",
) -> list[SensitivityResult]:
    """One-at-a-time sensitivity over ``parameters`` (default: all that apply)."""
    if parameters is None:
        parameters = tuple(p for p in PARAMETERS
                           if p != "adversary_skill" or adversary != "naive")
    unknown = [p for p in parameters if p not in PARAMETERS]
    if unknown:
        raise ValueError(f"unknown parameters: {', '.join(unknown)} "
                         f"(expected: {', '.join(PARAMETERS)})")

    def ranking(report) -> list[str]:
        return [a.label for a in report.ranked]

    baseline = ExperimentRunner(network, trials=trials, seed=seed, adversary=adversary).run(
        budget=budget, arms=arms)
    base_rank = ranking(baseline)

    results = []
    for name in parameters:
        parameter = PARAMETERS[name]
        values = sorted({round(min(1.0, max(0.0, parameter.default * m)), 4) for m in multipliers})
        result = SensitivityResult(parameter=name, description=parameter.description,
                                   values=values, detection={a: [] for a in arms})
        for value in values:
            with override(name, value):
                report = ExperimentRunner(network, trials=trials, seed=seed,
                                          adversary=adversary).run(budget=budget, arms=arms)
            for arm in report.arms:
                result.detection[arm.label].append(arm.metrics.detection_rate)
            order = ranking(report)
            result.winners.append(order[0])
            result.tau.append(kendall_tau(order, base_rank))
        results.append(result)
    return results
