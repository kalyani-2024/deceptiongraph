"""How much of the detection rate survives a smarter attacker?

Runs the placement experiment three times on identical seeds - against the
naive, cautious and learning adversaries (:mod:`deceptiongraph.runtime.adversary`)
- and lines the results up per strategy. The naive column is the old upper
bound; the other two are what replaces it.

For the learning adversary the trials of an arm are one group's successive
campaigns, so the first and last thirds are reported separately: the gap is
how fast a static deployment wears out once the attacker has seen it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .runner import DEFAULT_ARMS, ExperimentRunner


@dataclass(frozen=True, slots=True)
class AdversaryRow:
    strategy: str
    naive: float
    cautious: float
    learning: float
    learning_early: float
    learning_late: float
    spotted_per_campaign: float
    """Decoys the learning adversary stepped around, per campaign."""

    @property
    def retained(self) -> float:
        """Share of the naive detection rate the learning adversary still concedes."""
        return self.learning / self.naive if self.naive else 0.0

    def as_dict(self) -> dict:
        data = {k: round(v, 4) if isinstance(v, float) else v for k, v in asdict(self).items()}
        data["retained"] = round(self.retained, 4)
        return data


def compare_adversaries(
    network, budget: int = 3, trials: int = 200, seed: int = 2024,
    arms: tuple[str, ...] = DEFAULT_ARMS,
) -> list[AdversaryRow]:
    if trials < 3:
        raise ValueError("need at least 3 trials to split the learning curve into thirds")
    reports = {
        name: ExperimentRunner(network, trials=trials, seed=seed, adversary=name)
        .run(budget=budget, arms=arms, include_runs=True)
        for name in ("naive", "cautious", "learning")
    }
    by_arm = {name: {a.label: a for a in report.arms} for name, report in reports.items()}
    third = trials // 3
    rows = []
    for arm in arms:
        learning_runs = by_arm["learning"][arm].runs
        early = learning_runs[:third]
        late = learning_runs[-third:]
        rows.append(AdversaryRow(
            strategy=arm,
            naive=by_arm["naive"][arm].metrics.detection_rate,
            cautious=by_arm["cautious"][arm].metrics.detection_rate,
            learning=by_arm["learning"][arm].metrics.detection_rate,
            learning_early=sum(r.detected for r in early) / len(early),
            learning_late=sum(r.detected for r in late) / len(late),
            spotted_per_campaign=sum(r.decoys_spotted for r in learning_runs) / len(learning_runs),
        ))
    rows.sort(key=lambda r: r.learning, reverse=True)
    return rows


def network_label(network) -> str:
    return Path(network).stem if isinstance(network, (str, Path)) else getattr(
        network, "name", "network")
