"""Placement strategies measured against a real attacker.

The Monte Carlo experiment in :mod:`deceptiongraph.experiments` measures the
strategies against the *simulated* attacker, who walks the attack graph the
way the model says attackers walk. That is circular by construction. This
module measures them against the LANL red team instead: place decoys on the
twin, then check which of the red team's real logons (in the held-out test
period) landed on a decoyed host.

Metrics, per strategy and budget:

``target_hit_rate``
    Share of the red team's test-period targets (that exist in the twin) with
    a decoy on them.
``event_coverage``
    Share of red-team logons that landed on a decoyed host.
``events_before_detection``
    Red-team logons before the first one that landed on a decoy - the real-data
    counterpart of "attack path length before detection".
``hours_to_detection``
    Time from the first test-period red-team logon to the first one on a decoy.

This is an *exposure* measure: it records that the attacker logged on to a
host carrying a decoy, not that they took the bait. A decoy's believability
decides the second part, and there is no data on how the red team would have
reacted to one.
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass

from ..datasets.lanl import RedTeamEvent
from ..deception.placement import DeceptionPlacementStrategy, PlacementContext, RandomPlacement
from ..graph.repository import GraphRepository


@dataclass(frozen=True, slots=True)
class PlacementOutcome:
    """One strategy at one budget, against the real attacker."""

    strategy: str
    budget: int
    hosts: tuple[str, ...]
    target_hit_rate: float
    event_coverage: float
    events_before_detection: float | None
    hours_to_detection: float | None
    trials: int = 1
    target_hit_rate_sd: float = 0.0

    def as_dict(self) -> dict:
        data = asdict(self)
        data["hosts"] = list(self.hosts)
        for key in ("target_hit_rate", "event_coverage", "events_before_detection",
                    "hours_to_detection", "target_hit_rate_sd"):
            if data[key] is not None:
                data[key] = round(data[key], 4)
        return data


def score_placement(hosts: set[str], events: list[RedTeamEvent], targets: set[str]) -> dict:
    """Exposure metrics for one set of decoyed hosts."""
    hit_targets = len(targets & hosts) / len(targets) if targets else 0.0
    on_decoy = [e.dst in hosts for e in events]
    coverage = sum(on_decoy) / len(events) if events else 0.0
    first = next((i for i, hit in enumerate(on_decoy) if hit), None)
    if first is None:
        return {"target_hit_rate": hit_targets, "event_coverage": coverage,
                "events_before_detection": None, "hours_to_detection": None}
    hours = (events[first].time - events[0].time) / 3600.0
    return {"target_hit_rate": hit_targets, "event_coverage": coverage,
            "events_before_detection": float(first), "hours_to_detection": hours}


def evaluate_on_redteam(
    repository: GraphRepository,
    events: list[RedTeamEvent],
    strategies: dict[str, DeceptionPlacementStrategy],
    budgets: tuple[int, ...] = (3, 5, 10),
    random_trials: int = 50,
    seed: int = 7,
) -> list[PlacementOutcome]:
    """Every strategy at every budget, against the given red-team logons.

    ``events`` should be the held-out period only - the ``ml`` strategy was
    trained on the earlier part, and scoring it there would be marking its own
    homework. Random placement is averaged over ``random_trials`` seeds.
    """
    twin = set(repository.model.hosts)
    events = sorted((e for e in events if e.dst in twin), key=lambda e: e.time)
    if not events:
        raise ValueError("none of the red-team targets are in the twin; nothing to evaluate")
    targets = {e.dst for e in events}
    context = PlacementContext.build(repository)

    outcomes: list[PlacementOutcome] = []
    for budget in budgets:
        for name, strategy in strategies.items():
            if isinstance(strategy, RandomPlacement):
                outcomes.append(_random_outcome(name, context, budget, events, targets,
                                                random_trials, seed))
                continue
            hosts = {p.host_id for p in strategy.plan(context, budget)}
            metrics = score_placement(hosts, events, targets)
            outcomes.append(PlacementOutcome(
                strategy=name, budget=budget, hosts=tuple(sorted(hosts)), **metrics,
            ))
    return outcomes


def _random_outcome(name, context, budget, events, targets, trials, seed) -> PlacementOutcome:
    runs = []
    for i in range(trials):
        hosts = {p.host_id for p in RandomPlacement(seed=seed + i).plan(context, budget)}
        runs.append(score_placement(hosts, events, targets))

    def mean(key):
        values = [r[key] for r in runs if r[key] is not None]
        return statistics.fmean(values) if values else None

    hit_rates = [r["target_hit_rate"] for r in runs]
    return PlacementOutcome(
        strategy=name, budget=budget, hosts=(),
        target_hit_rate=statistics.fmean(hit_rates),
        event_coverage=mean("event_coverage") or 0.0,
        events_before_detection=mean("events_before_detection"),
        hours_to_detection=mean("hours_to_detection"),
        trials=trials,
        target_hit_rate_sd=statistics.pstdev(hit_rates) if len(hit_rates) > 1 else 0.0,
    )
