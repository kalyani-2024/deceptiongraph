"""The six metrics the brief asks for, computed from simulation runs.

| Metric | Meaning | Better |
| --- | --- | --- |
| `detection_rate` | share of runs where a decoy fired | higher |
| `mean_time_to_detection` | hops before the alert, when detected | lower |
| `mean_path_length` | hops the attacker completed per run | lower |
| `decoys_used` | size of the deployment | lower |
| `false_alerts_per_day` | expected benign alerts from the deployment | lower |
| `critical_asset_coverage` | share of crown jewels with a decoy on their best route | higher |

Two cautions about reading these.

*Detection rate is conditional on an attack happening at all.* Runs where the
attacker's first hop simply failed are counted, and they drag the rate down
without telling you anything about the deception. `attempted_runs` and
`detection_rate_given_progress` are both reported so the distinction is visible.

*Confidence intervals matter.* These are Monte Carlo estimates, so a 2-point
difference across 100 trials is noise. The half-width of the 95% interval is
reported alongside, and `beats()` will not call a winner inside it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..deception.assets import DeceptionAsset
from ..runtime.simulator import SimulationResult


@dataclass(frozen=True, slots=True)
class Metrics:
    """One strategy's scorecard over a batch of runs."""

    label: str
    trials: int
    attempted_runs: int
    """Runs where the attacker got at least one hop in."""
    detections: int
    objective_reached: int
    detection_rate: float
    detection_rate_given_progress: float
    detection_ci95: float
    """Half-width of the 95% confidence interval on `detection_rate`."""
    mean_time_to_detection: float | None
    mean_path_length: float
    decoys_used: int
    false_alerts_per_day: float
    critical_asset_coverage: float

    @property
    def missed(self) -> int:
        return self.objective_reached

    @property
    def detection_rate_low(self) -> float:
        return max(0.0, self.detection_rate - self.detection_ci95)

    @property
    def detection_rate_high(self) -> float:
        return min(1.0, self.detection_rate + self.detection_ci95)

    def beats(self, other: "Metrics") -> bool:
        """True only if this strategy's advantage is outside both intervals.

        Deliberately conservative: overlapping intervals mean 'no difference
        shown', not 'a small win'.
        """
        return self.detection_rate_low > other.detection_rate_high

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "trials": self.trials,
            "attempted_runs": self.attempted_runs,
            "detections": self.detections,
            "objective_reached": self.objective_reached,
            "detection_rate": round(self.detection_rate, 4),
            "detection_rate_given_progress": round(self.detection_rate_given_progress, 4),
            "detection_ci95": round(self.detection_ci95, 4),
            "mean_time_to_detection": (
                None if self.mean_time_to_detection is None
                else round(self.mean_time_to_detection, 4)
            ),
            "mean_path_length": round(self.mean_path_length, 4),
            "decoys_used": self.decoys_used,
            "false_alerts_per_day": round(self.false_alerts_per_day, 4),
            "critical_asset_coverage": round(self.critical_asset_coverage, 4),
        }


def false_alerts_per_day(
    assets: tuple[DeceptionAsset, ...] | list[DeceptionAsset],
) -> float:
    """Expected benign alerts per day from a deployment.

    Independent sensors, so the rates add. This is the cost side of deception:
    a strategy that wins on detection by carpeting the network with honeyfiles
    is also the one that buries the analyst.
    """
    return sum(a.sensor.false_alert_rate for a in assets)


def summarise(
    label: str,
    results: tuple[SimulationResult, ...] | list[SimulationResult],
    assets: tuple[DeceptionAsset, ...] | list[DeceptionAsset],
    critical_asset_coverage: float,
    decoys_used: int | None = None,
    false_alerts: float | None = None,
) -> Metrics:
    """Reduce a batch of runs to one scorecard.

    ``decoys_used`` and ``false_alerts`` override what is derived from
    ``assets``. The adaptive arm needs that: its deployment changes during a
    campaign and differs between campaigns, so the honest figure is the mean
    live count rather than any single snapshot.
    """
    trials = len(results)
    if trials == 0:
        raise ValueError("cannot summarise zero runs")

    detections = sum(1 for r in results if r.detected)
    attempted = sum(1 for r in results if r.hops > 0)
    reached = sum(1 for r in results if r.reached_objective and not r.detected)

    detection_times = [
        r.hops_before_detection for r in results if r.detected and r.hops_before_detection
    ]
    rate = detections / trials

    return Metrics(
        label=label,
        trials=trials,
        attempted_runs=attempted,
        detections=detections,
        objective_reached=reached,
        detection_rate=rate,
        detection_rate_given_progress=(detections / attempted) if attempted else 0.0,
        detection_ci95=_wald_half_width(rate, trials),
        mean_time_to_detection=(
            sum(detection_times) / len(detection_times) if detection_times else None
        ),
        mean_path_length=sum(r.hops for r in results) / trials,
        decoys_used=len(assets) if decoys_used is None else decoys_used,
        false_alerts_per_day=(
            false_alerts_per_day(assets) if false_alerts is None else false_alerts
        ),
        critical_asset_coverage=critical_asset_coverage,
    )


def _wald_half_width(proportion: float, n: int) -> float:
    """95% half-width for a proportion. 1.96 * sqrt(p(1-p)/n)."""
    if n <= 0:
        return 0.0
    return 1.96 * math.sqrt(max(0.0, proportion * (1.0 - proportion)) / n)
