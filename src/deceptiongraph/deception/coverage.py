"""Measuring a deception deployment.

The question a deployment has to answer is not "how many decoys did we place?"
but "how likely are we to notice, and how early?". Both are computed by walking
the attacker's most likely route and simulating, hop by hop, whether they trip
something before they arrive.

At each hop the attacker either

* fails the hop outright (probability ``1 - p``),
* takes the bait and is detected (probability ``d``), or
* survives, undetected, and carries on (probability ``1 - d``).

Tracking the surviving mass across the path gives both the probability of
detection and the distribution of *when* it happens, which is what
``mean_hops_to_detection`` summarises. Detection is treated as terminal: once
the alert fires the run is over, so a decoy further along the path cannot claim
the same interception twice.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..analysis.attack_graph import AttackPath
from .assets import DeceptionAsset


@dataclass(frozen=True, slots=True)
class PathInterception:
    """How a deployment performs against one attack path."""

    target: str
    nodes: tuple[str, ...]
    detection_probability: float
    mean_hops_to_detection: float | None
    """Expected hops before the alert, given detection happens at all."""
    undetected_arrival: float
    """P(attacker reaches the target with nothing having fired)."""
    covered_hops: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "nodes": list(self.nodes),
            "detection_probability": round(self.detection_probability, 4),
            "mean_hops_to_detection": (
                None if self.mean_hops_to_detection is None
                else round(self.mean_hops_to_detection, 4)
            ),
            "undetected_arrival": round(self.undetected_arrival, 4),
            "covered_hops": list(self.covered_hops),
        }


@dataclass(frozen=True, slots=True)
class Coverage:
    """The scorecard for a deployment, as the brief's experiment list requires."""

    strategy: str
    decoys_used: int
    detection_probability: float
    """P(detected | attacker runs the most dangerous path)."""
    mean_hops_to_detection: float | None
    critical_asset_coverage: float
    """Share of crown jewels whose best route has at least one decoy on it."""
    host_coverage: float
    """Share of reachable hosts carrying at least one decoy."""
    undetected_crown_jewel_risk: float
    """Residual risk: P(reach a jewel) x impact, with detection accounted for."""
    interceptions: tuple[PathInterception, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "decoys_used": self.decoys_used,
            "detection_probability": round(self.detection_probability, 4),
            "mean_hops_to_detection": (
                None if self.mean_hops_to_detection is None
                else round(self.mean_hops_to_detection, 4)
            ),
            "critical_asset_coverage": round(self.critical_asset_coverage, 4),
            "host_coverage": round(self.host_coverage, 4),
            "undetected_crown_jewel_risk": round(self.undetected_crown_jewel_risk, 4),
            "interceptions": [i.as_dict() for i in self.interceptions],
        }


def detection_by_host(assets: tuple[DeceptionAsset, ...] | list[DeceptionAsset]) -> dict[str, float]:
    """P(alert | attacker reaches host), combining that host's decoys.

    Several decoys on one host are independent chances to catch the same
    intruder, so they combine with a noisy-OR rather than adding up.
    """
    miss: dict[str, float] = {}
    for asset in assets:
        current = miss.get(asset.host_id, 1.0)
        miss[asset.host_id] = current * (1.0 - asset.detection_probability)
    return {host_id: 1.0 - m for host_id, m in miss.items()}


def intercept(path: AttackPath, detection: dict[str, float]) -> PathInterception:
    """Walk one attack path and work out whether, and when, the alert fires."""
    surviving = 1.0
    detected_total = 0.0
    weighted_hops = 0.0
    covered: list[str] = []

    for index, step in enumerate(path.steps, start=1):
        arrived = surviving * step.probability
        chance = detection.get(step.target, 0.0)
        if chance > 0.0:
            covered.append(step.target)
        detected_here = arrived * chance
        detected_total += detected_here
        weighted_hops += index * detected_here
        surviving = arrived * (1.0 - chance)

    mean_hops = (weighted_hops / detected_total) if detected_total > 0.0 else None
    return PathInterception(
        target=path.target,
        nodes=path.nodes,
        detection_probability=detected_total,
        mean_hops_to_detection=mean_hops,
        undetected_arrival=surviving,
        covered_hops=tuple(covered),
    )
