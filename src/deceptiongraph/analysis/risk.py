"""Risk analysis.

Two notions of risk are kept distinct, then combined:

*Intrinsic risk* is what the Composite reports for an asset or a group of
assets in isolation: how soft it is, times how much it is worth.

*Path risk* is what the attack graph reports: how likely an attacker who starts
on the internet actually arrives, times what arriving costs the business.

An unpatched host nobody can reach is intrinsically risky but not urgent. A
hardened host at the end of a wide-open chain is the opposite. Ranking assets on
the blend of the two is what makes the ordering useful.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.composite import RiskScore
from ..domain.entities import Host
from ..graph.model import INTERNET
from ..graph.repository import GraphRepository
from .attack_graph import AttackGraphEngine, AttackPath

PATH_WEIGHT = 0.65
"""How much reachability dominates the blended score, versus intrinsic softness."""


@dataclass(frozen=True, slots=True)
class AssetRisk:
    """Risk verdict for a single host."""

    host_id: str
    name: str
    intrinsic: float
    compromise_probability: float
    criticality: float
    path_risk: float
    score: float
    hops_from_internet: int | None
    is_crown_jewel: bool
    best_path: AttackPath | None = None

    @property
    def reachable(self) -> bool:
        return self.hops_from_internet is not None

    def as_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "name": self.name,
            "intrinsic": round(self.intrinsic, 4),
            "compromise_probability": round(self.compromise_probability, 4),
            "criticality": round(self.criticality, 4),
            "path_risk": round(self.path_risk, 4),
            "score": round(self.score, 4),
            "hops_from_internet": self.hops_from_internet,
            "is_crown_jewel": self.is_crown_jewel,
            "best_path": self.best_path.as_dict() if self.best_path else None,
        }


@dataclass(frozen=True, slots=True)
class NetworkRisk:
    """Risk verdict for the whole network."""

    name: str
    score: float
    crown_jewel_exposure: float
    mean_asset_score: float
    worst_asset: AssetRisk | None
    assets: tuple[AssetRisk, ...]
    intrinsic: RiskScore | None = None

    def top(self, n: int = 5) -> tuple[AssetRisk, ...]:
        return self.assets[:n]

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "score": round(self.score, 4),
            "crown_jewel_exposure": round(self.crown_jewel_exposure, 4),
            "mean_asset_score": round(self.mean_asset_score, 4),
            "worst_asset": self.worst_asset.host_id if self.worst_asset else None,
            "assets": [a.as_dict() for a in self.assets],
            "intrinsic": self.intrinsic.as_dict() if self.intrinsic else None,
        }


class RiskEngine:
    """Scores assets and the network by blending intrinsic and path risk."""

    def __init__(self, repository: GraphRepository, engine: AttackGraphEngine | None = None) -> None:
        self.repository = repository
        self.engine = engine or AttackGraphEngine(repository)

    @property
    def model(self):
        return self.repository.model  # type: ignore[attr-defined]

    def asset_risk(self, host_id: str, source: str = INTERNET) -> AssetRisk:
        host = self.repository.host(host_id)
        if host is None:
            raise KeyError(f"unknown host: {host_id}")

        intrinsic = self._intrinsic(host)
        path = self.engine.best_path(host_id, source=source)
        probability = path.probability if path else 0.0
        path_risk = probability * host.criticality
        score = PATH_WEIGHT * path_risk + (1.0 - PATH_WEIGHT) * intrinsic

        return AssetRisk(
            host_id=host.id,
            name=host.name,
            intrinsic=intrinsic,
            compromise_probability=probability,
            criticality=host.criticality,
            path_risk=path_risk,
            score=min(1.0, score),
            hops_from_internet=path.length if path else None,
            is_crown_jewel=host.is_crown_jewel,
            best_path=path,
        )

    def rank_assets(self, source: str = INTERNET) -> tuple[AssetRisk, ...]:
        risks = [self.asset_risk(host_id, source=source) for host_id in self.model.hosts]
        risks.sort(key=lambda r: (r.score, r.path_risk, r.criticality), reverse=True)
        return tuple(risks)

    def crown_jewel_exposure(self, source: str = INTERNET) -> float:
        """Probability the attacker reaches at least one crown jewel."""
        jewels = self.model.crown_jewels
        if not jewels:
            return 0.0
        miss = 1.0
        for host_id in jewels:
            path = self.engine.best_path(host_id, source=source)
            miss *= 1.0 - (path.probability if path else 0.0)
        return 1.0 - miss

    def network_risk(self, source: str = INTERNET) -> NetworkRisk:
        assets = self.rank_assets(source=source)
        mean = sum(a.score for a in assets) / len(assets) if assets else 0.0
        exposure = self.crown_jewel_exposure(source=source)
        worst = assets[0] if assets else None

        # Crown jewel exposure drives the headline number; the average asset
        # score keeps a network of uniformly weak machines from scoring well
        # just because it has no single catastrophic path.
        score = max(exposure, worst.score if worst else 0.0) * 0.75 + mean * 0.25

        return NetworkRisk(
            name=self.model.name,
            score=min(1.0, score),
            crown_jewel_exposure=exposure,
            mean_asset_score=mean,
            worst_asset=worst,
            assets=assets,
            intrinsic=self.model.root.calculate_risk() if self.model.root else None,
        )

    def _intrinsic(self, host: Host) -> float:
        """Composite risk for one host, via the leaf component."""
        from ..domain.composite import HostComponent

        return HostComponent(host).calculate_risk().value
