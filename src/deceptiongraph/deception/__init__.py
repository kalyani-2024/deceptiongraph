"""Deception layer: what to plant, where to plant it, and what that buys you."""

from .assets import DeceptionAsset, DeceptionKind, DeceptionState, Lure, Marker, Sensor
from .coverage import Coverage, PathInterception, detection_by_host, intercept
from .engine import DeceptionEngine, Deployment
from .factory import (
    CredentialDecoyFactory,
    DeceptionFactory,
    DocumentDecoyFactory,
    NetworkDecoyFactory,
    factory_for,
)
from .placement import (
    AttackPathPlacement,
    CentralityBasedPlacement,
    DeceptionPlacementStrategy,
    Placement,
    PlacementContext,
    RandomPlacement,
    RiskBasedPlacement,
    STRATEGIES,
    strategy_for,
    suggest_kind,
)

__all__ = [
    "STRATEGIES",
    "AttackPathPlacement",
    "CentralityBasedPlacement",
    "Coverage",
    "CredentialDecoyFactory",
    "DeceptionAsset",
    "DeceptionEngine",
    "DeceptionFactory",
    "DeceptionKind",
    "DeceptionPlacementStrategy",
    "DeceptionState",
    "Deployment",
    "DocumentDecoyFactory",
    "Lure",
    "Marker",
    "NetworkDecoyFactory",
    "PathInterception",
    "Placement",
    "PlacementContext",
    "RandomPlacement",
    "RiskBasedPlacement",
    "Sensor",
    "detection_by_host",
    "factory_for",
    "intercept",
    "strategy_for",
    "suggest_kind",
]
