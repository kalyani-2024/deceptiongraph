"""DeceptionGraph - adaptive cyber-deception digital twin.

Stages 1 and 2 cover the analysis and deception halves of the architecture:

    network definition -> asset discovery -> graph builder -> attack graph
                                                   |
                                        risk analysis + path prediction
                                                   |
                                           deception engine
                                     (honeyfile / decoy host / honeytoken)

Event monitoring, the attacker profiler and the adaptation loop arrive in
stage 3 and consume the objects exported here.
"""

from .analysis import AttackGraphEngine, PathPredictor, RiskEngine
from .deception import (
    DeceptionEngine,
    DeceptionFactory,
    DeceptionKind,
    DeceptionPlacementStrategy,
    Deployment,
    strategy_for,
)
from .facade import NetworkAnalysis, SecurityFacade
from .graph import InMemoryGraphRepository, NetworkModel, load_network

__version__ = "0.2.0"

__all__ = [
    "AttackGraphEngine",
    "DeceptionEngine",
    "DeceptionFactory",
    "DeceptionKind",
    "DeceptionPlacementStrategy",
    "Deployment",
    "InMemoryGraphRepository",
    "NetworkAnalysis",
    "NetworkModel",
    "PathPredictor",
    "RiskEngine",
    "SecurityFacade",
    "__version__",
    "load_network",
    "strategy_for",
]
