"""DeceptionGraph - adaptive cyber-deception digital twin.

The whole pipeline, from a network definition to a deception posture that
moves while an intrusion is in progress:

    network definition -> asset discovery -> graph builder -> attack graph
                                                   |
                                        risk analysis + path prediction
                                                   |
                                           deception engine
                                     (honeyfile / decoy host / honeytoken)
                                                   |
                                          event monitoring
                                                   |
                                        attacker profiler (state)
                                                   |
                                          adaptation loop

Most callers want :class:`SecurityFacade`, which assembles all of it. The
subsystems stay public for anyone who needs one directly.
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
from .runtime import (
    AttackerProfile,
    AttackerStage,
    AttackSimulator,
    Event,
    EventBus,
    EventType,
    SecurityMediator,
)

__version__ = "1.0.0"

__all__ = [
    "AttackGraphEngine",
    "AttackSimulator",
    "AttackerProfile",
    "AttackerStage",
    "DeceptionEngine",
    "DeceptionFactory",
    "DeceptionKind",
    "DeceptionPlacementStrategy",
    "Deployment",
    "Event",
    "EventBus",
    "EventType",
    "InMemoryGraphRepository",
    "NetworkAnalysis",
    "NetworkModel",
    "PathPredictor",
    "RiskEngine",
    "SecurityFacade",
    "SecurityMediator",
    "__version__",
    "load_network",
    "strategy_for",
]
