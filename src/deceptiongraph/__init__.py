"""DeceptionGraph - adaptive cyber-deception digital twin.

Stage 1 covers the analysis half of the architecture:

    network definition -> asset discovery -> graph builder -> attack graph
                                                   |
                                        risk analysis + path prediction

The deception engine, event monitoring, attacker profiler and adaptation loop
arrive in later stages and consume the objects exported here.
"""

from .analysis import AttackGraphEngine, PathPredictor, RiskEngine
from .graph import InMemoryGraphRepository, NetworkModel, load_network

__version__ = "0.1.0"

__all__ = [
    "AttackGraphEngine",
    "InMemoryGraphRepository",
    "NetworkModel",
    "PathPredictor",
    "RiskEngine",
    "__version__",
    "load_network",
]
