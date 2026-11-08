"""Machine-learning components, trained on the LANL red-team labels.

Two models, each answering a question the rule-based engine answers by formula:

``LateralMovementDetector`` (:mod:`.detector`)
    *Is this logon an attacker moving laterally?* Gradient-boosted trees over
    per-logon behaviour features. Plugs into the live loop as a sensor
    (:mod:`.sensor`), so a suspicious logon reaches the mediator the same way a
    decoy trigger does.
``TargetRanker`` (:mod:`.targets`)
    *Which hosts will an attacker go for?* A logistic model over host features
    of the digital twin. Exposed as the ``ml`` placement strategy, so it can be
    measured against random, centrality and attack-path placement.

Needs the ``ml`` extra (scikit-learn, numpy, joblib). Nothing in the core
imports this package, so the rest of the system runs without it.

What stays rule-based, and why: the attacker's kill-chain *stage* and
*sophistication*. LANL labels which logons were the red team, not which stage
they were in, and training a stage classifier on labels the simulator made up
would only teach a model to imitate the rules.
"""

from .data import FeatureTable, load_features, split_by_time
from .detector import DetectionMetrics, LateralMovementDetector, evaluate_scores, rule_scores
from .targets import HOST_FEATURES, MLPlacement, TargetRanker, host_features

__all__ = [
    "DetectionMetrics",
    "FeatureTable",
    "HOST_FEATURES",
    "LateralMovementDetector",
    "MLPlacement",
    "TargetRanker",
    "evaluate_scores",
    "host_features",
    "load_features",
    "rule_scores",
    "split_by_time",
]
