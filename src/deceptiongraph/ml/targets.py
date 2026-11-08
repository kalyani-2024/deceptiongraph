"""Target ranker: which hosts will an attacker go for?

The rule-based strategies each bet on one signal: centrality, risk, or position
on the best attack path. This model learns how to weigh those signals - and a
few plain structural ones - from where a real red team actually went.

Features are computed from the digital twin alone (:func:`host_features`), so a
ranker trained on the LANL twin can score any network, YAML-defined ones
included. Labels are the hosts the LANL red team logged on to.

Exposed as the ``ml`` placement strategy (:class:`MLPlacement`), which slots
into the same Strategy interface as the four hand-written ones and is measured
the same way.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
import numpy as np

from ..deception.placement import (
    AttackPathPlacement,
    DeceptionPlacementStrategy,
    PlacementContext,
)
from ..domain.enums import Exposure

HOST_FEATURES: tuple[str, ...] = (
    "criticality",
    "crown_jewel",
    "exposure_level",
    "attack_surface",
    "log_in_degree",
    "log_out_degree",
    "log_credentials_stored",
    "log_credentials_granting",
    "log_users",
    "reach_probability",
    "betweenness",
    "attack_path_score",
    "risk_score",
)

_EXPOSURE_LEVEL = {
    Exposure.INTERNET: 0.0,
    Exposure.DMZ: 1.0,
    Exposure.INTERNAL: 2.0,
    Exposure.RESTRICTED: 3.0,
}

DEFAULT_MODEL_PATH = Path("models") / "target_ranker.joblib"
MODEL_ENV = "DG_ML_TARGET_MODEL"


def host_features(context: PlacementContext) -> tuple[list[str], np.ndarray]:
    """One feature row per host in the twin, in a stable order."""
    model = context.model
    host_ids = sorted(model.hosts)
    connectivity = context.repository.connectivity_graph()
    attack = context.attack.graph()

    if attack.number_of_nodes() > 400:
        # Exact betweenness is O(n*m); a sampled estimate ranks the same hosts.
        betweenness = nx.betweenness_centrality(attack, k=200, weight="weight", seed=7)
    else:
        betweenness = nx.betweenness_centrality(attack, weight="weight")

    path_scores = AttackPathPlacement().score_hosts(context)
    granting: dict[str, int] = {h: 0 for h in host_ids}
    for host in model.hosts.values():
        for credential in host.credentials:
            for target in credential.grants_access:
                if target in granting:
                    granting[target] += 1
    users: dict[str, int] = {h: 0 for h in host_ids}
    for user in model.users.values():
        for host_id in user.logs_into:
            if host_id in users:
                users[host_id] += 1

    rows = []
    for host_id in host_ids:
        host = model.hosts[host_id]
        path = context.attack.best_path(host_id, source=context.source)
        in_degree = sum(1 for s in connectivity.predecessors(host_id) if s != "INTERNET") \
            if host_id in connectivity else 0
        out_degree = connectivity.out_degree(host_id) if host_id in connectivity else 0
        rows.append([
            host.criticality,
            1.0 if host.is_crown_jewel else 0.0,
            _EXPOSURE_LEVEL[host.exposure],
            host.attack_surface,
            math.log1p(in_degree),
            math.log1p(out_degree),
            math.log1p(len(host.credentials)),
            math.log1p(granting[host_id]),
            math.log1p(users[host_id]),
            path.probability if path else 0.0,
            float(betweenness.get(host_id, 0.0)),
            float(path_scores.get(host_id, 0.0)),
            context.risk.asset_risk(host_id, source=context.source).score,
        ])
    return host_ids, np.asarray(rows, dtype=np.float64)


@dataclass(slots=True)
class TargetRanker:
    """Logistic model of P(host is targeted | its features)."""

    model: object
    features: tuple[str, ...] = HOST_FEATURES
    info: dict = field(default_factory=dict)

    @classmethod
    def fit(
        cls, context: PlacementContext, targeted: set[str] | frozenset[str], C: float = 0.5
    ) -> "TargetRanker":
        """Train on one twin, with the hosts the attacker went to as positives.

        Logistic regression rather than something larger on purpose: there are
        a few hundred hosts and perhaps a hundred positives, and the
        coefficients are worth being able to read.
        """
        import sklearn
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler

        host_ids, X = host_features(context)
        y = np.array([1 if h in targeted else 0 for h in host_ids])
        if y.sum() == 0:
            raise ValueError("none of the targeted hosts are in the twin; nothing to learn")
        if y.sum() == len(y):
            raise ValueError("every host is a target; the ranker needs negatives")

        pipeline = make_pipeline(
            StandardScaler(),
            LogisticRegression(C=C, class_weight="balanced", max_iter=5000),
        )
        pipeline.fit(X, y)
        coefficients = pipeline[-1].coef_[0]
        return cls(
            model=pipeline,
            info={
                "algorithm": "LogisticRegression (standardised, class-balanced)",
                "sklearn_version": sklearn.__version__,
                "network": context.model.name,
                "hosts": len(host_ids),
                "positives": int(y.sum()),
                "coefficients": {
                    name: round(float(c), 4)
                    for name, c in sorted(zip(HOST_FEATURES, coefficients),
                                          key=lambda kv: abs(kv[1]), reverse=True)
                },
            },
        )

    def scores(self, context: PlacementContext) -> dict[str, float]:
        """P(targeted) for every host in the network."""
        host_ids, X = host_features(context)
        if not host_ids:
            return {}
        probabilities = self.model.predict_proba(X)[:, 1]
        return {h: float(p) for h, p in zip(host_ids, probabilities)}

    def save(self, path: str | Path) -> Path:
        import joblib

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"kind": "target-ranker", "model": self.model,
                     "features": list(self.features), "info": self.info}, path)
        path.with_suffix(".json").write_text(
            json.dumps({"features": list(self.features), **self.info}, indent=2),
            encoding="utf-8",
        )
        return path

    @classmethod
    def load(cls, path: str | Path) -> "TargetRanker":
        import joblib

        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(
                f"target ranker not found: {path} (run `dgraph lanl train`, or set {MODEL_ENV})"
            )
        blob = joblib.load(path)
        if blob.get("kind") != "target-ranker":
            raise ValueError(f"{path} is not a target ranker")
        return cls(model=blob["model"], features=tuple(blob["features"]),
                   info=dict(blob.get("info") or {}))


class MLPlacement(DeceptionPlacementStrategy):
    """Place decoys where the learned model expects the attacker to go."""

    name = "ml"
    description = "Rank by a model trained on where the LANL red team went."

    def __init__(self, ranker: TargetRanker | None = None, path: str | Path | None = None) -> None:
        self._ranker = ranker
        self._path = Path(path) if path else None
        self._cache: tuple[int, dict[str, float]] | None = None

    @property
    def ranker(self) -> TargetRanker:
        if self._ranker is None:
            self._ranker = TargetRanker.load(self._path or default_model_path())
        return self._ranker

    def score_hosts(self, context: PlacementContext) -> dict[str, float]:
        scores = self._scores(context)
        candidates = {h.id for h in context.candidate_hosts()}
        return {h: s for h, s in scores.items() if h in candidates}

    def explain(self, host_id: str, score: float, context: PlacementContext) -> str:
        return f"model estimates P(targeted)={score:.2f}"

    def _scores(self, context: PlacementContext) -> dict[str, float]:
        # plan() calls score_hosts once, but explain() may run per host; the
        # feature pass is the expensive part, so keep the last result.
        key = id(context)
        if self._cache is None or self._cache[0] != key:
            self._cache = (key, self.ranker.scores(context))
        return self._cache[1]


def default_model_path() -> Path:
    return Path(os.environ.get(MODEL_ENV) or DEFAULT_MODEL_PATH)
