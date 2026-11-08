"""Lateral-movement detector: is this logon the attacker?

Supervised on the LANL red-team labels. A gradient-boosted tree ensemble over
the per-logon features in :data:`~deceptiongraph.datasets.lanl.AUTH_FEATURES` -
whether the user has ever logged on to this host before, whether anyone has
used this route before, how many distinct users the source machine has seen,
and so on.

Two things make the numbers honest:

*Weighted metrics.* Normal logons are sampled (1% by default) when the feature
table is written, and each kept row carries weight ``1 / rate``. Every metric
here uses those weights, so precision and false alerts per day describe the
full stream, not the convenient sample.

*A rule-based baseline.* :func:`rule_scores` counts the classic analyst
heuristics (first-time user-to-host, first-time route, NTLM). The model has to
beat it on the same test rows to have earned its complexity.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

from ..datasets.lanl import AUTH_FEATURES
from .data import FeatureTable

DEFAULT_TARGET_FPR = 0.001
"""Alert threshold is set to flag about 1 in 1,000 normal logons."""


@dataclass(frozen=True, slots=True)
class DetectionMetrics:
    """How well a score separates red-team logons from normal ones."""

    average_precision: float
    """Area under the precision-recall curve. Chance level is the positive rate."""
    roc_auc: float
    recall_at_fpr: dict[str, float]
    positives: int
    negatives_sampled: int
    negatives_weighted: float
    threshold: float | None = None
    recall_at_threshold: float | None = None
    precision_at_threshold: float | None = None
    false_alerts_per_day: float | None = None

    def as_dict(self) -> dict:
        data = asdict(self)
        for key, value in list(data.items()):
            if isinstance(value, float):
                data[key] = round(value, 6)
        data["recall_at_fpr"] = {k: round(v, 6) for k, v in self.recall_at_fpr.items()}
        return data


def evaluate_scores(
    y: np.ndarray,
    scores: np.ndarray,
    weight: np.ndarray,
    threshold: float | None = None,
    days: float | None = None,
    fprs: tuple[float, ...] = (0.0001, 0.001, 0.01),
) -> DetectionMetrics:
    """Weighted detection metrics for any scoring of the rows."""
    from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

    y = np.asarray(y).astype(int)
    positives = int(y.sum())
    negatives = int(len(y) - positives)
    if positives == 0 or negatives == 0:
        raise ValueError("need both red-team and normal rows to evaluate")

    ap = float(average_precision_score(y, scores, sample_weight=weight))
    auc = float(roc_auc_score(y, scores, sample_weight=weight))
    fpr, tpr, _ = roc_curve(y, scores, sample_weight=weight)
    recall_at = {str(f): float(np.interp(f, fpr, tpr)) for f in fprs}

    recall_t = precision_t = alerts_per_day = None
    if threshold is not None:
        flagged = scores >= threshold
        tp = float(weight[flagged & (y == 1)].sum())
        fp = float(weight[flagged & (y == 0)].sum())
        recall_t = tp / float(weight[y == 1].sum())
        precision_t = tp / (tp + fp) if tp + fp > 0 else 0.0
        if days:
            alerts_per_day = fp / days

    return DetectionMetrics(
        average_precision=ap, roc_auc=auc, recall_at_fpr=recall_at,
        positives=positives, negatives_sampled=negatives,
        negatives_weighted=float(weight[y == 0].sum()),
        threshold=threshold, recall_at_threshold=recall_t,
        precision_at_threshold=precision_t, false_alerts_per_day=alerts_per_day,
    )


def rule_scores(table: FeatureTable) -> np.ndarray:
    """Analyst heuristic baseline: first-time user->host + first-time route + NTLM."""
    index = {name: i for i, name in enumerate(table.features)}
    X = table.X
    return (X[:, index["new_user_dst"]] + X[:, index["new_pair"]]
            + X[:, index["auth_ntlm"]]) / 3.0


def threshold_for_fpr(
    scores: np.ndarray, y: np.ndarray, weight: np.ndarray, target_fpr: float
) -> float:
    """Lowest score that keeps the weighted false-positive rate at or below target."""
    negative = y == 0
    neg_scores = scores[negative]
    neg_weight = weight[negative]
    if len(neg_scores) == 0:
        return 0.5
    order = np.argsort(neg_scores)[::-1]
    cumulative = np.cumsum(neg_weight[order]) / neg_weight.sum()
    # Index of the first negative that would push FPR above the target.
    cut = int(np.searchsorted(cumulative, target_fpr, side="right"))
    if cut >= len(order):
        return float(neg_scores.min())
    return float(np.nextafter(neg_scores[order[cut]], np.inf))


def _balanced_weights(y: np.ndarray, weight: np.ndarray) -> np.ndarray:
    """Give the two classes equal total weight, keeping the within-class sampling weights."""
    out = np.asarray(weight, dtype=np.float64).copy()
    pos = y == 1
    neg = ~pos
    if pos.any():
        out[pos] = out[pos] / out[pos].sum()
    if neg.any():
        out[neg] = out[neg] / out[neg].sum()
    return out * len(y) / 2.0


@dataclass(slots=True)
class LateralMovementDetector:
    """A fitted model plus the threshold it alerts at."""

    model: object
    threshold: float
    features: tuple[str, ...] = AUTH_FEATURES
    info: dict = field(default_factory=dict)

    # -- training ----------------------------------------------------------

    @classmethod
    def fit(
        cls,
        table: FeatureTable,
        target_fpr: float = DEFAULT_TARGET_FPR,
        seed: int = 7,
        max_iter: int = 300,
    ) -> "LateralMovementDetector":
        """Train on ``table`` and set the alert threshold for ``target_fpr``.

        The threshold is a weighted quantile of the *final* model's scores on
        the training negatives. It has to come from the same model that will
        use it: an earlier version picked it on a separately fitted probe
        model, whose probabilities sat on a different scale, and on LANL the
        threshold landed below the median normal logon - alerting on
        everything. Negatives number in the millions (weighted), so fitting to
        them barely moves the quantile; the held-out false-alert rate is
        measured separately by :meth:`evaluate` either way.
        """
        import sklearn
        from sklearn.ensemble import HistGradientBoostingClassifier

        if table.positives == 0:
            raise ValueError("training rows contain no red-team logons")

        model = HistGradientBoostingClassifier(
            max_iter=max_iter, learning_rate=0.05, max_leaf_nodes=31,
            l2_regularization=1.0, min_samples_leaf=20, random_state=seed,
        )
        model.fit(table.X, table.y, sample_weight=_balanced_weights(table.y, table.weight))
        threshold = threshold_for_fpr(
            model.predict_proba(table.X)[:, 1], table.y, table.weight, target_fpr
        )
        threshold_source = "weighted quantile of the final model's scores on training negatives"

        return cls(
            model=model,
            threshold=float(threshold),
            features=table.features,
            info={
                "algorithm": "HistGradientBoostingClassifier",
                "sklearn_version": sklearn.__version__,
                "trained_rows": len(table),
                "trained_positives": table.positives,
                "train_time_range": [int(table.time.min()), int(table.time.max())],
                "target_fpr": target_fpr,
                "threshold_source": threshold_source,
                "seed": seed,
            },
        )

    # -- scoring -----------------------------------------------------------

    def score(self, X: np.ndarray) -> np.ndarray:
        """Probability each row is red-team activity."""
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.model.predict_proba(X)[:, 1]

    def score_one(self, vector) -> float:
        return float(self.score(np.asarray(vector, dtype=np.float64))[0])

    def is_alert(self, probability: float) -> bool:
        return probability >= self.threshold

    def evaluate(self, table: FeatureTable) -> DetectionMetrics:
        return evaluate_scores(
            table.y, self.score(table.X), table.weight,
            threshold=self.threshold, days=table.days,
        )

    def feature_importance(self, table: FeatureTable, repeats: int = 3, seed: int = 7) -> dict:
        """Permutation importance: drop in average precision when a feature is shuffled."""
        from sklearn.metrics import average_precision_score

        rng = np.random.default_rng(seed)
        base = average_precision_score(table.y, self.score(table.X), sample_weight=table.weight)
        result = {}
        for i, name in enumerate(self.features):
            drops = []
            for _ in range(repeats):
                shuffled = table.X.copy()
                rng.shuffle(shuffled[:, i])
                ap = average_precision_score(
                    table.y, self.score(shuffled), sample_weight=table.weight
                )
                drops.append(base - ap)
            result[name] = round(float(np.mean(drops)), 6)
        return dict(sorted(result.items(), key=lambda kv: kv[1], reverse=True))

    # -- persistence -------------------------------------------------------

    def save(self, path: str | Path) -> Path:
        import joblib

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"kind": "lateral-movement-detector", "model": self.model,
             "threshold": self.threshold, "features": list(self.features), "info": self.info},
            path,
        )
        path.with_suffix(".json").write_text(
            json.dumps({"threshold": self.threshold, "features": list(self.features),
                        **self.info}, indent=2),
            encoding="utf-8",
        )
        return path

    @classmethod
    def load(cls, path: str | Path) -> "LateralMovementDetector":
        import joblib

        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"detector model not found: {path} (run `dgraph lanl train`)")
        blob = joblib.load(path)
        if blob.get("kind") != "lateral-movement-detector":
            raise ValueError(f"{path} is not a lateral-movement detector")
        return cls(model=blob["model"], threshold=float(blob["threshold"]),
                   features=tuple(blob["features"]), info=dict(blob.get("info") or {}))
