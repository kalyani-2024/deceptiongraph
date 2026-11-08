"""Loading the per-logon feature table that ``dgraph lanl prepare`` writes."""

from __future__ import annotations

import csv
import gzip
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from ..datasets.lanl import AUTH_FEATURES


@dataclass(slots=True)
class FeatureTable:
    """Feature rows plus the identifiers needed to replay them."""

    X: np.ndarray
    y: np.ndarray
    weight: np.ndarray
    """1 for red-team rows; ``1 / negative_rate`` for sampled normal rows."""
    time: np.ndarray
    user: np.ndarray
    src: np.ndarray
    dst: np.ndarray
    features: tuple[str, ...] = AUTH_FEATURES

    def __len__(self) -> int:
        return len(self.y)

    @property
    def positives(self) -> int:
        return int(self.y.sum())

    @property
    def days(self) -> float:
        """Span of the rows in days, at least one second."""
        if len(self.time) == 0:
            return 0.0
        return max(1.0, float(self.time.max() - self.time.min())) / 86_400

    def subset(self, mask: np.ndarray) -> "FeatureTable":
        return FeatureTable(
            X=self.X[mask], y=self.y[mask], weight=self.weight[mask], time=self.time[mask],
            user=self.user[mask], src=self.src[mask], dst=self.dst[mask],
            features=self.features,
        )


def load_features(path: str | Path) -> FeatureTable:
    """Read ``auth_features.csv.gz`` (or a plain ``.csv``)."""
    path = Path(path)
    if path.is_dir():
        path = path / "auth_features.csv.gz"
    if not path.exists():
        raise FileNotFoundError(f"feature table not found: {path} (run `dgraph lanl prepare`)")

    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        features = tuple(header[4:-2])
        if features != AUTH_FEATURES:
            raise ValueError(
                f"{path} has features {features}, expected {AUTH_FEATURES}; "
                "re-run `dgraph lanl prepare` with this version"
            )
        width = len(features)
        # Converted in chunks: a million rows held as Python lists of strings
        # would need several gigabytes; as numpy blocks it is tens of megabytes.
        blocks: list[tuple] = []
        chunk: list[list[str]] = []
        for row in reader:
            chunk.append(row)
            if len(chunk) >= 100_000:
                blocks.append(_to_block(chunk, width))
                chunk = []
        if chunk or not blocks:
            blocks.append(_to_block(chunk, width))

    return FeatureTable(
        X=np.concatenate([b[0] for b in blocks]),
        y=np.concatenate([b[1] for b in blocks]),
        weight=np.concatenate([b[2] for b in blocks]),
        time=np.concatenate([b[3] for b in blocks]),
        user=np.concatenate([b[4] for b in blocks]),
        src=np.concatenate([b[5] for b in blocks]),
        dst=np.concatenate([b[6] for b in blocks]),
        features=features,
    )


def _to_block(rows: list[list[str]], width: int) -> tuple:
    n = len(rows)
    if n == 0:
        empty = np.empty(0, dtype=object)
        return (np.empty((0, width)), np.empty(0, dtype=np.int8), np.empty(0),
                np.empty(0, dtype=np.int64), empty, empty, empty)
    X = np.array([row[4:4 + width] for row in rows], dtype=np.float64)
    y = np.array([row[4 + width] for row in rows], dtype=np.int8)
    weight = np.array([row[5 + width] for row in rows], dtype=np.float64)
    when = np.array([row[0] for row in rows], dtype=np.int64)
    user = np.array([row[1] for row in rows], dtype=object)
    src = np.array([row[2] for row in rows], dtype=object)
    dst = np.array([row[3] for row in rows], dtype=object)
    return X, y, weight, when, user, src, dst


def split_by_time(
    table: FeatureTable, split_time: int | None = None
) -> tuple[FeatureTable, FeatureTable, int]:
    """Train on the past, test on the future.

    The default split is the median red-team timestamp, so each side holds about
    half of the attack. A random split would let the model see the attacker's
    later moves while being tested on their earlier ones.
    """
    if split_time is None:
        positive_times = table.time[table.y == 1]
        if len(positive_times) == 0:
            raise ValueError("no red-team rows in the feature table; nothing to learn from")
        split_time = int(np.median(positive_times))
    train = table.subset(table.time < split_time)
    test = table.subset(table.time >= split_time)
    return train, test, split_time
