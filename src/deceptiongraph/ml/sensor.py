"""The detector as a live sensor, and a replay of the real red team through it.

:class:`MLDetectionSensor` is an Adapter: raw authentication telemetry in,
mediator events out. A logon the model flags becomes a ``HOST_COMPROMISED``
event, so it drives the profiler, the incident manager and the adaptation
engine exactly as a decoy trigger does.

:func:`replay` pushes the held-out LANL period through that sensor and a live
deception deployment on the twin, in time order. Red-team logons that land on
a decoyed host roll against the decoy's detection probability, as in the
simulator - the only part that is counterfactual, since LANL had no decoys.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

from ..datasets.lanl import AuthEvent, AuthFeaturizer
from ..deception.coverage import detection_by_host
from ..deception.engine import DeceptionEngine
from ..deception.placement import DeceptionPlacementStrategy
from ..graph.loader import load_network
from ..graph.repository import GraphRepository, InMemoryGraphRepository
from ..runtime.events import Event, EventType
from ..runtime.mediator import Reaction, SecurityMediator
from ..runtime.telemetry import Telemetry
from .data import FeatureTable, load_features
from .detector import LateralMovementDetector


def actor_for(src: str) -> str:
    """Actor identity for a logon: the machine it came from.

    The red team used dozens of stolen accounts from a handful of machines, so
    keying the profile on the account would split one intruder into many.
    """
    return f"src:{src}"


class MLDetectionSensor:
    """Scores logons as they arrive and reports the suspicious ones."""

    name = "ml-detection-sensor"

    def __init__(
        self,
        detector: LateralMovementDetector,
        mediator: SecurityMediator | None = None,
        featurizer: AuthFeaturizer | None = None,
    ) -> None:
        self.detector = detector
        self.mediator = mediator
        self.featurizer = featurizer or AuthFeaturizer()
        self.scored = 0
        self.alerts = 0

    def observe(self, event: AuthEvent) -> tuple[float, Reaction | None]:
        """Score one raw logon. Returns the probability and any reaction."""
        if not event.success:
            self.featurizer.observe_failure(event.user)
            return 0.0, None
        if not event.is_lateral_logon:
            return 0.0, None
        vector = self.featurizer.step_event(event)
        return self.report(vector, event.user, event.src, event.dst)

    def report(
        self, vector, user: str, src: str, dst: str, probability: float | None = None,
        metadata: dict | None = None,
    ) -> tuple[float, Reaction | None]:
        """Score a precomputed feature vector and alert if it crosses the threshold."""
        self.scored += 1
        p = self.detector.score_one(vector) if probability is None else probability
        if not self.detector.is_alert(p):
            return p, None
        self.alerts += 1
        event = self.to_event(p, user, src, dst, metadata)
        reaction = self.mediator.handle(event) if self.mediator is not None else None
        return p, reaction

    def to_event(self, p: float, user: str, src: str, dst: str, metadata=None) -> Event:
        host_id = dst
        if self.mediator is not None and dst not in self.mediator.repository.model.hosts:
            host_id = None  # outside the twin: still an alert, just not placeable
        return Event(
            type=EventType.HOST_COMPROMISED,
            host_id=host_id,
            actor_id=actor_for(src),
            detail=f"ML detector: {user} {src}->{dst} p={p:.3f}",
            metadata={"score": round(p, 6), "user": user, "src": src, "dst": dst,
                      "source": "ml-detector", **(metadata or {})},
        )


@dataclass(slots=True)
class ReplaySummary:
    """What happened when the held-out period was replayed."""

    strategy: str
    budget: int
    rows: int
    redteam_rows: int
    ml_alerts: int
    ml_true_alerts: int
    ml_false_alerts: int
    ml_false_alerts_per_day: float
    decoy_triggers: int
    first_redteam_time: int | None
    first_ml_detection_time: int | None
    first_decoy_detection_time: int | None
    redteam_before_first_detection: int | None
    incidents: int
    adaptations: int
    live_decoys: int
    highlights: list[str] = field(default_factory=list)

    @property
    def hours_to_first_detection(self) -> float | None:
        times = [t for t in (self.first_ml_detection_time, self.first_decoy_detection_time)
                 if t is not None]
        if not times or self.first_redteam_time is None:
            return None
        return (min(times) - self.first_redteam_time) / 3600.0

    def as_dict(self) -> dict:
        data = asdict(self)
        data["hours_to_first_detection"] = (
            None if self.hours_to_first_detection is None
            else round(self.hours_to_first_detection, 3)
        )
        data["ml_false_alerts_per_day"] = round(self.ml_false_alerts_per_day, 3)
        return data


def replay(
    prepared_dir: str | Path,
    detector: LateralMovementDetector,
    strategy: DeceptionPlacementStrategy | str = "attack-path",
    budget: int = 5,
    start_time: int | None = None,
    seed: int = 7,
    max_total_decoys: int = 20,
    table: FeatureTable | None = None,
    repository: GraphRepository | None = None,
    highlight_limit: int = 12,
) -> ReplaySummary:
    """Replay logons from ``start_time`` on through the live loop.

    Rows are the prepared feature table: every red-team logon plus a sample of
    normal ones, so false-alert counts are scaled by each row's weight when
    reported per day.
    """
    prepared = Path(prepared_dir)
    table = table if table is not None else load_features(prepared)
    repository = repository or InMemoryGraphRepository(load_network(prepared / "network.yaml"))
    if start_time is not None:
        table = table.subset(table.time >= start_time)
    order = np.argsort(table.time, kind="stable")
    table = table.subset(order)

    engine = DeceptionEngine(repository)
    deployment = engine.deploy(budget=budget, strategy=strategy)
    # Offline analysis of historical data: keep it out of the live metrics.
    mediator = SecurityMediator(repository, deception=engine, deployment=deployment,
                                max_total_decoys=max_total_decoys,
                                telemetry=Telemetry.disabled())
    sensor = MLDetectionSensor(detector, mediator=mediator)
    rng = random.Random(seed)

    probabilities = detector.score(table.X) if len(table) else np.empty(0)
    ml_true = ml_false = triggers = 0
    false_weight = 0.0
    first_rt = first_ml = first_decoy = None
    rt_seen = 0
    rt_before: int | None = None
    highlights: list[str] = []

    for i in range(len(table)):
        is_attack = bool(table.y[i])
        when = int(table.time[i])
        user, src, dst = str(table.user[i]), str(table.src[i]), str(table.dst[i])
        if is_attack:
            rt_seen += 1
            if first_rt is None:
                first_rt = when

        p, reaction = sensor.report(table.X[i], user, src, dst,
                                    probability=float(probabilities[i]),
                                    metadata={"time": when})
        if reaction is not None:
            if is_attack:
                ml_true += 1
                if first_ml is None:
                    first_ml = when
                    if rt_before is None:
                        rt_before = rt_seen - 1
                    highlights.append(f"t={when} first ML detection: {reaction.event.detail}")
            else:
                ml_false += 1
                false_weight += float(table.weight[i])

        if is_attack and dst in repository.model.hosts:
            live = [a for a in mediator.live_assets if a.host_id == dst]
            if live and rng.random() < detection_by_host(live).get(dst, 0.0):
                decoy = rng.choices(live, weights=[a.detection_probability for a in live])[0]
                trigger = mediator.handle(Event(
                    type=EventType.DECOY_AUTHENTICATED, host_id=dst, actor_id=actor_for(src),
                    asset_id=decoy.id, token=decoy.marker.token,
                    detail=f"red team ({user}) touched {decoy.lure.name}",
                    metadata={"time": when},
                ))
                triggers += 1
                if first_decoy is None:
                    first_decoy = when
                    if rt_before is None:
                        rt_before = rt_seen - 1
                    highlights.append(f"t={when} first decoy trigger:\n{trigger.describe()}")

    if len(highlights) < highlight_limit:
        for incident in mediator.incidents.incidents[: highlight_limit - len(highlights)]:
            highlights.append(
                f"{incident.id} [{incident.severity.value}] {incident.actor_id}: {incident.summary}"
            )

    return ReplaySummary(
        strategy=deployment.strategy,
        budget=budget,
        rows=len(table),
        redteam_rows=int(table.y.sum()) if len(table) else 0,
        ml_alerts=ml_true + ml_false,
        ml_true_alerts=ml_true,
        ml_false_alerts=ml_false,
        ml_false_alerts_per_day=false_weight / table.days if len(table) else 0.0,
        decoy_triggers=triggers,
        first_redteam_time=first_rt,
        first_ml_detection_time=first_ml,
        first_decoy_detection_time=first_decoy,
        redteam_before_first_detection=rt_before,
        incidents=len(mediator.incidents.incidents),
        adaptations=sum(1 for a in mediator.adaptation.history if a.changed),
        live_decoys=len(mediator.live_assets),
        highlights=highlights,
    )
