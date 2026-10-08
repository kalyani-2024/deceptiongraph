"""Attacker profiler.

Builds a picture of who is in the network from the only evidence available: a
stream of decoy triggers and compromise events. Everything here is an
*estimate* and is labelled as one - the profile carries a confidence, and the
confidence is low until several independent observations agree.

Sophistication is inferred from behaviour rather than asserted:

* using a stolen credential is more advanced than tripping over a honeyfile;
* reaching a restricted host means they got through segmentation;
* covering several hosts per observation means they are moving deliberately,
  not stumbling.

The profiler owns the :class:`AttackerState`, so inferring the stage and
inferring the actor are the same walk over the same events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..analysis.prediction import PathPredictor
from ..graph.repository import GraphRepository
from .events import Event, EventType
from .states import AttackerStage, AttackerState, DeceptionPosture, Reconnaissance


class Sophistication(str, Enum):
    """How capable the actor appears to be."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @classmethod
    def from_score(cls, score: float) -> "Sophistication":
        if score >= 0.66:
            return cls.HIGH
        if score >= 0.33:
            return cls.MEDIUM
        return cls.LOW


@dataclass(frozen=True, slots=True)
class AttackerProfile:
    """A snapshot of what is believed about one actor."""

    actor_id: str
    stage: AttackerStage
    sophistication: Sophistication
    sophistication_score: float
    objective: str | None
    """The asset they appear to be heading for."""
    likely_next_target: str | None
    hosts_seen: tuple[str, ...]
    decoys_triggered: tuple[str, ...]
    events_observed: int
    confidence: float
    """0-1. How much weight to put on this profile."""
    posture: DeceptionPosture

    @property
    def current_host(self) -> str | None:
        return self.hosts_seen[-1] if self.hosts_seen else None

    def as_dict(self) -> dict:
        return {
            "actor_id": self.actor_id,
            "stage": self.stage.value,
            "sophistication": self.sophistication.value,
            "sophistication_score": round(self.sophistication_score, 4),
            "objective": self.objective,
            "likely_next_target": self.likely_next_target,
            "current_host": self.current_host,
            "hosts_seen": list(self.hosts_seen),
            "decoys_triggered": list(self.decoys_triggered),
            "events_observed": self.events_observed,
            "confidence": round(self.confidence, 4),
            "posture": self.posture.as_dict(),
        }


@dataclass(slots=True)
class _ActorTrack:
    """Mutable accumulator for one actor, kept separate from the public profile."""

    actor_id: str
    state: AttackerState = field(default_factory=Reconnaissance)
    hosts_seen: list[str] = field(default_factory=list)
    decoys_triggered: list[str] = field(default_factory=list)
    events: int = 0
    credential_use: int = 0
    restricted_reached: int = 0
    privileged_reached: int = 0
    exfiltrated: bool = False


class ThreatProfiler:
    """Observer that maintains one :class:`AttackerProfile` per actor."""

    name = "threat-profiler"

    def __init__(
        self,
        repository: GraphRepository,
        predictor: PathPredictor | None = None,
        on_state_change=None,
    ) -> None:
        self.repository = repository
        self.predictor = predictor or PathPredictor(repository)
        self._tracks: dict[str, _ActorTrack] = {}
        self._on_state_change = on_state_change
        """Optional callback(actor_id, old_stage, new_stage); the mediator uses it."""

    # -- Observer role -----------------------------------------------------

    def on_event(self, event: Event) -> None:
        if event.type in (
            EventType.ALERT_RAISED,
            EventType.DECEPTION_ADAPTED,
            EventType.PROFILE_UPDATED,
            EventType.STATE_CHANGED,
        ):
            return  # our own downstream noise, not attacker behaviour

        track = self._tracks.setdefault(event.actor_id, _ActorTrack(event.actor_id))
        track.events += 1

        if event.host_id and event.host_id not in track.hosts_seen:
            track.hosts_seen.append(event.host_id)
            self._score_host(track, event.host_id)

        if event.asset_id and event.asset_id not in track.decoys_triggered:
            track.decoys_triggered.append(event.asset_id)

        if event.type is EventType.DECOY_AUTHENTICATED:
            track.credential_use += 1
        if event.type is EventType.EXFIL_OBSERVED:
            track.exfiltrated = True

        previous = track.state
        track.state = track.state.next_state(event, hosts_seen=len(track.hosts_seen))
        if track.state.stage is not previous.stage and self._on_state_change is not None:
            self._on_state_change(track.actor_id, previous.stage, track.state.stage)

    # -- queries -----------------------------------------------------------

    @property
    def actors(self) -> tuple[str, ...]:
        return tuple(self._tracks)

    def profile(self, actor_id: str) -> AttackerProfile | None:
        """The current estimate for an actor, or None if never seen."""
        track = self._tracks.get(actor_id)
        return self._build(track) if track else None

    def profiles(self) -> tuple[AttackerProfile, ...]:
        return tuple(self._build(t) for t in self._tracks.values())

    def most_advanced(self) -> AttackerProfile | None:
        """The actor furthest along the kill chain - who to worry about first."""
        profiles = self.profiles()
        if not profiles:
            return None
        return max(profiles, key=lambda p: (p.stage.order, p.sophistication_score))

    def reset(self) -> None:
        self._tracks.clear()

    # -- inference ---------------------------------------------------------

    def _score_host(self, track: _ActorTrack, host_id: str) -> None:
        host = self.repository.host(host_id)
        if host is None:
            return
        if host.exposure.value == "RESTRICTED":
            track.restricted_reached += 1
        if host.is_crown_jewel or host.criticality >= 0.8:
            track.privileged_reached += 1

    def _sophistication(self, track: _ActorTrack) -> float:
        """Weighted evidence of capability, clamped to [0, 1].

        Weights are judgement calls, documented so they can be argued with:
        using a credential is the strongest single signal, because it means
        they looted, understood and replayed a secret rather than blundering
        into a file.
        """
        score = 0.0
        score += min(0.35, 0.35 * track.credential_use)
        score += min(0.25, 0.25 * track.restricted_reached)
        score += min(0.20, 0.10 * track.privileged_reached)
        score += min(0.10, 0.05 * max(0, len(track.hosts_seen) - 1))
        if track.exfiltrated:
            score += 0.10
        return min(1.0, score)

    def _confidence(self, track: _ActorTrack) -> float:
        """Confidence grows with corroboration, not with raw event count.

        Ten alerts from one decoy on one host is one observation repeated; two
        decoys on two hosts is genuinely two.
        """
        breadth = len(set(track.hosts_seen)) + len(set(track.decoys_triggered))
        return min(1.0, round(0.25 * breadth, 6))

    def _build(self, track: _ActorTrack) -> AttackerProfile:
        current = track.hosts_seen[-1] if track.hosts_seen else None
        objective = next_target = None
        if current is not None and current in self.repository.model.hosts:
            objective = self.predictor.objective(current)
            hop = self.predictor.most_likely_next(current, visited=tuple(track.hosts_seen))
            next_target = hop.target if hop else objective

        score = self._sophistication(track)
        return AttackerProfile(
            actor_id=track.actor_id,
            stage=track.state.stage,
            sophistication=Sophistication.from_score(score),
            sophistication_score=score,
            objective=objective,
            likely_next_target=next_target,
            hosts_seen=tuple(track.hosts_seen),
            decoys_triggered=tuple(track.decoys_triggered),
            events_observed=track.events,
            confidence=self._confidence(track),
            posture=track.state.posture(),
        )
