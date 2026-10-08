"""State pattern over attacker progression.

    RECONNAISSANCE
          |
    INITIAL_ACCESS
          |
      DISCOVERY
          |
    LATERAL_MOVEMENT
          |
      COLLECTION
          |
     EXFILTRATION

Each stage is an object, not a flag, because each one answers two questions
differently: *what does this event mean?* and *what should the deception look
like now?* A scan during reconnaissance is routine noise; the same scan during
collection means they are hunting for a way out with your data.

That second question is the point of the pattern here - the deception posture
is a property of the state object, so adding a stage means adding a class, not
editing a chain of conditionals in the adaptation engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

from ..deception.assets import DeceptionKind
from .events import Event, EventType


class AttackerStage(str, Enum):
    """The kill-chain stages this system models."""

    RECONNAISSANCE = "RECONNAISSANCE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"

    @property
    def order(self) -> int:
        return _STAGE_ORDER[self]


_STAGE_ORDER = {
    AttackerStage.RECONNAISSANCE: 0,
    AttackerStage.INITIAL_ACCESS: 1,
    AttackerStage.DISCOVERY: 2,
    AttackerStage.LATERAL_MOVEMENT: 3,
    AttackerStage.COLLECTION: 4,
    AttackerStage.EXFILTRATION: 5,
}


@dataclass(frozen=True, slots=True)
class DeceptionPosture:
    """How the deception layer should behave while the attacker is in a stage."""

    stage: AttackerStage
    budget_delta: int
    """Extra decoys to authorise beyond the standing deployment."""
    preferred_kinds: tuple[DeceptionKind, ...]
    focus: str
    """Where to concentrate: 'perimeter', 'foothold', 'ahead', 'crown-jewel'."""
    urgency: float
    """0-1. Drives incident severity and how aggressively decoys are re-placed."""
    note: str

    def as_dict(self) -> dict:
        return {
            "stage": self.stage.value,
            "budget_delta": self.budget_delta,
            "preferred_kinds": [k.value for k in self.preferred_kinds],
            "focus": self.focus,
            "urgency": round(self.urgency, 4),
            "note": self.note,
        }


class AttackerState(ABC):
    """State role. Decides both the transition and the deception posture."""

    stage: AttackerStage

    @abstractmethod
    def posture(self) -> DeceptionPosture: ...

    @abstractmethod
    def next_state(self, event: Event, hosts_seen: int) -> "AttackerState":
        """Which state this event moves us to. Returning ``self`` means no change."""

    # Progression is monotonic: evidence of a later stage is evidence the
    # attacker got there, and they do not un-learn what they found. Anything
    # that would move backwards is kept at the current stage instead.
    def _advance(self, candidate: "AttackerState") -> "AttackerState":
        if candidate.stage.order <= self.stage.order:
            return self
        return candidate

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AttackerState) and other.stage is self.stage

    def __hash__(self) -> int:
        return hash(self.stage)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


class Reconnaissance(AttackerState):
    """Looking, not touching. Nothing is compromised yet."""

    stage = AttackerStage.RECONNAISSANCE

    def posture(self) -> DeceptionPosture:
        return DeceptionPosture(
            stage=self.stage,
            budget_delta=0,
            preferred_kinds=(DeceptionKind.NETWORK,),
            focus="perimeter",
            urgency=0.2,
            note="Scanning only. Keep decoy services on the perimeter to see what they probe.",
        )

    def next_state(self, event: Event, hosts_seen: int) -> AttackerState:
        if event.type is EventType.HOST_COMPROMISED:
            return InitialAccess()
        if event.type is EventType.DECOY_AUTHENTICATED:
            # Using a credential means they already had a foothold to find it on.
            return LateralMovement()
        if event.type is EventType.DECOY_TOUCHED:
            return InitialAccess()
        return self


class InitialAccess(AttackerState):
    """They are inside, on one host."""

    stage = AttackerStage.INITIAL_ACCESS

    def posture(self) -> DeceptionPosture:
        return DeceptionPosture(
            stage=self.stage,
            budget_delta=1,
            preferred_kinds=(DeceptionKind.CREDENTIAL, DeceptionKind.DOCUMENT),
            focus="foothold",
            urgency=0.5,
            note="Foothold established. Seed credentials on the entry host so the "
            "first thing they loot is fake.",
        )

    def next_state(self, event: Event, hosts_seen: int) -> AttackerState:
        if event.type is EventType.EXFIL_OBSERVED:
            return self._advance(Exfiltration())
        if event.type is EventType.DECOY_AUTHENTICATED:
            return self._advance(LateralMovement())
        if hosts_seen >= 2:
            return self._advance(LateralMovement())
        if event.type in (EventType.SCAN_OBSERVED, EventType.DECOY_TOUCHED):
            return self._advance(Discovery())
        return self


class Discovery(AttackerState):
    """Mapping the inside: what else is here, what can I reach?"""

    stage = AttackerStage.DISCOVERY

    def posture(self) -> DeceptionPosture:
        return DeceptionPosture(
            stage=self.stage,
            budget_delta=2,
            preferred_kinds=(DeceptionKind.NETWORK, DeceptionKind.CREDENTIAL),
            focus="ahead",
            urgency=0.6,
            note="They are enumerating. Put decoy hosts on the routes they are "
            "about to discover, not where they already are.",
        )

    def next_state(self, event: Event, hosts_seen: int) -> AttackerState:
        if event.type is EventType.EXFIL_OBSERVED:
            return self._advance(Exfiltration())
        if event.type is EventType.DECOY_AUTHENTICATED or hosts_seen >= 2:
            return self._advance(LateralMovement())
        return self


class LateralMovement(AttackerState):
    """Moving host to host, usually on stolen credentials."""

    stage = AttackerStage.LATERAL_MOVEMENT

    def posture(self) -> DeceptionPosture:
        return DeceptionPosture(
            stage=self.stage,
            budget_delta=2,
            preferred_kinds=(DeceptionKind.CREDENTIAL, DeceptionKind.NETWORK),
            focus="ahead",
            urgency=0.8,
            note="Moving laterally. Place decoys one hop ahead of the predicted "
            "path so the next step they take is into a trap.",
        )

    def next_state(self, event: Event, hosts_seen: int) -> AttackerState:
        if event.type is EventType.EXFIL_OBSERVED:
            return self._advance(Exfiltration())
        if event.host_id and event.metadata.get("is_crown_jewel"):
            return self._advance(Collection())
        if hosts_seen >= 3:
            return self._advance(Collection())
        return self


class Collection(AttackerState):
    """On or beside the objective, gathering what they came for."""

    stage = AttackerStage.COLLECTION

    def posture(self) -> DeceptionPosture:
        return DeceptionPosture(
            stage=self.stage,
            budget_delta=3,
            preferred_kinds=(DeceptionKind.DOCUMENT, DeceptionKind.NETWORK),
            focus="crown-jewel",
            urgency=0.95,
            note="They are at the objective. Flood it with honeyfiles - at this "
            "point a false positive costs far less than a miss.",
        )

    def next_state(self, event: Event, hosts_seen: int) -> AttackerState:
        if event.type is EventType.EXFIL_OBSERVED:
            return self._advance(Exfiltration())
        return self


class Exfiltration(AttackerState):
    """Data is moving out. Containment, not observation."""

    stage = AttackerStage.EXFILTRATION

    def posture(self) -> DeceptionPosture:
        return DeceptionPosture(
            stage=self.stage,
            budget_delta=3,
            preferred_kinds=(DeceptionKind.DOCUMENT,),
            focus="crown-jewel",
            urgency=1.0,
            note="Exfiltration in progress. Deception has done its job; this is "
            "an incident response problem now.",
        )

    def next_state(self, event: Event, hosts_seen: int) -> AttackerState:
        return self


STATES: dict[AttackerStage, type[AttackerState]] = {
    AttackerStage.RECONNAISSANCE: Reconnaissance,
    AttackerStage.INITIAL_ACCESS: InitialAccess,
    AttackerStage.DISCOVERY: Discovery,
    AttackerStage.LATERAL_MOVEMENT: LateralMovement,
    AttackerStage.COLLECTION: Collection,
    AttackerStage.EXFILTRATION: Exfiltration,
}


def state_for(stage: AttackerStage | str) -> AttackerState:
    """Build the state object for a stage."""
    if isinstance(stage, str):
        try:
            stage = AttackerStage(stage.upper())
        except ValueError as exc:
            allowed = ", ".join(s.value for s in AttackerStage)
            raise ValueError(f"unknown attacker stage {stage!r} (expected one of: {allowed})") from exc
    return STATES[stage]()
