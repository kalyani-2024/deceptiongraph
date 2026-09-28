"""Deception assets: the things an attacker touches, and what notices.

Every deception asset is three related parts, never one:

``Lure``
    The bait itself - a credential file, a decoy host, a planted document.
    It has to look like something worth taking.
``Sensor``
    What fires when the lure is touched. A lure without a sensor is just
    litter; it wastes the attacker's time but tells you nothing.
``Marker``
    A canary token woven into the lure so a later sighting can be traced back
    to *this* decoy on *this* host - which is how stage 3 will work out where
    the attacker has been.

Keeping the three together is why the factory is an Abstract Factory rather
than three unrelated constructors: the parts must match, and a credential lure
needs a credential sensor, not a file-access one.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from enum import Enum


class DeceptionKind(str, Enum):
    """Families of deception, one per concrete factory."""

    CREDENTIAL = "CREDENTIAL"
    NETWORK = "NETWORK"
    DOCUMENT = "DOCUMENT"


class DeceptionState(str, Enum):
    """Lifecycle of a deployed asset. Stage 3 drives the transitions."""

    STAGED = "STAGED"
    DEPLOYED = "DEPLOYED"
    TRIGGERED = "TRIGGERED"
    BURNED = "BURNED"
    """The attacker worked out it was fake; it now costs credibility to keep."""
    RETIRED = "RETIRED"


@dataclass(frozen=True, slots=True)
class Lure:
    """The bait placed on a host."""

    id: str
    kind: DeceptionKind
    name: str
    host_id: str
    believability: float
    """P(attacker engages | attacker is on this host and finds it)."""
    payload: dict = field(default_factory=dict)
    mimics: str | None = None
    """The real asset this decoy imitates, when it imitates one."""

    def __post_init__(self) -> None:
        if not 0.0 <= self.believability <= 1.0:
            raise ValueError(
                f"{self.id}: believability must be in [0, 1], got {self.believability}"
            )


@dataclass(frozen=True, slots=True)
class Sensor:
    """What raises an alert when the paired lure is touched."""

    id: str
    kind: DeceptionKind
    lure_id: str
    watches: str
    """Human-readable description of the observed action."""
    fidelity: float
    """P(alert | attacker engaged the lure). Below 1 because telemetry drops."""

    def __post_init__(self) -> None:
        if not 0.0 <= self.fidelity <= 1.0:
            raise ValueError(f"{self.id}: fidelity must be in [0, 1], got {self.fidelity}")


@dataclass(frozen=True, slots=True)
class Marker:
    """A canary token embedded in the lure, unique to this asset."""

    id: str
    kind: DeceptionKind
    lure_id: str
    token: str

    @staticmethod
    def mint(prefix: str) -> str:
        return f"{prefix}-{secrets.token_hex(4)}"


@dataclass(slots=True)
class DeceptionAsset:
    """A complete, deployable unit of deception: lure + sensor + marker."""

    id: str
    kind: DeceptionKind
    host_id: str
    lure: Lure
    sensor: Sensor
    marker: Marker
    state: DeceptionState = DeceptionState.STAGED
    rationale: str = ""

    @property
    def detection_probability(self) -> float:
        """P(alert | attacker reaches this host).

        The attacker has to take the bait *and* the telemetry has to survive,
        so the two multiply.
        """
        return self.lure.believability * self.sensor.fidelity

    @property
    def protects(self) -> str | None:
        return self.lure.mimics

    def deploy(self) -> None:
        self.state = DeceptionState.DEPLOYED

    def describe(self) -> str:
        return f"{self.lure.name} on {self.host_id}"

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "host_id": self.host_id,
            "state": self.state.value,
            "name": self.lure.name,
            "mimics": self.lure.mimics,
            "believability": round(self.lure.believability, 4),
            "fidelity": round(self.sensor.fidelity, 4),
            "detection_probability": round(self.detection_probability, 4),
            "watches": self.sensor.watches,
            "token": self.marker.token,
            "rationale": self.rationale,
            "payload": self.lure.payload,
        }
