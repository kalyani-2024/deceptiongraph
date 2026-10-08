"""Events and the Observer fan-out.

A decoy being touched is the only ground truth this system ever gets. Everything
downstream - the attacker profile, the incident, the decision to move decoys -
is inference from a stream of these.

    Decoy touched
        |
    EventBus.publish()
        |
        +---- ThreatProfiler
        +---- IncidentManager
        +---- RiskRecalculator
        +---- AdaptationEngine

The bus is the Observer pattern: publishers do not know who is listening, and
observers do not know about each other. When one observer's work needs to
*cause* another's, that coordination goes through the mediator instead, so the
ordering lives in one place rather than being smeared across the observers.
"""

from __future__ import annotations

import itertools
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Iterable, Protocol, runtime_checkable


class EventType(str, Enum):
    """What the twin can observe."""

    SCAN_OBSERVED = "SCAN_OBSERVED"
    """Reconnaissance against a host or decoy service."""
    HOST_COMPROMISED = "HOST_COMPROMISED"
    """Ground truth from the simulator, or a real EDR verdict."""
    DECOY_TOUCHED = "DECOY_TOUCHED"
    """A lure was read or opened."""
    DECOY_AUTHENTICATED = "DECOY_AUTHENTICATED"
    """A decoy credential was actually used - the strongest signal there is."""
    EXFIL_OBSERVED = "EXFIL_OBSERVED"
    """Data leaving, usually a honeyfile being copied out."""
    ALERT_RAISED = "ALERT_RAISED"
    DECEPTION_ADAPTED = "DECEPTION_ADAPTED"
    PROFILE_UPDATED = "PROFILE_UPDATED"
    STATE_CHANGED = "STATE_CHANGED"


#: Events that mean a decoy did its job.
DECEPTION_TRIGGERS = frozenset(
    {EventType.DECOY_TOUCHED, EventType.DECOY_AUTHENTICATED, EventType.EXFIL_OBSERVED}
)

_SEQUENCE = itertools.count(1)


@dataclass(frozen=True, slots=True)
class Event:
    """One observation. Immutable, so observers cannot rewrite history."""

    type: EventType
    host_id: str | None = None
    actor_id: str = "unknown"
    asset_id: str | None = None
    """The deception asset involved, when there is one."""
    token: str | None = None
    """Canary token, which is how an alert is traced back to its decoy."""
    detail: str = ""
    metadata: dict = field(default_factory=dict)
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sequence: int = field(default_factory=lambda: next(_SEQUENCE))

    @property
    def is_deception_trigger(self) -> bool:
        return self.type in DECEPTION_TRIGGERS

    def describe(self) -> str:
        where = f" on {self.host_id}" if self.host_id else ""
        return f"{self.type.value}{where}: {self.detail}" if self.detail else f"{self.type.value}{where}"

    def as_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "type": self.type.value,
            "host_id": self.host_id,
            "actor_id": self.actor_id,
            "asset_id": self.asset_id,
            "token": self.token,
            "detail": self.detail,
            "metadata": self.metadata,
            "at": self.at.isoformat(),
        }


@runtime_checkable
class Observer(Protocol):
    """Observer role. Implementations react to events and nothing else."""

    name: str

    def on_event(self, event: Event) -> None: ...


class EventBus:
    """Subject role: broadcasts events and keeps an audit trail."""

    def __init__(self, history: int = 500) -> None:
        self._observers: list[tuple[Observer, frozenset[EventType] | None]] = []
        self._history: deque[Event] = deque(maxlen=history)
        self._errors: list[tuple[str, Event, Exception]] = []

    # -- registration ------------------------------------------------------

    def subscribe(
        self, observer: Observer, types: Iterable[EventType] | None = None
    ) -> Observer:
        """Register an observer, optionally narrowed to certain event types."""
        wanted = frozenset(types) if types is not None else None
        self._observers.append((observer, wanted))
        return observer

    def unsubscribe(self, observer: Observer) -> None:
        self._observers = [(o, t) for o, t in self._observers if o is not observer]

    @property
    def observers(self) -> tuple[Observer, ...]:
        return tuple(o for o, _ in self._observers)

    # -- publishing --------------------------------------------------------

    def publish(self, event: Event) -> Event:
        """Deliver an event to every interested observer.

        One observer raising must not stop the others from hearing about an
        intrusion, so failures are captured rather than propagated. They are
        kept in :attr:`errors` so a silent observer cannot hide a bug.
        """
        self._history.append(event)
        for observer, wanted in list(self._observers):
            if wanted is not None and event.type not in wanted:
                continue
            try:
                observer.on_event(event)
            except Exception as exc:  # noqa: BLE001 - deliberately broad
                self._errors.append((getattr(observer, "name", repr(observer)), event, exc))
        return event

    def emit(self, type: EventType, **kwargs) -> Event:
        """Convenience: build and publish in one call."""
        return self.publish(Event(type=type, **kwargs))

    # -- inspection --------------------------------------------------------

    @property
    def history(self) -> tuple[Event, ...]:
        return tuple(self._history)

    @property
    def errors(self) -> tuple[tuple[str, Event, Exception], ...]:
        return tuple(self._errors)

    def of_type(self, *types: EventType) -> tuple[Event, ...]:
        wanted = set(types)
        return tuple(e for e in self._history if e.type in wanted)

    def triggers(self) -> tuple[Event, ...]:
        return tuple(e for e in self._history if e.is_deception_trigger)


class CallbackObserver:
    """Adapter so a plain function can be an observer, mostly for tests."""

    def __init__(self, name: str, callback: Callable[[Event], None]) -> None:
        self.name = name
        self._callback = callback

    def on_event(self, event: Event) -> None:
        self._callback(event)
