"""Incident management.

Turns a stream of events into a small number of incidents a human would
actually read. The hard part is not raising alerts, it is *not* raising five
hundred of them: one actor tripping four decoys on their way to the database is
one incident with four pieces of evidence, not four incidents.

Deduplication is therefore by actor, not by event. Severity rises as the actor
progresses, so an incident opened at reconnaissance escalates in place rather
than spawning a second ticket.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from .events import Event, EventType
from .profiler import AttackerProfile


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_urgency(cls, urgency: float) -> "Severity":
        if urgency >= 0.9:
            return cls.CRITICAL
        if urgency >= 0.7:
            return cls.HIGH
        if urgency >= 0.4:
            return cls.MEDIUM
        if urgency >= 0.2:
            return cls.LOW
        return cls.INFO


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(slots=True)
class Incident:
    """One actor's intrusion, accumulating evidence as it unfolds."""

    id: str
    actor_id: str
    severity: Severity
    opened_at: datetime
    updated_at: datetime
    summary: str
    evidence: list[Event] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    stage: str | None = None
    sophistication: str | None = None
    objective: str | None = None
    closed: bool = False

    def add(self, event: Event) -> None:
        self.evidence.append(event)
        if event.host_id and event.host_id not in self.hosts:
            self.hosts.append(event.host_id)
        self.updated_at = event.at

    def escalate(self, severity: Severity) -> bool:
        """Raise severity, never lower it. Returns True if it changed."""
        if severity.rank > self.severity.rank:
            self.severity = severity
            return True
        return False

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "actor_id": self.actor_id,
            "severity": self.severity.value,
            "stage": self.stage,
            "sophistication": self.sophistication,
            "objective": self.objective,
            "summary": self.summary,
            "hosts": list(self.hosts),
            "evidence_count": len(self.evidence),
            "opened_at": self.opened_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "closed": self.closed,
        }


class IncidentManager:
    """Observer that opens and escalates incidents."""

    name = "incident-manager"

    def __init__(self) -> None:
        self._incidents: dict[str, Incident] = {}
        self._counter = 0

    # -- Observer role -----------------------------------------------------

    def on_event(self, event: Event) -> None:
        """Open or update an incident for events that imply an intruder."""
        if not self._is_actionable(event):
            return

        incident = self._incidents.get(event.actor_id)
        if incident is None:
            incident = self._open(event)
        incident.add(event)
        incident.escalate(self._baseline_severity(event))

    # -- mediator-driven enrichment ---------------------------------------

    def apply_profile(self, profile: AttackerProfile) -> Incident | None:
        """Fold the profiler's conclusions into the actor's incident.

        Called by the mediator rather than by the profiler: the incident
        manager and the profiler never speak to each other directly.
        """
        incident = self._incidents.get(profile.actor_id)
        if incident is None:
            return None
        incident.stage = profile.stage.value
        incident.sophistication = profile.sophistication.value
        incident.objective = profile.objective
        incident.escalate(Severity.from_urgency(profile.posture.urgency))
        incident.summary = (
            f"{profile.sophistication.value} sophistication actor at "
            f"{profile.stage.value}"
            + (f", heading for {profile.objective}" if profile.objective else "")
        )
        return incident

    # -- queries -----------------------------------------------------------

    @property
    def incidents(self) -> tuple[Incident, ...]:
        return tuple(self._incidents.values())

    @property
    def open_incidents(self) -> tuple[Incident, ...]:
        return tuple(i for i in self._incidents.values() if not i.closed)

    def for_actor(self, actor_id: str) -> Incident | None:
        return self._incidents.get(actor_id)

    def worst(self) -> Incident | None:
        if not self._incidents:
            return None
        return max(self._incidents.values(), key=lambda i: (i.severity.rank, len(i.evidence)))

    def close(self, actor_id: str) -> bool:
        incident = self._incidents.get(actor_id)
        if incident is None or incident.closed:
            return False
        incident.closed = True
        return True

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _is_actionable(event: Event) -> bool:
        return event.is_deception_trigger or event.type is EventType.HOST_COMPROMISED

    @staticmethod
    def _baseline_severity(event: Event) -> Severity:
        """Severity from the event alone, before the profile refines it."""
        if event.type is EventType.EXFIL_OBSERVED:
            return Severity.CRITICAL
        if event.type is EventType.DECOY_AUTHENTICATED:
            return Severity.HIGH
        if event.type is EventType.DECOY_TOUCHED:
            return Severity.MEDIUM
        return Severity.LOW

    def _open(self, event: Event) -> Incident:
        self._counter += 1
        incident = Incident(
            id=f"INC-{self._counter:04d}",
            actor_id=event.actor_id,
            severity=Severity.LOW,
            opened_at=event.at,
            updated_at=event.at,
            summary=f"Deception triggered by {event.actor_id}",
        )
        self._incidents[event.actor_id] = incident
        return incident
