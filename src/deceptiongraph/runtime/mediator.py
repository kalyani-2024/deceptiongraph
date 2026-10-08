"""Mediator over the defensive subsystems.

Without a mediator the dependencies go everywhere: the profiler needs to tell
the adaptation engine to re-plan, the adaptation engine needs the risk engine
to rescore, the incident manager needs the profile to set severity, and every
one of them ends up holding a reference to the others.

    SecurityMediator
        |
        +-- EventBus          (Observer fan-out)
        +-- ThreatProfiler    "who is this, and how far have they got?"
        +-- IncidentManager   "what does a human need to see?"
        +-- AdaptationEngine  "where should the decoys be now?"
        +-- RiskEngine        "what does this do to the numbers?"

The split with the Observer pattern is deliberate and worth being precise
about. The **bus** delivers each event to everyone who cares, with no ordering
guarantees and no knowledge of what they do with it. The **mediator** owns the
workflow that must happen *in order* after an event lands: profile first,
because everything else keys off the stage; then adaptation, because it needs
the fresh profile to know where "ahead" is; then the incident, so the severity
reflects both. Observers stay ignorant of each other; the sequence lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..analysis.risk import NetworkRisk, RiskEngine
from ..deception.assets import DeceptionAsset
from ..deception.engine import DeceptionEngine, Deployment
from ..graph.repository import GraphRepository
from .adaptation import Adaptation, AdaptationEngine
from .events import Event, EventBus, EventType
from .incidents import Incident, IncidentManager, Severity
from .profiler import AttackerProfile, ThreatProfiler
from .states import AttackerStage


@dataclass(slots=True)
class Reaction:
    """Everything the system did about one event."""

    event: Event
    profile: AttackerProfile | None = None
    incident: Incident | None = None
    adaptation: Adaptation | None = None
    stage_changed: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return self.event.is_deception_trigger

    def describe(self) -> str:
        lines = [self.event.describe()]
        if self.triggered:
            lines.append("DECEPTION TRIGGERED")
        if self.profile is not None:
            lines.append(f"Attacker stage: {self.profile.stage.value}")
            lines.append(f"Sophistication: {self.profile.sophistication.value}")
            if self.profile.objective:
                lines.append(f"Objective: {self.profile.objective}")
            if self.profile.likely_next_target:
                lines.append(f"Likely next target: {self.profile.likely_next_target}")
        if self.incident is not None:
            lines.append(f"Incident {self.incident.id} [{self.incident.severity.value}]")
        if self.adaptation is not None and self.adaptation.changed:
            lines.append(f"Adapted: {self.adaptation.describe()}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "event": self.event.as_dict(),
            "triggered": self.triggered,
            "stage_changed": self.stage_changed,
            "profile": self.profile.as_dict() if self.profile else None,
            "incident": self.incident.as_dict() if self.incident else None,
            "adaptation": self.adaptation.as_dict() if self.adaptation else None,
            "notes": list(self.notes),
        }


class RiskRecalculator:
    """Observer that rescores the network when the picture changes.

    Scoring the whole network on every event would be wasteful, so this just
    marks the cached score stale and recomputes on demand.
    """

    name = "risk-recalculator"

    def __init__(self, risk: RiskEngine) -> None:
        self.risk = risk
        self._cached: NetworkRisk | None = None
        self._stale = True
        self.recalculations = 0

    def on_event(self, event: Event) -> None:
        if event.is_deception_trigger or event.type is EventType.HOST_COMPROMISED:
            self._stale = True

    def current(self) -> NetworkRisk:
        if self._stale or self._cached is None:
            self._cached = self.risk.network_risk()
            self.recalculations += 1
            self._stale = False
        return self._cached


class SecurityMediator:
    """Colleague channel: subsystems talk to this, never to each other."""

    def __init__(
        self,
        repository: GraphRepository,
        deception: DeceptionEngine | None = None,
        deployment: Deployment | None = None,
        bus: EventBus | None = None,
        adapt_on_trigger: bool = True,
        max_total_decoys: int = 12,
    ) -> None:
        self.repository = repository
        self.bus = bus or EventBus()
        self.deception = deception or DeceptionEngine(repository)
        self.adapt_on_trigger = adapt_on_trigger

        live = list(deployment.assets) if deployment else []
        self.profiler = ThreatProfiler(
            repository,
            predictor=self.deception.context.predictor,
            on_state_change=self._on_state_change,
        )
        self.incidents = IncidentManager()
        self.adaptation = AdaptationEngine(
            repository, self.deception, live_assets=live, max_total=max_total_decoys
        )
        self.risk = RiskRecalculator(self.deception.context.risk)

        # Observer registration. Order here does not imply ordering of the
        # workflow - that is handled explicitly in `handle`.
        for observer in (self.profiler, self.incidents, self.adaptation, self.risk):
            self.bus.subscribe(observer)

        self._stage_changes: list[tuple[str, AttackerStage, AttackerStage]] = []
        self.reactions: list[Reaction] = []

    # -- the one entry point -----------------------------------------------

    def handle(self, event: Event) -> Reaction:
        """Publish an event and run the coordinated response."""
        self._stage_changes.clear()
        self.bus.publish(event)

        reaction = Reaction(event=event)
        reaction.stage_changed = bool(self._stage_changes)

        profile = self.profiler.profile(event.actor_id)
        if profile is None:
            reaction.notes.append("event carried no attacker signal")
            self.reactions.append(reaction)
            return reaction
        reaction.profile = profile

        # Adaptation needs the fresh profile; the incident needs both.
        if self.adapt_on_trigger and self._should_adapt(event, reaction.stage_changed):
            reaction.adaptation = self.adaptation.adapt(profile)
            if reaction.adaptation.changed:
                self.bus.publish(
                    Event(
                        type=EventType.DECEPTION_ADAPTED,
                        actor_id=event.actor_id,
                        detail=reaction.adaptation.describe(),
                        metadata={"stage": profile.stage.value},
                    )
                )

        reaction.incident = self.incidents.apply_profile(profile)
        if reaction.incident is not None:
            self.bus.publish(
                Event(
                    type=EventType.ALERT_RAISED,
                    actor_id=event.actor_id,
                    host_id=event.host_id,
                    detail=f"{reaction.incident.id} {reaction.incident.severity.value}",
                )
            )

        self.reactions.append(reaction)
        return reaction

    def emit(self, type: EventType, **kwargs) -> Reaction:
        """Build an event and handle it."""
        return self.handle(Event(type=type, **kwargs))

    # -- queries -----------------------------------------------------------

    @property
    def live_assets(self) -> tuple[DeceptionAsset, ...]:
        return self.adaptation.active

    def status(self) -> dict:
        """A single snapshot of the defensive posture."""
        worst = self.incidents.worst()
        profile = self.profiler.most_advanced()
        coverage = self.adaptation.coverage()
        return {
            "network": self.repository.model.name,
            "events_seen": len(self.bus.history),
            "triggers": len(self.bus.triggers()),
            "live_decoys": len(self.live_assets),
            "burned_decoys": len(self.adaptation.live) - len(self.live_assets),
            "adaptations": sum(1 for a in self.adaptation.history if a.changed),
            "network_risk": round(self.risk.current().score, 4),
            "coverage": coverage.as_dict(),
            "worst_incident": worst.as_dict() if worst else None,
            "most_advanced_actor": profile.as_dict() if profile else None,
            "open_incidents": [i.as_dict() for i in self.incidents.open_incidents],
        }

    def timeline(self) -> tuple[dict, ...]:
        return tuple(e.as_dict() for e in self.bus.history)

    # -- internals ---------------------------------------------------------

    def _on_state_change(
        self, actor_id: str, previous: AttackerStage, current: AttackerStage
    ) -> None:
        """Profiler callback. Recorded, then re-published for anyone listening."""
        self._stage_changes.append((actor_id, previous, current))

    def _should_adapt(self, event: Event, stage_changed: bool) -> bool:
        """Re-plan on a real trigger, or whenever the actor's stage moved.

        Not on every event: a chatty sensor must not be able to drive a
        re-plan per packet.
        """
        return event.is_deception_trigger or stage_changed


__all__ = ["Reaction", "RiskRecalculator", "SecurityMediator", "Severity"]
