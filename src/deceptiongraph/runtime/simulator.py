"""Simulated attacker.

Drives the adaptation loop, and is the measurement instrument for the stage 5
experiments. One run is a Monte Carlo walk of the attack graph:

1. Start at the source and pick the most attractive next move, as the path
   predictor scores it.
2. Roll against the hop's success probability. On failure, that target is
   written off for this campaign and the attacker tries the next-best move
   from where they are - a real intruder whose exploit bounces pivots rather
   than going home. After `max_failures` dead ends they give up.
3. On arrival, roll against each decoy on that host. Trip one and the run ends
   in detection; the event goes to the mediator, which may move the remaining
   decoys before the next step.
4. Stop on reaching the objective, on detection, on exhausting the retries, or
   at the step limit.

A deliberate simplification: the simulated attacker does not know which assets
are decoys, and does not get warier after tripping one. That makes these
numbers an *upper* bound on how well deception performs. A real adversary who
spots one honeyfile starts treating everything with suspicion, and modelling
that honestly needs adversary data this project does not have.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from ..deception.assets import DeceptionAsset, DeceptionState
from ..deception.coverage import detection_by_host
from ..graph.model import INTERNET
from ..graph.repository import GraphRepository
from .events import Event, EventType
from .mediator import Reaction, SecurityMediator


@dataclass(slots=True)
class SimulationStep:
    """One hop of one run."""

    index: int
    source: str
    target: str
    succeeded: bool
    detected: bool
    decoy_id: str | None = None
    reaction: Reaction | None = None

    @property
    def abandoned(self) -> bool:
        """A failed hop: this target was written off and another tried."""
        return not self.succeeded


@dataclass(slots=True)
class SimulationResult:
    """The outcome of one run."""

    actor_id: str
    detected: bool
    reached_objective: bool
    objective: str | None
    path: tuple[str, ...]
    steps: tuple[SimulationStep, ...] = ()
    detected_at: str | None = None
    hops_before_detection: int | None = None
    events: tuple[Event, ...] = ()
    failed_hops: int = 0
    """Exploits that bounced. High values mean the network resisted, not that
    the deception worked."""

    @property
    def hops(self) -> int:
        return len(self.path) - 1 if self.path else 0

    def describe(self) -> str:
        route = " -> ".join(self.path)
        if self.detected:
            return f"{route}  DETECTED at {self.detected_at} after {self.hops_before_detection} hops"
        if self.reached_objective:
            return f"{route}  REACHED {self.objective} undetected"
        if self.hops == 0:
            return f"{route}  never gained a foothold ({self.failed_hops} failed exploits)"
        return f"{route}  stalled undetected ({self.failed_hops} failed exploits)"

    def as_dict(self) -> dict:
        return {
            "actor_id": self.actor_id,
            "detected": self.detected,
            "reached_objective": self.reached_objective,
            "objective": self.objective,
            "path": list(self.path),
            "hops": self.hops,
            "detected_at": self.detected_at,
            "hops_before_detection": self.hops_before_detection,
            "failed_hops": self.failed_hops,
        }


class AttackSimulator:
    """Walks the attack graph against a set of decoys."""

    def __init__(
        self,
        repository: GraphRepository,
        mediator: SecurityMediator | None = None,
        assets: tuple[DeceptionAsset, ...] | list[DeceptionAsset] | None = None,
        seed: int | None = None,
        max_steps: int = 10,
        source: str = INTERNET,
        max_failures: int = 3,
    ) -> None:
        self.repository = repository
        self.mediator = mediator
        self._static_assets = list(assets or [])
        self.rng = random.Random(seed)
        self.max_steps = max_steps
        self.source = source
        self.max_failures = max_failures
        """How many bounced exploits before the attacker abandons the campaign."""

        if mediator is not None:
            self.predictor = mediator.deception.context.predictor
            self.attack = mediator.deception.context.attack
        else:
            from ..analysis.attack_graph import AttackGraphEngine
            from ..analysis.prediction import PathPredictor

            self.attack = AttackGraphEngine(repository)
            self.predictor = PathPredictor(repository, self.attack)

    # -- running -----------------------------------------------------------

    def run(self, actor_id: str = "actor-1") -> SimulationResult:
        """One run. Feeds the mediator as it goes, when there is one."""
        current = self.source
        path = [current]
        steps: list[SimulationStep] = []
        events: list[Event] = []
        objective = self.predictor.objective(current) if current != INTERNET else None
        if objective is None:
            jewels = self.repository.model.crown_jewels
            objective = jewels[0] if jewels else None

        failures = 0
        blocked: set[str] = set()

        for index in range(1, self.max_steps + 1):
            hop = self._choose(current, tuple(path) + tuple(blocked))
            if hop is None:
                break

            if self.rng.random() > hop.hop_probability:
                # The exploit bounced. Write this target off and try elsewhere
                # from the same foothold rather than ending the campaign.
                failures += 1
                blocked.add(hop.target)
                steps.append(
                    SimulationStep(index, current, hop.target, succeeded=False, detected=False)
                )
                if failures >= self.max_failures:
                    break
                continue

            current = hop.target
            path.append(current)
            host = self.repository.host(current)
            compromise = Event(
                type=EventType.HOST_COMPROMISED,
                host_id=current,
                actor_id=actor_id,
                detail=f"compromised via {hop.vector.value}",
                metadata={"is_crown_jewel": bool(host and host.is_crown_jewel)},
            )
            events.append(compromise)
            reaction = self._dispatch(compromise)

            decoy, trigger = self._roll_decoys(current, actor_id)
            if decoy is not None and trigger is not None:
                events.append(trigger)
                reaction = self._dispatch(trigger)
                steps.append(
                    SimulationStep(
                        index, path[-2], current, succeeded=True, detected=True,
                        decoy_id=decoy.id, reaction=reaction,
                    )
                )
                return SimulationResult(
                    actor_id=actor_id,
                    detected=True,
                    reached_objective=current == objective,
                    objective=objective,
                    path=tuple(path),
                    steps=tuple(steps),
                    detected_at=current,
                    hops_before_detection=len(path) - 1,
                    events=tuple(events),
                    failed_hops=failures,
                )

            steps.append(
                SimulationStep(index, path[-2], current, succeeded=True, detected=False,
                               reaction=reaction)
            )

            if objective is not None and current == objective:
                break

        return SimulationResult(
            actor_id=actor_id,
            detected=False,
            reached_objective=objective is not None and path[-1] == objective,
            objective=objective,
            path=tuple(path),
            steps=tuple(steps),
            events=tuple(events),
            failed_hops=failures,
        )

    def run_many(self, trials: int, actor_prefix: str = "actor") -> tuple[SimulationResult, ...]:
        """Independent runs. Each gets a fresh actor id so profiles do not merge."""
        if trials < 1:
            raise ValueError(f"trials must be at least 1, got {trials}")
        return tuple(self.run(actor_id=f"{actor_prefix}-{i + 1}") for i in range(trials))

    # -- internals ---------------------------------------------------------

    def _assets(self) -> tuple[DeceptionAsset, ...]:
        """Live decoys. Read from the mediator so adaptation takes effect mid-run."""
        if self.mediator is not None:
            return self.mediator.live_assets
        return tuple(
            a for a in self._static_assets if a.state is not DeceptionState.RETIRED
        )

    def _choose(self, current: str, visited: tuple[str, ...]):
        try:
            hops = self.predictor.next_hops(current, visited=visited)
        except KeyError:
            return None
        if not hops:
            return None
        # Weighted choice over the predicted distribution, rather than always
        # the top move: a real attacker is not perfectly greedy.
        weights = [h.probability for h in hops]
        return self.rng.choices(hops, weights=weights, k=1)[0]

    def _roll_decoys(self, host_id: str, actor_id: str):
        """Does a decoy on this host catch them?"""
        on_host = [a for a in self._assets() if a.host_id == host_id]
        if not on_host:
            return None, None

        combined = detection_by_host(on_host).get(host_id, 0.0)
        if self.rng.random() >= combined:
            return None, None

        # Which decoy fired: weighted by each one's own detection probability.
        weights = [a.detection_probability for a in on_host]
        if sum(weights) <= 0.0:
            return None, None
        decoy = self.rng.choices(on_host, weights=weights, k=1)[0]

        from ..deception.assets import DeceptionKind

        event_type = (
            EventType.DECOY_AUTHENTICATED
            if decoy.kind is DeceptionKind.CREDENTIAL
            else EventType.EXFIL_OBSERVED
            if decoy.kind is DeceptionKind.DOCUMENT and self.rng.random() < 0.3
            else EventType.DECOY_TOUCHED
        )
        host = self.repository.host(host_id)
        return decoy, Event(
            type=event_type,
            host_id=host_id,
            actor_id=actor_id,
            asset_id=decoy.id,
            token=decoy.marker.token,
            detail=f"attacker accessed {decoy.lure.name}",
            metadata={"is_crown_jewel": bool(host and host.is_crown_jewel)},
        )

    def _dispatch(self, event: Event) -> Reaction | None:
        return self.mediator.handle(event) if self.mediator is not None else None
