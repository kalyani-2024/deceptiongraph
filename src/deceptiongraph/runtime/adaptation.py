"""Adaptation: moving the deception once you know who is in the building.

The standing deployment is built against a *hypothetical* attacker - the most
dangerous path from the internet. Once a decoy fires, the attacker stops being
hypothetical: you know where they are, what they want, and what they are
capable of. The deployment should change to match.

Three things drive a re-plan, all read off the profile:

* **Where they are now.** Decoys go one hop *ahead* of them, on the moves the
  path predictor says they are most likely to make next. A decoy behind the
  attacker is wasted.
* **What stage they are in.** The state object's posture sets the extra budget
  and the preferred kinds - honeyfiles at collection, decoy hosts at discovery.
* **Burned assets.** A decoy they already touched has told you everything it
  will ever tell you, and a sophisticated actor now knows that host is
  monitored. It is retired rather than counted as live coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..deception.assets import DeceptionAsset, DeceptionKind, DeceptionState
from ..deception.engine import DeceptionEngine
from ..deception.placement import Placement, suggest_kind
from ..graph.repository import GraphRepository
from .events import Event, EventType
from .profiler import AttackerProfile


@dataclass(slots=True)
class Adaptation:
    """One re-planning decision and its justification."""

    actor_id: str
    stage: str
    reason: str
    added: tuple[DeceptionAsset, ...] = ()
    burned: tuple[str, ...] = ()
    targeted_hosts: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.added or self.burned)

    def describe(self) -> str:
        if not self.changed:
            return f"no change ({self.reason})"
        parts = []
        if self.added:
            parts.append(f"+{len(self.added)} decoys on {', '.join(self.targeted_hosts)}")
        if self.burned:
            parts.append(f"retired {len(self.burned)} burned")
        return "; ".join(parts)

    def as_dict(self) -> dict:
        return {
            "actor_id": self.actor_id,
            "stage": self.stage,
            "reason": self.reason,
            "changed": self.changed,
            "added": [a.as_dict() for a in self.added],
            "burned": list(self.burned),
            "targeted_hosts": list(self.targeted_hosts),
        }


class AdaptationEngine:
    """Observer that retires burned decoys and places new ones ahead of the actor."""

    name = "adaptation-engine"

    def __init__(
        self,
        repository: GraphRepository,
        deception: DeceptionEngine,
        live_assets: list[DeceptionAsset] | None = None,
        max_total: int = 12,
    ) -> None:
        self.repository = repository
        self.deception = deception
        self.live: list[DeceptionAsset] = list(live_assets or [])
        self.max_total = max_total
        """Ceiling on live decoys. Deception has a cost; it is not free to spam."""
        self.history: list[Adaptation] = []

    # -- Observer role -----------------------------------------------------

    def on_event(self, event: Event) -> None:
        """Mark a touched decoy as burned. Re-planning is the mediator's call.

        The engine deliberately does *not* adapt on every event: that would let
        a noisy decoy drive a dozen re-plans a second. The mediator decides when
        a re-plan is warranted, after the profiler has updated.
        """
        if event.type not in (
            EventType.DECOY_TOUCHED,
            EventType.DECOY_AUTHENTICATED,
            EventType.EXFIL_OBSERVED,
        ):
            return
        for asset in self.live:
            if asset.id == event.asset_id or (
                event.token is not None and asset.marker.token == event.token
            ):
                asset.state = DeceptionState.BURNED

    # -- mediator-driven re-planning ---------------------------------------

    def adapt(self, profile: AttackerProfile) -> Adaptation:
        """Re-place deception for what is now known about this actor."""
        posture = profile.posture
        burned = tuple(a.id for a in self.live if a.state is DeceptionState.BURNED)
        self._retire(burned)

        budget = self._budget(posture.budget_delta)
        if budget <= 0:
            return self._record(
                Adaptation(
                    actor_id=profile.actor_id,
                    stage=profile.stage.value,
                    reason=f"at the {self.max_total}-decoy ceiling; retired {len(burned)}",
                    burned=burned,
                )
            )

        # A burned decoy leaves a hole exactly where deception was working.
        # The actor who tripped it knows that host is watched, but the *next*
        # actor does not - so re-seed it with a different family rather than
        # abandoning the position.
        reseeded = self._reseed(burned, profile)

        targets = self._targets(profile, budget)
        if not targets:
            return self._record(
                Adaptation(
                    actor_id=profile.actor_id,
                    stage=profile.stage.value,
                    reason=(
                        "re-seeded burned positions; nowhere new ahead of this actor"
                        if reseeded
                        else "nowhere new to place a decoy ahead of this actor"
                    ),
                    added=reseeded,
                    burned=burned,
                    targeted_hosts=tuple(a.host_id for a in reseeded),
                )
            )

        added = reseeded + tuple(
            self._build(host_id, posture.preferred_kinds, profile) for host_id in targets
        )
        self.live.extend(a for a in added if a not in reseeded)
        return self._record(
            Adaptation(
                actor_id=profile.actor_id,
                stage=profile.stage.value,
                reason=posture.note,
                added=added,
                burned=burned,
                targeted_hosts=tuple(a.host_id for a in reseeded) + tuple(targets),
            )
        )

    # -- queries -----------------------------------------------------------

    @property
    def active(self) -> tuple[DeceptionAsset, ...]:
        return tuple(
            a for a in self.live if a.state in (DeceptionState.DEPLOYED, DeceptionState.STAGED)
        )

    def coverage(self):
        """Score the *current* live set, after adaptation."""
        return self.deception.evaluate(self.active, strategy_name="adaptive")

    # -- internals ---------------------------------------------------------

    def _budget(self, delta: int) -> int:
        headroom = self.max_total - len(self.active)
        return max(0, min(delta, headroom))

    def _retire(self, burned: tuple[str, ...]) -> None:
        for asset in self.live:
            if asset.id in burned:
                asset.state = DeceptionState.RETIRED

    def _reseed(
        self, burned: tuple[str, ...], profile: AttackerProfile
    ) -> tuple[DeceptionAsset, ...]:
        """Replace each retired decoy on its own host with a different family.

        Capped by the ceiling like any other placement, and skipped where the
        host already has something live.
        """
        retired_hosts: list[tuple[str, DeceptionKind]] = []
        for asset in self.live:
            if asset.id in burned:
                retired_hosts.append((asset.host_id, asset.kind))

        occupied = {a.host_id for a in self.active}
        fresh: list[DeceptionAsset] = []
        for host_id, previous_kind in retired_hosts:
            if host_id in occupied or len(self.active) + len(fresh) >= self.max_total:
                continue
            kind = self._rotate(host_id, previous_kind)
            asset = self._build(host_id, (kind,), profile)
            fresh.append(asset)
            occupied.add(host_id)
        self.live.extend(fresh)
        self._prune()
        return tuple(fresh)

    def _rotate(self, host_id: str, previous: DeceptionKind) -> DeceptionKind:
        """Pick a different family than the one that was burned."""
        host = self.repository.host(host_id)
        order = [DeceptionKind.NETWORK, DeceptionKind.DOCUMENT, DeceptionKind.CREDENTIAL]
        for kind in order:
            if kind is previous:
                continue
            if kind is DeceptionKind.CREDENTIAL and host is not None and not host.credentials:
                continue
            return kind
        return previous

    def _prune(self, keep_retired: int = 50) -> None:
        """Bound the retired tail, so a long-running defence does not grow forever."""
        retired = [a for a in self.live if a.state is DeceptionState.RETIRED]
        if len(retired) <= keep_retired:
            return
        drop = {id(a) for a in retired[: len(retired) - keep_retired]}
        self.live = [a for a in self.live if id(a) not in drop]

    def _targets(self, profile: AttackerProfile, budget: int) -> tuple[str, ...]:
        """Hosts to cover: the actor's predicted next moves, then the objective.

        Hosts already carrying a live decoy are skipped, as is anywhere the
        actor has already been - deception there cannot catch them any earlier.
        """
        occupied = {a.host_id for a in self.active}
        behind = set(profile.hosts_seen)
        chosen: list[str] = []

        current = profile.current_host
        if current and current in self.repository.model.hosts:
            try:
                hops = self.deception.context.predictor.next_hops(
                    current, visited=profile.hosts_seen
                )
            except KeyError:
                hops = ()
            for hop in hops:
                if hop.target not in occupied and hop.target not in behind:
                    chosen.append(hop.target)
                if len(chosen) >= budget:
                    return tuple(chosen)

        for candidate in (profile.likely_next_target, profile.objective):
            if (
                candidate
                and candidate in self.repository.model.hosts
                and candidate not in occupied
                and candidate not in behind
                and candidate not in chosen
            ):
                chosen.append(candidate)
                if len(chosen) >= budget:
                    break

        return tuple(chosen[:budget])

    def _build(
        self, host_id: str, preferred: tuple[DeceptionKind, ...], profile: AttackerProfile
    ) -> DeceptionAsset:
        """Build one decoy, honouring the state's preferred family where sensible."""
        context = self.deception.context
        kind = preferred[0] if preferred else suggest_kind(host_id, context)

        # A credential decoy only makes sense somewhere credentials would live.
        host = self.repository.host(host_id)
        if kind is DeceptionKind.CREDENTIAL and host is not None and not host.credentials:
            kind = suggest_kind(host_id, context)

        mimics = profile.objective or profile.likely_next_target
        placement = Placement(
            host_id=host_id,
            kind=kind,
            score=profile.posture.urgency,
            rationale=(
                f"adaptive: actor {profile.actor_id} at {profile.stage.value}, "
                f"placed ahead of their predicted move"
            ),
            mimics=mimics if mimics != host_id else None,
        )
        asset = self.deception.build_asset(placement)
        asset.deploy()
        return asset

    def _record(self, adaptation: Adaptation) -> Adaptation:
        self.history.append(adaptation)
        return adaptation
