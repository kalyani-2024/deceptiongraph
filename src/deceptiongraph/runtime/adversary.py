"""Attacker models: how an intruder reacts to the decoys in front of them.

The original simulator's attacker is *naive*: on a host carrying decoys it is
caught with exactly the probability the decoys promise, never notices one, and
never learns. That makes every detection rate it produces an upper bound.
These models replace that bound with something closer to a real adversary.

``NaiveAdversary``
    The original behaviour, kept bit-for-bit (same random draws) so existing
    results reproduce.
``CautiousAdversary``
    Can *spot* a decoy instead of falling for it. The less believable the lure,
    the likelier it is spotted (``skill x (1 - believability)``). A spotted
    decoy fires no alert, and it makes the attacker warier: lures of that kind
    become less tempting for the rest of the campaign, and every other kind a
    little less tempting too.
``CautiousAdversary(learns=True)``
    The same, but the wariness carries over between campaigns, as it would for
    a group that keeps coming back. Being *caught* by a decoy also teaches it -
    the next campaign treats that kind of lure with suspicion. Run many
    campaigns against one deployment and detection decays: the curve
    :mod:`deceptiongraph.experiments.adversaries` measures.

Learned wariness saturates at ``max_wariness`` (0.7) rather than reaching 1:
an intruder who refused every credential and document it found would be
refusing the real ones too, and could no longer do the job it came for.

The numbers (skill 0.6, wariness gain 0.5, spill-over 0.25, learning rate
0.1, ceiling 0.7) are judgement calls like the rest of the model's probabilities, kept in
one place so the sensitivity analysis can vary them.
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field

from ..deception.assets import DeceptionAsset, DeceptionKind
from ..deception.coverage import detection_by_host

DEFAULT_SKILL = 0.6
"""How readily a cautious attacker spots an unconvincing lure. Read at
construction time, so the sensitivity analysis can vary it."""


@dataclass(slots=True)
class Encounter:
    """What happened when the attacker met the decoys on one host."""

    fired: DeceptionAsset | None = None
    """The decoy that caught them, if any."""
    spotted: list[DeceptionAsset] = field(default_factory=list)
    """Decoys they recognised as fake and stepped around."""


class Adversary(ABC):
    """Strategy role: decides whether the decoys on a host catch the attacker."""

    name = "abstract"

    def begin_campaign(self) -> None:
        """Called before each simulated intrusion."""

    @abstractmethod
    def encounter(self, decoys: list[DeceptionAsset], host_id: str,
                  rng: random.Random) -> Encounter:
        """The attacker arrives on ``host_id`` where ``decoys`` are live."""

    def end_campaign(self, caught_by: DeceptionAsset | None) -> None:
        """Called after each intrusion, with the decoy that caught them (if one did)."""

    def describe(self) -> dict:
        return {"adversary": self.name}


class NaiveAdversary(Adversary):
    """Never notices a decoy, never learns: the upper bound."""

    name = "naive"

    def encounter(self, decoys, host_id, rng) -> Encounter:
        combined = detection_by_host(decoys).get(host_id, 0.0)
        if rng.random() >= combined:
            return Encounter()
        weights = [a.detection_probability for a in decoys]
        if sum(weights) <= 0.0:
            return Encounter()
        return Encounter(fired=rng.choices(decoys, weights=weights, k=1)[0])


class CautiousAdversary(Adversary):
    """Spots unconvincing decoys, gets warier, and optionally learns across campaigns."""

    def __init__(
        self,
        skill: float | None = None,
        wariness_gain: float = 0.5,
        spillover: float = 0.25,
        learns: bool = False,
        learning_rate: float = 0.1,
        max_wariness: float = 0.7,
    ) -> None:
        skill = DEFAULT_SKILL if skill is None else skill
        for label, value in (("skill", skill), ("wariness_gain", wariness_gain),
                             ("spillover", spillover), ("max_wariness", max_wariness)):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{label} must be in [0, 1], got {value}")
        self.skill = skill
        self.wariness_gain = wariness_gain
        self.spillover = spillover
        self.learns = learns
        self.learning_rate = learning_rate
        self.max_wariness = max_wariness
        self.name = "learning" if learns else "cautious"
        self.wariness: dict[DeceptionKind, float] = {}
        """Per kind, 0-1: how much less likely they are to take a lure of it."""
        self.burned: Counter[DeceptionKind] = Counter()
        """Across campaigns: times a kind of decoy was spotted or caught them."""
        self.campaigns = 0
        self.spotted_total = 0

    # -- campaign lifecycle --------------------------------------------------

    def begin_campaign(self) -> None:
        self.campaigns += 1
        if self.learns:
            # Experience becomes a prior that saturates at the ceiling.
            self.wariness = {
                kind: self.max_wariness * (1.0 - math.exp(-self.learning_rate * count))
                for kind, count in self.burned.items()
            }
        else:
            self.wariness = {}

    def end_campaign(self, caught_by: DeceptionAsset | None) -> None:
        if caught_by is not None:
            self.burned[caught_by.kind] += 1

    # -- the encounter -------------------------------------------------------

    def encounter(self, decoys, host_id, rng) -> Encounter:
        result = Encounter()
        for decoy in decoys:
            wary = self.wariness.get(decoy.kind, 0.0)
            # Already suspicious attackers look harder.
            p_spot = min(1.0, self.skill * (1.0 - decoy.lure.believability) * (1.0 + wary))
            if rng.random() < p_spot:
                result.spotted.append(decoy)
                self._grow_wary(decoy.kind)
                continue
            p_take = decoy.lure.believability * (1.0 - wary)
            if rng.random() < p_take * decoy.sensor.fidelity:
                result.fired = decoy
                return result
        return result

    def _grow_wary(self, kind: DeceptionKind) -> None:
        self.spotted_total += 1
        self.burned[kind] += 1
        for other in DeceptionKind:
            gain = self.wariness_gain if other is kind else self.wariness_gain * self.spillover
            current = self.wariness.get(other, 0.0)
            grown = 1.0 - (1.0 - current) * (1.0 - gain)
            self.wariness[other] = min(self.max_wariness, grown)

    def describe(self) -> dict:
        return {
            "adversary": self.name, "skill": self.skill, "wariness_gain": self.wariness_gain,
            "spillover": self.spillover, "learns": self.learns,
            "learning_rate": self.learning_rate, "max_wariness": self.max_wariness,
            "campaigns": self.campaigns, "decoys_spotted": self.spotted_total,
            "wariness": {k.value: round(v, 4) for k, v in self.wariness.items()},
        }


ADVERSARIES = ("naive", "cautious", "learning")


def adversary_for(name: str, **kwargs) -> Adversary:
    key = name.lower()
    if key == "naive":
        return NaiveAdversary()
    if key == "cautious":
        return CautiousAdversary(learns=False, **kwargs)
    if key == "learning":
        return CautiousAdversary(learns=True, **kwargs)
    raise ValueError(f"unknown adversary {name!r} (expected one of: {', '.join(ADVERSARIES)})")
