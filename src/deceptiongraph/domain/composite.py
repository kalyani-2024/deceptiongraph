"""Composite pattern over enterprise infrastructure.

    Organisation
     |- Department
          |- Subnet
               |- Host

``calculate_risk()`` answers the same question at every level, so a caller can
ask a single host or the whole organisation without branching.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator

from .entities import Host
from .enums import NodeType


@dataclass(slots=True)
class RiskScore:
    """Result of a risk calculation, carrying its own explanation."""

    component_id: str
    component_type: NodeType
    value: float
    breakdown: dict[str, float] = field(default_factory=dict)
    children: list["RiskScore"] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "component_id": self.component_id,
            "component_type": self.component_type.value,
            "value": round(self.value, 4),
            "breakdown": {k: round(v, 4) for k, v in self.breakdown.items()},
            "children": [c.as_dict() for c in self.children],
        }


class InfrastructureComponent(ABC):
    """Component role of the Composite pattern."""

    id: str
    name: str

    @property
    @abstractmethod
    def node_type(self) -> NodeType: ...

    @abstractmethod
    def calculate_risk(self) -> RiskScore:
        """Intrinsic risk of this component, ignoring attack paths."""

    @abstractmethod
    def hosts(self) -> Iterator[Host]:
        """Every host at or below this component."""

    def walk(self) -> Iterator["InfrastructureComponent"]:
        yield self


class HostComponent(InfrastructureComponent):
    """Leaf role. Wraps a :class:`Host` so it can sit in the tree."""

    def __init__(self, host: Host) -> None:
        self.host = host
        self.id = host.id
        self.name = host.name

    @property
    def node_type(self) -> NodeType:
        return NodeType.HOST

    def calculate_risk(self) -> RiskScore:
        surface = self.host.attack_surface
        criticality = self.host.criticality
        credential_exposure = _max_or_zero(c.reuse_probability for c in self.host.credentials)

        # Likelihood-weighted impact, nudged up when the host also hoards secrets
        # that unlock other machines.
        value = surface * (0.6 + 0.4 * criticality)
        value = value + (1.0 - value) * 0.25 * credential_exposure
        if self.host.is_crown_jewel:
            value = min(1.0, value * 1.15)

        return RiskScore(
            component_id=self.id,
            component_type=NodeType.HOST,
            value=round(min(1.0, value), 6),
            breakdown={
                "attack_surface": surface,
                "criticality": criticality,
                "credential_exposure": credential_exposure,
                "patch_level": self.host.patch_level,
            },
        )

    def hosts(self) -> Iterator[Host]:
        yield self.host

    def __repr__(self) -> str:
        return f"HostComponent({self.id!r})"


class CompositeComponent(InfrastructureComponent):
    """Composite role: an organisation, department or subnet."""

    def __init__(self, id: str, name: str, node_type: NodeType) -> None:
        self.id = id
        self.name = name
        self._node_type = node_type
        self._children: list[InfrastructureComponent] = []

    @property
    def node_type(self) -> NodeType:
        return self._node_type

    @property
    def children(self) -> tuple[InfrastructureComponent, ...]:
        return tuple(self._children)

    def add(self, child: InfrastructureComponent) -> "CompositeComponent":
        self._children.append(child)
        return self

    def remove(self, child_id: str) -> None:
        self._children = [c for c in self._children if c.id != child_id]

    def find(self, component_id: str) -> InfrastructureComponent | None:
        for component in self.walk():
            if component.id == component_id:
                return component
        return None

    def calculate_risk(self) -> RiskScore:
        child_scores = [c.calculate_risk() for c in self._children]
        if not child_scores:
            return RiskScore(self.id, self.node_type, 0.0)

        values = [s.value for s in child_scores]
        worst = max(values)
        mean = sum(values) / len(values)
        # A group is as weak as its weakest member, but a group where *everything*
        # is weak is worse still, so blend the worst case with the average.
        value = 0.7 * worst + 0.3 * mean

        return RiskScore(
            component_id=self.id,
            component_type=self.node_type,
            value=round(min(1.0, value), 6),
            breakdown={"worst_child": worst, "mean_child": mean, "child_count": len(values)},
            children=child_scores,
        )

    def hosts(self) -> Iterator[Host]:
        for child in self._children:
            yield from child.hosts()

    def walk(self) -> Iterator[InfrastructureComponent]:
        yield self
        for child in self._children:
            yield from child.walk()

    def __repr__(self) -> str:
        return f"CompositeComponent({self.id!r}, {self._node_type.value}, {len(self._children)} children)"


def _max_or_zero(values) -> float:
    collected = list(values)
    return max(collected) if collected else 0.0
