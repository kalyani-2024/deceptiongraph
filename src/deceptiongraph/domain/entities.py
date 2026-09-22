"""Core asset entities.

These are plain dataclasses rather than ORM/OGM objects on purpose: the graph
repository (``deceptiongraph.graph.repository``) is what knows about storage, so
the domain stays usable with the in-memory backend today and Neo4j later.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .enums import Exposure, NodeType, Privilege


@dataclass(frozen=True, slots=True)
class Vulnerability:
    """A CVE (or unnamed weakness) affecting a service."""

    cve_id: str
    cvss: float = 5.0
    exploitability: float = 0.5
    privilege_gained: Privilege = Privilege.USER
    description: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.cvss <= 10.0:
            raise ValueError(f"{self.cve_id}: cvss must be in [0, 10], got {self.cvss}")
        if not 0.0 <= self.exploitability <= 1.0:
            raise ValueError(
                f"{self.cve_id}: exploitability must be in [0, 1], got {self.exploitability}"
            )

    @property
    def node_type(self) -> NodeType:
        return NodeType.VULNERABILITY

    @property
    def severity_weight(self) -> float:
        """CVSS normalised to [0, 1]."""
        return self.cvss / 10.0

    @property
    def exploit_probability(self) -> float:
        """Chance a capable attacker turns this weakness into access."""
        return self.severity_weight * self.exploitability


@dataclass(frozen=True, slots=True)
class Service:
    """A listening service on a host."""

    id: str
    name: str
    port: int
    protocol: str = "tcp"
    version: str = ""
    vulnerabilities: tuple[Vulnerability, ...] = ()

    @property
    def node_type(self) -> NodeType:
        return NodeType.SERVICE

    @property
    def exploit_probability(self) -> float:
        """Probability at least one of this service's weaknesses is exploited."""
        return _noisy_or(v.exploit_probability for v in self.vulnerabilities)

    @property
    def max_privilege_gained(self) -> Privilege:
        if not self.vulnerabilities:
            return Privilege.NONE
        return max((v.privilege_gained for v in self.vulnerabilities), key=lambda p: p.level)


@dataclass(frozen=True, slots=True)
class Credential:
    """A secret stored on one host that unlocks others."""

    id: str
    username: str
    kind: str = "password"
    privilege: Privilege = Privilege.USER
    grants_access: tuple[str, ...] = ()
    strength: float = 0.5
    """0 = trivially recoverable/reusable, 1 = hardened (MFA, vaulted, rotated)."""

    def __post_init__(self) -> None:
        if not 0.0 <= self.strength <= 1.0:
            raise ValueError(f"{self.id}: strength must be in [0, 1], got {self.strength}")

    @property
    def node_type(self) -> NodeType:
        return NodeType.CREDENTIAL

    @property
    def reuse_probability(self) -> float:
        """Chance an attacker on the storing host can replay this credential."""
        return 1.0 - self.strength


@dataclass(frozen=True, slots=True)
class User:
    """A human or service principal that logs into hosts."""

    id: str
    username: str
    role: str = "employee"
    privilege: Privilege = Privilege.USER
    logs_into: tuple[str, ...] = ()

    @property
    def node_type(self) -> NodeType:
        return NodeType.USER


@dataclass(slots=True)
class Host:
    """A machine: the leaf of the infrastructure composite."""

    id: str
    name: str
    ip: str = ""
    os: str = "unknown"
    exposure: Exposure = Exposure.INTERNAL
    criticality: float = 0.5
    """Business value of the asset. Crown jewels sit near 1.0."""
    is_crown_jewel: bool = False
    patch_level: float = 0.5
    """0 = unpatched, 1 = fully hardened. Dampens vulnerability exploitability."""
    services: list[Service] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, value in (("criticality", self.criticality), ("patch_level", self.patch_level)):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{self.id}: {name} must be in [0, 1], got {value}")

    @property
    def node_type(self) -> NodeType:
        return NodeType.HOST

    @property
    def vulnerabilities(self) -> tuple[Vulnerability, ...]:
        return tuple(v for s in self.services for v in s.vulnerabilities)

    @property
    def attack_surface(self) -> float:
        """Probability this host falls to a direct network exploit, in [0, 1].

        Noisy-OR across services, damped by how well the host is patched.
        """
        raw = _noisy_or(s.exploit_probability for s in self.services)
        return raw * (1.0 - 0.7 * self.patch_level)

    @property
    def max_privilege_gained(self) -> Privilege:
        if not self.services:
            return Privilege.NONE
        return max((s.max_privilege_gained for s in self.services), key=lambda p: p.level)

    def service_by_id(self, service_id: str) -> Service | None:
        return next((s for s in self.services if s.id == service_id), None)


def _noisy_or(probabilities) -> float:
    """Probability that at least one independent event occurs."""
    miss = 1.0
    for p in probabilities:
        miss *= 1.0 - max(0.0, min(1.0, p))
    return 1.0 - miss
