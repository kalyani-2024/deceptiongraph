"""The network model: everything asset discovery produced, before analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from ..domain.composite import CompositeComponent, HostComponent
from ..domain.entities import Host, User
from ..domain.enums import Exposure, NodeType

INTERNET = "INTERNET"
"""Synthetic source node representing an unauthenticated external attacker."""


@dataclass(frozen=True, slots=True)
class Connection:
    """A permitted network path between two hosts (or from the internet)."""

    source: str
    target: str
    protocol: str = "tcp"
    ports: tuple[int, ...] = ()
    filtered: float = 0.0
    """0 = wide open, 1 = blocked by a firewall/segmentation control."""

    def __post_init__(self) -> None:
        if not 0.0 <= self.filtered <= 1.0:
            raise ValueError(
                f"{self.source}->{self.target}: filtered must be in [0, 1], got {self.filtered}"
            )

    @property
    def traversal_probability(self) -> float:
        return 1.0 - self.filtered


@dataclass(slots=True)
class NetworkModel:
    """A discovered enterprise network."""

    name: str
    hosts: dict[str, Host] = field(default_factory=dict)
    users: dict[str, User] = field(default_factory=dict)
    connections: list[Connection] = field(default_factory=list)
    root: CompositeComponent | None = None

    def add_host(self, host: Host) -> None:
        if host.id in self.hosts:
            raise ValueError(f"duplicate host id: {host.id}")
        self.hosts[host.id] = host

    def add_user(self, user: User) -> None:
        if user.id in self.users:
            raise ValueError(f"duplicate user id: {user.id}")
        self.users[user.id] = user

    def add_connection(self, connection: Connection) -> None:
        for endpoint in (connection.source, connection.target):
            if endpoint != INTERNET and endpoint not in self.hosts:
                raise ValueError(f"connection references unknown host: {endpoint}")
        self.connections.append(connection)

    @property
    def crown_jewels(self) -> tuple[str, ...]:
        return tuple(h.id for h in self.hosts.values() if h.is_crown_jewel)

    @property
    def entry_points(self) -> tuple[str, ...]:
        """Hosts an external attacker can reach without a foothold."""
        from_internet = {c.target for c in self.connections if c.source == INTERNET}
        exposed = {h.id for h in self.hosts.values() if h.exposure is Exposure.INTERNET}
        return tuple(sorted(from_internet | exposed))

    def credentials_on(self, host_id: str) -> tuple:
        host = self.hosts.get(host_id)
        return tuple(host.credentials) if host else ()

    def users_of(self, host_id: str) -> Iterator[User]:
        for user in self.users.values():
            if host_id in user.logs_into:
                yield user

    def build_default_composite(self) -> CompositeComponent:
        """Group hosts into a two-level tree when the source gave no hierarchy."""
        root = CompositeComponent(self.name, self.name, NodeType.ORGANISATION)
        buckets: dict[str, CompositeComponent] = {}
        for host in self.hosts.values():
            key = host.exposure.value
            bucket = buckets.get(key)
            if bucket is None:
                bucket = CompositeComponent(f"subnet:{key.lower()}", key, NodeType.SUBNET)
                buckets[key] = bucket
                root.add(bucket)
            bucket.add(HostComponent(host))
        self.root = root
        return root

    def summary(self) -> dict:
        return {
            "name": self.name,
            "hosts": len(self.hosts),
            "users": len(self.users),
            "services": sum(len(h.services) for h in self.hosts.values()),
            "vulnerabilities": sum(len(h.vulnerabilities) for h in self.hosts.values()),
            "credentials": sum(len(h.credentials) for h in self.hosts.values()),
            "connections": len(self.connections),
            "crown_jewels": list(self.crown_jewels),
            "entry_points": list(self.entry_points),
        }
