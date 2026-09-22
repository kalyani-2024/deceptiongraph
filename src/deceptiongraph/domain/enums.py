"""Enumerations shared across the domain model."""

from __future__ import annotations

from enum import Enum


class NodeType(str, Enum):
    """Entity labels. Mirrors the Neo4j labels planned for stage 2."""

    HOST = "HOST"
    USER = "USER"
    SERVICE = "SERVICE"
    CREDENTIAL = "CREDENTIAL"
    VULNERABILITY = "VULNERABILITY"
    SUBNET = "SUBNET"
    DEPARTMENT = "DEPARTMENT"
    ORGANISATION = "ORGANISATION"


class RelationType(str, Enum):
    """Edge labels between entities."""

    CONNECTS_TO = "CONNECTS_TO"
    RUNS = "RUNS"
    LOGS_INTO = "LOGS_INTO"
    GRANTS_ACCESS = "GRANTS_ACCESS"
    HAS_VULNERABILITY = "HAS_VULNERABILITY"
    STORES = "STORES"
    CONTAINS = "CONTAINS"


class Privilege(str, Enum):
    """Privilege obtained on a host, ordered from lowest to highest."""

    NONE = "NONE"
    USER = "USER"
    SERVICE = "SERVICE"
    ADMIN = "ADMIN"
    ROOT = "ROOT"

    @property
    def level(self) -> int:
        return _PRIVILEGE_ORDER[self]

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Privilege):
            return NotImplemented
        return self.level < other.level

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Privilege):
            return NotImplemented
        return self.level <= other.level


_PRIVILEGE_ORDER = {
    Privilege.NONE: 0,
    Privilege.USER: 1,
    Privilege.SERVICE: 2,
    Privilege.ADMIN: 3,
    Privilege.ROOT: 4,
}


class Exposure(str, Enum):
    """Where a host sits relative to the network perimeter."""

    INTERNET = "INTERNET"
    DMZ = "DMZ"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"


class AttackVector(str, Enum):
    """How an attacker moved from one host to the next."""

    NETWORK_EXPLOIT = "NETWORK_EXPLOIT"
    CREDENTIAL_REUSE = "CREDENTIAL_REUSE"
    TRUSTED_SESSION = "TRUSTED_SESSION"
    PERIMETER_ENTRY = "PERIMETER_ENTRY"
