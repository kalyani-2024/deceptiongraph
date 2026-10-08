"""Abstract Factory over families of deception assets.

    DeceptionFactory
          |
          +--- CredentialDecoyFactory   fake secrets that unlock nothing
          +--- NetworkDecoyFactory      hosts and services that should not exist
          +--- DocumentDecoyFactory     files nobody has a reason to open

Each concrete factory builds a *matched set* - lure, sensor and marker that
belong together. Callers ask for a family, never for the individual parts, so
a credential lure can never end up paired with a file-access sensor.

Decoys imitate something real where they can. A fake credential on the app
server that claims to unlock the production database is believable precisely
because that relationship exists; the same file on a backup box is not.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from itertools import count

from ..domain.entities import Host
from .assets import DeceptionAsset, DeceptionKind, Lure, Marker, Sensor


class DeceptionFactory(ABC):
    """Abstract factory: creates one coherent family of deception assets."""

    kind: DeceptionKind
    base_believability: float = 0.5
    sensor_fidelity: float = 0.9
    false_alert_rate: float = 0.05
    """Expected benign alerts per day from one sensor of this family."""

    def __init__(self) -> None:
        self._serial = count(1)

    # -- family members ----------------------------------------------------

    @abstractmethod
    def create_lure(self, host: Host, mimics: Host | None = None) -> Lure: ...

    @abstractmethod
    def create_sensor(self, lure: Lure) -> Sensor: ...

    def create_marker(self, lure: Lure) -> Marker:
        return Marker(
            id=f"{lure.id}:marker",
            kind=self.kind,
            lure_id=lure.id,
            token=Marker.mint(self.kind.value.lower()),
        )

    # -- assembly ----------------------------------------------------------

    def create(self, host: Host, mimics: Host | None = None, rationale: str = "") -> DeceptionAsset:
        """Build a complete asset. This is the only method callers need."""
        lure = self.create_lure(host, mimics)
        sensor = self.create_sensor(lure)
        marker = self.create_marker(lure)
        return DeceptionAsset(
            id=lure.id,
            kind=self.kind,
            host_id=host.id,
            lure=lure,
            sensor=sensor,
            marker=marker,
            rationale=rationale,
        )

    # -- helpers shared by the concrete factories --------------------------

    def _next_id(self, host: Host) -> str:
        return f"decoy:{self.kind.value.lower()}:{host.id}:{next(self._serial)}"

    def _believability(self, host: Host, mimics: Host | None) -> float:
        """A decoy that imitates a real, valuable neighbour is more convincing."""
        score = self.base_believability
        if mimics is not None:
            score += 0.25 * mimics.criticality
            if mimics.is_crown_jewel:
                score += 0.05
        return min(1.0, round(score, 6))


class CredentialDecoyFactory(DeceptionFactory):
    """Fake secrets: passwords, tokens and keys that grant access to nothing."""

    kind = DeceptionKind.CREDENTIAL
    base_believability = 0.6
    sensor_fidelity = 0.95
    false_alert_rate = 0.05
    """Inventory and secret-scanning agents occasionally read credential stores."""

    def create_lure(self, host: Host, mimics: Host | None = None) -> Lure:
        target = _slug(mimics.name) if mimics else "prod"
        username = f"svc_{target}_backup"
        return Lure(
            id=self._next_id(host),
            kind=self.kind,
            name=f"fake_{target}_password.txt",
            host_id=host.id,
            believability=self._believability(host, mimics),
            mimics=mimics.id if mimics else None,
            payload={
                "username": username,
                "secret": "REDACTED-DECOY",
                "note": f"service account for {mimics.name if mimics else 'production'}",
                "path": _credential_path(host, target),
            },
        )

    def create_sensor(self, lure: Lure) -> Sensor:
        return Sensor(
            id=f"{lure.id}:sensor",
            kind=self.kind,
            lure_id=lure.id,
            watches=f"authentication attempt as {lure.payload['username']}, or read of {lure.name}",
            fidelity=self.sensor_fidelity,
            false_alert_rate=self.false_alert_rate,
        )


class NetworkDecoyFactory(DeceptionFactory):
    """Decoy hosts and services: machines that exist only to be scanned."""

    kind = DeceptionKind.NETWORK
    base_believability = 0.5
    sensor_fidelity = 0.98
    false_alert_rate = 0.01
    """The cleanest signal of the three: almost nothing legitimate connects."""

    def create_lure(self, host: Host, mimics: Host | None = None) -> Lure:
        if mimics is not None:
            name = f"{mimics.id}-replica"
            service = mimics.services[0].name if mimics.services else "ssh"
            port = mimics.services[0].port if mimics.services else 22
        else:
            name = f"{host.id}-standby"
            service, port = "ssh", 22
        return Lure(
            id=self._next_id(host),
            kind=self.kind,
            name=name,
            host_id=host.id,
            believability=self._believability(host, mimics),
            mimics=mimics.id if mimics else None,
            payload={
                "hostname": name,
                "service": service,
                "port": port,
                "banner": f"{service} (decoy)",
                "placed_beside": host.id,
            },
        )

    def create_sensor(self, lure: Lure) -> Sensor:
        return Sensor(
            id=f"{lure.id}:sensor",
            kind=self.kind,
            lure_id=lure.id,
            watches=f"any connection to {lure.payload['hostname']}:{lure.payload['port']}",
            fidelity=self.sensor_fidelity,
            false_alert_rate=self.false_alert_rate,
        )


class DocumentDecoyFactory(DeceptionFactory):
    """Honeyfiles: documents that look like the thing worth stealing."""

    kind = DeceptionKind.DOCUMENT
    base_believability = 0.45
    sensor_fidelity = 0.85
    false_alert_rate = 0.20
    """Backup and indexing jobs crawl file shares, so honeyfiles are noisiest."""

    def create_lure(self, host: Host, mimics: Host | None = None) -> Lure:
        subject = _slug(mimics.name) if mimics else _slug(host.name)
        return Lure(
            id=self._next_id(host),
            kind=self.kind,
            name=f"{subject}_credentials_backup.xlsx",
            host_id=host.id,
            believability=self._believability(host, mimics),
            mimics=mimics.id if mimics else None,
            payload={
                "path": f"/srv/backups/{subject}_credentials_backup.xlsx",
                "summary": f"connection strings and recovery keys for {mimics.name if mimics else host.name}",
                "size_kb": 48,
            },
        )

    def create_sensor(self, lure: Lure) -> Sensor:
        return Sensor(
            id=f"{lure.id}:sensor",
            kind=self.kind,
            lure_id=lure.id,
            watches=f"open, copy or exfiltration of {lure.payload['path']}",
            fidelity=self.sensor_fidelity,
            false_alert_rate=self.false_alert_rate,
        )


FACTORIES: dict[DeceptionKind, type[DeceptionFactory]] = {
    DeceptionKind.CREDENTIAL: CredentialDecoyFactory,
    DeceptionKind.NETWORK: NetworkDecoyFactory,
    DeceptionKind.DOCUMENT: DocumentDecoyFactory,
}


def factory_for(kind: DeceptionKind) -> DeceptionFactory:
    """Instantiate the factory for a family."""
    try:
        return FACTORIES[kind]()
    except KeyError as exc:
        allowed = ", ".join(k.value for k in FACTORIES)
        raise ValueError(f"unknown deception kind {kind!r} (expected one of: {allowed})") from exc


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "asset"


def _credential_path(host: Host, target: str) -> str:
    if "windows" in host.os.lower():
        return f"C:\\\\ProgramData\\\\{target}\\\\credentials.txt"
    return f"/etc/{target}/credentials.txt"
