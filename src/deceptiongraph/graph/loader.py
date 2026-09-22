"""Asset discovery: read a network definition into a :class:`NetworkModel`.

Stage 1 discovers assets from a YAML inventory. The same ``AssetDiscovery``
interface is what a live scanner (nmap/CMDB import) plugs into later.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

import yaml

from ..domain.composite import CompositeComponent, HostComponent
from ..domain.entities import Credential, Host, Service, User, Vulnerability
from ..domain.enums import Exposure, NodeType, Privilege
from .model import Connection, NetworkModel


class AssetDiscovery(Protocol):
    """Anything that can produce a network model."""

    def discover(self) -> NetworkModel: ...


class YamlAssetDiscovery:
    """Loads an inventory file describing hosts, users, links and hierarchy."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def discover(self) -> NetworkModel:
        if not self.path.exists():
            raise FileNotFoundError(f"network definition not found: {self.path}")
        raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        return build_model(raw, default_name=self.path.stem)


def load_network(path: str | Path) -> NetworkModel:
    """Convenience wrapper around :class:`YamlAssetDiscovery`."""
    return YamlAssetDiscovery(path).discover()


def build_model(raw: dict[str, Any], default_name: str = "network") -> NetworkModel:
    """Validate and materialise a raw inventory mapping."""
    model = NetworkModel(name=str(raw.get("name") or default_name))

    for entry in raw.get("hosts") or []:
        model.add_host(_build_host(entry))

    for entry in raw.get("users") or []:
        model.add_user(_build_user(entry))

    for entry in raw.get("connections") or []:
        model.add_connection(_build_connection(entry))

    _validate_references(model)

    hierarchy = raw.get("hierarchy")
    if hierarchy:
        model.root = _build_hierarchy(hierarchy, model)
    else:
        model.build_default_composite()

    return model


# -- entity construction ---------------------------------------------------


def _build_host(entry: dict[str, Any]) -> Host:
    host_id = _require(entry, "id", "host")
    services = [_build_service(host_id, s) for s in entry.get("services") or []]
    credentials = [_build_credential(host_id, c) for c in entry.get("credentials") or []]
    return Host(
        id=host_id,
        name=str(entry.get("name") or host_id),
        ip=str(entry.get("ip") or ""),
        os=str(entry.get("os") or "unknown"),
        exposure=_enum(Exposure, entry.get("exposure"), Exposure.INTERNAL, host_id, "exposure"),
        criticality=float(entry.get("criticality", 0.5)),
        is_crown_jewel=bool(entry.get("crown_jewel", False)),
        patch_level=float(entry.get("patch_level", 0.5)),
        services=services,
        credentials=credentials,
        tags=tuple(str(t) for t in entry.get("tags") or ()),
    )


def _build_service(host_id: str, entry: dict[str, Any]) -> Service:
    name = _require(entry, "name", f"service on {host_id}")
    port = int(entry.get("port", 0))
    service_id = str(entry.get("id") or f"{host_id}:{name}:{port}")
    vulns = tuple(_build_vulnerability(service_id, v) for v in entry.get("vulnerabilities") or [])
    return Service(
        id=service_id,
        name=name,
        port=port,
        protocol=str(entry.get("protocol") or "tcp"),
        version=str(entry.get("version") or ""),
        vulnerabilities=vulns,
    )


def _build_vulnerability(service_id: str, entry: dict[str, Any]) -> Vulnerability:
    cve_id = str(entry.get("cve") or entry.get("id") or f"{service_id}:weakness")
    return Vulnerability(
        cve_id=cve_id,
        cvss=float(entry.get("cvss", 5.0)),
        exploitability=float(entry.get("exploitability", 0.5)),
        privilege_gained=_enum(
            Privilege, entry.get("privilege_gained"), Privilege.USER, cve_id, "privilege_gained"
        ),
        description=str(entry.get("description") or ""),
    )


def _build_credential(host_id: str, entry: dict[str, Any]) -> Credential:
    username = _require(entry, "username", f"credential on {host_id}")
    return Credential(
        id=str(entry.get("id") or f"{host_id}:cred:{username}"),
        username=username,
        kind=str(entry.get("kind") or "password"),
        privilege=_enum(
            Privilege, entry.get("privilege"), Privilege.USER, host_id, "credential privilege"
        ),
        grants_access=tuple(str(h) for h in entry.get("grants_access") or ()),
        strength=float(entry.get("strength", 0.5)),
    )


def _build_user(entry: dict[str, Any]) -> User:
    username = _require(entry, "username", "user")
    return User(
        id=str(entry.get("id") or f"user:{username}"),
        username=username,
        role=str(entry.get("role") or "employee"),
        privilege=_enum(Privilege, entry.get("privilege"), Privilege.USER, username, "privilege"),
        logs_into=tuple(str(h) for h in entry.get("logs_into") or ()),
    )


def _build_connection(entry: dict[str, Any]) -> Connection:
    return Connection(
        source=_require(entry, "from", "connection"),
        target=_require(entry, "to", "connection"),
        protocol=str(entry.get("protocol") or "tcp"),
        ports=tuple(int(p) for p in entry.get("ports") or ()),
        filtered=float(entry.get("filtered", 0.0)),
    )


# -- hierarchy -------------------------------------------------------------

_COMPOSITE_TYPES = {
    "organisation": NodeType.ORGANISATION,
    "organization": NodeType.ORGANISATION,
    "department": NodeType.DEPARTMENT,
    "subnet": NodeType.SUBNET,
}


def _build_hierarchy(entry: dict[str, Any], model: NetworkModel) -> CompositeComponent:
    kind = str(entry.get("type") or "organisation").lower()
    if kind not in _COMPOSITE_TYPES:
        raise ValueError(f"unknown hierarchy node type: {kind!r}")
    node_id = str(entry.get("id") or entry.get("name") or kind)
    composite = CompositeComponent(
        node_id, str(entry.get("name") or node_id), _COMPOSITE_TYPES[kind]
    )

    for child in entry.get("children") or []:
        composite.add(_build_hierarchy(child, model))

    for host_id in entry.get("hosts") or []:
        host = model.hosts.get(str(host_id))
        if host is None:
            raise ValueError(f"hierarchy references unknown host: {host_id}")
        composite.add(HostComponent(host))

    return composite


# -- validation ------------------------------------------------------------


def _validate_references(model: NetworkModel) -> None:
    for host in model.hosts.values():
        for credential in host.credentials:
            for target in credential.grants_access:
                if target not in model.hosts:
                    raise ValueError(
                        f"credential {credential.id} grants access to unknown host {target}"
                    )
    for user in model.users.values():
        for host_id in user.logs_into:
            if host_id not in model.hosts:
                raise ValueError(f"user {user.id} logs into unknown host {host_id}")


def _require(entry: dict[str, Any], key: str, context: str) -> str:
    value = entry.get(key)
    if value in (None, ""):
        raise ValueError(f"{context}: missing required field {key!r}")
    return str(value)


def _enum(enum_cls, value, default, context: str, field: str):
    if value in (None, ""):
        return default
    try:
        return enum_cls(str(value).upper())
    except ValueError as exc:
        allowed = ", ".join(m.value for m in enum_cls)
        raise ValueError(
            f"{context}: invalid {field} {value!r} (expected one of: {allowed})"
        ) from exc
