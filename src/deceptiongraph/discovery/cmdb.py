"""CMDB export -> network model.

A configuration-management database knows what a scan cannot: who owns a
machine, what it is worth, which accounts sit on it. Most can export CSV, so
that is the format. A directory holds up to five files; only ``hosts.csv`` is
required:

``hosts.csv``
    ``id,name,ip,os,exposure,criticality,crown_jewel,patch_level,tags``
``services.csv``
    ``host_id,name,port,protocol,version,cves`` - ``cves`` as
    ``CVE-2021-44228:10.0|CVE-2022-0001:5.5`` (id:cvss, pipe-separated)
``connections.csv``
    ``from,to,ports,filtered`` - ``ports`` pipe-separated; ``from`` may be
    ``INTERNET``
``credentials.csv``
    ``host_id,username,kind,privilege,strength,grants_access`` - targets
    pipe-separated
``users.csv``
    ``username,role,privilege,logs_into`` - hosts pipe-separated

Column names are matched case-insensitively and surrounding whitespace is
ignored, because CMDB exports are rarely tidy. Errors name the file and line.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterator

from ..graph.loader import build_model
from ..graph.model import NetworkModel

_TRUE = {"1", "true", "yes", "y", "x"}


def _rows(path: Path) -> Iterator[tuple[int, dict[str, str]]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for line, row in enumerate(reader, start=2):
            clean = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            if any(clean.values()):
                yield line, clean


def _split(value: str) -> list[str]:
    return [p.strip() for p in value.split("|") if p.strip()]


def _float(value: str, default: float, where: str) -> float:
    if value == "":
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{where}: expected a number, got {value!r}") from exc


class CmdbAssetDiscovery:
    """Adapter: a directory of CMDB CSV exports as asset discovery."""

    def __init__(self, directory: str | Path, name: str | None = None) -> None:
        self.directory = Path(directory)
        self.name = name or self.directory.name

    def raw(self) -> dict[str, Any]:
        hosts_file = self.directory / "hosts.csv"
        if not hosts_file.exists():
            raise FileNotFoundError(f"CMDB export needs {hosts_file}")

        hosts: dict[str, dict] = {}
        for line, row in _rows(hosts_file):
            where = f"hosts.csv:{line}"
            host_id = row.get("id")
            if not host_id:
                raise ValueError(f"{where}: missing id")
            if host_id in hosts:
                raise ValueError(f"{where}: duplicate host id {host_id!r}")
            hosts[host_id] = {
                "id": host_id,
                "name": row.get("name") or host_id,
                "ip": row.get("ip", ""),
                "os": row.get("os") or "unknown",
                "exposure": (row.get("exposure") or "INTERNAL").upper(),
                "criticality": _float(row.get("criticality", ""), 0.5, where),
                "crown_jewel": row.get("crown_jewel", "").lower() in _TRUE,
                "patch_level": _float(row.get("patch_level", ""), 0.5, where),
                "tags": ["source=cmdb", *_split(row.get("tags", ""))],
                "services": [],
                "credentials": [],
            }

        def host_for(row: dict, where: str) -> dict:
            host_id = row.get("host_id", "")
            if host_id not in hosts:
                raise ValueError(f"{where}: unknown host {host_id!r}")
            return hosts[host_id]

        services = self.directory / "services.csv"
        if services.exists():
            for line, row in _rows(services):
                where = f"services.csv:{line}"
                host = host_for(row, where)
                vulns = []
                for item in _split(row.get("cves", "")):
                    cve, _, score = item.partition(":")
                    cvss = _float(score, 5.0, where)
                    vulns.append({"cve": cve, "cvss": cvss, "exploitability": 0.5,
                                  "privilege_gained": "ADMIN" if cvss >= 9.0 else "USER"})
                host["services"].append({
                    "name": row.get("name") or "service",
                    "port": int(_float(row.get("port", ""), 0, where)),
                    "protocol": row.get("protocol") or "tcp",
                    "version": row.get("version", ""),
                    "vulnerabilities": vulns,
                })

        credentials = self.directory / "credentials.csv"
        if credentials.exists():
            for line, row in _rows(credentials):
                where = f"credentials.csv:{line}"
                host = host_for(row, where)
                if not row.get("username"):
                    raise ValueError(f"{where}: missing username")
                host["credentials"].append({
                    "username": row["username"],
                    "kind": row.get("kind") or "password",
                    "privilege": (row.get("privilege") or "USER").upper(),
                    "strength": _float(row.get("strength", ""), 0.5, where),
                    "grants_access": _split(row.get("grants_access", "")),
                })

        connections = []
        conn_file = self.directory / "connections.csv"
        if conn_file.exists():
            for line, row in _rows(conn_file):
                where = f"connections.csv:{line}"
                connections.append({
                    "from": row.get("from", ""), "to": row.get("to", ""),
                    "protocol": row.get("protocol") or "tcp",
                    "ports": [int(p) for p in _split(row.get("ports", ""))],
                    "filtered": _float(row.get("filtered", ""), 0.0, where),
                })

        users = []
        users_file = self.directory / "users.csv"
        if users_file.exists():
            for _, row in _rows(users_file):
                users.append({
                    "username": row.get("username", ""),
                    "role": row.get("role") or "employee",
                    "privilege": (row.get("privilege") or "USER").upper(),
                    "logs_into": _split(row.get("logs_into", "")),
                })

        return {"name": self.name, "hosts": list(hosts.values()), "users": users,
                "connections": connections}

    def discover(self) -> NetworkModel:
        return build_model(self.raw(), default_name=self.name)
