"""nmap XML -> network model.

Takes the output of a service scan, ideally with the ``vulners`` script so
open services come with their CVEs::

    nmap -sV --script vulners -oX scan.xml 10.0.0.0/16

What a scan can see and what it cannot:

* **Seen:** live hosts, their open ports, service product and version, OS
  guess, and (with ``vulners``) known CVEs with CVSS scores.
* **Not seen:** which zone a host sits in, what the firewall lets through,
  what each machine is worth, and anything about credentials or users. Those
  come from a small *zone policy* file (:class:`ZonePolicy`) that maps subnets
  to exposure, says which zones can reach which, and optionally names crown
  jewels and adds credentials and users in the ordinary network-file format.

Where the policy says nothing, the defaults are stated here rather than
hidden: hosts in one zone reach each other freely; DMZ -> internal is
partly filtered (0.3); internal -> restricted is mostly filtered (0.6).
Criticality is guessed from the services a host runs - a directory server or
database is worth more than a web front end - and the guess is recorded in the
host's tags so it can be checked.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..graph.loader import build_model
from ..graph.model import NetworkModel

DEFAULT_FLOWS: dict[tuple[str, str], float] = {
    ("DMZ", "INTERNAL"): 0.3,
    ("INTERNAL", "DMZ"): 0.0,
    ("INTERNAL", "RESTRICTED"): 0.6,
    ("INTERNET", "DMZ"): 0.0,
}
"""(from zone, to zone) -> filtered. Same-zone traffic is always open."""

#: Ports that say what a machine is for, and so roughly what it is worth.
ROLE_PORTS: dict[str, tuple[set[int], float]] = {
    "directory": ({88, 389, 636, 3268, 3269}, 0.95),
    "database": ({1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 27017}, 0.85),
    "file-server": ({445, 2049}, 0.6),
    "remote-admin": ({22, 3389, 5985, 5986}, 0.5),
    "web": ({80, 443, 8080, 8443}, 0.4),
}

MAX_CVES_PER_SERVICE = 5


@dataclass(slots=True)
class ZonePolicy:
    """What the scan cannot see: zones, flows, value, credentials."""

    zones: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = field(
        default_factory=list)
    flows: dict[tuple[str, str], float] = field(default_factory=lambda: dict(DEFAULT_FLOWS))
    default_exposure: str = "INTERNAL"
    crown_jewels: set[str] = field(default_factory=set)
    criticality: dict[str, float] = field(default_factory=dict)
    patch_level: dict[str, float] = field(default_factory=dict)
    credentials: dict[str, list[dict]] = field(default_factory=dict)
    users: list[dict] = field(default_factory=list)
    name: str | None = None

    @classmethod
    def load(cls, path: str | Path | None) -> "ZonePolicy":
        if path is None:
            return cls()
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        policy = cls(name=raw.get("name"))
        for entry in raw.get("zones") or []:
            exposure = str(entry.get("exposure", "INTERNAL")).upper()
            policy.zones.append((ipaddress.ip_network(str(entry["cidr"]), strict=False),
                                 exposure))
        # Most specific subnet wins.
        policy.zones.sort(key=lambda z: z[0].prefixlen, reverse=True)
        for entry in raw.get("flows") or []:
            key = (str(entry["from"]).upper(), str(entry["to"]).upper())
            policy.flows[key] = float(entry.get("filtered", 0.0))
        for entry in raw.get("deny") or []:
            policy.flows.pop((str(entry["from"]).upper(), str(entry["to"]).upper()), None)
        policy.default_exposure = str(raw.get("default_exposure", "INTERNAL")).upper()
        policy.crown_jewels = {str(h) for h in raw.get("crown_jewels") or []}
        policy.criticality = {str(k): float(v) for k, v in (raw.get("criticality") or {}).items()}
        policy.patch_level = {str(k): float(v) for k, v in (raw.get("patch_level") or {}).items()}
        for host_id, creds in (raw.get("credentials") or {}).items():
            policy.credentials[str(host_id)] = list(creds or [])
        policy.users = list(raw.get("users") or [])
        return policy

    def exposure_of(self, ip: str) -> str:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return self.default_exposure
        for network, exposure in self.zones:
            if address in network:
                return exposure
        return self.default_exposure


@dataclass(slots=True)
class ScannedHost:
    ip: str
    hostname: str | None
    os: str
    services: list[dict]

    @property
    def id(self) -> str:
        if self.hostname:
            return self.hostname.split(".")[0]
        return self.ip.replace(".", "-").replace(":", "-")

    @property
    def ports(self) -> set[int]:
        return {int(s["port"]) for s in self.services}


def parse_nmap_xml(path: str | Path) -> list[ScannedHost]:
    """Every host nmap reported as up, with its open services."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"nmap XML not found: {path}")
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"{path} is not valid nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError(f"{path} is not nmap XML (root element <{root.tag}>, expected <nmaprun>)")

    hosts = []
    for node in root.findall("host"):
        status = node.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = next((a.get("addr") for a in node.findall("address")
                   if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if ip is None:
            continue
        hostname = next((h.get("name") for h in node.findall("hostnames/hostname")), None)
        osmatch = node.find("os/osmatch")
        services = []
        for port in node.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            name = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            services.append({
                "name": name,
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", "tcp"),
                "version": " ".join(v for v in (product, version) if v),
                "vulnerabilities": _vulners(port),
            })
        hosts.append(ScannedHost(ip=ip, hostname=hostname,
                                 os=osmatch.get("name", "unknown") if osmatch is not None
                                 else "unknown",
                                 services=services))
    return hosts


def _vulners(port: ET.Element) -> list[dict]:
    """CVEs from the ``vulners`` NSE script, worst first."""
    found: dict[str, dict] = {}
    for script in port.findall("script"):
        if script.get("id") != "vulners":
            continue
        for entry in script.iter("table"):
            elems = {e.get("key"): (e.text or "") for e in entry.findall("elem")}
            if elems.get("type", "cve").lower() != "cve" or not elems.get("id"):
                continue
            try:
                cvss = max(0.0, min(10.0, float(elems.get("cvss", 5.0))))
            except ValueError:
                cvss = 5.0
            exploit = elems.get("is_exploit", "false").lower() == "true"
            found[elems["id"]] = {
                "cve": elems["id"],
                "cvss": cvss,
                # A public exploit makes the weakness far likelier to be used.
                "exploitability": 0.9 if exploit else 0.4,
                "privilege_gained": "ADMIN" if cvss >= 9.0 else "USER",
                "description": "from nmap vulners" + (" (public exploit)" if exploit else ""),
            }
    ranked = sorted(found.values(), key=lambda v: v["cvss"], reverse=True)
    return ranked[:MAX_CVES_PER_SERVICE]


def _role(ports: set[int]) -> tuple[str, float]:
    best = ("unknown", 0.3)
    for role, (role_ports, value) in ROLE_PORTS.items():
        if ports & role_ports and value > best[1]:
            best = (role, value)
    return best


def build_from_scan(scanned: list[ScannedHost], policy: ZonePolicy, name: str) -> dict:
    """Loader-shaped network definition from scan results plus policy."""
    if not scanned:
        raise ValueError("the scan reported no live hosts")
    hosts, zone_of, seen = [], {}, set()
    for host in scanned:
        host_id = host.id
        if host_id in seen:
            host_id = f"{host_id}-{host.ip.replace('.', '-')}"
        seen.add(host_id)
        exposure = policy.exposure_of(host.ip)
        zone_of[host_id] = exposure
        role, guessed = _role(host.ports)
        criticality = policy.criticality.get(host_id, policy.criticality.get(host.ip, guessed))
        is_jewel = host_id in policy.crown_jewels or host.ip in policy.crown_jewels
        hosts.append({
            "id": host_id,
            "name": host.hostname or host_id,
            "ip": host.ip,
            "os": host.os,
            "exposure": exposure,
            "criticality": round(min(1.0, max(criticality, 0.9 if is_jewel else 0.0)), 4),
            "crown_jewel": is_jewel,
            "patch_level": policy.patch_level.get(host_id, 0.5),
            "tags": ["source=nmap", f"role={role}"],
            "services": [dict(s, id=f"{host_id}:{s['name']}:{s['port']}") for s in host.services],
            "credentials": policy.credentials.get(host_id, []),
        })

    if not any(h["crown_jewel"] for h in hosts):
        # Nothing named: protect the most valuable machines the scan found.
        top = max(h["criticality"] for h in hosts)
        for h in hosts:
            if h["criticality"] >= max(0.85, top):
                h["crown_jewel"] = True

    ports_of = {h["id"]: sorted({s["port"] for s in h["services"]}) for h in hosts}
    connections = []
    for a in hosts:
        for b in hosts:
            if a["id"] == b["id"] or not ports_of[b["id"]]:
                continue
            za, zb = zone_of[a["id"]], zone_of[b["id"]]
            if za == zb:
                filtered = 0.0
            elif (za, zb) in policy.flows:
                filtered = policy.flows[(za, zb)]
            else:
                continue
            connections.append({"from": a["id"], "to": b["id"], "protocol": "tcp",
                                "ports": ports_of[b["id"]], "filtered": filtered})

    known = {h["id"] for h in hosts}
    users = [u for u in policy.users if set(u.get("logs_into") or []) <= known]
    return {"name": policy.name or name, "hosts": hosts, "users": users,
            "connections": connections}


class NmapAssetDiscovery:
    """Adapter: an nmap XML scan (plus a zone policy) as asset discovery."""

    def __init__(self, scan: str | Path, policy: str | Path | ZonePolicy | None = None,
                 name: str | None = None) -> None:
        self.scan = Path(scan)
        self.policy = policy if isinstance(policy, ZonePolicy) else ZonePolicy.load(policy)
        self.name = name or self.scan.stem

    def raw(self) -> dict[str, Any]:
        return build_from_scan(parse_nmap_xml(self.scan), self.policy, self.name)

    def discover(self) -> NetworkModel:
        return build_model(self.raw(), default_name=self.name)
