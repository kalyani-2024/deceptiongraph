"""Generate enterprise-shaped networks of any size, for scaling experiments.

The hand-written networks have 5 and 16 hosts - too few to tell strategies
apart with confidence, and too few to say whether anything holds at a size an
organisation actually has. This builds a tiered network from a seed:

    INTERNET -> DMZ (web, mail, VPN) -> application tier -> data tier
                     workstations -> file servers, app tier, domain controller
                     admin jump hosts -> everything internal

with services and synthetic CVEs per tier, credentials cached where they
plausibly would be (service accounts on app servers, admin hashes on jump
hosts and on the odd workstation an admin once logged in to), and a
department hierarchy for the Composite. The same seed always gives the same
network.

Generated, so not evidence about any real organisation; its use is measuring
how results change with size, and how fast the analysis runs.
"""

from __future__ import annotations

import random

TIERS = (
    # name, share of hosts, exposure, criticality range, base cvss range, ports
    ("dmz", 0.08, "INTERNET", (0.3, 0.5), (5.0, 9.8), [("https", 443), ("ssh", 22)]),
    ("app", 0.18, "INTERNAL", (0.4, 0.7), (4.0, 9.0), [("http", 8080), ("ssh", 22)]),
    ("data", 0.07, "RESTRICTED", (0.7, 0.95), (3.0, 8.0), [("postgresql", 5432)]),
    ("file", 0.05, "INTERNAL", (0.5, 0.7), (3.0, 8.0), [("smb", 445)]),
    ("admin", 0.03, "INTERNAL", (0.6, 0.8), (2.0, 7.0), [("rdp", 3389)]),
    ("dc", 0.02, "RESTRICTED", (0.95, 0.95), (2.0, 9.0), [("ldap", 389), ("kerberos", 88)]),
    ("ws", 0.57, "INTERNAL", (0.1, 0.3), (3.0, 8.8), [("rdp", 3389), ("smb", 445)]),
)

DEPARTMENTS = ("engineering", "finance", "sales", "operations", "hr")


def generate_network(hosts: int = 100, seed: int = 0, name: str | None = None) -> dict:
    """A loader-shaped network definition with roughly ``hosts`` hosts."""
    if hosts < 10:
        raise ValueError(f"need at least 10 hosts for every tier, got {hosts}")
    rng = random.Random(seed)
    tiers: dict[str, list[dict]] = {}
    cve = 0

    for tier, share, exposure, crit, cvss, ports in TIERS:
        count = max(1, round(hosts * share))
        tiers[tier] = []
        for i in range(1, count + 1):
            host_id = f"{tier}-{i:03d}"
            services = []
            for service, port in ports:
                vulns = []
                for _ in range(rng.choice((0, 0, 1, 1, 2))):
                    cve += 1
                    score = round(rng.uniform(*cvss), 1)
                    vulns.append({
                        "cve": f"GEN-{seed}-{cve:05d}",
                        "cvss": score,
                        "exploitability": round(rng.uniform(0.2, 0.9), 2),
                        "privilege_gained": "ADMIN" if score >= 9.0 else "USER",
                    })
                services.append({"name": service, "port": port, "vulnerabilities": vulns})
            tiers[tier].append({
                "id": host_id,
                "name": host_id,
                "exposure": exposure,
                "criticality": round(rng.uniform(*crit), 3),
                "crown_jewel": False,
                "patch_level": round(rng.betavariate(2, 2), 3),
                "tags": [f"tier={tier}"],
                "services": services,
                "credentials": [],
            })

    # Crown jewels: the domain controllers and the two most valuable databases.
    for host in tiers["dc"]:
        host["crown_jewel"] = True
    for host in sorted(tiers["data"], key=lambda h: h["criticality"], reverse=True)[:2]:
        host["crown_jewel"] = True
        host["criticality"] = max(host["criticality"], 0.9)

    ids = {tier: [h["id"] for h in members] for tier, members in tiers.items()}
    connections: list[dict] = []

    def link(src: str, dst: str, filtered: float, ports=()):
        connections.append({"from": src, "to": dst, "filtered": round(filtered, 2),
                            "ports": list(ports)})

    for d in ids["dmz"]:
        for a in rng.sample(ids["app"], k=min(3, len(ids["app"]))):
            link(d, a, rng.uniform(0.1, 0.4), (8080,))
    for a in ids["app"]:
        for db in rng.sample(ids["data"], k=min(2, len(ids["data"]))):
            link(a, db, rng.uniform(0.2, 0.5), (5432,))
    for w in ids["ws"]:
        for f in rng.sample(ids["file"], k=min(2, len(ids["file"]))):
            link(w, f, 0.0, (445,))
        link(w, rng.choice(ids["app"]), rng.uniform(0.0, 0.2), (8080,))
        link(w, rng.choice(ids["dc"]), 0.0, (88, 389))
        link(w, rng.choice(ids["admin"]), rng.uniform(0.3, 0.7), (3389,))
    for adm in ids["admin"]:
        for target in ids["app"] + ids["data"] + ids["dc"] + ids["file"]:
            link(adm, target, rng.uniform(0.0, 0.1), (3389, 22))

    # Credentials, where a real intruder would find them.
    for host in tiers["app"]:
        targets = rng.sample(ids["data"], k=min(2, len(ids["data"])))
        host["credentials"].append({"username": f"svc-{host['id']}", "kind": "password",
                                    "privilege": "SERVICE", "strength": round(rng.uniform(0.1, 0.5), 2),
                                    "grants_access": targets})
    for host in tiers["admin"]:
        host["credentials"].append({"username": "domain-admin", "kind": "ntlm-hash",
                                    "privilege": "ADMIN", "strength": round(rng.uniform(0.3, 0.6), 2),
                                    "grants_access": ids["dc"] + ids["file"]})
    for host in tiers["dmz"]:
        if rng.random() < 0.5:
            host["credentials"].append({"username": "deploy", "kind": "ssh-key",
                                        "privilege": "SERVICE", "strength": 0.3,
                                        "grants_access": [rng.choice(ids["app"])]})
    for host in rng.sample(tiers["ws"], k=max(1, len(tiers["ws"]) // 20)):
        # The workstation an admin once logged in to, and left a hash behind.
        host["credentials"].append({"username": "it-admin", "kind": "ntlm-hash",
                                    "privilege": "ADMIN", "strength": 0.3,
                                    "grants_access": [rng.choice(ids["admin"])]})

    users = []
    for i, ws in enumerate(ids["ws"], start=1):
        if rng.random() < 0.3:
            users.append({"username": f"user{i:03d}", "role": "employee", "privilege": "USER",
                          "logs_into": [ws, rng.choice(ids["file"])]})
    for i, adm in enumerate(ids["admin"], start=1):
        users.append({"username": f"admin{i:02d}", "role": "it-admin", "privilege": "ADMIN",
                      "logs_into": [adm, *rng.sample(ids["app"], k=min(2, len(ids["app"])))]})

    all_hosts = [h for members in tiers.values() for h in members]
    departments: dict[str, list[str]] = {d: [] for d in DEPARTMENTS}
    for h in tiers["ws"] + tiers["app"] + tiers["file"]:
        departments[rng.choice(DEPARTMENTS)].append(h["id"])
    hierarchy = {
        "type": "organisation", "id": f"gen-{hosts}", "name": f"Generated ({hosts} hosts)",
        "children": [
            {"type": "subnet", "id": "dmz", "name": "DMZ", "hosts": ids["dmz"]},
            {"type": "subnet", "id": "core", "name": "Core services",
             "hosts": ids["data"] + ids["dc"] + ids["admin"]},
            *({"type": "department", "id": d, "name": d.title(), "hosts": members}
              for d, members in departments.items() if members),
        ],
    }
    return {"name": name or f"generated-{hosts}-s{seed}", "hosts": all_hosts, "users": users,
            "connections": connections, "hierarchy": hierarchy}
