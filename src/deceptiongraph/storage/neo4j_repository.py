"""Neo4j-backed graph repository.

Implements the same :class:`GraphRepository` protocol as the in-memory one, so
nothing above this layer changes. The schema mirrors the asset graph:

    (:Host)-[:CONNECTS_TO]->(:Host)
    (:Host)-[:RUNS]->(:Service)
    (:Host)-[:STORES]->(:Credential)
    (:Credential)-[:GRANTS_ACCESS]->(:Host)
    (:Service)-[:HAS_VULNERABILITY]->(:Vulnerability)
    (:User)-[:LOGS_INTO]->(:Host)
    (:Network {name, hierarchy})

Every node carries a ``network`` property, so one database holds several
networks side by side and saving one never touches another. Writes are batched
with ``UNWIND`` inside a single transaction: a twin built from the LANL data has
thousands of credentials, and one round trip per entity would take minutes.

Analysis still happens in NetworkX. Loading the graph into memory once and
running the algorithms there beats round-tripping every traversal to the
database, and the attack graph is derived rather than stored. What Neo4j buys
is durable shared state, ad-hoc Cypher over the asset graph (the Neo4j browser
at :7474), and the server-side :meth:`paths_to_crown_jewel` query.

Integration-tested against a live Neo4j 5 container in
``tests/integration/test_live_backends.py``: a network saved here and reloaded
gives the same analysis as the in-memory original.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

import networkx as nx

from ..domain.composite import CompositeComponent, HostComponent
from ..domain.entities import Host
from ..graph.model import INTERNET, NetworkModel
from ..graph.repository import InMemoryGraphRepository

SCHEMA = (
    "CREATE INDEX dg_host IF NOT EXISTS FOR (n:Host) ON (n.network, n.id)",
    "CREATE INDEX dg_service IF NOT EXISTS FOR (n:Service) ON (n.network, n.id)",
    "CREATE INDEX dg_credential IF NOT EXISTS FOR (n:Credential) ON (n.network, n.id)",
    "CREATE INDEX dg_vulnerability IF NOT EXISTS FOR (n:Vulnerability) ON (n.network, n.cve_id)",
    "CREATE INDEX dg_user IF NOT EXISTS FOR (n:User) ON (n.network, n.id)",
    "CREATE INDEX dg_network IF NOT EXISTS FOR (n:Network) ON (n.name)",
)

CLEAR_NETWORK = """
MATCH (n {network: $network})
WHERE n:Host OR n:Service OR n:Credential OR n:Vulnerability OR n:User
DETACH DELETE n
"""

MERGE_NETWORK = """
MERGE (n:Network {name: $network})
SET n.model_name = $model_name, n.hierarchy = $hierarchy, n.saved_at = datetime()
"""

WRITE_HOSTS = """
UNWIND $rows AS row
MERGE (h:Host {network: $network, id: row.id})
SET h += row.props
"""

WRITE_SERVICES = """
UNWIND $rows AS row
MATCH (h:Host {network: $network, id: row.host_id})
MERGE (s:Service {network: $network, id: row.id})
SET s.name = row.name, s.port = row.port, s.protocol = row.protocol,
    s.version = row.version, s.ord = row.ord
MERGE (h)-[:RUNS]->(s)
"""

WRITE_VULNERABILITIES = """
UNWIND $rows AS row
MATCH (s:Service {network: $network, id: row.service_id})
MERGE (v:Vulnerability {network: $network, cve_id: row.cve_id})
SET v.cvss = row.cvss, v.exploitability = row.exploitability,
    v.privilege_gained = row.privilege_gained, v.description = row.description
MERGE (s)-[r:HAS_VULNERABILITY]->(v)
SET r.ord = row.ord
"""

WRITE_CREDENTIALS = """
UNWIND $rows AS row
MATCH (h:Host {network: $network, id: row.host_id})
MERGE (c:Credential {network: $network, id: row.id})
SET c.username = row.username, c.kind = row.kind, c.privilege = row.privilege,
    c.strength = row.strength, c.ord = row.ord
MERGE (h)-[:STORES]->(c)
"""

WRITE_GRANTS = """
UNWIND $rows AS row
MATCH (c:Credential {network: $network, id: row.credential_id})
MATCH (h:Host {network: $network, id: row.host_id})
MERGE (c)-[r:GRANTS_ACCESS]->(h)
SET r.privilege = row.privilege, r.ord = row.ord
"""

WRITE_USERS = """
UNWIND $rows AS row
MERGE (u:User {network: $network, id: row.id})
SET u.username = row.username, u.role = row.role, u.privilege = row.privilege,
    u.ord = row.ord
"""

WRITE_LOGS_INTO = """
UNWIND $rows AS row
MATCH (u:User {network: $network, id: row.user_id})
MATCH (h:Host {network: $network, id: row.host_id})
MERGE (u)-[r:LOGS_INTO]->(h)
SET r.privilege = row.privilege, r.ord = row.ord
"""

WRITE_CONNECTIONS = """
UNWIND $rows AS row
MATCH (a:Host {network: $network, id: row.source})
MATCH (b:Host {network: $network, id: row.target})
CREATE (a)-[:CONNECTS_TO {protocol: row.protocol, ports: row.ports,
                          filtered: row.filtered, ord: row.ord}]->(b)
"""

#: Connections from the synthetic internet node have no Host to hang off, so
#: they are kept on the Network node instead.
FETCH_NETWORK = """
MATCH (n:Network {name: $network})
RETURN n.model_name AS model_name, n.hierarchy AS hierarchy,
       n.internet_edges AS internet_edges
"""

SET_INTERNET_EDGES = """
MATCH (n:Network {name: $network})
SET n.internet_edges = $edges
"""

FETCH_HOSTS = """
MATCH (h:Host {network: $network})
RETURN h,
  [(h)-[:RUNS]->(s:Service) | {
      service: s,
      vulns: [(s)-[r:HAS_VULNERABILITY]->(v:Vulnerability) | {vuln: v, ord: r.ord}]
  }] AS services,
  [(h)-[:STORES]->(c:Credential) | {
      credential: c,
      grants: [(c)-[g:GRANTS_ACCESS]->(t:Host) | {id: t.id, ord: g.ord}]
  }] AS credentials
ORDER BY h.ord
"""

FETCH_USERS = """
MATCH (u:User {network: $network})
RETURN u, [(u)-[r:LOGS_INTO]->(h:Host) | {id: h.id, ord: r.ord}] AS hosts
ORDER BY u.ord
"""

FETCH_CONNECTIONS = """
MATCH (a:Host {network: $network})-[r:CONNECTS_TO]->(b:Host)
RETURN a.id AS source, b.id AS target, r.protocol AS protocol,
       r.ports AS ports, r.filtered AS filtered
ORDER BY r.ord
"""

LIST_NETWORKS = "MATCH (n:Network) RETURN n.name AS name ORDER BY name"

#: Server-side equivalent of `AttackGraphEngine.paths`, for ad-hoc querying.
PATHS_TO_CROWN_JEWEL = """
MATCH (start:Host {network: $network, id: $start}),
      (jewel:Host {network: $network, is_crown_jewel: true})
MATCH path = (start)-[:CONNECTS_TO|STORES|GRANTS_ACCESS*1..8]->(jewel)
WHERE all(n IN nodes(path) WHERE n.network = $network)
// A network link and a stolen credential can join the same two hosts; report
// each host sequence once.
WITH DISTINCT [n IN nodes(path) WHERE n:Host | n.id] AS hosts
RETURN hosts, size(hosts) - 1 AS hops
ORDER BY hops ASC
LIMIT $limit
"""

BATCH = 1000


class Neo4jGraphRepository:
    """Persists the asset graph in Neo4j, analyses it in NetworkX.

    The projection is cached: `save` writes through and rebuilds it, and
    `reload` pulls a fresh copy from the database.
    """

    def __init__(self, driver: Any, database: str = "neo4j", network: str | None = None) -> None:
        self.driver = driver
        self.database = database
        self.network = network
        """Which network in the database this repository reads and writes.

        Defaults to the model's name on the first save."""
        self._memory: InMemoryGraphRepository | None = None

    @classmethod
    def connect(cls, settings=None, network: str | None = None) -> "Neo4jGraphRepository":
        """Build a driver from settings. Raises if the uri is not configured."""
        from ..config import Neo4jSettings

        resolved = settings or Neo4jSettings.from_env()
        if not resolved.enabled:
            raise RuntimeError(
                "Neo4j is not configured; set DG_NEO4J_URI to use the graph backend"
            )
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(
            resolved.uri, auth=(resolved.user, resolved.password),
            # Fail in seconds, not the default minute, when the server is down.
            connection_timeout=10.0, connection_acquisition_timeout=15.0,
        )
        repository = cls(driver, database=resolved.database, network=network)
        try:
            repository.ensure_schema()
        except Exception:
            driver.close()
            raise
        return repository

    def close(self) -> None:
        self.driver.close()

    def ping(self) -> bool:
        """True when the server answers."""
        self.driver.verify_connectivity()
        return True

    def ensure_schema(self) -> None:
        with self.driver.session(database=self.database) as session:
            for statement in SCHEMA:
                session.run(statement).consume()

    # -- GraphRepository protocol -----------------------------------------

    @property
    def model(self) -> NetworkModel:
        return self._projection().model

    def save(self, model: NetworkModel) -> None:
        """Replace this network in the database, then cache the projection."""
        if self.network is None:
            self.network = model.name
        network = self.network
        rows = _rows(model)

        def write(tx) -> None:
            tx.run(CLEAR_NETWORK, network=network).consume()
            tx.run(MERGE_NETWORK, network=network, model_name=model.name,
                   hierarchy=_hierarchy_json(model)).consume()
            tx.run(SET_INTERNET_EDGES, network=network,
                   edges=json.dumps(rows.pop("internet"))).consume()
            for query, key in (
                (WRITE_HOSTS, "hosts"), (WRITE_SERVICES, "services"),
                (WRITE_VULNERABILITIES, "vulnerabilities"),
                (WRITE_CREDENTIALS, "credentials"), (WRITE_GRANTS, "grants"),
                (WRITE_USERS, "users"), (WRITE_LOGS_INTO, "logs_into"),
                (WRITE_CONNECTIONS, "connections"),
            ):
                batch = rows[key]
                for start in range(0, len(batch), BATCH):
                    tx.run(query, network=network, rows=batch[start:start + BATCH]).consume()

        with self.driver.session(database=self.database) as session:
            session.execute_write(write)

        self._memory = InMemoryGraphRepository(model)

    def host(self, host_id: str) -> Host | None:
        return self._projection().host(host_id)

    def hosts(self) -> Iterable[Host]:
        return self._projection().hosts()

    def asset_graph(self) -> nx.MultiDiGraph:
        return self._projection().asset_graph()

    def connectivity_graph(self) -> nx.DiGraph:
        return self._projection().connectivity_graph()

    def neighbours(self, host_id: str) -> tuple[str, ...]:
        return self._projection().neighbours(host_id)

    # -- Neo4j specific ----------------------------------------------------

    def networks(self) -> list[str]:
        """Every network stored in this database."""
        with self.driver.session(database=self.database) as session:
            return [record["name"] for record in session.run(LIST_NETWORKS)]

    def paths_to_crown_jewel(self, start: str, limit: int = 10) -> list[dict]:
        """Run the traversal server-side. Useful for ad-hoc investigation."""
        with self.driver.session(database=self.database) as session:
            result = session.run(PATHS_TO_CROWN_JEWEL, network=self._require_network(),
                                 start=start, limit=limit)
            return [dict(record) for record in result]

    def reload(self) -> NetworkModel:
        """Rebuild the model from what is in the database."""
        from ..graph.loader import build_model

        network = self._require_network()
        with self.driver.session(database=self.database) as session:
            meta_rows = [dict(r) for r in session.run(FETCH_NETWORK, network=network)]
            host_rows = [dict(r) for r in session.run(FETCH_HOSTS, network=network)]
            user_rows = [dict(r) for r in session.run(FETCH_USERS, network=network)]
            conn_rows = [dict(r) for r in session.run(FETCH_CONNECTIONS, network=network)]

        if not meta_rows and not host_rows:
            raise LookupError(f"network {network!r} is not in the database")
        meta = meta_rows[0] if meta_rows else {}
        internet = json.loads(meta.get("internet_edges") or "[]")
        raw = {
            "name": meta.get("model_name") or network,
            "hosts": [_row_to_host(row) for row in host_rows],
            "users": [_row_to_user(row) for row in user_rows],
            "connections": [
                {
                    "from": row["source"], "to": row["target"],
                    "protocol": row.get("protocol") or "tcp",
                    "ports": row.get("ports") or [],
                    "filtered": row.get("filtered") or 0.0,
                }
                for row in [*internet, *conn_rows]
            ],
        }
        hierarchy = meta.get("hierarchy")
        if hierarchy:
            raw["hierarchy"] = json.loads(hierarchy)
        model = build_model(raw, default_name=network)
        self._memory = InMemoryGraphRepository(model)
        return model

    # -- internals ---------------------------------------------------------

    def _require_network(self) -> str:
        if self.network is None:
            names = self.networks()
            if len(names) != 1:
                raise LookupError(
                    "say which network to use: the database holds "
                    + (", ".join(names) if names else "none")
                )
            self.network = names[0]
        return self.network

    def _projection(self) -> InMemoryGraphRepository:
        if self._memory is None:
            self.reload()
        assert self._memory is not None
        return self._memory


# -- mapping ---------------------------------------------------------------


def _rows(model: NetworkModel) -> dict[str, list]:
    """Flatten a model into the batches the UNWIND writes take."""
    rows: dict[str, list] = {k: [] for k in (
        "hosts", "services", "vulnerabilities", "credentials", "grants", "users",
        "logs_into", "connections", "internet")}
    for h_ord, host in enumerate(model.hosts.values()):
        rows["hosts"].append({"id": host.id, "props": {
            "name": host.name, "ip": host.ip, "os": host.os,
            "exposure": host.exposure.value, "criticality": host.criticality,
            "is_crown_jewel": host.is_crown_jewel, "patch_level": host.patch_level,
            "tags": list(host.tags), "ord": h_ord,
        }})
        for s_ord, service in enumerate(host.services):
            rows["services"].append({
                "host_id": host.id, "id": service.id, "name": service.name,
                "port": service.port, "protocol": service.protocol,
                "version": service.version, "ord": s_ord,
            })
            for v_ord, vuln in enumerate(service.vulnerabilities):
                rows["vulnerabilities"].append({
                    "service_id": service.id, "cve_id": vuln.cve_id, "cvss": vuln.cvss,
                    "exploitability": vuln.exploitability,
                    "privilege_gained": vuln.privilege_gained.value,
                    "description": vuln.description, "ord": v_ord,
                })
        for c_ord, credential in enumerate(host.credentials):
            rows["credentials"].append({
                "host_id": host.id, "id": credential.id, "username": credential.username,
                "kind": credential.kind, "privilege": credential.privilege.value,
                "strength": credential.strength, "ord": c_ord,
            })
            for g_ord, target in enumerate(credential.grants_access):
                rows["grants"].append({
                    "credential_id": credential.id, "host_id": target,
                    "privilege": credential.privilege.value, "ord": g_ord,
                })
    for u_ord, user in enumerate(model.users.values()):
        rows["users"].append({
            "id": user.id, "username": user.username, "role": user.role,
            "privilege": user.privilege.value, "ord": u_ord,
        })
        for l_ord, host_id in enumerate(user.logs_into):
            rows["logs_into"].append({
                "user_id": user.id, "host_id": host_id,
                "privilege": user.privilege.value, "ord": l_ord,
            })
    for c_ord, connection in enumerate(model.connections):
        row = {"source": connection.source, "target": connection.target,
               "protocol": connection.protocol, "ports": list(connection.ports),
               "filtered": connection.filtered, "ord": c_ord}
        if INTERNET in (connection.source, connection.target):
            rows["internet"].append(row)  # synthetic node, not an asset
        else:
            rows["connections"].append(row)
    return rows


def _hierarchy_json(model: NetworkModel) -> str | None:
    """The Composite tree in the loader's ``hierarchy`` format, or None."""
    if model.root is None:
        return None
    return json.dumps(_composite_to_dict(model.root))


def _composite_to_dict(node: CompositeComponent) -> dict:
    children, hosts = [], []
    for child in node.children:
        if isinstance(child, CompositeComponent):
            children.append(_composite_to_dict(child))
        elif isinstance(child, HostComponent):
            hosts.append(child.id)
    return {"type": node.node_type.value.lower(), "id": node.id, "name": node.name,
            "children": children, "hosts": hosts}


def _by_ord(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda item: (item.get("ord") is None, item.get("ord") or 0))


def _row_to_host(row: dict) -> dict:
    """Map one FETCH_HOSTS record back into loader-shaped data."""
    node = dict(row["h"])
    services = []
    for entry in row.get("services") or []:
        service = dict(entry["service"])
        vulns = [dict(v["vuln"]) | {"_ord": v.get("ord")} for v in entry.get("vulns") or []]
        vulns.sort(key=lambda v: (v["_ord"] is None, v["_ord"] or 0))
        services.append({
            "ord": service.get("ord"),
            "id": service["id"], "name": service.get("name", "unknown"),
            "port": service.get("port", 0), "protocol": service.get("protocol", "tcp"),
            "version": service.get("version", ""),
            "vulnerabilities": [
                {
                    "cve": v.get("cve_id"), "cvss": v.get("cvss", 5.0),
                    "exploitability": v.get("exploitability", 0.5),
                    "privilege_gained": v.get("privilege_gained", "USER"),
                    "description": v.get("description", ""),
                }
                for v in vulns
            ],
        })

    credentials = []
    for entry in row.get("credentials") or []:
        credential = dict(entry["credential"])
        grants = _by_ord([dict(g) for g in entry.get("grants") or []])
        credentials.append({
            "ord": credential.get("ord"),
            "id": credential["id"], "username": credential.get("username", "unknown"),
            "kind": credential.get("kind", "password"),
            "privilege": credential.get("privilege", "USER"),
            "strength": credential.get("strength", 0.5),
            "grants_access": [g["id"] for g in grants],
        })

    return {
        "id": node["id"], "name": node.get("name", node["id"]),
        "ip": node.get("ip", ""), "os": node.get("os", "unknown"),
        "exposure": node.get("exposure", "INTERNAL"),
        "criticality": node.get("criticality", 0.5),
        "crown_jewel": node.get("is_crown_jewel", False),
        "patch_level": node.get("patch_level", 0.5),
        "tags": node.get("tags") or [],
        "services": [{k: v for k, v in s.items() if k != "ord"} for s in _by_ord(services)],
        "credentials": [{k: v for k, v in c.items() if k != "ord"}
                        for c in _by_ord(credentials)],
    }


def _row_to_user(row: dict) -> dict:
    node = dict(row["u"])
    hosts = _by_ord([dict(h) for h in row.get("hosts") or []])
    return {
        "id": node["id"], "username": node.get("username", node["id"]),
        "role": node.get("role", "employee"), "privilege": node.get("privilege", "USER"),
        "logs_into": [h["id"] for h in hosts],
    }


def build_graph_repository(settings=None, network: str | None = None):
    """Pick a graph backend from configuration.

    Returns the Neo4j repository when a uri is configured, otherwise the
    in-memory one. Callers get the protocol either way.
    """
    from ..config import settings as read_settings

    resolved = settings or read_settings()
    if resolved.neo4j.enabled:
        return Neo4jGraphRepository.connect(resolved.neo4j, network=network)
    return InMemoryGraphRepository()
