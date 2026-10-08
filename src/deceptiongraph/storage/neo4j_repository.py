"""Neo4j-backed graph repository.

Implements the same :class:`GraphRepository` protocol as the in-memory one, so
nothing above this layer changes. The labels and relationship types were chosen
in stage 1 to match this schema, which is why the translation is mechanical:

    (:Host)-[:CONNECTS_TO]->(:Host)
    (:Host)-[:RUNS]->(:Service)
    (:Host)-[:STORES]->(:Credential)
    (:Credential)-[:GRANTS_ACCESS]->(:Host)
    (:Service)-[:HAS_VULNERABILITY]->(:Vulnerability)
    (:User)-[:LOGS_INTO]->(:Host)

Analysis still happens in NetworkX. Loading the graph into memory once and
running the algorithms there beats round-tripping every traversal to the
database, and the attack graph is derived rather than stored. What Neo4j buys
is durable shared state, ad-hoc Cypher over the asset graph, and the
`paths_to_crown_jewel` query below for anyone who wants it server-side.

NOT INTEGRATION TESTED. The constructor, Cypher and mapping are exercised
against a fake driver in `tests/test_storage.py`; they have never been run
against a live Neo4j, because this project has no server to run them against.
Treat the queries as reviewed, not proven.
"""

from __future__ import annotations

from typing import Any, Iterable

import networkx as nx

from ..domain.entities import Host
from ..graph.builder import GraphBuilder
from ..graph.model import NetworkModel
from ..graph.repository import InMemoryGraphRepository

MERGE_HOST = """
MERGE (h:Host {id: $id})
SET h.name = $name, h.ip = $ip, h.os = $os, h.exposure = $exposure,
    h.criticality = $criticality, h.is_crown_jewel = $is_crown_jewel,
    h.patch_level = $patch_level, h.tags = $tags
"""

MERGE_SERVICE = """
MATCH (h:Host {id: $host_id})
MERGE (s:Service {id: $id})
SET s.name = $name, s.port = $port, s.protocol = $protocol, s.version = $version
MERGE (h)-[:RUNS]->(s)
"""

MERGE_VULNERABILITY = """
MATCH (s:Service {id: $service_id})
MERGE (v:Vulnerability {cve_id: $cve_id})
SET v.cvss = $cvss, v.exploitability = $exploitability,
    v.privilege_gained = $privilege_gained, v.description = $description
MERGE (s)-[:HAS_VULNERABILITY]->(v)
"""

MERGE_CREDENTIAL = """
MATCH (h:Host {id: $host_id})
MERGE (c:Credential {id: $id})
SET c.username = $username, c.kind = $kind, c.privilege = $privilege,
    c.strength = $strength
MERGE (h)-[:STORES]->(c)
"""

MERGE_GRANTS = """
MATCH (c:Credential {id: $credential_id}), (h:Host {id: $host_id})
MERGE (c)-[r:GRANTS_ACCESS]->(h)
SET r.privilege = $privilege
"""

MERGE_USER = """
MERGE (u:User {id: $id})
SET u.username = $username, u.role = $role, u.privilege = $privilege
"""

MERGE_LOGS_INTO = """
MATCH (u:User {id: $user_id}), (h:Host {id: $host_id})
MERGE (u)-[r:LOGS_INTO]->(h)
SET r.privilege = $privilege
"""

MERGE_CONNECTION = """
MATCH (a:Host {id: $source}), (b:Host {id: $target})
MERGE (a)-[r:CONNECTS_TO {protocol: $protocol}]->(b)
SET r.ports = $ports, r.filtered = $filtered
"""

FETCH_HOSTS = """
MATCH (h:Host)
OPTIONAL MATCH (h)-[:RUNS]->(s:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)
OPTIONAL MATCH (h)-[:STORES]->(c:Credential)-[:GRANTS_ACCESS]->(t:Host)
RETURN h,
       collect(DISTINCT {service: s, vuln: v}) AS services,
       collect(DISTINCT {credential: c, grants: t.id}) AS credentials
"""

FETCH_CONNECTIONS = """
MATCH (a:Host)-[r:CONNECTS_TO]->(b:Host)
RETURN a.id AS source, b.id AS target, r.protocol AS protocol,
       r.ports AS ports, r.filtered AS filtered
"""

#: Server-side equivalent of `AttackGraphEngine.paths`, for ad-hoc querying.
PATHS_TO_CROWN_JEWEL = """
MATCH (start:Host {id: $start}), (jewel:Host {is_crown_jewel: true})
MATCH path = (start)-[:CONNECTS_TO|GRANTS_ACCESS*1..6]->(jewel)
RETURN [n IN nodes(path) WHERE n:Host | n.id] AS hosts,
       length(path) AS hops
ORDER BY hops ASC
LIMIT $limit
"""

CLEAR_NETWORK = """
MATCH (n)
WHERE n:Host OR n:Service OR n:Credential OR n:Vulnerability OR n:User
DETACH DELETE n
"""


class Neo4jGraphRepository:
    """Persists the asset graph in Neo4j, analyses it in NetworkX.

    The projection is cached: `save` writes through and rebuilds it, and
    `reload` pulls a fresh copy from the database.
    """

    def __init__(self, driver: Any, database: str = "neo4j") -> None:
        self.driver = driver
        self.database = database
        self._memory: InMemoryGraphRepository | None = None

    @classmethod
    def connect(cls, settings=None) -> "Neo4jGraphRepository":
        """Build a driver from settings. Raises if the uri is not configured."""
        from ..config import Neo4jSettings

        resolved = settings or Neo4jSettings.from_env()
        if not resolved.enabled:
            raise RuntimeError(
                "Neo4j is not configured; set DG_NEO4J_URI to use the graph backend"
            )
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(
            resolved.uri, auth=(resolved.user, resolved.password)
        )
        return cls(driver, database=resolved.database)

    def close(self) -> None:
        self.driver.close()

    # -- GraphRepository protocol -----------------------------------------

    @property
    def model(self) -> NetworkModel:
        return self._projection().model

    def save(self, model: NetworkModel) -> None:
        """Write the whole network, then cache the in-memory projection."""
        with self.driver.session(database=self.database) as session:
            session.run(CLEAR_NETWORK)
            for host in model.hosts.values():
                session.run(MERGE_HOST, **_host_params(host))
                for service in host.services:
                    session.run(
                        MERGE_SERVICE,
                        host_id=host.id, id=service.id, name=service.name,
                        port=service.port, protocol=service.protocol,
                        version=service.version,
                    )
                    for vuln in service.vulnerabilities:
                        session.run(
                            MERGE_VULNERABILITY,
                            service_id=service.id, cve_id=vuln.cve_id, cvss=vuln.cvss,
                            exploitability=vuln.exploitability,
                            privilege_gained=vuln.privilege_gained.value,
                            description=vuln.description,
                        )
                for credential in host.credentials:
                    session.run(
                        MERGE_CREDENTIAL,
                        host_id=host.id, id=credential.id, username=credential.username,
                        kind=credential.kind, privilege=credential.privilege.value,
                        strength=credential.strength,
                    )
                    for target in credential.grants_access:
                        session.run(
                            MERGE_GRANTS,
                            credential_id=credential.id, host_id=target,
                            privilege=credential.privilege.value,
                        )
            for user in model.users.values():
                session.run(
                    MERGE_USER,
                    id=user.id, username=user.username, role=user.role,
                    privilege=user.privilege.value,
                )
                for host_id in user.logs_into:
                    session.run(
                        MERGE_LOGS_INTO,
                        user_id=user.id, host_id=host_id, privilege=user.privilege.value,
                    )
            for connection in model.connections:
                if connection.source == "INTERNET" or connection.target == "INTERNET":
                    continue  # synthetic node, not an asset
                session.run(
                    MERGE_CONNECTION,
                    source=connection.source, target=connection.target,
                    protocol=connection.protocol, ports=list(connection.ports),
                    filtered=connection.filtered,
                )

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

    def paths_to_crown_jewel(self, start: str, limit: int = 10) -> list[dict]:
        """Run the traversal server-side. Useful for ad-hoc investigation."""
        with self.driver.session(database=self.database) as session:
            result = session.run(PATHS_TO_CROWN_JEWEL, start=start, limit=limit)
            return [dict(record) for record in result]

    def reload(self) -> NetworkModel:
        """Rebuild the model from what is in the database."""
        from ..graph.loader import build_model

        with self.driver.session(database=self.database) as session:
            host_rows = [dict(r) for r in session.run(FETCH_HOSTS)]
            conn_rows = [dict(r) for r in session.run(FETCH_CONNECTIONS)]

        raw = {
            "name": "neo4j",
            "hosts": [_row_to_host(row) for row in host_rows],
            "connections": [
                {
                    "from": row["source"], "to": row["target"],
                    "protocol": row.get("protocol") or "tcp",
                    "ports": row.get("ports") or [],
                    "filtered": row.get("filtered") or 0.0,
                }
                for row in conn_rows
            ],
        }
        model = build_model(raw, default_name="neo4j")
        self._memory = InMemoryGraphRepository(model)
        return model

    # -- internals ---------------------------------------------------------

    def _projection(self) -> InMemoryGraphRepository:
        if self._memory is None:
            self.reload()
        assert self._memory is not None
        return self._memory


def _host_params(host: Host) -> dict:
    return {
        "id": host.id, "name": host.name, "ip": host.ip, "os": host.os,
        "exposure": host.exposure.value, "criticality": host.criticality,
        "is_crown_jewel": host.is_crown_jewel, "patch_level": host.patch_level,
        "tags": list(host.tags),
    }


def _row_to_host(row: dict) -> dict:
    """Map one FETCH_HOSTS record back into loader-shaped data."""
    node = dict(row["h"])
    services: dict[str, dict] = {}
    for entry in row.get("services") or []:
        service = entry.get("service")
        if service is None:
            continue
        service = dict(service)
        bucket = services.setdefault(
            service["id"],
            {
                "id": service["id"], "name": service.get("name", "unknown"),
                "port": service.get("port", 0),
                "protocol": service.get("protocol", "tcp"),
                "version": service.get("version", ""),
                "vulnerabilities": [],
            },
        )
        vuln = entry.get("vuln")
        if vuln is not None:
            vuln = dict(vuln)
            bucket["vulnerabilities"].append(
                {
                    "cve": vuln.get("cve_id"), "cvss": vuln.get("cvss", 5.0),
                    "exploitability": vuln.get("exploitability", 0.5),
                    "privilege_gained": vuln.get("privilege_gained", "USER"),
                    "description": vuln.get("description", ""),
                }
            )

    credentials: dict[str, dict] = {}
    for entry in row.get("credentials") or []:
        credential = entry.get("credential")
        if credential is None:
            continue
        credential = dict(credential)
        bucket = credentials.setdefault(
            credential["id"],
            {
                "id": credential["id"], "username": credential.get("username", "unknown"),
                "kind": credential.get("kind", "password"),
                "privilege": credential.get("privilege", "USER"),
                "strength": credential.get("strength", 0.5),
                "grants_access": [],
            },
        )
        grants = entry.get("grants")
        if grants:
            bucket["grants_access"].append(grants)

    return {
        "id": node["id"], "name": node.get("name", node["id"]),
        "ip": node.get("ip", ""), "os": node.get("os", "unknown"),
        "exposure": node.get("exposure", "INTERNAL"),
        "criticality": node.get("criticality", 0.5),
        "crown_jewel": node.get("is_crown_jewel", False),
        "patch_level": node.get("patch_level", 0.5),
        "tags": node.get("tags") or [],
        "services": list(services.values()),
        "credentials": list(credentials.values()),
    }


def build_graph_repository(settings=None):
    """Pick a graph backend from configuration.

    Returns the Neo4j repository when a uri is configured, otherwise the
    in-memory one. Callers get the protocol either way.
    """
    from ..config import settings as read_settings

    resolved = settings or read_settings()
    if resolved.neo4j.enabled:
        return Neo4jGraphRepository.connect(resolved.neo4j)
    return InMemoryGraphRepository()
