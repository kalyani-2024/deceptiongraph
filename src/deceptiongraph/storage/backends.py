"""The configured storage backends, held in one place.

The API (and the ``dgraph db`` commands) ask this object for a graph
repository, the relational store and the cache, and never branch on what is
configured themselves:

* **Neo4j** configured: every network the service loads is written to Neo4j
  and analysed from the projection, so the graph in the database is the graph
  the answers came from.
* **PostgreSQL** configured: sessions, decoys, events, incidents and
  experiment results are recorded as they happen.
* **Redis** configured: network analyses are cached by model fingerprint.

Nothing configured: in memory, exactly as before.

A backend that is configured but unreachable at startup is reported as down by
:meth:`status` (and so by ``/health``) rather than crashing the service; the
service then carries on without it. Silently dropping writes would be worse
than failing, which is why ``/health`` says so plainly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ..config import Settings
from ..graph.model import NetworkModel
from ..graph.repository import GraphRepository, InMemoryGraphRepository
from .cache import Cache, NullCache, RedisCache

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Backends:
    settings: Settings
    store: Any = None
    """A :class:`RelationalStore`, or None."""
    cache: Cache = field(default_factory=NullCache)
    errors: dict[str, str] = field(default_factory=dict)
    _neo4j_driver: Any = None

    @classmethod
    def from_settings(cls, settings: Settings) -> "Backends":
        backends = cls(settings=settings)
        if settings.postgres.enabled:
            try:
                from .relational import RelationalStore

                backends.store = RelationalStore(settings.postgres.url, echo=settings.postgres.echo)
            except Exception as exc:  # noqa: BLE001 - report, do not crash the service
                backends._down("postgresql", exc)
        if settings.redis.enabled:
            try:
                cache = RedisCache.connect(settings.redis)
                cache.ping()
                backends.cache = cache
            except Exception as exc:  # noqa: BLE001
                backends._down("redis", exc)
        if settings.neo4j.enabled:
            try:
                from .neo4j_repository import Neo4jGraphRepository

                repository = Neo4jGraphRepository.connect(settings.neo4j)
                backends._neo4j_driver = repository.driver
            except Exception as exc:  # noqa: BLE001
                backends._down("neo4j", exc)
        return backends

    def _down(self, name: str, exc: Exception) -> None:
        self.errors[name] = f"{type(exc).__name__}: {exc}"
        log.warning("%s is configured but unavailable: %s", name, exc)

    # -- what callers use --------------------------------------------------

    @property
    def neo4j_live(self) -> bool:
        return self._neo4j_driver is not None

    def graph_repository(self, model: NetworkModel) -> GraphRepository:
        """Neo4j when it is up (the model is written through), memory otherwise."""
        if self._neo4j_driver is None:
            return InMemoryGraphRepository(model)
        from .neo4j_repository import Neo4jGraphRepository

        repository = Neo4jGraphRepository(
            self._neo4j_driver, database=self.settings.neo4j.database, network=model.name
        )
        repository.save(model)
        return repository

    def status(self) -> dict[str, str]:
        """``live``, ``down: <reason>`` or ``not configured``, per backend."""
        report = {}
        for name, configured, probe in (
            ("neo4j", self.settings.neo4j.enabled, self._ping_neo4j),
            ("postgresql", self.settings.postgres.enabled,
             lambda: self.store is not None and self.store.ping()),
            ("redis", self.settings.redis.enabled,
             lambda: self.cache.enabled and self.cache.ping()),
        ):
            if not configured:
                report[name] = "not configured"
                continue
            if name in self.errors:
                report[name] = f"down: {self.errors[name]}"
                continue
            try:
                report[name] = "live" if probe() else "down"
            except Exception as exc:  # noqa: BLE001
                report[name] = f"down: {type(exc).__name__}: {exc}"
        return report

    def close(self) -> None:
        if self._neo4j_driver is not None:
            self._neo4j_driver.close()
        if self.store is not None:
            self.store.close()

    def _ping_neo4j(self) -> bool:
        if self._neo4j_driver is None:
            return False
        self._neo4j_driver.verify_connectivity()
        return True
