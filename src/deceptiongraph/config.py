"""Configuration, read from the environment.

Everything has a working default, so the whole system runs with no services at
all: the in-memory NetworkX repository, no Postgres, no Redis. That is
deliberate - the analysis and deception layers are the project, and a
dependency on four containers to see them work would be a design failure.

Set `DG_NEO4J_URI` or `DG_DATABASE_URL` and the matching backend is used
instead. `storage.build_graph_repository()` decides based on what is
configured, not on what is installed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PREFIX = "DG_"


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(f"{PREFIX}{name}", default)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{PREFIX}{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True, slots=True)
class Neo4jSettings:
    """Graph store. Unset `uri` means use the in-memory repository."""

    uri: str | None = None
    user: str = "neo4j"
    password: str = "deceptiongraph"
    database: str = "neo4j"

    @property
    def enabled(self) -> bool:
        return bool(self.uri)

    @classmethod
    def from_env(cls) -> "Neo4jSettings":
        return cls(
            uri=_env("NEO4J_URI"),
            user=_env("NEO4J_USER", "neo4j") or "neo4j",
            password=_env("NEO4J_PASSWORD", "deceptiongraph") or "deceptiongraph",
            database=_env("NEO4J_DATABASE", "neo4j") or "neo4j",
        )


@dataclass(frozen=True, slots=True)
class PostgresSettings:
    """Relational store for sessions, alerts, decoys, events and experiments."""

    url: str | None = None
    echo: bool = False

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    @classmethod
    def from_env(cls) -> "PostgresSettings":
        return cls(url=_env("DATABASE_URL"), echo=_env_bool("SQL_ECHO", False))


@dataclass(frozen=True, slots=True)
class RedisSettings:
    """Cache for computed attack graphs and session state."""

    url: str | None = None
    ttl_seconds: int = 300

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    @classmethod
    def from_env(cls) -> "RedisSettings":
        return cls(url=_env("REDIS_URL"), ttl_seconds=_env_int("REDIS_TTL", 300))


@dataclass(frozen=True, slots=True)
class Settings:
    """Everything the application reads from its environment."""

    network_path: Path = field(default_factory=lambda: Path("data/networks/enterprise.yaml"))
    default_strategy: str = "attack-path"
    default_budget: int = 3
    max_total_decoys: int = 12
    neo4j: Neo4jSettings = field(default_factory=Neo4jSettings)
    postgres: PostgresSettings = field(default_factory=PostgresSettings)
    redis: RedisSettings = field(default_factory=RedisSettings)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            network_path=Path(_env("NETWORK", "data/networks/enterprise.yaml")),
            default_strategy=_env("STRATEGY", "attack-path") or "attack-path",
            default_budget=_env_int("BUDGET", 3),
            max_total_decoys=_env_int("MAX_DECOYS", 12),
            neo4j=Neo4jSettings.from_env(),
            postgres=PostgresSettings.from_env(),
            redis=RedisSettings.from_env(),
        )

    def describe(self) -> dict:
        """What is actually wired up, for the API's health endpoint."""
        return {
            "network_path": str(self.network_path),
            "default_strategy": self.default_strategy,
            "default_budget": self.default_budget,
            "graph_backend": "neo4j" if self.neo4j.enabled else "in-memory",
            "relational_backend": "postgresql" if self.postgres.enabled else "none",
            "cache_backend": "redis" if self.redis.enabled else "none",
        }


def settings() -> Settings:
    """Read settings fresh. Not cached, so tests can monkeypatch the environment."""
    return Settings.from_env()
