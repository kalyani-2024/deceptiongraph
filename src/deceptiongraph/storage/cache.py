"""Redis cache for derived graphs and session state.

The attack graph is derived, not stored, and deriving it costs real time on a
large network. Caching it keyed on a hash of the model means a second API
request against an unchanged network skips the work entirely.

A null implementation is always available, so nothing has to branch on whether
Redis is configured - `build_cache()` returns something that answers `get` and
`set` either way.

VERIFIED AGAINST THE NULL AND FAKE BACKENDS ONLY. `RedisCache` has not been
run against a live Redis server; `tests/test_storage.py` drives it through a
fake client that implements the three commands used here.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Cache(Protocol):
    """What the rest of the system needs from a cache."""

    enabled: bool

    def get(self, key: str) -> Any | None: ...

    def set(self, key: str, value: Any, ttl: int | None = None) -> None: ...

    def invalidate(self, key: str) -> None: ...


class NullCache:
    """Does nothing, successfully. The default when Redis is not configured."""

    enabled = False

    def get(self, key: str) -> Any | None:
        return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        return None

    def invalidate(self, key: str) -> None:
        return None


class RedisCache:
    """JSON-serialising cache over a Redis client."""

    enabled = True

    def __init__(self, client: Any, ttl_seconds: int = 300, prefix: str = "dg") -> None:
        self.client = client
        self.ttl_seconds = ttl_seconds
        self.prefix = prefix

    @classmethod
    def connect(cls, settings=None) -> "RedisCache":
        from ..config import RedisSettings

        resolved = settings or RedisSettings.from_env()
        if not resolved.enabled:
            raise RuntimeError("Redis is not configured; set DG_REDIS_URL")
        import redis

        return cls(redis.Redis.from_url(resolved.url), ttl_seconds=resolved.ttl_seconds)

    def _key(self, key: str) -> str:
        return f"{self.prefix}:{key}"

    def get(self, key: str) -> Any | None:
        """Return the cached value, or None. A corrupt entry is a miss, not a crash."""
        raw = self.client.get(self._key(key))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            self.invalidate(key)
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        self.client.set(
            self._key(key),
            json.dumps(value, default=str),
            ex=ttl if ttl is not None else self.ttl_seconds,
        )

    def invalidate(self, key: str) -> None:
        self.client.delete(self._key(key))


def build_cache(settings=None) -> Cache:
    """Redis when configured, a null cache otherwise."""
    from ..config import settings as read_settings

    resolved = settings or read_settings()
    if resolved.redis.enabled:
        return RedisCache.connect(resolved.redis)
    return NullCache()


def model_fingerprint(model) -> str:
    """Stable hash of a network model, for use as a cache key.

    Covers everything the attack graph is derived from. Anything that changes
    a traversal probability has to change this, or the cache would serve a
    stale graph - so it includes patch levels and filtering, not just topology.
    """
    parts: list[str] = [model.name]
    for host in sorted(model.hosts.values(), key=lambda h: h.id):
        parts.append(
            f"{host.id}|{host.criticality}|{host.patch_level}|{host.is_crown_jewel}"
            f"|{host.exposure.value}"
        )
        for service in host.services:
            parts.append(f"s:{service.id}:{service.port}")
            for vuln in service.vulnerabilities:
                parts.append(f"v:{vuln.cve_id}:{vuln.cvss}:{vuln.exploitability}")
        for credential in host.credentials:
            parts.append(
                f"c:{credential.id}:{credential.strength}:{','.join(credential.grants_access)}"
            )
    for connection in sorted(model.connections, key=lambda c: (c.source, c.target)):
        parts.append(f"e:{connection.source}->{connection.target}:{connection.filtered}")
    for user in sorted(model.users.values(), key=lambda u: u.id):
        parts.append(f"u:{user.id}:{','.join(user.logs_into)}")

    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return digest[:32]
