"""Storage adapters: Neo4j for the graph, PostgreSQL for the record, Redis to cache.

All three are optional. With nothing configured the system runs entirely in
memory, which is how the tests and the CLI run by default.
"""

from .cache import Cache, NullCache, RedisCache, build_cache, model_fingerprint
from .neo4j_repository import Neo4jGraphRepository, build_graph_repository

__all__ = [
    "Cache",
    "Neo4jGraphRepository",
    "NullCache",
    "RedisCache",
    "build_cache",
    "build_graph_repository",
    "model_fingerprint",
]


def __getattr__(name: str):
    """Load the SQLAlchemy layer lazily.

    Importing `deceptiongraph.storage` must not require SQLAlchemy to be
    installed, since the in-memory path never touches it.
    """
    if name in {"RelationalStore", "Base"}:
        from . import relational

        return getattr(relational, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
