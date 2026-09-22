"""Storage seam for the asset graph.

Stage 1 ships an in-memory NetworkX backend. Stage 2 adds ``Neo4jGraphRepository``
implementing the same protocol, so nothing above this layer changes.
"""

from __future__ import annotations

from typing import Iterable, Protocol, runtime_checkable

import networkx as nx

from ..domain.entities import Host
from .builder import GraphBuilder
from .model import NetworkModel


@runtime_checkable
class GraphRepository(Protocol):
    """What the analysis layer needs from whatever stores the graph."""

    @property
    def model(self) -> NetworkModel: ...

    def save(self, model: NetworkModel) -> None: ...

    def host(self, host_id: str) -> Host | None: ...

    def hosts(self) -> Iterable[Host]: ...

    def asset_graph(self) -> nx.MultiDiGraph: ...

    def connectivity_graph(self) -> nx.DiGraph: ...

    def neighbours(self, host_id: str) -> tuple[str, ...]: ...


class InMemoryGraphRepository:
    """NetworkX-backed repository. Graphs are built once and cached."""

    def __init__(self, model: NetworkModel | None = None) -> None:
        self._model: NetworkModel | None = None
        self._asset_graph: nx.MultiDiGraph | None = None
        self._connectivity: nx.DiGraph | None = None
        if model is not None:
            self.save(model)

    @property
    def model(self) -> NetworkModel:
        if self._model is None:
            raise RuntimeError("no network loaded; call save(model) first")
        return self._model

    def save(self, model: NetworkModel) -> None:
        self._model = model
        builder = GraphBuilder(model)
        self._asset_graph = builder.build()
        self._connectivity = builder.build_connectivity()
        if model.root is None:
            model.build_default_composite()

    def host(self, host_id: str) -> Host | None:
        return self.model.hosts.get(host_id)

    def hosts(self) -> Iterable[Host]:
        return tuple(self.model.hosts.values())

    def asset_graph(self) -> nx.MultiDiGraph:
        if self._asset_graph is None:
            raise RuntimeError("no network loaded; call save(model) first")
        return self._asset_graph

    def connectivity_graph(self) -> nx.DiGraph:
        if self._connectivity is None:
            raise RuntimeError("no network loaded; call save(model) first")
        return self._connectivity

    def neighbours(self, host_id: str) -> tuple[str, ...]:
        graph = self.connectivity_graph()
        if host_id not in graph:
            return ()
        return tuple(graph.successors(host_id))
