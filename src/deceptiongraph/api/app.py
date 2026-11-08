"""FastAPI service over the facade.

Read-only analysis is GET; anything that changes the deception posture or
reports an intrusion is POST. There is no UI - this exists so the system can be
driven by other software, including the agent tools in
:mod:`deceptiongraph.agent`.

Storage follows configuration (see :mod:`deceptiongraph.storage.backends`):

* ``DG_NEO4J_URI`` - networks are written to Neo4j and analysed from there;
  ``/graph/paths/{host}`` runs the traversal server-side in Cypher.
* ``DG_DATABASE_URL`` - every session, decoy, event, incident and experiment is
  recorded in PostgreSQL; ``/history/*`` reads it back.
* ``DG_REDIS_URL`` - ``/analysis`` results are cached by model fingerprint.

With none set, everything is in memory. The live loop itself (the mediator and
its profiles) is per-process either way; the databases are the durable record
of what it did. ``/health`` says which backends are actually reachable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Response
from pydantic import BaseModel, Field

from ..config import Settings, settings as read_settings
from ..deception.placement import OPTIONAL_STRATEGIES, STRATEGIES
from ..facade import SecurityFacade
from ..graph.loader import load_network
from ..runtime.events import Event, EventType
from ..runtime.mediator import SecurityMediator
from ..runtime.telemetry import get_telemetry
from ..storage.backends import Backends
from ..storage.cache import model_fingerprint
from .. import __version__


class DeployRequest(BaseModel):
    """Ask for a deception deployment."""

    budget: int = Field(3, ge=1, le=50)
    strategy: str | None = Field(
        None, description="random | risk | centrality | attack-path | ml"
    )


class EventRequest(BaseModel):
    """Report an observation - a decoy firing, or a host falling."""

    type: EventType
    actor_id: str = "unknown"
    host_id: str | None = None
    asset_id: str | None = None
    token: str | None = Field(None, description="Canary token from the decoy that fired")
    detail: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExperimentRequest(BaseModel):
    """Run the placement experiment."""

    budget: int = Field(3, ge=1, le=50)
    trials: int = Field(100, ge=1, le=5000)
    seed: int = 2024
    arms: list[str] | None = None


class _Workspace:
    """One network's live state: the facade plus its mediator."""

    def __init__(self, facade: SecurityFacade, session_id: int | None = None) -> None:
        self.facade = facade
        self.mediator: SecurityMediator | None = None
        self.session_id = session_id
        """Row in the relational ``sessions`` table, when PostgreSQL is configured."""
        self.recorded_through = 0
        """Highest event sequence already written to the relational store."""

    def ensure_mediator(self, max_decoys: int) -> SecurityMediator:
        if self.mediator is None:
            self.mediator = SecurityMediator(
                self.facade.repository,
                deception=self.facade.deception,
                deployment=self.facade.deployment,
                max_total_decoys=max_decoys,
            )
        return self.mediator


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. Takes settings so tests can inject their own."""
    config = settings or read_settings()
    backends = Backends.from_settings(config)
    app = FastAPI(
        title="DeceptionGraph",
        version=__version__,
        description="Adaptive cyber-deception digital twin. Analysis, deception placement "
        "and the adaptation loop over a graph model of an enterprise network.",
    )
    app.state.backends = backends
    workspaces: dict[str, _Workspace] = {}

    def workspace(network: str | None = None) -> _Workspace:
        """Load a network on first use, then reuse it."""
        path = Path(network) if network else config.network_path
        key = str(path)
        if key not in workspaces:
            if not path.exists():
                raise HTTPException(404, f"network definition not found: {path}")
            try:
                model = load_network(path)
                repository = backends.graph_repository(model)
                facade = SecurityFacade(repository, strategy=config.default_strategy)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
            session_id = None
            if backends.store is not None:
                session_id = backends.store.open_session(
                    model.name, config.default_strategy, config.default_budget
                )
            workspaces[key] = _Workspace(facade, session_id=session_id)
        return workspaces[key]

    def record(ws: _Workspace, response: dict) -> dict:
        """Write whatever the live loop did since last time to PostgreSQL.

        By the time this runs the mediator has already acted on the event, so a
        database failure must not turn into an HTTP error - the sensor would
        retry and the event would be handled twice. It is reported in the
        response instead.
        """
        store = backends.store
        if store is None or ws.session_id is None:
            return response
        try:
            if ws.mediator is not None:
                fresh = [e for e in ws.mediator.bus.history
                         if e.sequence > ws.recorded_through]
                if fresh:
                    store.record_events(ws.session_id, fresh)
                    ws.recorded_through = max(e.sequence for e in fresh)
                store.record_incidents(ws.session_id, ws.mediator.incidents.incidents)
                store.record_decoys(ws.session_id, ws.mediator.adaptation.live)
            elif ws.facade.deployment is not None:
                store.record_decoys(ws.session_id, ws.facade.deployment.assets)
        except Exception as exc:  # noqa: BLE001 - see docstring
            response["persistence_error"] = f"{type(exc).__name__}: {exc}"
        return response

    def history_store():
        if backends.store is None:
            raise HTTPException(
                503, "no relational store: set DG_DATABASE_URL to record history"
            )
        return backends.store

    # -- meta --------------------------------------------------------------

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        """Liveness, plus which backends are actually configured."""
        return {
            "status": "ok",
            "version": __version__,
            "backends": {**config.describe(), "status": backends.status()},
            "strategies": sorted(STRATEGIES) + list(OPTIONAL_STRATEGIES),
            "loaded_networks": sorted(workspaces),
        }

    @app.get("/metrics", tags=["meta"], include_in_schema=False)
    def metrics() -> Response:
        """Prometheus metrics for the live loop (see runtime/telemetry.py)."""
        body, content_type = get_telemetry().exposition()
        return Response(content=body, media_type=content_type)

    # -- analysis ----------------------------------------------------------

    @app.get("/network", tags=["analysis"])
    def network_summary(network: str | None = Query(None)) -> dict:
        """What asset discovery found."""
        return workspace(network).facade.model.summary()

    @app.get("/analysis", tags=["analysis"])
    def analysis(network: str | None = Query(None)) -> dict:
        """Attack graph, risk ranking, worst path and choke points."""
        facade = workspace(network).facade
        key = f"analysis:{model_fingerprint(facade.model)}"
        cached = backends.cache.get(key)
        if cached is not None:
            return cached
        result = facade.analyse_network().as_dict()
        backends.cache.set(key, result)
        return result

    @app.get("/paths/{host_id}", tags=["analysis"])
    def paths(
        host_id: str,
        network: str | None = Query(None),
        all_paths: bool = Query(False, description="Enumerate every simple path"),
        limit: int = Query(5, ge=1, le=100),
    ) -> dict:
        """Attack paths to one host."""
        facade = workspace(network).facade
        if host_id not in facade.model.hosts:
            raise HTTPException(404, f"unknown host: {host_id}")
        if all_paths:
            found = facade.attack.paths(host_id)[:limit]
        else:
            best = facade.attack.best_path(host_id)
            found = [best] if best else []
        return {"host_id": host_id, "paths": [p.as_dict() for p in found]}

    @app.get("/predict/{host_id}", tags=["analysis"])
    def predict(
        host_id: str, network: str | None = Query(None), depth: int = Query(4, ge=1, le=20)
    ) -> dict:
        """Where an attacker on this host goes next."""
        facade = workspace(network).facade
        if host_id not in facade.model.hosts:
            raise HTTPException(404, f"unknown host: {host_id}")
        return {
            "from": host_id,
            "objective": facade.predictor.objective(host_id),
            "next_hops": [h.as_dict() for h in facade.next_moves(host_id)],
            "trajectory": facade.predict_from(host_id, depth=depth).as_dict(),
        }

    # -- deception ---------------------------------------------------------

    @app.post("/deception/deploy", tags=["deception"])
    def deploy(request: DeployRequest, network: str | None = Query(None)) -> dict:
        """Place decoys. Replaces any previous deployment for this network."""
        ws = workspace(network)
        try:
            deployment = ws.facade.deploy_deception(
                budget=request.budget, strategy=request.strategy
            )
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(422, str(exc)) from exc
        ws.mediator = None  # the posture changed; rebuild the loop around it
        return record(ws, deployment.as_dict())

    @app.get("/deception", tags=["deception"])
    def deception(network: str | None = Query(None)) -> dict:
        """The current deployment, or 404 if nothing is deployed."""
        ws = workspace(network)
        if ws.mediator is not None:
            return {
                "live_assets": [a.as_dict() for a in ws.mediator.live_assets],
                "coverage": ws.mediator.adaptation.coverage().as_dict(),
                "adaptations": [a.as_dict() for a in ws.mediator.adaptation.history],
            }
        if ws.facade.deployment is None:
            raise HTTPException(404, "no deception deployed; POST /deception/deploy first")
        return ws.facade.deployment.as_dict()

    @app.get("/deception/compare", tags=["deception"])
    def compare(
        network: str | None = Query(None),
        budget: int = Query(3, ge=1, le=50),
        seed: int = Query(1337),
    ) -> dict:
        """Static comparison of the placement strategies by coverage."""
        results = workspace(network).facade.deception.compare(budget=budget, seed=seed)
        return {"budget": budget, "results": [d.as_dict() for d in results]}

    # -- runtime -----------------------------------------------------------

    @app.post("/events", tags=["runtime"])
    def report_event(request: EventRequest, network: str | None = Query(None)) -> dict:
        """Report an observation and get the coordinated response back.

        This is the endpoint a real sensor would call. If a token is supplied
        and matches a live decoy, the asset is resolved automatically.
        """
        ws = workspace(network)
        if ws.facade.deployment is None:
            # A sensor should not have to deploy deception before reporting;
            # stand up the default posture so the event has somewhere to land.
            ws.facade.deploy_deception(budget=config.default_budget)
        mediator = ws.ensure_mediator(config.max_total_decoys)

        asset_id = request.asset_id
        host_id = request.host_id
        if asset_id is None and request.token:
            resolved = next(
                (a for a in mediator.adaptation.live if a.marker.token == request.token), None
            )
            if resolved is None:
                raise HTTPException(404, f"no decoy matches token {request.token}")
            asset_id = resolved.id
            # The token says which decoy fired, and so where the attacker is.
            host_id = host_id or resolved.host_id

        reaction = mediator.handle(
            Event(
                type=request.type, actor_id=request.actor_id, host_id=host_id,
                asset_id=asset_id, token=request.token, detail=request.detail,
                metadata=request.metadata,
            )
        )
        return record(ws, reaction.as_dict())

    @app.get("/status", tags=["runtime"])
    def status(network: str | None = Query(None)) -> dict:
        """Current defensive posture: decoys, incidents, profile, risk."""
        ws = workspace(network)
        if ws.mediator is None:
            raise HTTPException(404, "no runtime loop active; POST an event first")
        return ws.mediator.status()

    @app.get("/incidents", tags=["runtime"])
    def incidents(network: str | None = Query(None)) -> dict:
        ws = workspace(network)
        if ws.mediator is None:
            return {"incidents": []}
        return {"incidents": [i.as_dict() for i in ws.mediator.incidents.incidents]}

    @app.get("/timeline", tags=["runtime"])
    def timeline(network: str | None = Query(None), limit: int = Query(100, ge=1, le=1000)) -> dict:
        ws = workspace(network)
        if ws.mediator is None:
            return {"events": []}
        return {"events": list(ws.mediator.timeline())[-limit:]}

    # -- experiments -------------------------------------------------------

    @app.post("/experiments", tags=["experiments"])
    def run_experiment(request: ExperimentRequest, network: str | None = Query(None)) -> dict:
        """Run the placement experiment. Slow - it is a Monte Carlo simulation."""
        from ..experiments.runner import DEFAULT_ARMS, ExperimentRunner

        path = Path(network) if network else config.network_path
        if not path.exists():
            raise HTTPException(404, f"network definition not found: {path}")
        arms = tuple(request.arms) if request.arms else DEFAULT_ARMS
        known = set(STRATEGIES) | set(OPTIONAL_STRATEGIES) | {"adaptive"}
        unknown = [a for a in arms if a not in known]
        if unknown:
            raise HTTPException(422, f"unknown arms: {', '.join(unknown)}")

        runner = ExperimentRunner(path, trials=request.trials, seed=request.seed)
        try:
            report = runner.run(budget=request.budget, arms=arms)
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(422, str(exc)) from exc
        result = report.as_dict()
        if backends.store is not None:
            result["experiment_id"] = backends.store.record_experiment(report)
        return result

    # -- graph store -------------------------------------------------------

    @app.get("/graph/paths/{host_id}", tags=["graph"])
    def graph_paths(
        host_id: str, network: str | None = Query(None), limit: int = Query(10, ge=1, le=100)
    ) -> dict:
        """Routes from a host to the crown jewels, traversed in Neo4j itself."""
        repository = workspace(network).facade.repository
        if not hasattr(repository, "paths_to_crown_jewel"):
            raise HTTPException(503, "Neo4j is not configured: set DG_NEO4J_URI")
        if host_id not in repository.model.hosts:
            raise HTTPException(404, f"unknown host: {host_id}")
        return {"host_id": host_id, "network": repository.network,
                "paths": repository.paths_to_crown_jewel(host_id, limit=limit)}

    # -- history (PostgreSQL) ----------------------------------------------

    @app.get("/history/counts", tags=["history"])
    def history_counts() -> dict:
        """How much has been recorded, across every session."""
        return history_store().counts()

    @app.get("/history/alerts", tags=["history"])
    def history_alerts(
        severity: str | None = Query(None), session_id: int | None = Query(None)
    ) -> dict:
        return {"alerts": history_store().alerts(session_id=session_id, severity=severity)}

    @app.get("/history/events", tags=["history"])
    def history_events(
        session_id: int | None = Query(None), limit: int = Query(100, ge=1, le=1000)
    ) -> dict:
        return {"events": history_store().events(session_id=session_id, limit=limit)}

    @app.get("/history/decoys", tags=["history"])
    def history_decoys(session_id: int | None = Query(None)) -> dict:
        return {"decoys": history_store().decoys(session_id=session_id)}

    @app.get("/history/leaderboard", tags=["history"])
    def history_leaderboard() -> dict:
        """Mean detection per strategy over every experiment ever recorded."""
        return {"strategies": history_store().strategy_leaderboard()}

    @app.get("/report", tags=["meta"])
    def report(network: str | None = Query(None)) -> dict:
        """Everything known about this network, as one document."""
        return workspace(network).facade.generate_report()

    return app


app = create_app()
