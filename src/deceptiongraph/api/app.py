"""FastAPI service over the facade.

Read-only analysis is GET; anything that changes the deception posture or
reports an intrusion is POST. There is no UI - this exists so the system can be
driven by other software, including the agent tools in
:mod:`deceptiongraph.agent`.

State is per-process and in-memory by default, held in a small registry keyed by
network name. That is a deliberate limit, not an oversight: a single-worker
service is enough to demonstrate the system, and anything multi-worker needs
the PostgreSQL and Redis backends wired up to share state properly. The
`/health` endpoint says which backends are live so a caller can tell.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from ..config import Settings, settings as read_settings
from ..deception.placement import STRATEGIES
from ..facade import SecurityFacade
from ..runtime.events import Event, EventType
from ..runtime.mediator import SecurityMediator
from .. import __version__


class DeployRequest(BaseModel):
    """Ask for a deception deployment."""

    budget: int = Field(3, ge=1, le=50)
    strategy: str | None = Field(None, description="random | risk | centrality | attack-path")


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

    def __init__(self, facade: SecurityFacade) -> None:
        self.facade = facade
        self.mediator: SecurityMediator | None = None

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
    app = FastAPI(
        title="DeceptionGraph",
        version=__version__,
        description="Adaptive cyber-deception digital twin. Analysis, deception placement "
        "and the adaptation loop over a graph model of an enterprise network.",
    )
    workspaces: dict[str, _Workspace] = {}

    def workspace(network: str | None = None) -> _Workspace:
        """Load a network on first use, then reuse it."""
        path = Path(network) if network else config.network_path
        key = str(path)
        if key not in workspaces:
            if not path.exists():
                raise HTTPException(404, f"network definition not found: {path}")
            try:
                workspaces[key] = _Workspace(
                    SecurityFacade(path, strategy=config.default_strategy)
                )
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
        return workspaces[key]

    # -- meta --------------------------------------------------------------

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        """Liveness, plus which backends are actually configured."""
        return {
            "status": "ok",
            "version": __version__,
            "backends": config.describe(),
            "strategies": sorted(STRATEGIES),
            "loaded_networks": sorted(workspaces),
        }

    # -- analysis ----------------------------------------------------------

    @app.get("/network", tags=["analysis"])
    def network_summary(network: str | None = Query(None)) -> dict:
        """What asset discovery found."""
        return workspace(network).facade.model.summary()

    @app.get("/analysis", tags=["analysis"])
    def analysis(network: str | None = Query(None)) -> dict:
        """Attack graph, risk ranking, worst path and choke points."""
        return workspace(network).facade.analyse_network().as_dict()

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
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        ws.mediator = None  # the posture changed; rebuild the loop around it
        return deployment.as_dict()

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
        if asset_id is None and request.token:
            resolved = next(
                (a for a in mediator.adaptation.live if a.marker.token == request.token), None
            )
            if resolved is None:
                raise HTTPException(404, f"no decoy matches token {request.token}")
            asset_id = resolved.id

        reaction = mediator.handle(
            Event(
                type=request.type, actor_id=request.actor_id, host_id=request.host_id,
                asset_id=asset_id, token=request.token, detail=request.detail,
                metadata=request.metadata,
            )
        )
        return reaction.as_dict()

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
        unknown = [a for a in arms if a != "adaptive" and a not in STRATEGIES]
        if unknown:
            raise HTTPException(422, f"unknown arms: {', '.join(unknown)}")

        runner = ExperimentRunner(path, trials=request.trials, seed=request.seed)
        return runner.run(budget=request.budget, arms=arms).as_dict()

    @app.get("/report", tags=["meta"])
    def report(network: str | None = Query(None)) -> dict:
        """Everything known about this network, as one document."""
        return workspace(network).facade.generate_report()

    return app


app = create_app()
