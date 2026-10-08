"""MCP-style tool definitions, so an LLM agent can drive the system.

Each tool is a name, a JSON Schema for its arguments, and a callable. That is
the shape both the Model Context Protocol and OpenAI-style function calling
want, so :func:`tool_schemas` output can be handed to either without
translation. Nothing here imports an LLM client - this is the tool surface,
not an agent.

Two decisions worth stating:

*Tools are read-mostly by default.* `analyse_network`, `find_attack_paths`,
`predict_movement` and `get_status` only read. `deploy_deception` and
`report_event` change state, and are flagged ``mutates=True`` so a caller can
require confirmation before exposing them. An agent that can silently
re-arrange your deception posture is a worse problem than the one it solves.

*Errors come back as data.* A tool that raises inside an agent loop usually
derails it, so every tool returns ``{"error": ...}`` instead and lets the
agent decide what to do.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..deception.placement import STRATEGIES
from ..facade import SecurityFacade
from ..runtime.events import Event, EventType
from ..runtime.mediator import SecurityMediator

STRATEGY_NAMES = sorted(STRATEGIES)
EVENT_NAMES = [e.value for e in EventType]


@dataclass(frozen=True, slots=True)
class Tool:
    """One callable tool with its schema."""

    name: str
    description: str
    parameters: dict
    handler: Callable[..., dict]
    mutates: bool = False

    def schema(self) -> dict:
        """MCP / function-calling tool definition."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.parameters,
        }

    def __call__(self, **kwargs) -> dict:
        try:
            return self.handler(**kwargs)
        except Exception as exc:  # noqa: BLE001 - errors are data for the agent
            return {"error": f"{type(exc).__name__}: {exc}"}


class DeceptionGraphTools:
    """The tool surface for one network.

    Holds a facade and, once an event arrives, a mediator - so an agent can
    analyse, deploy, report an intrusion and read the consequences across
    several turns without losing state.
    """

    def __init__(
        self, network: str | Path | None = None, strategy: str | None = None
    ) -> None:
        from ..config import settings as read_settings

        self._network = Path(network) if network else read_settings().network_path
        self._strategy = strategy or read_settings().default_strategy
        self._facade: SecurityFacade | None = None
        self._mediator: SecurityMediator | None = None

    # -- state -------------------------------------------------------------

    @property
    def facade(self) -> SecurityFacade:
        if self._facade is None:
            self._facade = SecurityFacade(self._network, strategy=self._strategy)
        return self._facade

    def _mediator_for(self) -> SecurityMediator:
        if self._mediator is None:
            if self.facade.deployment is None:
                self.facade.deploy_deception(budget=3)
            self._mediator = SecurityMediator(
                self.facade.repository,
                deception=self.facade.deception,
                deployment=self.facade.deployment,
            )
        return self._mediator

    # -- tool handlers -----------------------------------------------------

    def analyse_network(self) -> dict:
        """Summary, risk ranking, worst path and choke points."""
        analysis = self.facade.analyse_network()
        worst = analysis.most_dangerous_path
        return {
            "network": self.facade.model.name,
            "summary": analysis.summary,
            "network_risk": round(analysis.risk.score, 4),
            "crown_jewel_exposure": round(analysis.risk.crown_jewel_exposure, 4),
            "most_dangerous_path": {
                "route": worst.describe(),
                "probability": round(worst.probability, 4),
                "risk": round(worst.risk, 4),
            }
            if worst
            else None,
            "choke_points": {k: round(v, 4) for k, v in analysis.choke_points.items()},
            "top_assets": [
                {
                    "host_id": a.host_id, "score": round(a.score, 4),
                    "compromise_probability": round(a.compromise_probability, 4),
                    "is_crown_jewel": a.is_crown_jewel,
                }
                for a in analysis.risk.top(5)
            ],
        }

    def find_attack_paths(self, host_id: str, all_paths: bool = False, limit: int = 5) -> dict:
        """Attack paths to a host."""
        if host_id not in self.facade.model.hosts:
            return {
                "error": f"unknown host {host_id!r}",
                "known_hosts": sorted(self.facade.model.hosts),
            }
        if all_paths:
            found = self.facade.attack.paths(host_id)[:limit]
        else:
            best = self.facade.attack.best_path(host_id)
            found = [best] if best else []
        return {
            "host_id": host_id,
            "path_count": len(found),
            "paths": [
                {
                    "route": p.describe(), "hops": p.length,
                    "probability": round(p.probability, 4), "risk": round(p.risk, 4),
                    "steps": [s.describe() for s in p.steps],
                }
                for p in found
            ],
        }

    def predict_movement(self, host_id: str, depth: int = 4) -> dict:
        """Where an attacker on this host is likely to go next."""
        if host_id not in self.facade.model.hosts:
            return {
                "error": f"unknown host {host_id!r}",
                "known_hosts": sorted(self.facade.model.hosts),
            }
        trajectory = self.facade.predict_from(host_id, depth=depth)
        return {
            "from": host_id,
            "objective": self.facade.predictor.objective(host_id),
            "predicted_route": trajectory.describe(),
            "confidence": round(trajectory.confidence, 4),
            "next_hops": [
                {
                    "target": h.target, "likelihood": round(h.probability, 4),
                    "vector": h.vector.value,
                    "leads_to_crown_jewel": h.leads_to_crown_jewel,
                }
                for h in self.facade.next_moves(host_id)
            ],
        }

    def deploy_deception(self, budget: int = 3, strategy: str | None = None) -> dict:
        """Place decoys. Changes the deception posture."""
        if budget < 1:
            return {"error": f"budget must be at least 1, got {budget}"}
        if strategy is not None and strategy not in STRATEGIES:
            return {"error": f"unknown strategy {strategy!r}", "known": STRATEGY_NAMES}
        deployment = self.facade.deploy_deception(budget=budget, strategy=strategy)
        self._mediator = None
        return {
            "strategy": deployment.strategy,
            "recommendations": list(deployment.recommendations()),
            "decoys": [
                {
                    "host_id": a.host_id, "kind": a.kind.value, "name": a.lure.name,
                    "mimics": a.protects, "token": a.marker.token,
                    "detection_probability": round(a.detection_probability, 4),
                    "watches": a.sensor.watches,
                }
                for a in deployment.assets
            ],
            "coverage": deployment.coverage.as_dict(),
        }

    def compare_strategies(self, budget: int = 3) -> dict:
        """Compare placement strategies by coverage, without simulating."""
        if budget < 1:
            return {"error": f"budget must be at least 1, got {budget}"}
        results = self.facade.deception.compare(budget=budget)
        return {
            "budget": budget,
            "results": [
                {
                    "strategy": d.strategy, "hosts": list(d.hosts),
                    "detection_probability": round(d.coverage.detection_probability, 4),
                    "mean_hops_to_detection": (
                        None if d.coverage.mean_hops_to_detection is None
                        else round(d.coverage.mean_hops_to_detection, 4)
                    ),
                    "critical_asset_coverage": round(d.coverage.critical_asset_coverage, 4),
                }
                for d in results
            ],
        }

    def report_event(
        self,
        type: str,
        actor_id: str = "unknown",
        host_id: str | None = None,
        token: str | None = None,
        detail: str = "",
    ) -> dict:
        """Report an observation and get the coordinated response. Changes state."""
        try:
            event_type = EventType(type.upper())
        except ValueError:
            return {"error": f"unknown event type {type!r}", "known": EVENT_NAMES}

        mediator = self._mediator_for()
        asset_id = None
        if token:
            resolved = next(
                (a for a in mediator.adaptation.live if a.marker.token == token), None
            )
            if resolved is None:
                return {"error": f"no decoy matches token {token!r}"}
            asset_id = resolved.id
            host_id = host_id or resolved.host_id

        reaction = mediator.handle(
            Event(
                type=event_type, actor_id=actor_id, host_id=host_id,
                asset_id=asset_id, token=token, detail=detail,
            )
        )
        profile = reaction.profile
        return {
            "narrative": reaction.describe(),
            "deception_triggered": reaction.triggered,
            "stage": profile.stage.value if profile else None,
            "sophistication": profile.sophistication.value if profile else None,
            "objective": profile.objective if profile else None,
            "likely_next_target": profile.likely_next_target if profile else None,
            "confidence": round(profile.confidence, 4) if profile else None,
            "incident": reaction.incident.as_dict() if reaction.incident else None,
            "adapted": (
                reaction.adaptation.describe()
                if reaction.adaptation and reaction.adaptation.changed
                else None
            ),
        }

    def get_status(self) -> dict:
        """Current defensive posture."""
        if self._mediator is None:
            return {
                "runtime_active": False,
                "note": "no events reported yet; call report_event to start the loop",
                "deployment": (
                    self.facade.deployment.as_dict()["coverage"]
                    if self.facade.deployment
                    else None
                ),
            }
        return {"runtime_active": True, **self._mediator.status()}

    # -- registry ----------------------------------------------------------

    def tools(self) -> tuple[Tool, ...]:
        """Every tool, with its schema."""
        host_arg = {"type": "string", "description": "Host id, e.g. 'web01'."}
        return (
            Tool(
                name="analyse_network",
                description=(
                    "Analyse the network: risk score, the most dangerous attack path from "
                    "the internet, choke points, and the highest-risk assets. Call this "
                    "first - the other tools are easier to use once you know the topology."
                ),
                parameters={"type": "object", "properties": {}, "required": []},
                handler=self.analyse_network,
            ),
            Tool(
                name="find_attack_paths",
                description=(
                    "Find how an attacker could reach a specific host, with the probability "
                    "and risk of each route."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "host_id": host_arg,
                        "all_paths": {
                            "type": "boolean",
                            "description": "Enumerate every route instead of only the likeliest.",
                            "default": False,
                        },
                        "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 5},
                    },
                    "required": ["host_id"],
                },
                handler=self.find_attack_paths,
            ),
            Tool(
                name="predict_movement",
                description=(
                    "Given a compromised host, predict where the attacker moves next, with "
                    "a likelihood for each option and their probable objective."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "host_id": host_arg,
                        "depth": {"type": "integer", "minimum": 1, "maximum": 20, "default": 4},
                    },
                    "required": ["host_id"],
                },
                handler=self.predict_movement,
            ),
            Tool(
                name="compare_strategies",
                description=(
                    "Compare decoy placement strategies at a given budget by expected "
                    "detection coverage. Read-only: places nothing."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "budget": {"type": "integer", "minimum": 1, "maximum": 50, "default": 3}
                    },
                    "required": [],
                },
                handler=self.compare_strategies,
            ),
            Tool(
                name="deploy_deception",
                description=(
                    "Place decoys across the network and report the resulting coverage. "
                    "CHANGES STATE: replaces any existing deployment."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "budget": {
                            "type": "integer", "minimum": 1, "maximum": 50, "default": 3,
                            "description": "How many decoys to place.",
                        },
                        "strategy": {
                            "type": "string", "enum": STRATEGY_NAMES,
                            "description": "Placement algorithm. Defaults to attack-path.",
                        },
                    },
                    "required": [],
                },
                handler=self.deploy_deception,
                mutates=True,
            ),
            Tool(
                name="report_event",
                description=(
                    "Report an observed event - a decoy being touched, or a host being "
                    "compromised - and get back the updated attacker profile, the incident, "
                    "and any change to the deception posture. CHANGES STATE."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string", "enum": EVENT_NAMES,
                            "description": "What was observed.",
                        },
                        "actor_id": {
                            "type": "string", "default": "unknown",
                            "description": "Identifier for the actor, so events correlate.",
                        },
                        "host_id": host_arg,
                        "token": {
                            "type": "string",
                            "description": "Canary token from the decoy that fired, if known.",
                        },
                        "detail": {"type": "string", "default": ""},
                    },
                    "required": ["type"],
                },
                handler=self.report_event,
                mutates=True,
            ),
            Tool(
                name="get_status",
                description=(
                    "Current defensive posture: live decoys, open incidents, the most "
                    "advanced attacker profile, and network risk."
                ),
                parameters={"type": "object", "properties": {}, "required": []},
                handler=self.get_status,
            ),
        )

    def by_name(self, name: str) -> Tool | None:
        return next((t for t in self.tools() if t.name == name), None)

    def call(self, name: str, arguments: dict[str, Any] | None = None) -> dict:
        """Dispatch by name, the way an agent loop would."""
        tool = self.by_name(name)
        if tool is None:
            return {
                "error": f"unknown tool {name!r}",
                "known": [t.name for t in self.tools()],
            }
        return tool(**(arguments or {}))

    def read_only_tools(self) -> tuple[Tool, ...]:
        """The subset safe to expose without confirmation."""
        return tuple(t for t in self.tools() if not t.mutates)


def tool_schemas(network: str | Path | None = None, read_only: bool = False) -> list[dict]:
    """Tool definitions for an MCP server or a function-calling request."""
    tools = DeceptionGraphTools(network)
    selected = tools.read_only_tools() if read_only else tools.tools()
    return [t.schema() for t in selected]
