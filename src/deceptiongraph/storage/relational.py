"""PostgreSQL store for the operational record.

Neo4j holds the network's *shape*; this holds what *happened to it*: sessions,
events, decoys, alerts, experiments and their metrics. The split follows the
brief, and it is the right one - "which paths lead to the database" is a
traversal, while "how many alerts did strategy X raise last week" is an
aggregate over rows.

SQLite works too, which is what the tests use: pass
``sqlite+pysqlite:///:memory:`` and the schema builds identically. Postgres
specifics are avoided for exactly that reason.

VERIFIED AGAINST SQLITE ONLY. The schema and every query here are exercised in
`tests/test_storage.py` against an in-memory SQLite database. They have not
been run against a real PostgreSQL server, because this project has none to run
them against. The DDL uses nothing Postgres-specific, but that is an argument,
not a test result.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

from ..deception.assets import DeceptionAsset
from ..runtime.events import Event
from ..runtime.incidents import Incident


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class SessionRow(Base):
    """One analysis or defence session: a network, loaded at a point in time."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    network: Mapped[str] = mapped_column(String(200), index=True)
    strategy: Mapped[str] = mapped_column(String(50))
    budget: Mapped[int] = mapped_column(Integer, default=3)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    network_risk: Mapped[float | None] = mapped_column(Float, nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")

    decoys: Mapped[list["DecoyRow"]] = relationship(back_populates="session")
    events: Mapped[list["EventRow"]] = relationship(back_populates="session")
    alerts: Mapped[list["AlertRow"]] = relationship(back_populates="session")


class DecoyRow(Base):
    """A deployed deception asset."""

    __tablename__ = "decoys"

    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    host_id: Mapped[str] = mapped_column(String(100), index=True)
    name: Mapped[str] = mapped_column(String(200))
    mimics: Mapped[str | None] = mapped_column(String(100), nullable=True)
    token: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    believability: Mapped[float] = mapped_column(Float)
    fidelity: Mapped[float] = mapped_column(Float)
    detection_probability: Mapped[float] = mapped_column(Float)
    state: Mapped[str] = mapped_column(String(20), default="DEPLOYED")
    rationale: Mapped[str] = mapped_column(Text, default="")
    deployed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    session: Mapped[SessionRow] = relationship(back_populates="decoys")


class EventRow(Base):
    """One observation from the event bus."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String(40), index=True)
    actor_id: Mapped[str] = mapped_column(String(100), index=True)
    host_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    token: Mapped[str | None] = mapped_column(String(100), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[str] = mapped_column(Text, default="{}")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)

    session: Mapped[SessionRow] = relationship(back_populates="events")


class AlertRow(Base):
    """An incident as a human would see it."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), index=True)
    actor_id: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    stage: Mapped[str | None] = mapped_column(String(40), nullable=True)
    sophistication: Mapped[str | None] = mapped_column(String(20), nullable=True)
    objective: Mapped[str | None] = mapped_column(String(100), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    hosts: Mapped[str] = mapped_column(Text, default="[]")
    closed: Mapped[bool] = mapped_column(Boolean, default=False)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    session: Mapped[SessionRow] = relationship(back_populates="alerts")


class ExperimentRow(Base):
    """One experiment run: a network, a budget, a trial count."""

    __tablename__ = "experiments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    network: Mapped[str] = mapped_column(String(200), index=True)
    budget: Mapped[int] = mapped_column(Integer)
    trials: Mapped[int] = mapped_column(Integer)
    seed: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(Text, default="")
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    metrics: Mapped[list["MetricRow"]] = relationship(back_populates="experiment")


class MetricRow(Base):
    """One arm's scorecard within an experiment."""

    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    experiment_id: Mapped[int] = mapped_column(ForeignKey("experiments.id"), index=True)
    strategy: Mapped[str] = mapped_column(String(50), index=True)
    detection_rate: Mapped[float] = mapped_column(Float)
    detection_ci95: Mapped[float] = mapped_column(Float)
    mean_time_to_detection: Mapped[float | None] = mapped_column(Float, nullable=True)
    mean_path_length: Mapped[float] = mapped_column(Float)
    decoys_used: Mapped[int] = mapped_column(Integer)
    false_alerts_per_day: Mapped[float] = mapped_column(Float)
    critical_asset_coverage: Mapped[float] = mapped_column(Float)

    experiment: Mapped[ExperimentRow] = relationship(back_populates="metrics")


class RelationalStore:
    """Thin repository over the tables above.

    Deliberately not generic: a handful of named methods that the API and CLI
    actually call, rather than a leaky query builder.
    """

    def __init__(self, url: str, echo: bool = False, create: bool = True) -> None:
        self.engine = create_engine(url, echo=echo, future=True)
        if create:
            self.create_schema()

    @classmethod
    def from_settings(cls, settings=None) -> "RelationalStore | None":
        """Build from configuration, or None when no database is configured."""
        from ..config import settings as read_settings

        resolved = settings or read_settings()
        if not resolved.postgres.enabled:
            return None
        return cls(resolved.postgres.url, echo=resolved.postgres.echo)

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def drop_schema(self) -> None:
        Base.metadata.drop_all(self.engine)

    def session(self) -> Session:
        return Session(self.engine, future=True)

    # -- writes ------------------------------------------------------------

    def open_session(
        self, network: str, strategy: str, budget: int, network_risk: float | None = None
    ) -> int:
        with self.session() as db:
            row = SessionRow(
                network=network, strategy=strategy, budget=budget, network_risk=network_risk
            )
            db.add(row)
            db.commit()
            return row.id

    def record_decoys(
        self, session_id: int, assets: Iterable[DeceptionAsset]
    ) -> int:
        """Insert or update the decoys for a session. Returns how many were written."""
        written = 0
        with self.session() as db:
            for asset in assets:
                existing = db.get(DecoyRow, asset.id)
                if existing is not None:
                    existing.state = asset.state.value
                    written += 1
                    continue
                db.add(
                    DecoyRow(
                        id=asset.id, session_id=session_id, kind=asset.kind.value,
                        host_id=asset.host_id, name=asset.lure.name,
                        mimics=asset.protects, token=asset.marker.token,
                        believability=asset.lure.believability,
                        fidelity=asset.sensor.fidelity,
                        detection_probability=asset.detection_probability,
                        state=asset.state.value, rationale=asset.rationale,
                    )
                )
                written += 1
            db.commit()
        return written

    def record_events(self, session_id: int, events: Iterable[Event]) -> int:
        written = 0
        with self.session() as db:
            for event in events:
                db.add(
                    EventRow(
                        session_id=session_id, sequence=event.sequence,
                        type=event.type.value, actor_id=event.actor_id,
                        host_id=event.host_id, asset_id=event.asset_id,
                        token=event.token, detail=event.detail,
                        payload=json.dumps(event.metadata, default=str), at=event.at,
                    )
                )
                written += 1
            db.commit()
        return written

    def record_incidents(self, session_id: int, incidents: Iterable[Incident]) -> int:
        written = 0
        with self.session() as db:
            for incident in incidents:
                row = db.get(AlertRow, incident.id)
                if row is None:
                    row = AlertRow(id=incident.id, session_id=session_id,
                                   actor_id=incident.actor_id)
                    db.add(row)
                row.severity = incident.severity.value
                row.stage = incident.stage
                row.sophistication = incident.sophistication
                row.objective = incident.objective
                row.summary = incident.summary
                row.evidence_count = len(incident.evidence)
                row.hosts = json.dumps(list(incident.hosts))
                row.closed = incident.closed
                row.opened_at = incident.opened_at
                row.updated_at = incident.updated_at
                written += 1
            db.commit()
        return written

    def record_experiment(self, report) -> int:
        """Persist an :class:`ExperimentReport` and its arms."""
        with self.session() as db:
            experiment = ExperimentRow(
                network=report.network, budget=report.budget, trials=report.trials,
                seed=report.seed, verdict=report.verdict(),
            )
            db.add(experiment)
            db.flush()
            for arm in report.arms:
                m = arm.metrics
                db.add(
                    MetricRow(
                        experiment_id=experiment.id, strategy=arm.label,
                        detection_rate=m.detection_rate, detection_ci95=m.detection_ci95,
                        mean_time_to_detection=m.mean_time_to_detection,
                        mean_path_length=m.mean_path_length, decoys_used=m.decoys_used,
                        false_alerts_per_day=m.false_alerts_per_day,
                        critical_asset_coverage=m.critical_asset_coverage,
                    )
                )
            db.commit()
            return experiment.id

    # -- reads -------------------------------------------------------------

    def alerts(self, session_id: int | None = None, severity: str | None = None) -> list[dict]:
        stmt = select(AlertRow).order_by(AlertRow.updated_at.desc())
        if session_id is not None:
            stmt = stmt.where(AlertRow.session_id == session_id)
        if severity is not None:
            stmt = stmt.where(AlertRow.severity == severity)
        with self.session() as db:
            return [_alert_dict(r) for r in db.scalars(stmt)]

    def events(self, session_id: int | None = None, limit: int = 100) -> list[dict]:
        stmt = select(EventRow).order_by(EventRow.sequence.desc()).limit(limit)
        if session_id is not None:
            stmt = stmt.where(EventRow.session_id == session_id)
        with self.session() as db:
            return [_event_dict(r) for r in db.scalars(stmt)]

    def decoys(self, session_id: int | None = None) -> list[dict]:
        stmt = select(DecoyRow)
        if session_id is not None:
            stmt = stmt.where(DecoyRow.session_id == session_id)
        with self.session() as db:
            return [_decoy_dict(r) for r in db.scalars(stmt)]

    def decoy_by_token(self, token: str) -> dict | None:
        """Resolve a canary token to its decoy - the alert triage path."""
        with self.session() as db:
            row = db.scalar(select(DecoyRow).where(DecoyRow.token == token))
            return _decoy_dict(row) if row else None

    def strategy_leaderboard(self) -> list[dict]:
        """Mean detection rate per strategy across every recorded experiment."""
        stmt = (
            select(
                MetricRow.strategy,
                func.avg(MetricRow.detection_rate).label("detection_rate"),
                func.avg(MetricRow.mean_time_to_detection).label("hops"),
                func.avg(MetricRow.false_alerts_per_day).label("false_alerts"),
                func.count(MetricRow.id).label("runs"),
            )
            .group_by(MetricRow.strategy)
            .order_by(func.avg(MetricRow.detection_rate).desc())
        )
        with self.session() as db:
            return [
                {
                    "strategy": row.strategy,
                    "detection_rate": round(row.detection_rate or 0.0, 4),
                    "mean_time_to_detection": (
                        None if row.hops is None else round(row.hops, 4)
                    ),
                    "false_alerts_per_day": round(row.false_alerts or 0.0, 4),
                    "experiments": row.runs,
                }
                for row in db.execute(stmt)
            ]

    def counts(self) -> dict[str, int]:
        with self.session() as db:
            return {
                "sessions": db.scalar(select(func.count(SessionRow.id))) or 0,
                "decoys": db.scalar(select(func.count(DecoyRow.id))) or 0,
                "events": db.scalar(select(func.count(EventRow.id))) or 0,
                "alerts": db.scalar(select(func.count(AlertRow.id))) or 0,
                "experiments": db.scalar(select(func.count(ExperimentRow.id))) or 0,
            }


def _alert_dict(row: AlertRow) -> dict:
    return {
        "id": row.id, "session_id": row.session_id, "actor_id": row.actor_id,
        "severity": row.severity, "stage": row.stage,
        "sophistication": row.sophistication, "objective": row.objective,
        "summary": row.summary, "evidence_count": row.evidence_count,
        "hosts": json.loads(row.hosts or "[]"), "closed": row.closed,
        "opened_at": row.opened_at.isoformat() if row.opened_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _event_dict(row: EventRow) -> dict:
    return {
        "sequence": row.sequence, "type": row.type, "actor_id": row.actor_id,
        "host_id": row.host_id, "asset_id": row.asset_id, "token": row.token,
        "detail": row.detail, "metadata": json.loads(row.payload or "{}"),
        "at": row.at.isoformat() if row.at else None,
    }


def _decoy_dict(row: DecoyRow) -> dict:
    return {
        "id": row.id, "session_id": row.session_id, "kind": row.kind,
        "host_id": row.host_id, "name": row.name, "mimics": row.mimics,
        "token": row.token, "believability": row.believability,
        "fidelity": row.fidelity, "detection_probability": row.detection_probability,
        "state": row.state, "rationale": row.rationale,
    }
