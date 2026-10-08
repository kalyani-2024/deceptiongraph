"""Runtime tests: events, state machine, profiler, incidents, adaptation, mediator."""

from __future__ import annotations

import pytest

from deceptiongraph.deception.assets import DeceptionKind, DeceptionState
from deceptiongraph.deception.engine import DeceptionEngine
from deceptiongraph.runtime.events import (
    CallbackObserver,
    Event,
    EventBus,
    EventType,
)
from deceptiongraph.runtime.incidents import IncidentManager, Severity
from deceptiongraph.runtime.mediator import SecurityMediator
from deceptiongraph.runtime.profiler import Sophistication, ThreatProfiler
from deceptiongraph.runtime.simulator import AttackSimulator
from deceptiongraph.runtime.states import (
    AttackerStage,
    Collection,
    Discovery,
    Exfiltration,
    InitialAccess,
    LateralMovement,
    Reconnaissance,
    state_for,
)


@pytest.fixture
def mediated(enterprise_repo):
    """A mediator with three attack-path decoys already standing."""
    engine = DeceptionEngine(enterprise_repo)
    deployment = engine.deploy(budget=3)
    return SecurityMediator(enterprise_repo, deception=engine, deployment=deployment)


def trigger(mediated, host: str = "api02", actor: str = "apt-1", type=EventType.DECOY_AUTHENTICATED):
    """Fire the decoy standing on `host`."""
    asset = next(a for a in mediated.live_assets if a.host_id == host)
    return mediated.handle(
        Event(type=type, host_id=host, actor_id=actor, asset_id=asset.id,
              token=asset.marker.token, detail=f"accessed {asset.lure.name}")
    )


class TestEventBus:
    def test_delivers_to_every_observer(self):
        bus, seen = EventBus(), []
        bus.subscribe(CallbackObserver("a", lambda e: seen.append(("a", e.type))))
        bus.subscribe(CallbackObserver("b", lambda e: seen.append(("b", e.type))))
        bus.emit(EventType.SCAN_OBSERVED, host_id="web01")
        assert [name for name, _ in seen] == ["a", "b"]

    def test_subscription_can_be_narrowed(self):
        bus, seen = EventBus(), []
        bus.subscribe(
            CallbackObserver("only-triggers", lambda e: seen.append(e.type)),
            types=[EventType.DECOY_TOUCHED],
        )
        bus.emit(EventType.SCAN_OBSERVED)
        bus.emit(EventType.DECOY_TOUCHED)
        assert seen == [EventType.DECOY_TOUCHED]

    def test_unsubscribe_stops_delivery(self):
        bus, seen = EventBus(), []
        observer = bus.subscribe(CallbackObserver("x", lambda e: seen.append(e)))
        bus.unsubscribe(observer)
        bus.emit(EventType.SCAN_OBSERVED)
        assert seen == []

    def test_one_failing_observer_does_not_silence_the_others(self):
        bus, seen = EventBus(), []

        def boom(event):
            raise RuntimeError("sensor offline")

        bus.subscribe(CallbackObserver("broken", boom))
        bus.subscribe(CallbackObserver("working", lambda e: seen.append(e)))
        bus.emit(EventType.DECOY_TOUCHED)

        assert len(seen) == 1
        assert len(bus.errors) == 1
        assert bus.errors[0][0] == "broken"

    def test_history_and_filtering(self):
        bus = EventBus()
        bus.emit(EventType.SCAN_OBSERVED)
        bus.emit(EventType.DECOY_TOUCHED)
        bus.emit(EventType.EXFIL_OBSERVED)
        assert len(bus.history) == 3
        assert len(bus.triggers()) == 2
        assert len(bus.of_type(EventType.SCAN_OBSERVED)) == 1

    def test_history_is_bounded(self):
        bus = EventBus(history=2)
        for _ in range(5):
            bus.emit(EventType.SCAN_OBSERVED)
        assert len(bus.history) == 2

    def test_events_are_sequenced_and_classified(self):
        first = Event(type=EventType.SCAN_OBSERVED)
        second = Event(type=EventType.DECOY_TOUCHED)
        assert second.sequence > first.sequence
        assert not first.is_deception_trigger
        assert second.is_deception_trigger

    def test_event_serialises(self):
        data = Event(type=EventType.DECOY_TOUCHED, host_id="h", detail="x").as_dict()
        assert data["type"] == "DECOY_TOUCHED"
        assert data["host_id"] == "h"
        assert "at" in data


class TestAttackerStates:
    def test_stages_are_ordered(self):
        assert AttackerStage.RECONNAISSANCE.order < AttackerStage.EXFILTRATION.order

    def test_lookup_by_name_and_enum(self):
        assert isinstance(state_for("discovery"), Discovery)
        assert isinstance(state_for(AttackerStage.COLLECTION), Collection)

    def test_unknown_stage_is_rejected(self):
        with pytest.raises(ValueError, match="unknown attacker stage"):
            state_for("victory")

    def test_compromise_moves_recon_to_initial_access(self):
        nxt = Reconnaissance().next_state(Event(type=EventType.HOST_COMPROMISED), 1)
        assert isinstance(nxt, InitialAccess)

    def test_credential_use_jumps_straight_to_lateral_movement(self):
        nxt = Reconnaissance().next_state(Event(type=EventType.DECOY_AUTHENTICATED), 1)
        assert isinstance(nxt, LateralMovement)

    def test_second_host_implies_lateral_movement(self):
        nxt = InitialAccess().next_state(Event(type=EventType.HOST_COMPROMISED), hosts_seen=2)
        assert isinstance(nxt, LateralMovement)

    def test_crown_jewel_arrival_implies_collection(self):
        event = Event(type=EventType.HOST_COMPROMISED, host_id="db01",
                      metadata={"is_crown_jewel": True})
        assert isinstance(LateralMovement().next_state(event, 2), Collection)

    def test_exfiltration_is_reachable_from_every_later_stage(self):
        event = Event(type=EventType.EXFIL_OBSERVED)
        for state in (InitialAccess(), Discovery(), LateralMovement(), Collection()):
            assert isinstance(state.next_state(event, 1), Exfiltration)

    def test_progression_never_goes_backwards(self):
        # A lone scan must not drag a lateral-movement actor back to discovery.
        state = LateralMovement().next_state(Event(type=EventType.SCAN_OBSERVED), 1)
        assert state.stage is AttackerStage.LATERAL_MOVEMENT

    def test_exfiltration_is_terminal(self):
        state = Exfiltration()
        assert state.next_state(Event(type=EventType.HOST_COMPROMISED), 5) is state

    def test_posture_sharpens_as_the_attack_advances(self):
        urgencies = [
            s().posture().urgency
            for s in (Reconnaissance, InitialAccess, Discovery, LateralMovement,
                      Collection, Exfiltration)
        ]
        assert urgencies == sorted(urgencies)

    def test_each_posture_names_a_focus_and_kinds(self):
        for state in (Reconnaissance(), LateralMovement(), Collection()):
            posture = state.posture()
            assert posture.focus
            assert posture.preferred_kinds
            assert posture.note
            assert posture.as_dict()["stage"] == state.stage.value

    def test_collection_prefers_honeyfiles(self):
        assert DeceptionKind.DOCUMENT in Collection().posture().preferred_kinds


class TestThreatProfiler:
    def test_unseen_actor_has_no_profile(self, enterprise_repo):
        assert ThreatProfiler(enterprise_repo).profile("nobody") is None

    def test_tracks_hosts_and_infers_objective(self, enterprise_repo):
        profiler = ThreatProfiler(enterprise_repo)
        profiler.on_event(Event(type=EventType.HOST_COMPROMISED, host_id="web01",
                                actor_id="a1"))
        profile = profiler.profile("a1")
        assert profile.hosts_seen == ("web01",)
        assert profile.objective == "db01"
        assert profile.current_host == "web01"

    def test_credential_use_raises_sophistication(self, enterprise_repo):
        profiler = ThreatProfiler(enterprise_repo)
        profiler.on_event(Event(type=EventType.DECOY_TOUCHED, host_id="web01", actor_id="a1"))
        low = profiler.profile("a1").sophistication_score
        profiler.on_event(
            Event(type=EventType.DECOY_AUTHENTICATED, host_id="api02", actor_id="a1")
        )
        assert profiler.profile("a1").sophistication_score > low

    def test_reaching_the_crown_jewel_makes_them_high(self, enterprise_repo):
        profiler = ThreatProfiler(enterprise_repo)
        for host in ("web01", "api02"):
            profiler.on_event(Event(type=EventType.HOST_COMPROMISED, host_id=host, actor_id="a1"))
        profiler.on_event(
            Event(type=EventType.DECOY_AUTHENTICATED, host_id="api02", actor_id="a1")
        )
        profiler.on_event(Event(type=EventType.HOST_COMPROMISED, host_id="db01", actor_id="a1"))
        assert profiler.profile("a1").sophistication is Sophistication.HIGH

    def test_confidence_rises_with_corroboration_not_repetition(self, enterprise_repo):
        profiler = ThreatProfiler(enterprise_repo)
        for _ in range(5):
            profiler.on_event(
                Event(type=EventType.DECOY_TOUCHED, host_id="web01", actor_id="a1",
                      asset_id="decoy-1")
            )
        repeated = profiler.profile("a1").confidence
        profiler.on_event(
            Event(type=EventType.DECOY_TOUCHED, host_id="api02", actor_id="a1",
                  asset_id="decoy-2")
        )
        assert profiler.profile("a1").confidence > repeated

    def test_actors_are_tracked_separately(self, enterprise_repo):
        profiler = ThreatProfiler(enterprise_repo)
        profiler.on_event(Event(type=EventType.HOST_COMPROMISED, host_id="web01", actor_id="a1"))
        profiler.on_event(Event(type=EventType.HOST_COMPROMISED, host_id="bak01", actor_id="a2"))
        assert set(profiler.actors) == {"a1", "a2"}
        assert profiler.profile("a1").hosts_seen != profiler.profile("a2").hosts_seen

    def test_most_advanced_picks_the_furthest_along(self, enterprise_repo):
        profiler = ThreatProfiler(enterprise_repo)
        profiler.on_event(Event(type=EventType.SCAN_OBSERVED, host_id="web01", actor_id="quiet"))
        profiler.on_event(
            Event(type=EventType.DECOY_AUTHENTICATED, host_id="api02", actor_id="loud")
        )
        assert profiler.most_advanced().actor_id == "loud"

    def test_own_downstream_events_are_ignored(self, enterprise_repo):
        profiler = ThreatProfiler(enterprise_repo)
        profiler.on_event(Event(type=EventType.ALERT_RAISED, actor_id="a1"))
        assert profiler.profile("a1") is None

    def test_state_change_callback_fires(self, enterprise_repo):
        seen = []
        profiler = ThreatProfiler(
            enterprise_repo, on_state_change=lambda a, o, n: seen.append((a, o, n))
        )
        profiler.on_event(Event(type=EventType.HOST_COMPROMISED, host_id="web01", actor_id="a1"))
        assert seen and seen[0][2] is AttackerStage.INITIAL_ACCESS

    def test_profile_serialises(self, enterprise_repo):
        profiler = ThreatProfiler(enterprise_repo)
        profiler.on_event(Event(type=EventType.HOST_COMPROMISED, host_id="web01", actor_id="a1"))
        data = profiler.profile("a1").as_dict()
        assert data["actor_id"] == "a1"
        assert data["posture"]["stage"] == data["stage"]


class TestIncidentManager:
    def test_routine_events_open_nothing(self):
        manager = IncidentManager()
        manager.on_event(Event(type=EventType.SCAN_OBSERVED, actor_id="a1"))
        assert manager.incidents == ()

    def test_one_actor_gets_one_incident(self):
        manager = IncidentManager()
        for _ in range(4):
            manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id="a1", host_id="web01"))
        assert len(manager.incidents) == 1
        assert len(manager.incidents[0].evidence) == 4

    def test_separate_actors_get_separate_incidents(self):
        manager = IncidentManager()
        manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id="a1"))
        manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id="a2"))
        assert len(manager.incidents) == 2

    def test_severity_escalates_but_never_falls(self):
        manager = IncidentManager()
        manager.on_event(Event(type=EventType.EXFIL_OBSERVED, actor_id="a1"))
        assert manager.for_actor("a1").severity is Severity.CRITICAL
        manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id="a1"))
        assert manager.for_actor("a1").severity is Severity.CRITICAL

    def test_credential_use_outranks_a_file_read(self):
        manager = IncidentManager()
        manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id="a1"))
        touched = manager.for_actor("a1").severity
        manager.on_event(Event(type=EventType.DECOY_AUTHENTICATED, actor_id="a2"))
        assert manager.for_actor("a2").severity.rank > touched.rank

    def test_hosts_accumulate_without_duplicates(self):
        manager = IncidentManager()
        for host in ("web01", "api02", "web01"):
            manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id="a1", host_id=host))
        assert manager.for_actor("a1").hosts == ["web01", "api02"]

    def test_profile_enriches_the_incident(self, enterprise_repo):
        manager = IncidentManager()
        manager.on_event(
            Event(type=EventType.DECOY_AUTHENTICATED, actor_id="a1", host_id="api02")
        )
        profiler = ThreatProfiler(enterprise_repo)
        profiler.on_event(
            Event(type=EventType.DECOY_AUTHENTICATED, actor_id="a1", host_id="api02")
        )
        incident = manager.apply_profile(profiler.profile("a1"))
        assert incident.stage == "LATERAL_MOVEMENT"
        assert incident.objective == "db01"
        assert "sophistication actor" in incident.summary

    def test_applying_a_profile_for_an_unknown_actor_is_a_no_op(self, enterprise_repo):
        profiler = ThreatProfiler(enterprise_repo)
        profiler.on_event(Event(type=EventType.HOST_COMPROMISED, host_id="web01", actor_id="ghost"))
        assert IncidentManager().apply_profile(profiler.profile("ghost")) is None

    def test_close_and_worst(self):
        manager = IncidentManager()
        manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id="a1"))
        manager.on_event(Event(type=EventType.EXFIL_OBSERVED, actor_id="a2"))
        assert manager.worst().actor_id == "a2"
        assert manager.close("a1") is True
        assert manager.close("a1") is False
        assert {i.actor_id for i in manager.open_incidents} == {"a2"}

    def test_incident_serialises(self):
        manager = IncidentManager()
        manager.on_event(Event(type=EventType.DECOY_TOUCHED, actor_id="a1", host_id="web01"))
        data = manager.for_actor("a1").as_dict()
        assert data["id"] == "INC-0001"
        assert data["hosts"] == ["web01"]


class TestAdaptation:
    def test_a_touched_decoy_is_burned_then_retired(self, mediated):
        asset = next(a for a in mediated.live_assets if a.host_id == "api02")
        trigger(mediated)
        assert asset.state is DeceptionState.RETIRED

    def test_a_burned_position_is_re_seeded_with_another_family(self, mediated):
        before = next(a for a in mediated.live_assets if a.host_id == "api02")
        trigger(mediated)
        after = [a for a in mediated.live_assets if a.host_id == "api02"]
        assert after, "the burned host should not be abandoned"
        assert after[0].kind is not before.kind

    def test_adaptation_is_recorded_with_a_reason(self, mediated):
        reaction = trigger(mediated)
        assert reaction.adaptation is not None
        assert reaction.adaptation.reason
        assert mediated.adaptation.history

    def test_routine_events_do_not_drive_a_replan(self, mediated):
        mediated.handle(Event(type=EventType.SCAN_OBSERVED, host_id="web01", actor_id="a1"))
        changed = [a for a in mediated.adaptation.history if a.changed]
        # A scan may change the stage once, but must not place decoys repeatedly.
        for _ in range(5):
            mediated.handle(Event(type=EventType.SCAN_OBSERVED, host_id="web01", actor_id="a1"))
        assert len([a for a in mediated.adaptation.history if a.changed]) <= len(changed) + 1

    def test_the_ceiling_is_respected(self, enterprise_repo):
        engine = DeceptionEngine(enterprise_repo)
        deployment = engine.deploy(budget=3)
        mediator = SecurityMediator(
            enterprise_repo, deception=engine, deployment=deployment, max_total_decoys=4
        )
        for index in range(12):
            mediator.handle(
                Event(type=EventType.DECOY_TOUCHED, host_id="web01",
                      actor_id=f"a{index}", detail="noise")
            )
        assert len(mediator.live_assets) <= 4

    def test_coverage_is_reported_for_the_live_set(self, mediated):
        coverage = mediated.adaptation.coverage()
        assert coverage.strategy == "adaptive"
        assert coverage.decoys_used == len(mediated.live_assets)

    def test_adaptation_serialises(self, mediated):
        data = trigger(mediated).adaptation.as_dict()
        assert data["actor_id"] == "apt-1"
        assert "stage" in data


class TestSecurityMediator:
    def test_a_trigger_produces_profile_incident_and_adaptation(self, mediated):
        reaction = trigger(mediated)
        assert reaction.triggered
        assert reaction.profile.stage is AttackerStage.LATERAL_MOVEMENT
        assert reaction.incident.severity.rank >= Severity.HIGH.rank
        assert reaction.adaptation is not None

    def test_the_narrative_reads_like_the_brief(self, mediated):
        narrative = trigger(mediated).describe()
        assert "DECEPTION TRIGGERED" in narrative
        assert "Sophistication:" in narrative
        assert "Likely next target:" in narrative

    def test_every_observer_is_registered(self, mediated):
        names = {getattr(o, "name", "") for o in mediated.bus.observers}
        assert {"threat-profiler", "incident-manager", "adaptation-engine",
                "risk-recalculator"} <= names

    def test_downstream_events_are_published(self, mediated):
        trigger(mediated)
        assert mediated.bus.of_type(EventType.ALERT_RAISED)

    def test_risk_is_recalculated_lazily(self, mediated):
        first = mediated.risk.current().score
        calls = mediated.risk.recalculations
        assert mediated.risk.current().score == first
        assert mediated.risk.recalculations == calls  # cached
        trigger(mediated)
        mediated.risk.current()
        assert mediated.risk.recalculations > calls  # invalidated

    def test_status_is_a_complete_snapshot(self, mediated):
        trigger(mediated)
        status = mediated.status()
        for key in ("events_seen", "triggers", "live_decoys", "adaptations",
                    "network_risk", "coverage", "worst_incident", "most_advanced_actor"):
            assert key in status
        assert status["triggers"] == 1

    def test_adaptation_can_be_turned_off(self, enterprise_repo):
        engine = DeceptionEngine(enterprise_repo)
        deployment = engine.deploy(budget=3)
        mediator = SecurityMediator(
            enterprise_repo, deception=engine, deployment=deployment, adapt_on_trigger=False
        )
        asset = next(a for a in mediator.live_assets if a.host_id == "api02")
        reaction = mediator.handle(
            Event(type=EventType.DECOY_AUTHENTICATED, host_id="api02", actor_id="a1",
                  asset_id=asset.id, token=asset.marker.token)
        )
        assert reaction.adaptation is None

    def test_reaction_serialises(self, mediated):
        data = trigger(mediated).as_dict()
        assert data["triggered"] is True
        assert data["profile"]["stage"] == "LATERAL_MOVEMENT"


class TestSimulator:
    def test_a_run_starts_at_the_internet(self, enterprise_repo):
        result = AttackSimulator(enterprise_repo, seed=1).run()
        assert result.path[0] == "INTERNET"
        assert result.as_dict()["actor_id"] == "actor-1"

    def test_the_same_seed_reproduces_the_run(self, enterprise_repo):
        first = AttackSimulator(enterprise_repo, seed=5).run()
        second = AttackSimulator(enterprise_repo, seed=5).run()
        assert first.path == second.path
        assert first.detected == second.detected

    def test_a_perfect_decoy_always_catches_them(self, enterprise_repo):
        engine = DeceptionEngine(enterprise_repo)
        deployment = engine.deploy(budget=1, strategy="attack-path")
        asset = deployment.assets[0]
        object.__setattr__(asset.lure, "believability", 1.0)
        object.__setattr__(asset.sensor, "fidelity", 1.0)

        caught = 0
        for index in range(20):
            result = AttackSimulator(
                enterprise_repo, assets=[asset], seed=index
            ).run(actor_id=f"a{index}")
            if asset.host_id in result.path:
                assert result.detected
                caught += 1
        assert caught > 0, "the attacker never reached the decoy host"

    def test_no_decoys_means_never_detected(self, enterprise_repo):
        results = AttackSimulator(enterprise_repo, seed=3).run_many(10)
        assert not any(r.detected for r in results)

    def test_a_failed_exploit_makes_them_pivot_not_quit(self, enterprise_repo):
        # Over many runs some must record a failed hop yet still progress.
        results = AttackSimulator(enterprise_repo, seed=9).run_many(40)
        pivoted = [r for r in results if r.failed_hops > 0 and r.hops > 0]
        assert pivoted, "no run recovered from a failed exploit"

    def test_the_campaign_ends_after_enough_failures(self, enterprise_repo):
        results = AttackSimulator(
            enterprise_repo, seed=4, max_failures=1
        ).run_many(20)
        assert all(r.failed_hops <= 1 for r in results)

    def test_runs_respect_the_step_limit(self, enterprise_repo):
        result = AttackSimulator(enterprise_repo, seed=2, max_steps=1).run()
        assert result.hops <= 1

    def test_trials_must_be_positive(self, enterprise_repo):
        with pytest.raises(ValueError, match="trials must be at least 1"):
            AttackSimulator(enterprise_repo).run_many(0)

    def test_driving_the_mediator_produces_incidents(self, enterprise_repo):
        engine = DeceptionEngine(enterprise_repo)
        deployment = engine.deploy(budget=3)
        mediator = SecurityMediator(enterprise_repo, deception=engine, deployment=deployment)
        simulator = AttackSimulator(enterprise_repo, mediator=mediator, seed=6)
        results = simulator.run_many(25)

        assert any(r.detected for r in results)
        assert mediator.incidents.incidents
        assert mediator.bus.triggers()

    def test_describe_distinguishes_the_outcomes(self, enterprise_repo):
        results = AttackSimulator(enterprise_repo, seed=8).run_many(30)
        descriptions = " ".join(r.describe() for r in results)
        assert "foothold" in descriptions or "stalled" in descriptions or "REACHED" in descriptions
