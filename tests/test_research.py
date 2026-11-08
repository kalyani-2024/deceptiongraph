"""Network generator and sensitivity analysis."""

from __future__ import annotations

import pytest

from deceptiongraph.analysis import attack_graph
from deceptiongraph.experiments.sensitivity import (
    PARAMETERS,
    kendall_tau,
    override,
    run_sensitivity,
)
from deceptiongraph.facade import SecurityFacade
from deceptiongraph.graph.generator import generate_network
from deceptiongraph.graph.loader import build_model

from conftest import DATA_DIR


class TestGenerator:
    def test_same_seed_same_network(self):
        assert generate_network(60, seed=3) == generate_network(60, seed=3)
        assert generate_network(60, seed=3) != generate_network(60, seed=4)

    @pytest.mark.parametrize("size", [10, 80, 250])
    def test_sizes_are_close_to_requested_and_valid(self, size):
        model = build_model(generate_network(size, seed=1))
        assert abs(len(model.hosts) - size) <= max(3, size * 0.05)
        assert model.crown_jewels and model.entry_points
        assert model.root is not None and model.root.calculate_risk().value > 0

    def test_crown_jewels_are_reachable_from_the_internet(self):
        security = SecurityFacade(build_model(generate_network(120, seed=2)))
        assert security.analyse_network().crown_jewel_paths

    def test_too_small_is_rejected(self):
        with pytest.raises(ValueError, match="at least 10"):
            generate_network(5)


class TestSensitivity:
    def test_override_restores_the_value(self):
        before = attack_graph.SESSION_HIJACK_BASE
        with override("session_hijack_base", 0.9):
            assert attack_graph.SESSION_HIJACK_BASE == 0.9
        assert attack_graph.SESSION_HIJACK_BASE == before

    def test_override_restores_after_an_error(self):
        before = attack_graph.SESSION_HIJACK_BASE
        with pytest.raises(RuntimeError):
            with override("session_hijack_base", 0.9):
                raise RuntimeError("boom")
        assert attack_graph.SESSION_HIJACK_BASE == before

    def test_every_parameter_points_at_a_real_attribute(self):
        import importlib

        for parameter in PARAMETERS.values():
            module = importlib.import_module(parameter.module)
            assert getattr(module, parameter.attribute) == parameter.default

    def test_the_parameters_change_the_model(self, enterprise_model):
        from deceptiongraph.analysis.attack_graph import AttackGraphEngine
        from deceptiongraph.graph.repository import InMemoryGraphRepository

        def worst():
            repo = InMemoryGraphRepository(enterprise_model)
            return AttackGraphEngine(repo).most_dangerous_path().probability

        base = worst()
        with override("patch_damping", 0.0):
            assert worst() != base

    def test_kendall_tau(self):
        assert kendall_tau(["a", "b", "c"], ["a", "b", "c"]) == 1.0
        assert kendall_tau(["a", "b", "c"], ["c", "b", "a"]) == -1.0
        assert kendall_tau(["a", "b", "c"], ["b", "a", "c"]) == pytest.approx(1 / 3)

    def test_run(self):
        results = run_sensitivity(DATA_DIR / "campus.yaml", parameters=("path_weight",),
                                  multipliers=(0.5, 1.0), trials=10,
                                  arms=("random", "attack-path"))
        (result,) = results
        assert result.values == [0.325, 0.65]
        assert len(result.winners) == 2 and len(result.tau) == 2
        assert result.tau[1] == 1.0  # the default reproduces the baseline ranking
        assert set(result.detection) == {"random", "attack-path"}

    def test_adversary_skill_only_with_a_smart_adversary(self):
        names = [r.parameter for r in run_sensitivity(
            DATA_DIR / "enterprise.yaml", multipliers=(1.0,), trials=3, arms=("random",))]
        assert "adversary_skill" not in names
        with pytest.raises(ValueError, match="unknown parameters"):
            run_sensitivity(DATA_DIR / "enterprise.yaml", parameters=("vibes",), trials=3)


def test_cli_generate_sensitivity_scale(tmp_path):
    from typer.testing import CliRunner

    from deceptiongraph.cli.main import app
    from deceptiongraph.graph.loader import load_network

    runner = CliRunner()
    out = tmp_path / "g.yaml"
    result = runner.invoke(app, ["generate", "-n", "40", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert len(load_network(out).hosts) >= 38

    result = runner.invoke(app, ["sensitivity", str(DATA_DIR / "enterprise.yaml"), "-t", "4",
                                 "-p", "path_weight", "-o", str(tmp_path / "s.json")])
    assert result.exit_code == 0, result.output
    assert "path_weight" in result.output

    result = runner.invoke(app, ["scale", "--sizes", "20", "-t", "3", "-b", "2"])
    assert result.exit_code == 0, result.output
    assert "Scaling" in result.output
