"""
Unit tests for test_env_integration.py pure-Python helpers.

calculate_difficulty_score and _detect_stratum have no external deps.
networkx and cyberbattle are mocked at sys.modules level so the module
can be imported without those packages installed.
"""

import sys
import types
import unittest.mock as mock
import pytest
from pathlib import Path

# ---------------------------------------------------------------------------
# Stub out heavy deps before importing the module under test
# ---------------------------------------------------------------------------
_nx_stub = types.ModuleType("networkx")
_nx_stub.density = mock.MagicMock(return_value=0.0)
_nx_stub.DiGraph = mock.MagicMock
_nx_stub.betweenness_centrality = mock.MagicMock(return_value={})
_nx_stub.number_weakly_connected_components = mock.MagicMock(return_value=1)
_nx_stub.number_strongly_connected_components = mock.MagicMock(return_value=1)
_nx_stub.is_connected = mock.MagicMock(return_value=False)
_nx_stub.diameter = mock.MagicMock(return_value=1)
_nx_stub.connected_components = mock.MagicMock(return_value=[])
sys.modules.setdefault("networkx", _nx_stub)

for _mod in (
    "cyberbattle",
    "cyberbattle._env",
    "cyberbattle._env.improved",
    "cyberbattle._env.improved.improved_cyberbattle_env",
    "cyberbattle._env.cyberbattle_env",
    "cyberbattle.runners",
    "cyberbattle.runners.common",
    "cyberbattle.runners.common.loaderenv",
    "cyberbattle.simulation",
    "cyberbattle.simulation.vulenrabilites",
):
    if _mod not in sys.modules:
        _stub = types.ModuleType(_mod)
        _stub.ImprovedCyberBattleEnv = mock.MagicMock()
        _stub.new_environment = mock.MagicMock()
        _stub.VulnerabilityType = mock.MagicMock()
        _stub.AttackerGoal = mock.MagicMock()
        sys.modules[_mod] = _stub

# Patch sys.exit so the module-level import guard doesn't kill pytest
import builtins as _builtins
_real_exit = sys.exit
sys.exit = lambda *a: None  # suppress exit(1) in except block

from pipeline.phase2.test_env_integration import (
    calculate_difficulty_score,
    _detect_stratum,
    _compute_slot_coverage_metrics,
)

sys.exit = _real_exit  # restore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_run_metrics(
    success_rate: float = 0.5,
    diameter: int = 4,
    node_count: int = 10,
    steps: int = 100,
    replay_sr: float = 1.0,
) -> dict:
    return {
        "action_stats": {"overall_actions_success_rate": success_rate},
        "topology_metrics": {
            "routing": {
                "diameter": diameter,
                "node_count": node_count,
            }
        },
        "steps_taken": steps,
        "replay_verification": {"success_rate": replay_sr},
    }


# ===========================================================================
# calculate_difficulty_score
# ===========================================================================

class TestCalculateDifficultyScore:
    def test_zero_metrics_is_trivial(self):
        metrics = make_run_metrics(
            success_rate=1.0,
            diameter=1,
            node_count=10,
            steps=1,
            replay_sr=1.0,
        )
        result = calculate_difficulty_score(metrics)
        assert result["rating"] == "TRIVIAL"
        assert result["score"] < 2.0

    def test_max_difficulty_is_extreme(self):
        metrics = make_run_metrics(
            success_rate=0.0,
            diameter=1000,
            node_count=1,
            steps=10000,
            replay_sr=0.0,
        )
        result = calculate_difficulty_score(metrics)
        assert result["rating"] == "EXTREME"
        assert result["score"] >= 8.0

    def test_rating_hard_boundary(self):
        """Craft metrics that produce score in [6.0, 8.0)."""
        # stochastic: (1-0.0)*2.5 = 2.5
        # structural: min(2.5, (5/10)*5) = 2.5
        # efficiency: min(2.5, (250/10)/5) = 2.5 → capped at 2.5 → wait, 250/10/5 = 5.0 > 2.5 → capped at 2.5
        # volatility: (1-1.0)*2.5 = 0.0
        # total = 7.5 → HARD
        metrics = make_run_metrics(
            success_rate=0.0,
            diameter=5,
            node_count=10,
            steps=250,
            replay_sr=1.0,
        )
        result = calculate_difficulty_score(metrics)
        assert result["rating"] in ("HARD", "EXTREME")
        assert result["score"] >= 6.0

    def test_rating_moderate_boundary(self):
        """Score around [4.0, 6.0) → MODERATE."""
        # stochastic: (1-0.5)*2.5 = 1.25
        # structural: min(2.5, (3/10)*5) = 1.5
        # efficiency: min(2.5, (50/10)/5) = 1.0
        # volatility: (1-1.0)*2.5 = 0.0
        # total = 3.75 → probably EASY or MODERATE
        metrics = make_run_metrics(
            success_rate=0.5,
            diameter=3,
            node_count=10,
            steps=50,
            replay_sr=1.0,
        )
        result = calculate_difficulty_score(metrics)
        assert result["score"] < 8.0

    def test_result_has_required_keys(self):
        metrics = make_run_metrics()
        result = calculate_difficulty_score(metrics)
        assert "score" in result
        assert "rating" in result
        assert "metrics" in result
        for key in ("stochastic_resistance", "topological_depth",
                    "operational_overhead", "stochastic_volatility"):
            assert key in result["metrics"]

    def test_stochastic_score_formula(self):
        """stochastic_resistance = (1 - SR) * 2.5"""
        metrics = make_run_metrics(success_rate=0.2, diameter=1, node_count=100, steps=1, replay_sr=1.0)
        result = calculate_difficulty_score(metrics)
        assert result["metrics"]["stochastic_resistance"] == pytest.approx(0.8 * 2.5)

    def test_volatility_from_replay(self):
        """volatility = (1 - replay_sr) * 2.5"""
        metrics = make_run_metrics(success_rate=1.0, diameter=1, node_count=100, steps=1, replay_sr=0.4)
        result = calculate_difficulty_score(metrics)
        assert result["metrics"]["stochastic_volatility"] == pytest.approx(0.6 * 2.5)

    def test_score_is_sum_of_components(self):
        metrics = make_run_metrics(
            success_rate=0.3,
            diameter=4,
            node_count=10,
            steps=100,
            replay_sr=0.8,
        )
        result = calculate_difficulty_score(metrics)
        m = result["metrics"]
        expected = round(
            m["stochastic_resistance"] + m["topological_depth"] +
            m["operational_overhead"] + m["stochastic_volatility"],
            2,
        )
        assert result["score"] == pytest.approx(expected, abs=0.01)

    def test_structural_score_capped_at_2_5(self):
        """diameter >> node_count → structural score capped at 2.5."""
        metrics = make_run_metrics(
            success_rate=1.0, diameter=1000, node_count=1, steps=1, replay_sr=1.0
        )
        result = calculate_difficulty_score(metrics)
        assert result["metrics"]["topological_depth"] == pytest.approx(2.5)

    def test_efficiency_score_capped_at_2_5(self):
        """steps/node_count very large → efficiency score capped at 2.5."""
        metrics = make_run_metrics(
            success_rate=1.0, diameter=1, node_count=1, steps=100000, replay_sr=1.0
        )
        result = calculate_difficulty_score(metrics)
        assert result["metrics"]["operational_overhead"] == pytest.approx(2.5)


# ===========================================================================
# _detect_stratum
# ===========================================================================

class TestDetectStratum:
    def test_small_detected(self):
        assert _detect_stratum(Path("/data/scenarios/small/scenario_001")) == "small"

    def test_medium_detected(self):
        assert _detect_stratum(Path("/output/medium/run")) == "medium"

    def test_large_detected(self):
        assert _detect_stratum(Path("/output/large/scenario")) == "large"

    def test_case_insensitive(self):
        assert _detect_stratum(Path("/output/SMALL/s")) == "small"
        assert _detect_stratum(Path("/output/Large/s")) == "large"

    def test_no_stratum_returns_unknown(self):
        assert _detect_stratum(Path("/data/scenarios/misc/run")) == "unknown"

    def test_stratum_in_middle_of_path(self):
        assert _detect_stratum(Path("/root/datasets/small/subdir/scenario")) == "small"


# ===========================================================================
# _compute_slot_coverage_metrics (pure, no env needed)
# ===========================================================================

class TestComputeSlotCoverage:
    def test_missing_nodes_dir_returns_empty(self, tmp_path):
        result = _compute_slot_coverage_metrics(tmp_path / "no_nodes")
        assert result == {}

    def test_empty_nodes_dir_returns_zero_slots(self, tmp_path):
        nodes_dir = tmp_path / "nodes"
        nodes_dir.mkdir()
        result = _compute_slot_coverage_metrics(tmp_path)
        assert result["unique_vuln_slots"] == 0

    def test_counts_solvability_vulns(self, tmp_path, monkeypatch):
        import yaml
        nodes_dir = tmp_path / "nodes"
        nodes_dir.mkdir()
        node_data = {
            "vulnerabilities": {
                "Solvability.BlueKeep": {},
                "Solvability.EternalBlue": {},
                "NotSolvability.Foo": {},
            }
        }
        (nodes_dir / "node_a.yaml").write_text(yaml.dump(node_data))
        result = _compute_slot_coverage_metrics(tmp_path)
        assert result["unique_vuln_slots"] == 2
        assert "Solvability.BlueKeep" in result["slot_coverage"]
        assert "NotSolvability.Foo" not in result["slot_coverage"]

    def test_entropy_zero_for_single_slot(self, tmp_path):
        import yaml
        nodes_dir = tmp_path / "nodes"
        nodes_dir.mkdir()
        node_data = {"vulnerabilities": {"Solvability.OnlyThis": {}}}
        (nodes_dir / "node_a.yaml").write_text(yaml.dump(node_data))
        result = _compute_slot_coverage_metrics(tmp_path)
        assert result["vuln_entropy"] == pytest.approx(0.0)
