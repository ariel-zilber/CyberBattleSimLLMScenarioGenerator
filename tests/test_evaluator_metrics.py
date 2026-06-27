"""
Unit tests for pipeline/phase2/evaluator.py metric helpers.

Covers: _vuln_cost, _classify_vuln, _gini, _cv,
        compute_fairness_metrics, _find_hop_path.
"""

import sys
import types
from pathlib import Path

# ── Stub heavy optional dependencies before any evaluator import ──────────────
_nx_stub = types.ModuleType("networkx")
sys.modules.setdefault("networkx", _nx_stub)
for _mod in (
    "cyberbattle", "cyberbattle._env", "cyberbattle._env.model",
    "cyberbattle.simulation", "cyberbattle.simulation.model",
):
    sys.modules.setdefault(_mod, types.ModuleType(_mod))
sys.exit = lambda *a: None  # prevent module-level sys.exit(1)

import pytest
from pipeline.phase2.evaluator import (
    _vuln_cost,
    _classify_vuln,
    _gini,
    _cv,
    compute_fairness_metrics,
    _find_hop_path,
    AT_REMOTE_EXPLOIT,
    AT_LOCAL_CRED_LEAK,
    AT_LOCAL_DISCOVERY,
    AT_LOCAL_PRIVESC,
    AT_LOCAL_DUMP,
)


# ===========================================================================
# _vuln_cost
# ===========================================================================

class TestVulnCost:
    def test_explicit_cost_returned(self):
        assert _vuln_cost({"cost": 3.5}) == 3.5

    def test_integer_cost_returned_as_float(self):
        assert _vuln_cost({"cost": 2}) == 2.0

    def test_missing_cost_defaults_to_one(self):
        assert _vuln_cost({}) == 1.0

    def test_none_cost_defaults_to_one(self):
        assert _vuln_cost({"cost": None}) == 1.0

    def test_string_cost_defaults_to_one(self):
        assert _vuln_cost({"cost": "cheap"}) == 1.0

    def test_zero_cost_returned(self):
        assert _vuln_cost({"cost": 0}) == 0.0

    def test_float_string_parseable(self):
        # "2.5" is a string but float("2.5") succeeds
        assert _vuln_cost({"cost": "2.5"}) == 2.5


# ===========================================================================
# _classify_vuln
# ===========================================================================

class TestClassifyVuln:
    def test_remote_type_3_is_remote_exploit(self):
        assert _classify_vuln(3, "anything") == AT_REMOTE_EXPLOIT

    def test_local_leaked_nodes_is_discovery(self):
        assert _classify_vuln(2, "leaked_nodes_id") == AT_LOCAL_DISCOVERY

    def test_local_privilege_escalation(self):
        assert _classify_vuln(2, "privilege_escalation") == AT_LOCAL_PRIVESC

    def test_local_customer_data_is_dump(self):
        assert _classify_vuln(2, "customer_data") == AT_LOCAL_DUMP

    def test_local_data_exfil_is_dump(self):
        assert _classify_vuln(2, "data_exfil") == AT_LOCAL_DUMP

    def test_local_leaked_credentials_is_cred_leak(self):
        assert _classify_vuln(2, "leaked_credentials") == AT_LOCAL_CRED_LEAK

    def test_local_unknown_outcome_falls_through_to_cred_leak(self):
        # Default branch: anything else is LOCAL_CRED_LEAK
        assert _classify_vuln(2, "some_other_outcome") == AT_LOCAL_CRED_LEAK

    def test_type_0_local_leaked_nodes_is_discovery(self):
        # vtype != 3 but outcome matches leaked_nodes_id
        assert _classify_vuln(0, "leaked_nodes_id") == AT_LOCAL_DISCOVERY


# ===========================================================================
# _gini
# ===========================================================================

class TestGini:
    def test_empty_list_returns_zero(self):
        assert _gini([]) == 0.0

    def test_all_zeros_returns_zero(self):
        assert _gini([0.0, 0.0, 0.0]) == 0.0

    def test_all_equal_values_returns_zero(self):
        # Perfect equality → Gini = 0
        assert _gini([5.0, 5.0, 5.0]) == 0.0

    def test_perfect_inequality_single_non_zero(self):
        # One non-zero out of many → high Gini
        g = _gini([0, 0, 0, 10])
        assert g > 0.5

    def test_two_equal_values(self):
        assert _gini([2.0, 2.0]) == 0.0

    def test_two_unequal_values(self):
        g = _gini([1.0, 3.0])
        assert 0.0 < g < 1.0

    def test_single_value_returns_zero(self):
        # Single element: numerically zero since only one term
        assert _gini([7.0]) == 0.0

    def test_sorted_output_same_as_unsorted(self):
        vals = [3.0, 1.0, 4.0, 1.0, 5.0]
        assert _gini(vals) == _gini(sorted(vals))


# ===========================================================================
# _cv
# ===========================================================================

class TestCV:
    def test_empty_list_returns_zero(self):
        assert _cv([]) == 0.0

    def test_all_zeros_returns_zero(self):
        assert _cv([0.0, 0.0]) == 0.0

    def test_all_equal_values_returns_zero(self):
        assert _cv([4.0, 4.0, 4.0]) == 0.0

    def test_varied_values_positive(self):
        cv = _cv([1.0, 2.0, 3.0])
        assert cv > 0.0

    def test_result_rounded_to_three_decimals(self):
        cv = _cv([1.0, 2.0, 3.0])
        assert cv == round(cv, 3)

    def test_single_value_returns_zero(self):
        # std of single value is 0 → cv = 0
        assert _cv([5.0]) == 0.0

    def test_high_spread_higher_than_low_spread(self):
        low  = _cv([10.0, 10.1, 10.2])
        high = _cv([1.0, 5.0, 20.0])
        assert high > low


# ===========================================================================
# compute_fairness_metrics
# ===========================================================================

class TestComputeFairnessMetrics:
    def _make_result(self, scenario_path: str, depth: float, cred: float, solvable: bool) -> dict:
        return {
            "scenario": scenario_path,
            "mean_goal_depth": depth,
            "cred_chain_ratio": cred,
            "solvable": solvable,
        }

    def test_single_domain_basic_structure(self):
        results = [
            self._make_result("data/dom_A/train/s1", 3.0, 0.5, True),
            self._make_result("data/dom_A/train/s2", 5.0, 0.6, True),
        ]
        out = compute_fairness_metrics(results)
        assert out["domains_evaluated"] == 1
        assert "dom_A" in out["mean_depth_per_domain"]

    def test_two_domains_counted(self):
        results = [
            self._make_result("data/dom_A/train/s1", 3.0, 0.5, True),
            self._make_result("data/dom_B/train/s1", 5.0, 0.7, False),
        ]
        out = compute_fairness_metrics(results)
        assert out["domains_evaluated"] == 2

    def test_gini_and_cv_present_in_output(self):
        results = [
            self._make_result("data/x/train/s1", 2.0, 0.4, True),
        ]
        out = compute_fairness_metrics(results)
        assert "difficulty_gini" in out
        assert "cv_mean_depth" in out

    def test_equal_depths_gini_zero(self):
        results = [
            self._make_result(f"data/dom_{c}/train/s1", 4.0, 0.5, True)
            for c in "ABC"
        ]
        out = compute_fairness_metrics(results)
        assert out["difficulty_gini"] == 0.0

    def test_solvability_rate_all_solved(self):
        results = [
            self._make_result("data/d/train/s1", 3.0, 0.5, True),
            self._make_result("data/d/train/s2", 4.0, 0.6, True),
        ]
        out = compute_fairness_metrics(results)
        assert out["solvability_per_domain"]["d"] == 1.0

    def test_solvability_rate_none_solved(self):
        results = [
            self._make_result("data/d/train/s1", 3.0, 0.5, False),
            self._make_result("data/d/train/s2", 4.0, 0.6, False),
        ]
        out = compute_fairness_metrics(results)
        assert out["solvability_per_domain"]["d"] == 0.0

    def test_empty_results_returns_zero_domains(self):
        out = compute_fairness_metrics([])
        assert out["domains_evaluated"] == 0

    def test_mean_depth_computed_correctly(self):
        results = [
            self._make_result("data/d/train/s1", 2.0, 0.5, True),
            self._make_result("data/d/train/s2", 4.0, 0.5, True),
        ]
        out = compute_fairness_metrics(results)
        assert out["mean_depth_per_domain"]["d"] == 3.0


# ===========================================================================
# _find_hop_path
# ===========================================================================

class TestFindHopPath:
    def test_start_equals_target_returns_single_element(self):
        path = _find_hop_path({}, "A", "A")
        assert path == ["A"]

    def test_direct_edge_found(self):
        adj = {"A": {"B": []}}
        path = _find_hop_path(adj, "A", "B")
        assert path == ["A", "B"]

    def test_two_hop_path_found(self):
        adj = {"A": {"B": []}, "B": {"C": []}}
        path = _find_hop_path(adj, "A", "C")
        assert path == ["A", "B", "C"]

    def test_unreachable_returns_none(self):
        adj = {"A": {"B": []}}
        path = _find_hop_path(adj, "A", "Z")
        assert path is None

    def test_empty_graph_unreachable(self):
        path = _find_hop_path({}, "A", "B")
        assert path is None

    def test_diamond_shortest_path_length(self):
        # A→B→D and A→C→D: both 3 nodes; BFS finds one of them
        adj = {"A": {"B": [], "C": []}, "B": {"D": []}, "C": {"D": []}}
        path = _find_hop_path(adj, "A", "D")
        assert path is not None
        assert path[0] == "A"
        assert path[-1] == "D"
        assert len(path) == 3

    def test_cycle_does_not_loop_forever(self):
        # A→B→A cycle; target C unreachable
        adj = {"A": {"B": []}, "B": {"A": []}}
        path = _find_hop_path(adj, "A", "C")
        assert path is None

    def test_long_chain_returns_full_path(self):
        adj = {str(i): {str(i + 1): []} for i in range(10)}
        path = _find_hop_path(adj, "0", "10")
        assert path == [str(i) for i in range(11)]
