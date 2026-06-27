"""
Unit tests for pipeline/constants.py

Verifies that constants encoding spec invariants (D-A5 allowlist,
LaTeX Table 1 action sums, threshold ranges) are correct.
"""

import pytest
from pipeline import constants as C


VALID_CATEGORIES = {
    "remote_access",
    "credential_leak",
    "discovery",
    "goal_access",
    "lateral_movement",
}

# Action distribution from LaTeX Table 1 (specialist_agent_design.tex §1.1)
SPECIALIST_ACTION_COUNTS = {
    "S_Network":  {"local": 18, "remote": 14, "connect": 18},
    "S_Linux":    {"local": 19, "remote": 17, "connect": 14},
    "S_Windows":  {"local": 12, "remote": 21, "connect": 17},
    "S_Identity": {"local": 15, "remote": 16, "connect": 19},
    "S_Lateral":  {"local": 34, "remote":  4, "connect": 12},
}


class TestAgentCategoryAllowlist:
    def test_all_specialists_present(self):
        expected = {"S_Network", "S_Linux", "S_Windows", "S_Identity", "S_Lateral", "Meta"}
        assert set(C.AGENT_CATEGORY_ALLOWLIST.keys()) == expected

    def test_every_specialist_has_at_least_one_category(self):
        for agent, cats in C.AGENT_CATEGORY_ALLOWLIST.items():
            assert len(cats) >= 1, f"{agent} has empty category list"

    def test_all_categories_are_known_strings(self):
        for agent, cats in C.AGENT_CATEGORY_ALLOWLIST.items():
            for cat in cats:
                assert cat in VALID_CATEGORIES, \
                    f"{agent} has unknown category '{cat}'"

    def test_s_network_excludes_lateral_movement(self):
        assert "lateral_movement" not in C.AGENT_CATEGORY_ALLOWLIST["S_Network"]

    def test_s_network_excludes_goal_access(self):
        assert "goal_access" not in C.AGENT_CATEGORY_ALLOWLIST["S_Network"]

    def test_s_lateral_excludes_goal_access(self):
        assert "goal_access" not in C.AGENT_CATEGORY_ALLOWLIST["S_Lateral"]

    def test_s_identity_excludes_lateral_movement(self):
        assert "lateral_movement" not in C.AGENT_CATEGORY_ALLOWLIST["S_Identity"]

    def test_meta_has_all_categories(self):
        meta_cats = set(C.AGENT_CATEGORY_ALLOWLIST["Meta"])
        assert meta_cats == VALID_CATEGORIES, \
            f"Meta missing: {VALID_CATEGORIES - meta_cats}"


class TestThresholdRanges:
    def test_target_score_in_range(self):
        assert 0 < C.TARGET_SCORE <= 10

    def test_min_solve_rate_in_range(self):
        assert 0 < C.MIN_SOLVE_RATE < 1

    def test_solve_rate_design_threshold_below_min_solve_rate(self):
        assert C.SOLVE_RATE_DESIGN_THRESHOLD < C.MIN_SOLVE_RATE

    def test_max_bfs_rounds_positive(self):
        assert C.MAX_BFS_ROUNDS >= 1

    def test_max_repair_attempts_positive(self):
        assert C.MAX_REPAIR_ATTEMPTS >= 1

    def test_bfs_episodes_positive(self):
        assert C.BFS_EPISODES >= 1

    def test_bfs_max_steps_positive(self):
        assert C.BFS_MAX_STEPS >= 1

    def test_solvability_prob_range_ordered(self):
        lo, hi = C.SOLVABILITY_PROB_RANGE
        assert lo < hi

    def test_solvability_prob_range_valid(self):
        lo, hi = C.SOLVABILITY_PROB_RANGE
        assert 0 <= lo and hi <= 1


class TestLatexSpecActionSums:
    """Each specialist's local + remote + connect must equal 50 (LaTeX Table 1)."""

    @pytest.mark.parametrize("specialist", list(SPECIALIST_ACTION_COUNTS.keys()))
    def test_action_sum_equals_50(self, specialist):
        counts = SPECIALIST_ACTION_COUNTS[specialist]
        total = counts["local"] + counts["remote"] + counts["connect"]
        assert total == 50, (
            f"{specialist}: {counts['local']}L + {counts['remote']}R "
            f"+ {counts['connect']}K = {total} ≠ 50"
        )

    def test_s_lateral_is_local_heavy(self):
        """S_Lateral is mostly local exploits (34/50) per LaTeX spec."""
        counts = SPECIALIST_ACTION_COUNTS["S_Lateral"]
        assert counts["local"] == 34

    def test_s_lateral_minimal_remote(self):
        """S_Lateral has only 4 remote exploits — post-exploitation specialist."""
        assert SPECIALIST_ACTION_COUNTS["S_Lateral"]["remote"] == 4

    def test_s_windows_remote_heavy(self):
        """S_Windows has most remote exploits (21) — RDP/SMB domain."""
        assert SPECIALIST_ACTION_COUNTS["S_Windows"]["remote"] == 21
