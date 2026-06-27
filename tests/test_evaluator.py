"""
Unit tests for pipeline/phase2/evaluator.py

Tests cover pure-Python BFS functions that have no external dependencies.
evaluate_scenario() is tested via tmpdir node YAML fixtures.
"""

import pytest
from pathlib import Path

from pipeline.phase2.evaluator import (
    _build_attack_edges,
    _compute_owned,
    _bfs_depth,
    _vuln_rate,
    _compute_stealth_margin,
    evaluate_scenario,
)
from conftest import (
    make_scenario_dir,
    local_discovery_node,
    local_cred_leak_node,
    remote_goal_node,
    cred_accepting_node,
)


# ===========================================================================
# _build_attack_edges
# ===========================================================================

class TestBuildAttackEdges:
    def test_empty_nodes_returns_empty(self):
        assert _build_attack_edges({}) == {}

    def test_single_node_no_vulns(self):
        nodes = {"a": {"vulnerabilities": {}}}
        adj = _build_attack_edges(nodes)
        assert "a" not in adj or len(adj.get("a", set())) == 0

    def test_cred_leak_creates_edge(self):
        """Node A leaks a credential pointing to B → edge A→B."""
        nodes = {
            "a": {
                "vulnerabilities": {
                    "v1": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_credentials",
                            "kwargs": {
                                "credentials": [
                                    {
                                        "kwargs": {
                                            "node": "b",
                                            "credential": "cred_b",
                                        }
                                    }
                                ]
                            },
                        },
                    }
                }
            },
            "b": {"vulnerabilities": {}},
        }
        adj = _build_attack_edges(nodes)
        assert "b" in adj.get("a", set())

    def test_cred_leak_to_nonexistent_node_ignored(self):
        """Credential pointing to a node not in the graph → no edge."""
        nodes = {
            "a": {
                "vulnerabilities": {
                    "v1": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_credentials",
                            "kwargs": {
                                "credentials": [
                                    {
                                        "kwargs": {
                                            "node": "ghost",
                                            "credential": "cred_ghost",
                                        }
                                    }
                                ]
                            },
                        },
                    }
                }
            },
        }
        adj = _build_attack_edges(nodes)
        assert len(adj.get("a", set())) == 0

    def test_discovery_with_remote_creates_edge(self):
        """A discovers B (leaked_nodes_id), B has REMOTE vuln → edge A→B."""
        nodes = {
            "a": {
                "vulnerabilities": {
                    "v1": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_nodes_id",
                            "kwargs": {"nodes": ["b"]},
                        },
                    }
                }
            },
            "b": {
                "vulnerabilities": {
                    "v2": {
                        "type": 3,  # REMOTE
                        "outcome": {"type": "lateral_move", "kwargs": {}},
                    }
                }
            },
        }
        adj = _build_attack_edges(nodes)
        assert "b" in adj.get("a", set())

    def test_discovery_without_remote_no_edge(self):
        """A discovers B but B has no REMOTE vuln → no edge A→B."""
        nodes = {
            "a": {
                "vulnerabilities": {
                    "v1": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_nodes_id",
                            "kwargs": {"nodes": ["b"]},
                        },
                    }
                }
            },
            "b": {
                "vulnerabilities": {
                    "v2": {
                        "type": 2,  # LOCAL only
                        "outcome": {"type": "privilege_escalation", "kwargs": {}},
                    }
                }
            },
        }
        adj = _build_attack_edges(nodes)
        assert "b" not in adj.get("a", set())

    def test_no_self_edges_from_discovery(self):
        """A discovers itself → no self-edge."""
        nodes = {
            "a": {
                "vulnerabilities": {
                    "v1": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_nodes_id",
                            "kwargs": {"nodes": ["a"]},
                        },
                    }
                }
            },
        }
        # a is not in has_remote (no REMOTE vuln), so no edge
        adj = _build_attack_edges(nodes)
        assert "a" not in adj.get("a", set())

    def test_linear_chain(self):
        """start → A → B: all three edges (start→A and A→B) must exist."""
        nodes = {
            "start": {
                "vulnerabilities": {
                    "v1": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_nodes_id",
                            "kwargs": {"nodes": ["a"]},
                        },
                    }
                }
            },
            "a": {
                "vulnerabilities": {
                    "v_remote": {"type": 3, "outcome": {"type": "lateral_move", "kwargs": {}}},
                    "v_disc": {
                        "type": 2,
                        "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["b"]}},
                    },
                }
            },
            "b": {
                "is_goal": True,
                "vulnerabilities": {
                    "v_remote": {"type": 3, "outcome": {"type": "lateral_move", "kwargs": {}}}
                },
            },
        }
        adj = _build_attack_edges(nodes)
        assert "a" in adj.get("start", set())
        assert "b" in adj.get("a", set())


# ===========================================================================
# _compute_owned
# ===========================================================================

class TestComputeOwned:
    def test_no_start_returns_empty(self):
        nodes = {"a": {"vulnerabilities": {}}}
        assert _compute_owned(nodes) == set()

    def test_isolated_start_owns_only_itself(self):
        nodes = {"start": {"vulnerabilities": {}}}
        assert _compute_owned(nodes) == {"start"}

    def test_cred_chain_propagation(self):
        """start discovers b AND leaks cred → b accepts cred → b owned.

        _compute_owned only uses credentials on nodes that are already in the
        'discovered' set, so both a leaked_nodes_id and a leaked_credentials
        vuln are required on the source node.
        """
        cred = "cred_b"
        nodes = {
            "start": {
                "vulnerabilities": {
                    "Solvability.Discover": {
                        "type": 2,
                        "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["b"]}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                    "Solvability.CredLeak": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_credentials",
                            "kwargs": {
                                "credentials": [
                                    {
                                        "type": "cached_credentials",
                                        "kwargs": {"node": "b", "port": "SSH", "credential": cred},
                                    }
                                ]
                            },
                        },
                        "rates": {"successRate": 0.7},
                        "cost": 1.0,
                    },
                }
            },
            "b": cred_accepting_node(cred, is_goal=True),
        }
        owned = _compute_owned(nodes)
        assert "b" in owned

    def test_discovery_plus_remote_propagation(self):
        """start discovers b, b has REMOTE vuln → b becomes owned."""
        nodes = {
            "start": local_discovery_node(["b"]),
            "b": remote_goal_node(),
        }
        owned = _compute_owned(nodes)
        assert "b" in owned

    def test_three_hop_chain(self):
        """start → a → b → goal via discovery+remote at each step."""
        nodes = {
            "start": local_discovery_node(["a"]),
            "a": {
                "vulnerabilities": {
                    "Solvability.Remote": {
                        "type": 3,
                        "outcome": {"type": "lateral_move", "kwargs": {}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                    "Solvability.Disc": {
                        "type": 2,
                        "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["b"]}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                }
            },
            "b": {
                "vulnerabilities": {
                    "Solvability.Remote2": {
                        "type": 3,
                        "outcome": {"type": "lateral_move", "kwargs": {}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                    "Solvability.Disc2": {
                        "type": 2,
                        "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["goal"]}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                }
            },
            "goal": remote_goal_node(),
        }
        owned = _compute_owned(nodes)
        assert "a" in owned
        assert "b" in owned
        assert "goal" in owned

    def test_undiscovered_node_not_reachable(self):
        """If a node is never discovered or credential-linked, it stays unowned."""
        nodes = {
            "start": {"vulnerabilities": {}},
            "isolated": remote_goal_node(),
        }
        owned = _compute_owned(nodes)
        assert "isolated" not in owned

    def test_cycle_does_not_loop_forever(self):
        """Mutual discovery between a and b must not infinite-loop."""
        cred_a = "cred_a_to_b"
        cred_b = "cred_b_to_a"
        nodes = {
            "start": local_cred_leak_node("a", cred_a),
            "a": {
                "services": [{"name": "SSH", "allowedCredentials": [cred_a]}],
                "vulnerabilities": {
                    "Solvability.Leak": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_credentials",
                            "kwargs": {
                                "credentials": [
                                    {
                                        "type": "cached_credentials",
                                        "kwargs": {
                                            "node": "b",
                                            "port": "SSH",
                                            "credential": cred_b,
                                        },
                                    }
                                ]
                            },
                        },
                        "rates": {"successRate": 0.7},
                        "cost": 1.0,
                    }
                },
            },
            "b": {
                "services": [{"name": "SSH", "allowedCredentials": [cred_b]}],
                "vulnerabilities": {
                    "Solvability.Leak2": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_credentials",
                            "kwargs": {
                                "credentials": [
                                    {
                                        "type": "cached_credentials",
                                        "kwargs": {
                                            "node": "a",
                                            "port": "SSH",
                                            "credential": cred_a,
                                        },
                                    }
                                ]
                            },
                        },
                        "rates": {"successRate": 0.7},
                        "cost": 1.0,
                    }
                },
            },
        }
        # Should not raise or hang
        owned = _compute_owned(nodes)
        assert "start" in owned


# ===========================================================================
# _bfs_depth
# ===========================================================================

class TestBfsDepth:
    def test_start_equals_target_returns_zero(self):
        adj = {"a": {"b"}}
        assert _bfs_depth(adj, "a", "a") == 0

    def test_direct_neighbor_returns_one(self):
        adj = {"a": {"b"}}
        assert _bfs_depth(adj, "a", "b") == 1

    def test_two_hops(self):
        adj = {"a": {"b"}, "b": {"c"}}
        assert _bfs_depth(adj, "a", "c") == 2

    def test_three_hops(self):
        adj = {"a": {"b"}, "b": {"c"}, "c": {"d"}}
        assert _bfs_depth(adj, "a", "d") == 3

    def test_unreachable_returns_minus_one(self):
        adj = {"a": {"b"}}
        assert _bfs_depth(adj, "a", "c") == -1

    def test_empty_adj_unreachable(self):
        assert _bfs_depth({}, "x", "y") == -1

    def test_shortest_path_chosen(self):
        """Two paths: a→b→d (2 hops) and a→c→d (also 2) — should return 2."""
        adj = {"a": {"b", "c"}, "b": {"d"}, "c": {"d"}}
        assert _bfs_depth(adj, "a", "d") == 2

    def test_no_edge_from_start(self):
        adj = {"b": {"c"}}
        assert _bfs_depth(adj, "a", "c") == -1


# ===========================================================================
# _vuln_rate
# ===========================================================================

class TestVulnRate:
    def test_rates_dict_successRate(self):
        vuln = {"rates": {"successRate": 0.7}}
        assert _vuln_rate(vuln) == pytest.approx(0.7)

    def test_rates_dict_success_rate(self):
        vuln = {"rates": {"success_rate": 0.55}}
        assert _vuln_rate(vuln) == pytest.approx(0.55)

    def test_rates_as_plain_float(self):
        vuln = {"rates": 0.6}
        assert _vuln_rate(vuln) == pytest.approx(0.6)

    def test_top_level_success_rate(self):
        vuln = {"success_rate": 0.45}
        assert _vuln_rate(vuln) == pytest.approx(0.45)

    def test_rates_string_embedded_float(self):
        vuln = {"rates": "Rates(successRate=0.75, probing=0.0)"}
        assert _vuln_rate(vuln) == pytest.approx(0.75)

    def test_missing_rates_returns_one(self):
        assert _vuln_rate({}) == pytest.approx(1.0)

    def test_capped_at_one(self):
        vuln = {"rates": {"successRate": 1.5}}
        assert _vuln_rate(vuln) == pytest.approx(1.0)

    def test_zero_rate(self):
        vuln = {"rates": {"successRate": 0.0}}
        assert _vuln_rate(vuln) == pytest.approx(0.0)


# ===========================================================================
# _compute_stealth_margin
# ===========================================================================

class TestComputeStealthMargin:
    def _make_path(self, actions: list, total_cost: float) -> dict:
        return {"actions": actions, "total_cost": total_cost}

    def test_low_cost_is_stealthy(self):
        result = _compute_stealth_margin(self._make_path([], 2.0), detection_threshold=10.0)
        assert result["is_stealthy"] is True
        assert result["stealth_margin"] == pytest.approx(8.0)

    def test_high_cost_not_stealthy(self):
        result = _compute_stealth_margin(self._make_path([], 12.0), detection_threshold=10.0)
        assert result["is_stealthy"] is False
        assert result["stealth_margin"] == pytest.approx(-2.0)

    def test_exact_threshold_not_stealthy(self):
        result = _compute_stealth_margin(self._make_path([], 10.0), detection_threshold=10.0)
        assert result["is_stealthy"] is False
        assert result["stealth_margin"] == pytest.approx(0.0)

    def test_no_actions_stealthiest_is_none(self):
        result = _compute_stealth_margin({"actions": [], "total_cost": 0.0})
        assert result["stealthiest_action"] is None

    def test_stealthiest_action_is_min_cost(self):
        actions = [
            {"action_type": "REMOTE_EXPLOIT", "vuln_name": "v1", "cost": 3.0},
            {"action_type": "LOCAL_CRED_LEAK", "vuln_name": "v2", "cost": 1.0},
            {"action_type": "CREDENTIAL_USE", "vuln_name": "v3", "cost": 5.0},
        ]
        result = _compute_stealth_margin({"actions": actions, "total_cost": 9.0})
        assert result["stealthiest_action"]["vuln_name"] == "v2"
        assert result["stealthiest_action"]["cost"] == pytest.approx(1.0)

    def test_stealth_ratio_computed(self):
        result = _compute_stealth_margin({"actions": [], "total_cost": 5.0}, detection_threshold=10.0)
        assert result["stealth_ratio"] == pytest.approx(0.5)

    def test_detection_threshold_in_result(self):
        result = _compute_stealth_margin({"actions": [], "total_cost": 1.0}, detection_threshold=7.5)
        assert result["detection_threshold"] == pytest.approx(7.5)


# ===========================================================================
# evaluate_scenario (integration via tmpdir)
# ===========================================================================

class TestEvaluateScenario:
    def test_no_nodes_dir_returns_none(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert evaluate_scenario(empty) is None

    def test_no_start_node_returns_none(self, tmp_path):
        nodes = {"a": remote_goal_node()}
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        # no 'start' → _compute_owned returns empty → solvable=False or None
        # evaluator returns None when non_start is empty or no nodes
        # With only 'a' (no start), _compute_owned returns {} so solvable=False
        assert result is None or result["solvable"] is False

    def test_minimal_solvable_scenario(self, tmp_path):
        """start discovers goal, goal has REMOTE vuln → solvable."""
        nodes = {
            "start": local_discovery_node(["goal"]),
            "goal": remote_goal_node(),
        }
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        assert result is not None
        assert result["solvable"] is True

    def test_unreachable_goal_not_solvable(self, tmp_path):
        """Goal exists but start has no path to it → solvable=False."""
        nodes = {
            "start": {"vulnerabilities": {}},
            "goal": remote_goal_node(),
        }
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        assert result is not None
        assert result["solvable"] is False

    def test_num_nodes_excludes_start(self, tmp_path):
        """num_nodes counts non-start nodes only."""
        nodes = {
            "start": local_discovery_node(["a", "b"]),
            "a": remote_goal_node(),
            "b": remote_goal_node(),
        }
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        assert result["num_nodes"] == 2

    def test_cred_chain_ratio(self, tmp_path):
        """cred_chain_ratio = nodes_with_cred_leak_vuln / non_start_nodes."""
        cred = "cred_for_b"
        nodes = {
            "start": local_discovery_node(["a", "b"]),
            "a": {
                # has a leaked_credentials vuln
                "vulnerabilities": {
                    "Solvability.Leak": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_credentials",
                            "kwargs": {
                                "credentials": [
                                    {"type": "cached_credentials", "kwargs": {"node": "b", "port": "SSH", "credential": cred}}
                                ]
                            },
                        },
                        "rates": {"successRate": 0.7},
                        "cost": 1.0,
                    }
                },
            },
            "b": cred_accepting_node(cred, is_goal=True),
        }
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        # a has cred_leak vuln → 1 out of 2 non-start nodes
        assert result["cred_chain_ratio"] == pytest.approx(0.5)

    def test_discovery_ratio(self, tmp_path):
        """discovery_ratio counts non-start nodes appearing in leaked_nodes_id outcomes.

        evaluate_scenario only scans non-start nodes' vulns for discovery coverage,
        so the leaked_nodes_id vuln must be on a non-start node (e.g. 'a' discovers 'b').
        """
        nodes = {
            "start": local_discovery_node(["a"]),
            "a": {
                # non-start node that discovers 'b'
                "vulnerabilities": {
                    "Solvability.Remote": {
                        "type": 3,
                        "outcome": {"type": "lateral_move", "kwargs": {}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                    "Solvability.Discover": {
                        "type": 2,
                        "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["b"]}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                }
            },
            "b": remote_goal_node(),  # discovered by 'a'
            "c": remote_goal_node(),  # never discovered by any non-start node
        }
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        # 'b' is discovered (via a), 'c' is not → 1 out of 3 non-start nodes
        assert result["discovery_ratio"] == pytest.approx(1.0 / 3.0, abs=0.01)

    def test_min_goal_depth_two_hops(self, tmp_path):
        """2-hop chain: start → a → goal, min_goal_depth should be 2."""
        nodes = {
            "start": local_discovery_node(["a"]),
            "a": {
                "vulnerabilities": {
                    "Solvability.Remote": {
                        "type": 3,
                        "outcome": {"type": "lateral_move", "kwargs": {}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                    "Solvability.Disc": {
                        "type": 2,
                        "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["goal"]}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                }
            },
            "goal": remote_goal_node(),
        }
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        assert result["min_goal_depth"] == 2

    def test_result_keys_present(self, tmp_path):
        nodes = {
            "start": local_discovery_node(["goal"]),
            "goal": remote_goal_node(),
        }
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        for key in ("solvable", "num_nodes", "num_goals", "goal_ratio",
                    "cred_chain_ratio", "discovery_ratio",
                    "min_goal_depth", "max_goal_depth", "mean_goal_depth"):
            assert key in result, f"missing key: {key}"
