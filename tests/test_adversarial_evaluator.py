"""
Adversarial tests for pipeline/phase2/evaluator.py

Tests that probe edge cases, malformed inputs, graph topology tricks,
and threshold boundary conditions that normal happy-path tests skip.
"""

import math
import pytest
from pathlib import Path

from pipeline.phase2.evaluator import (
    _build_attack_edges,
    _compute_owned,
    _bfs_depth,
    _vuln_rate,
    _compute_stealth_margin,
    _check_thresholds,
    evaluate_scenario,
    THRESHOLDS,
)
from conftest import (
    make_scenario_dir,
    local_discovery_node,
    remote_goal_node,
    write_node,
)


# ===========================================================================
# _vuln_rate: type coercion adversarials
# ===========================================================================

class TestVulnRateAdversarial:
    def test_none_success_rate_returns_one(self):
        """None in the rates dict must not crash — returns optimistic 1.0."""
        assert _vuln_rate({"rates": {"successRate": None}}) == pytest.approx(1.0)

    def test_non_numeric_string_returns_one(self):
        """A word with no digits must not crash."""
        assert _vuln_rate({"rates": {"successRate": "unknown"}}) == pytest.approx(1.0)

    def test_infinity_capped_at_one(self):
        assert _vuln_rate({"rates": {"successRate": float("inf")}}) == pytest.approx(1.0)

    def test_negative_rate_returned_as_is(self):
        """Negative rates are stored as-is; callers enforce [0.05, 0.95]."""
        result = _vuln_rate({"rates": {"successRate": -0.1}})
        # code does min(float(v), 1.0) but no max-clamp on lower end
        assert result <= 0.0

    def test_rates_dict_empty_falls_back_to_top_level(self):
        vuln = {"rates": {}, "success_rate": 0.65}
        assert _vuln_rate(vuln) == pytest.approx(0.65)

    def test_rates_dict_with_both_keys_prefers_successRate(self):
        vuln = {"rates": {"successRate": 0.7, "success_rate": 0.3}}
        # successRate is checked first in the loop
        assert _vuln_rate(vuln) == pytest.approx(0.7)

    def test_string_with_multiple_numbers_takes_first(self):
        vuln = {"rates": "Rates(successRate=0.6, probingRate=0.1, exploitDetection=0.2)"}
        assert _vuln_rate(vuln) == pytest.approx(0.6)

    def test_empty_string_rate_returns_one(self):
        assert _vuln_rate({"rates": ""}) == pytest.approx(1.0)

    def test_rates_as_zero_returns_zero(self):
        assert _vuln_rate({"rates": 0.0}) == pytest.approx(0.0)


# ===========================================================================
# _build_attack_edges: malformed input adversarials
# ===========================================================================

class TestBuildAttackEdgesAdversarial:
    def test_none_outcome_does_not_crash(self):
        """Vuln with outcome=None must be silently skipped."""
        nodes = {
            "a": {
                "vulnerabilities": {
                    "v1": {"type": 2, "outcome": None}
                }
            },
            "b": {"vulnerabilities": {}},
        }
        # Should not raise
        adj = _build_attack_edges(nodes)
        assert isinstance(adj, dict)

    def test_missing_outcome_key_does_not_crash(self):
        nodes = {
            "a": {"vulnerabilities": {"v1": {"type": 2}}},
        }
        adj = _build_attack_edges(nodes)
        assert isinstance(adj, dict)

    def test_credential_entry_missing_kwargs(self):
        """Credentials list entry without kwargs must be silently skipped."""
        nodes = {
            "a": {
                "vulnerabilities": {
                    "v1": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_credentials",
                            "kwargs": {
                                "credentials": [
                                    {"no_kwargs_key": "value"}
                                ]
                            },
                        },
                    }
                }
            },
            "b": {"vulnerabilities": {}},
        }
        adj = _build_attack_edges(nodes)
        # No edge created because the credential entry had no 'node' or 'credential'
        assert len(adj.get("a", set())) == 0

    def test_empty_credentials_list_no_edge(self):
        nodes = {
            "a": {
                "vulnerabilities": {
                    "v1": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_credentials",
                            "kwargs": {"credentials": []},
                        },
                    }
                }
            },
        }
        adj = _build_attack_edges(nodes)
        assert len(adj.get("a", set())) == 0

    def test_diamond_graph_both_paths_present(self):
        """start→a→goal AND start→b→goal: both edges must exist."""
        nodes = {
            "start": {
                "vulnerabilities": {
                    "v1": {
                        "type": 2,
                        "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["a", "b"]}},
                    }
                }
            },
            "a": {
                "vulnerabilities": {
                    "remote": {"type": 3, "outcome": {"type": "lateral_move", "kwargs": {}}},
                    "disc": {"type": 2, "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["goal"]}}},
                }
            },
            "b": {
                "vulnerabilities": {
                    "remote": {"type": 3, "outcome": {"type": "lateral_move", "kwargs": {}}},
                    "disc": {"type": 2, "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["goal"]}}},
                }
            },
            "goal": {
                "is_goal": True,
                "vulnerabilities": {
                    "remote": {"type": 3, "outcome": {"type": "lateral_move", "kwargs": {}}}
                },
            },
        }
        adj = _build_attack_edges(nodes)
        assert "a" in adj.get("start", set())
        assert "b" in adj.get("start", set())
        # Both a and b discover goal (which has REMOTE) → edges a→goal, b→goal
        assert "goal" in adj.get("a", set())
        assert "goal" in adj.get("b", set())

    def test_fifty_node_linear_chain_does_not_crash(self):
        """50-hop linear chain: BFS must terminate and return correct depth.

        Each intermediate node needs a REMOTE vuln so that _build_attack_edges
        creates discovery-based edges to it (edges only exist when the target is
        in the has_remote set).
        """
        n = 50
        nodes = {}
        for i in range(n):
            name = f"node_{i}"
            next_name = f"node_{i+1}" if i < n - 1 else "goal"
            nodes[name] = {
                "vulnerabilities": {
                    # REMOTE vuln so predecessors can create edges TO this node
                    f"r_{i}": {
                        "type": 3,
                        "outcome": {"type": "lateral_move", "kwargs": {}},
                    },
                    # LOCAL discovery so edges FROM this node to the next exist
                    f"v_{i}": {
                        "type": 2,
                        "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": [next_name]}},
                    },
                }
            }
        nodes["start"] = {
            "vulnerabilities": {
                "v_start": {
                    "type": 2,
                    "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["node_0"]}},
                }
            }
        }
        nodes["goal"] = {
            "is_goal": True,
            "vulnerabilities": {
                "r": {"type": 3, "outcome": {"type": "lateral_move", "kwargs": {}}}
            },
        }
        adj = _build_attack_edges(nodes)
        depth = _bfs_depth(adj, "start", "goal")
        assert depth == n + 1  # start→node_0→…→node_49→goal


# ===========================================================================
# _compute_owned: adversarial state propagation
# ===========================================================================

class TestComputeOwnedAdversarial:
    def test_start_not_owned_if_start_not_in_nodes(self):
        assert _compute_owned({}) == set()

    def test_credential_not_used_if_target_not_discovered(self):
        """Credential leak to an undiscovered node → node stays unowned."""
        nodes = {
            "start": {
                "vulnerabilities": {
                    "v_leak": {
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
                                            "credential": "cred_b",
                                        },
                                    }
                                ]
                            },
                        },
                        "rates": {"successRate": 0.7},
                        "cost": 1.0,
                    }
                }
            },
            "b": {
                "services": [{"name": "SSH", "allowedCredentials": ["cred_b"]}],
                "vulnerabilities": {},
            },
        }
        # b is never discovered → credential cred_b is never applied
        owned = _compute_owned(nodes)
        assert "b" not in owned

    def test_remote_vuln_on_undiscovered_node_not_fired(self):
        """REMOTE exploit on a node that's never discovered → stays unowned."""
        nodes = {
            "start": {"vulnerabilities": {}},
            "hidden": remote_goal_node(),
        }
        owned = _compute_owned(nodes)
        assert "hidden" not in owned

    def test_ownership_propagates_local_vulns_on_newly_owned(self):
        """Once A is owned its LOCAL vulns fire, discovering C."""
        nodes = {
            "start": local_discovery_node(["a"]),
            "a": {
                "vulnerabilities": {
                    "remote": {
                        "type": 3,
                        "outcome": {"type": "lateral_move", "kwargs": {}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                    "disc_c": {
                        "type": 2,
                        "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["c"]}},
                        "rates": {"successRate": 0.8},
                        "cost": 1.0,
                    },
                }
            },
            "c": remote_goal_node(),
        }
        # Once a is owned, its LOCAL disc_c fires → c discovered → c owned via REMOTE
        owned = _compute_owned(nodes)
        assert "a" in owned
        assert "c" in owned

    def test_goal_at_depth_one_is_solvable(self):
        """Goal directly discoverable and remotely exploitable from start."""
        nodes = {
            "start": local_discovery_node(["goal"]),
            "goal": remote_goal_node(),
        }
        owned = _compute_owned(nodes)
        assert "goal" in owned

    def test_multiple_credentials_independent_propagation(self):
        """Two separate credential chains both succeed."""
        nodes = {
            "start": {
                "vulnerabilities": {
                    "disc": {
                        "type": 2,
                        "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["b", "c"]}},
                        "rates": {"successRate": 0.9},
                        "cost": 1.0,
                    },
                    "cred1": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_credentials",
                            "kwargs": {
                                "credentials": [
                                    {"type": "cached_credentials",
                                     "kwargs": {"node": "b", "port": "SSH", "credential": "cred_b"}}
                                ]
                            },
                        },
                        "rates": {"successRate": 0.7},
                        "cost": 1.0,
                    },
                    "cred2": {
                        "type": 2,
                        "outcome": {
                            "type": "leaked_credentials",
                            "kwargs": {
                                "credentials": [
                                    {"type": "cached_credentials",
                                     "kwargs": {"node": "c", "port": "RDP", "credential": "cred_c"}}
                                ]
                            },
                        },
                        "rates": {"successRate": 0.7},
                        "cost": 1.0,
                    },
                }
            },
            "b": {"services": [{"name": "SSH", "allowedCredentials": ["cred_b"]}], "vulnerabilities": {}},
            "c": {"services": [{"name": "RDP", "allowedCredentials": ["cred_c"]}], "vulnerabilities": {}},
        }
        owned = _compute_owned(nodes)
        assert "b" in owned
        assert "c" in owned


# ===========================================================================
# _bfs_depth: adversarial graph structures
# ===========================================================================

class TestBfsDepthAdversarial:
    def test_back_edge_does_not_loop(self):
        """Cycle a↔b: BFS must terminate and return correct depth."""
        adj = {"start": {"a"}, "a": {"b"}, "b": {"a", "goal"}}
        assert _bfs_depth(adj, "start", "goal") == 3

    def test_target_with_no_outgoing_edges_reachable(self):
        adj = {"start": {"goal"}}
        assert _bfs_depth(adj, "start", "goal") == 1

    def test_large_fan_out_finds_shortest(self):
        """Start connects to 50 siblings; only one has an edge to goal."""
        adj = {"start": {f"n{i}" for i in range(50)}}
        adj["n25"] = {"goal"}
        assert _bfs_depth(adj, "start", "goal") == 2

    def test_disconnected_component_unreachable(self):
        adj = {"start": {"a"}, "b": {"goal"}}  # b component disconnected
        assert _bfs_depth(adj, "start", "goal") == -1

    def test_path_through_dense_clique(self):
        """Dense clique n0..n9 all connected to each other; goal reachable via n0."""
        adj = {f"n{i}": {f"n{j}" for j in range(10) if j != i} for i in range(10)}
        adj["start"] = {"n0"}
        adj["n9"] = adj.get("n9", set()) | {"goal"}
        assert _bfs_depth(adj, "start", "goal") == 3  # start→n0→n9→goal


# ===========================================================================
# evaluate_scenario: threshold adversarials via tmpdir
# ===========================================================================

class TestEvaluateScenarioThresholds:
    def _make_shallow_scenario(self, tmp_path):
        """Goal reachable in 1 hop → min_goal_depth=1 < threshold of 2."""
        nodes = {
            "start": local_discovery_node(["goal"]),
            "goal": remote_goal_node(),
        }
        return make_scenario_dir(tmp_path, nodes)

    def test_min_goal_depth_one_trips_threshold(self, tmp_path):
        scenario = self._make_shallow_scenario(tmp_path)
        result = evaluate_scenario(scenario)
        assert result["min_goal_depth"] == 1
        # Verify threshold check catches it
        violations = _check_thresholds(result)
        depth_violations = [v for v in violations if "min_goal_depth" in v]
        assert len(depth_violations) == 1

    def test_goal_ratio_above_max_trips_threshold(self, tmp_path):
        """3 goals out of 4 nodes → ratio 0.75 > 0.25 threshold."""
        nodes = {
            "start": local_discovery_node(["g1", "g2", "g3", "filler"]),
            "g1": remote_goal_node(),
            "g2": remote_goal_node(),
            "g3": remote_goal_node(),
            "filler": {"vulnerabilities": {}},
        }
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        assert result["goal_ratio"] > THRESHOLDS["max_goal_ratio"]
        violations = _check_thresholds(result)
        ratio_violations = [v for v in violations if "goal_ratio" in v]
        assert len(ratio_violations) == 1

    def test_unsolvable_scenario_trips_solvable_threshold(self, tmp_path):
        nodes = {
            "start": {"vulnerabilities": {}},
            "goal": remote_goal_node(),
        }
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        assert result["solvable"] is False
        violations = _check_thresholds(result)
        assert any("solvable" in v for v in violations)

    def test_zero_cred_chain_ratio_trips_threshold(self, tmp_path):
        """No non-start node has a credential-leak vuln → cred_chain_ratio=0."""
        nodes = {
            "start": local_discovery_node(["a", "b", "c", "goal"]),
            "a": {"vulnerabilities": {"r": {"type": 3, "outcome": {"type": "lateral_move", "kwargs": {}}}}},
            "b": {"vulnerabilities": {"r": {"type": 3, "outcome": {"type": "lateral_move", "kwargs": {}}}}},
            "c": {"vulnerabilities": {"r": {"type": 3, "outcome": {"type": "lateral_move", "kwargs": {}}}}},
            "goal": remote_goal_node(),
        }
        scenario = make_scenario_dir(tmp_path, nodes)
        result = evaluate_scenario(scenario)
        assert result["cred_chain_ratio"] == pytest.approx(0.0)
        violations = _check_thresholds(result)
        assert any("cred_chain_ratio" in v for v in violations)

    def test_all_thresholds_pass_for_well_formed_scenario(self, tmp_path):
        """
        Construct a scenario that passes every _check_thresholds gate.

        Requirements:
          - solvable (start can reach goal)
          - min_goal_depth >= 2 (goal is >= 2 hops away)
          - cred_chain_ratio >= 0.40 (enough nodes leak credentials)
          - goal_ratio <= 0.25 (few goals relative to total nodes)
          - remote_exploitable_goals >= 1 (goal has REMOTE vuln)
        """
        import yaml as _yaml

        # Build 5 non-start nodes where >=2 have cred-leak vulns (>= 0.4 ratio)
        # Goal is 2 hops from start: start→a→goal
        cred = "cred_for_goal"
        nodes_dir = (tmp_path / "well_formed" / "nodes")
        nodes_dir.mkdir(parents=True)

        start_data = {
            "vulnerabilities": {
                "disc_a": {
                    "type": 2,
                    "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["a"]}},
                    "rates": {"successRate": 0.8},
                    "cost": 1.0,
                }
            }
        }
        a_data = {
            "vulnerabilities": {
                "remote_a": {
                    "type": 3,
                    "outcome": {"type": "lateral_move", "kwargs": {}},
                    "rates": {"successRate": 0.7},
                    "cost": 1.0,
                },
                "disc_goal": {
                    "type": 2,
                    "outcome": {"type": "leaked_nodes_id", "kwargs": {"nodes": ["goal"]}},
                    "rates": {"successRate": 0.8},
                    "cost": 1.0,
                },
                "cred_leak_goal": {
                    "type": 2,
                    "outcome": {
                        "type": "leaked_credentials",
                        "kwargs": {
                            "credentials": [
                                {"type": "cached_credentials",
                                 "kwargs": {"node": "goal", "port": "SSH", "credential": cred}}
                            ]
                        },
                    },
                    "rates": {"successRate": 0.7},
                    "cost": 1.0,
                },
            }
        }
        # Extra non-goal, non-start nodes to keep goal_ratio low
        filler = {
            "vulnerabilities": {
                "cred": {
                    "type": 2,
                    "outcome": {
                        "type": "leaked_credentials",
                        "kwargs": {
                            "credentials": [
                                {"type": "cached_credentials",
                                 "kwargs": {"node": "goal", "port": "SSH", "credential": cred}}
                            ]
                        },
                    },
                    "rates": {"successRate": 0.6},
                    "cost": 1.0,
                }
            }
        }
        goal_data = {
            "is_goal": True,
            "services": [{"name": "SSH", "allowedCredentials": [cred]}],
            "vulnerabilities": {
                "remote_goal": {
                    "type": 3,
                    "outcome": {"type": "lateral_move", "kwargs": {}},
                    "rates": {"successRate": 0.6},
                    "cost": 1.0,
                }
            },
        }

        (nodes_dir / "start.yaml").write_text(_yaml.dump(start_data))
        (nodes_dir / "a.yaml").write_text(_yaml.dump(a_data))
        (nodes_dir / "f1.yaml").write_text(_yaml.dump(filler))
        (nodes_dir / "f2.yaml").write_text(_yaml.dump(filler))
        (nodes_dir / "f3.yaml").write_text(_yaml.dump(filler))
        (nodes_dir / "f4.yaml").write_text(_yaml.dump(filler))
        (nodes_dir / "goal.yaml").write_text(_yaml.dump(goal_data))

        scenario = tmp_path / "well_formed"
        result = evaluate_scenario(scenario, include_attack_paths=False)
        assert result is not None
        assert result["solvable"] is True
        assert result["min_goal_depth"] >= 2
        assert result["goal_ratio"] <= THRESHOLDS["max_goal_ratio"]
        assert result["cred_chain_ratio"] >= THRESHOLDS["min_cred_chain_ratio"]


# ===========================================================================
# _check_thresholds: direct unit tests
# ===========================================================================

class TestCheckThresholds:
    def _base_passing(self) -> dict:
        """Minimal result dict that passes every threshold."""
        return {
            "solvable": True,
            "num_goals": 1,
            "cred_chain_ratio": 0.50,
            "discovery_ratio": 0.70,
            "min_goal_depth": 3,
            "mean_goal_depth": 3.0,
            "goal_ratio": 0.10,
            "remote_exploitable_goals": 1,
        }

    def test_passing_result_has_no_violations(self):
        assert _check_thresholds(self._base_passing()) == []

    def test_unsolvable_always_violates(self):
        r = {**self._base_passing(), "solvable": False}
        assert any("solvable" in v for v in _check_thresholds(r))

    def test_cred_chain_ratio_exact_threshold_passes(self):
        r = {**self._base_passing(), "cred_chain_ratio": THRESHOLDS["min_cred_chain_ratio"]}
        assert not any("cred_chain_ratio" in v for v in _check_thresholds(r))

    def test_cred_chain_ratio_below_threshold_violates(self):
        r = {**self._base_passing(), "cred_chain_ratio": THRESHOLDS["min_cred_chain_ratio"] - 0.01}
        assert any("cred_chain_ratio" in v for v in _check_thresholds(r))

    def test_goal_ratio_at_max_passes(self):
        r = {**self._base_passing(), "goal_ratio": THRESHOLDS["max_goal_ratio"]}
        assert not any("goal_ratio" in v for v in _check_thresholds(r))

    def test_goal_ratio_above_max_violates(self):
        r = {**self._base_passing(), "goal_ratio": THRESHOLDS["max_goal_ratio"] + 0.01}
        assert any("goal_ratio" in v for v in _check_thresholds(r))

    def test_min_goal_depth_one_with_goals_violates(self):
        r = {**self._base_passing(), "min_goal_depth": 1}
        assert any("min_goal_depth" in v for v in _check_thresholds(r))

    def test_min_goal_depth_irrelevant_when_no_goals(self):
        r = {**self._base_passing(), "min_goal_depth": 0, "num_goals": 0}
        # With 0 goals, depth check is skipped
        violations = _check_thresholds(r)
        assert not any("min_goal_depth" in v for v in violations)

    def test_zero_remote_exploitable_goals_violates(self):
        r = {**self._base_passing(), "remote_exploitable_goals": 0}
        assert any("remote_exploitable_goals" in v for v in _check_thresholds(r))

    def test_multiple_violations_all_reported(self):
        r = {
            "solvable": False,
            "num_goals": 2,
            "cred_chain_ratio": 0.1,
            "discovery_ratio": 0.1,
            "min_goal_depth": 1,
            "mean_goal_depth": 1.0,
            "goal_ratio": 0.9,
            "remote_exploitable_goals": 0,
        }
        violations = _check_thresholds(r)
        assert len(violations) >= 5
