"""Shared fixtures and helpers for the llmgenerator test suite."""

import sys
from pathlib import Path

import pytest
import yaml

# Ensure repo root is on sys.path so `pipeline` and `tools` are importable.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------------
# Node / scenario construction helpers
# ---------------------------------------------------------------------------

def write_node(nodes_dir: Path, node_id: str, data: dict) -> None:
    (nodes_dir / f"{node_id}.yaml").write_text(yaml.dump(data))


def make_scenario_dir(tmp_path: Path, nodes: dict) -> Path:
    """Return a scenario dir with nodes/ populated from the given dict."""
    scenario = tmp_path / "scenario"
    nodes_dir = scenario / "nodes"
    nodes_dir.mkdir(parents=True)
    for node_id, node_data in nodes.items():
        write_node(nodes_dir, node_id, node_data)
    return scenario


# ---------------------------------------------------------------------------
# Minimal node building blocks
# ---------------------------------------------------------------------------

def local_discovery_node(discovers: list[str]) -> dict:
    """Node whose LOCAL vuln leaks the node IDs in `discovers`."""
    return {
        "vulnerabilities": {
            "Solvability.Discovery": {
                "type": 2,
                "outcome": {
                    "type": "leaked_nodes_id",
                    "kwargs": {"nodes": discovers},
                },
                "rates": {"successRate": 0.8},
                "cost": 1.0,
            }
        }
    }


def local_cred_leak_node(target_node: str, cred: str) -> dict:
    """Node whose LOCAL vuln leaks a credential for `target_node`."""
    return {
        "vulnerabilities": {
            "Solvability.CredLeak": {
                "type": 2,
                "outcome": {
                    "type": "leaked_credentials",
                    "kwargs": {
                        "credentials": [
                            {
                                "type": "cached_credentials",
                                "kwargs": {
                                    "node": target_node,
                                    "port": "SSH",
                                    "credential": cred,
                                },
                            }
                        ]
                    },
                },
                "rates": {"successRate": 0.7},
                "cost": 1.0,
            }
        }
    }


def remote_goal_node(cred: str | None = None) -> dict:
    """Goal node with one REMOTE exploit and an optional service accepting `cred`."""
    node: dict = {
        "is_goal": True,
        "vulnerabilities": {
            "Solvability.RemoteExploit": {
                "type": 3,
                "outcome": {"type": "lateral_move", "kwargs": {}},
                "rates": {"successRate": 0.6},
                "cost": 1.0,
            }
        },
    }
    if cred:
        node["services"] = [{"name": "SSH", "allowedCredentials": [cred]}]
    return node


def cred_accepting_node(cred: str, is_goal: bool = False) -> dict:
    """Non-goal (or goal) node whose SSH service accepts the given credential."""
    return {
        "is_goal": is_goal,
        "services": [{"name": "SSH", "allowedCredentials": [cred]}],
        "vulnerabilities": {},
    }
