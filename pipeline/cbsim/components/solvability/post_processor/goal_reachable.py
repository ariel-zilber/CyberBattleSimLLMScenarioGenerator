"""
Goal-reachability guarantee (SolvabilityPostProcessor). Extracted verbatim
from solvability_post_processor.py::_ensure_goal_reachable.

NOTE: this is the exact function whose reliance on the shared
find_reachable_targets() fallback pool caused the earlier depth-collapse
regression when that pool was restricted without also fixing this
function's own dependency on random target selection. This extraction is
behavior-preserving (task #4) - the fix (task #5) comes after.
"""

import random
from typing import Dict, List

from cyberbattle.simulation.vulenrabilites import VulnerabilityType, LeakedCredentials
from pipeline.cbsim.components.solvability.shared.credential_helpers import make_cached_credentials
from pipeline.cbsim.components.solvability.shared.firewall_helpers import open_firewall_for_cred
from pipeline.cbsim.components.solvability.post_processor.credential_chain import (
    has_credential_leak, add_credential_leak_vulnerability,
)


def ensure_goal_reachable(
    nodes: Dict,
    entry_node_ids: set,
    goal_node_ids: set,
    cred_leak_templates: List[Dict],
    attack_flow: List[Dict],
    reachable_cache: Dict,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
) -> None:
    """
    Verify each goal node can be REACHED (not just discovered).
    A goal is reachable if:
      (a) it has a REMOTE vuln with LeakedCredentials → attackable from afar, OR
      (b) at least one other node's credential leak includes creds for it

    If neither, inject the goal's credentials into the nearest node's
    credential leak. Without this, partial target_coverage can create
    goals that are visible but inaccessible.
    """
    for goal_id in list(goal_node_ids):
        goal_node = nodes.get(goal_id)
        if not goal_node:
            continue

        # Check (a): goal has a REMOTE LeakedCredentials vuln
        goal_vulns = getattr(goal_node, 'vulnerabilities', {})
        has_remote_cred = False
        if isinstance(goal_vulns, dict):
            has_remote_cred = any(
                getattr(v, 'type', None) == VulnerabilityType.REMOTE
                and isinstance(getattr(v, 'outcome', None), LeakedCredentials)
                for v in goal_vulns.values()
            )
        if has_remote_cred:
            continue

        # Check (b): any node's credential leak targets this goal
        has_cred_path = False
        for nid, node in nodes.items():
            if nid == goal_id or nid == 'start':
                continue
            vulns = getattr(node, 'vulnerabilities', {})
            if not isinstance(vulns, dict):
                continue
            for v in vulns.values():
                outcome = getattr(v, 'outcome', None)
                if isinstance(outcome, LeakedCredentials):
                    for cred in outcome.credentials:
                        if getattr(cred, 'node', None) == goal_id:
                            has_cred_path = True
                            break
                if has_cred_path:
                    break
            if has_cred_path:
                break

        if has_cred_path:
            continue

        # Neither — inject goal's creds into nearest node's credential leak
        goal_creds = make_cached_credentials(nodes, goal_id)
        if not goal_creds:
            print(f"[Solvability] WARNING: goal {goal_id} has no services/credentials "
                  f"— cannot establish a credential path. Scenario may be unsolvable.")
            continue

        injected = False
        # Prefer entry nodes or nodes with existing credential leaks
        candidates = list(entry_node_ids)
        if not candidates:
            candidates = [nid for nid in nodes
                          if nid != goal_id and nid != 'start'
                          and has_credential_leak(nodes[nid])]
        random.shuffle(candidates)

        for nid in candidates:
            node = nodes.get(nid)
            if not node:
                continue
            vulns = getattr(node, 'vulnerabilities', {})
            if not isinstance(vulns, dict):
                continue
            for _vname, v in vulns.items():
                outcome = getattr(v, 'outcome', None)
                if isinstance(outcome, LeakedCredentials):
                    existing_targets = {getattr(c, 'node', None)
                                        for c in outcome.credentials}
                    for gc in goal_creds:
                        if gc.node not in existing_targets:
                            outcome.credentials.append(gc)
                    open_firewall_for_cred(nodes, nid, goal_id)
                    injected = True
                    fixes_applied.append(
                        f"Injected goal {goal_id} creds into {nid}'s credential leak")
                    break
            if injected:
                break

        if not injected:
            if candidates:
                nid = candidates[0]
                node = nodes[nid]
                add_credential_leak_vulnerability(
                    nodes, node, nid, cred_leak_templates, attack_flow, reachable_cache,
                    should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                    force=True,
                )
                fixes_applied.append(
                    f"Created credential leak on {nid} for goal {goal_id}")
            else:
                print(f"[Solvability] WARNING: goal {goal_id} has no reachable "
                      f"credential path and no injection candidate. "
                      f"Scenario may be unsolvable.")
