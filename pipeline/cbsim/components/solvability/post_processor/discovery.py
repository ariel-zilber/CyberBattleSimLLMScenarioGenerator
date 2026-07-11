"""
Discovery vulnerability placement and the goal-discoverability guarantee
(SolvabilityPostProcessor). Extracted verbatim from solvability_post_processor.py.
"""

import random
from typing import Dict, List

from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, LeakedNodesId,
)
from cyberbattle.simulation.rate import Rates
from pipeline.cbsim.components.precondition_utils import precondition_from_properties
from pipeline.cbsim.components.solvability.shared.template_selection import get_discovery_template


def has_discovery_capability(node) -> bool:
    vulns = getattr(node, 'vulnerabilities', {})
    if isinstance(vulns, dict):
        return any(isinstance(getattr(v, 'outcome', None), LeakedNodesId)
                   for v in vulns.values())
    return False


def add_discovery_vulnerability(
    nodes: Dict,
    node: object,
    node_id: str,
    discovery_templates: List[Dict],
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    force: bool = False,
) -> None:
    vulns = getattr(node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        vulns = {}

    tmpl = get_discovery_template(discovery_templates)
    if not tmpl or not check_planned_fn(tmpl, 'discovery'):
        return

    if not should_place_fn(tmpl, force=force):
        return

    all_others = [n for n in nodes if n != node_id and n != 'start']
    # Pick a SUBSET based on YAML target_coverage
    discovered = _select_targets(all_others, tmpl)

    vulns[tmpl['name']] = VulnerabilityInfo(
        description=tmpl['description'],
        type=VulnerabilityType.LOCAL,
        outcome=LeakedNodesId(nodes=discovered),
        precondition=precondition_from_properties(tmpl.get('match_properties', [])),
        reward_string=tmpl.get('reward', 'Exploit successful'),
        cost=get_vulnerability_cost_fn(tmpl),
        rates=Rates(successRate=tmpl['success_rate'])
    )
    node.vulnerabilities = vulns
    fixes_applied.append(f"Added discovery ({tmpl['name']}) to {node_id}")


def _select_targets(candidates: List[str], template: Dict) -> List[str]:
    import math
    coverage = template.get('target_coverage', 1.0)
    min_targets = template.get('min_targets', 1)

    if coverage >= 1.0:
        return list(candidates)
    if not candidates:
        return []

    n = max(min_targets, math.ceil(len(candidates) * coverage))
    n = min(n, len(candidates))
    return random.sample(candidates, n)


def ensure_goal_discoverable(
    nodes: Dict,
    entry_node_ids: set,
    goal_node_ids: set,
    fixes_applied: List[str],
) -> None:
    """
    Verify every goal node appears in at least one node's LeakedNodesId.
    Pre-computes a ``goal → discoverers`` mapping so each goal lookup is
    O(1) instead of re-scanning the full node set per goal.
    """
    discovered_anywhere: set = set()
    nodes_with_discovery = []  # (nid, vuln) pairs

    for nid, node in nodes.items():
        if nid == 'start':
            continue
        vulns = getattr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            continue
        for v in vulns.values():
            outcome = getattr(v, 'outcome', None)
            if isinstance(outcome, LeakedNodesId):
                discovered_anywhere.update(outcome.nodes)
                nodes_with_discovery.append((nid, v))

    start = nodes.get('start')
    if start:
        start_vulns = getattr(start, 'vulnerabilities', {})
        if isinstance(start_vulns, dict):
            for v in start_vulns.values():
                outcome = getattr(v, 'outcome', None)
                if isinstance(outcome, LeakedNodesId):
                    discovered_anywhere.update(outcome.nodes)

    # Shuffle once before iterating goals (not per-goal)
    random.shuffle(nodes_with_discovery)

    for goal_id in list(goal_node_ids):
        if goal_id in discovered_anywhere:
            continue

        injected = False
        for nid in entry_node_ids:
            if nid == goal_id:
                continue
            node = nodes.get(nid)
            if not node:
                continue
            vulns = getattr(node, 'vulnerabilities', {})
            if isinstance(vulns, dict):
                for v in vulns.values():
                    outcome = getattr(v, 'outcome', None)
                    if isinstance(outcome, LeakedNodesId):
                        outcome.nodes.append(goal_id)
                        discovered_anywhere.add(goal_id)
                        injected = True
                        fixes_applied.append(
                            f"Injected goal {goal_id} into {nid}'s discovery")
                        break
            if injected:
                break

        if not injected:
            for nid, v in nodes_with_discovery:
                if nid == goal_id:
                    continue
                outcome = getattr(v, 'outcome', None)
                if isinstance(outcome, LeakedNodesId):
                    outcome.nodes.append(goal_id)
                    discovered_anywhere.add(goal_id)
                    fixes_applied.append(
                        f"Injected goal {goal_id} into {nid}'s discovery (fallback)")
                    break


def ensure_discovery(
    nodes: Dict,
    entry_node_ids: set,
    goal_node_ids: set,
    discovery_templates: List[Dict],
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
) -> None:
    for node_id, node in nodes.items():
        if node_id == 'start':
            continue
        if has_discovery_capability(node):
            continue

        is_critical = node_id in entry_node_ids
        tmpl = get_discovery_template(discovery_templates)
        if tmpl and should_place_fn(tmpl, force=is_critical):
            add_discovery_vulnerability(
                nodes, node, node_id, discovery_templates,
                should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                force=True,
            )

    # After probabilistic placement, verify goal nodes are reachable
    ensure_goal_discoverable(nodes, entry_node_ids, goal_node_ids, fixes_applied)
