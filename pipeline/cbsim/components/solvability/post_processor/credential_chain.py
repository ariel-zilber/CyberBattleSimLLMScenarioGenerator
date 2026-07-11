"""
Credential-leak/dump vulnerability placement and the probabilistic
credential-chain enforcement pass (SolvabilityPostProcessor).
Extracted verbatim from solvability_post_processor.py.
"""

import random
from typing import Dict, List

from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, LeakedCredentials,
)
from cyberbattle.simulation.rate import Rates
from pipeline import constants as C
from pipeline.cbsim.components.precondition_utils import precondition_from_properties
from pipeline.cbsim.components.solvability.shared.template_selection import (
    get_cred_leak_template, pick_goal_template,
)
from pipeline.cbsim.components.solvability.shared.reachability import find_reachable_targets
from pipeline.cbsim.components.solvability.shared.credential_helpers import make_cached_credentials
from pipeline.cbsim.components.solvability.shared.firewall_helpers import open_firewall_for_cred
from pipeline.cbsim.components.solvability.shared.node_lookup import get_nodes_by_group_pattern


def has_credential_leak(node) -> bool:
    vulns = getattr(node, 'vulnerabilities', {})
    if isinstance(vulns, dict):
        return any(isinstance(getattr(v, 'outcome', None), LeakedCredentials)
                   for v in vulns.values())
    return False


def add_credential_leak_vulnerability(
    nodes: Dict,
    node: object,
    node_id: str,
    cred_leak_templates: List[Dict],
    attack_flow: List[Dict],
    reachable_cache: Dict,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    force: bool = False,
) -> None:
    vulns = getattr(node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        vulns = {}

    tmpl = get_cred_leak_template(cred_leak_templates)
    if not tmpl or not check_planned_fn(tmpl, 'cred_leak'):
        return

    if not should_place_fn(tmpl, force=force):
        return

    targets = find_reachable_targets(nodes, attack_flow, node_id, cache=reachable_cache)
    # Pick a SUBSET of reachable targets based on YAML target_coverage
    selected = _select_targets(targets, tmpl)
    all_cached = []
    for tid in selected:
        all_cached.extend(make_cached_credentials(nodes, tid))

    # If forced placement but random subset had no creds, try all targets
    if not all_cached and force and len(selected) < len(targets):
        for tid in targets:
            if tid not in selected:
                all_cached.extend(make_cached_credentials(nodes, tid))

    if not all_cached:
        return

    vulns[tmpl['name']] = VulnerabilityInfo(
        description=tmpl['description'],
        type=VulnerabilityType.LOCAL,
        outcome=LeakedCredentials(credentials=all_cached),
        precondition=precondition_from_properties(tmpl.get('match_properties', [])),
        reward_string=tmpl.get('reward', 'Exploit successful'),
        cost=get_vulnerability_cost_fn(tmpl),
        rates=Rates(successRate=tmpl['success_rate'])
    )
    node.vulnerabilities = vulns

    # Ensure the firewall allows credential-based lateral movement for each
    # credential we just leaked.  Without matching rules the simulation
    # blocks the connection even when the agent has valid credentials.
    target_ids = {cred.node for cred in all_cached}
    for tid in target_ids:
        open_firewall_for_cred(nodes, node_id, tid)

    fixes_applied.append(f"Added cred leak ({tmpl['name']}) to {node_id}")


def add_credential_dump_vulnerability(
    nodes: Dict,
    node: object,
    node_id: str,
    goal_templates: List[Dict],
    attack_flow: List[Dict],
    reachable_cache: Dict,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    force: bool = False,
) -> None:
    vulns = getattr(node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        vulns = {}

    properties = set(getattr(node, 'properties', []))
    tmpl = pick_goal_template(goal_templates, properties, 'dump')
    if not tmpl or not check_planned_fn(tmpl, 'dump'):
        return

    if not should_place_fn(tmpl, force=force):
        return

    # Start with self-creds (the node's own credentials)
    all_creds = list(make_cached_credentials(nodes, node_id))

    # Find reachable targets, then pick a SUBSET via target_coverage
    match_props = tmpl.get('match_properties', [])
    if match_props and any(p in properties for p in match_props):
        # DC-style dump: targets from attack flow
        reachable = []
        for rule in attack_flow:
            sp = rule.get('source_pattern', '')
            if sp and sp in node_id:
                for pattern in rule.get('targets', []):
                    for other_id in get_nodes_by_group_pattern(nodes, pattern):
                        if other_id != node_id:
                            reachable.append(other_id)
                break
        selected = _select_targets(reachable, tmpl)
    else:
        # Generic dump: targets from reachability
        reachable = find_reachable_targets(nodes, attack_flow, node_id, cache=reachable_cache)
        selected = _select_targets(reachable, tmpl)

    for tid in selected:
        all_creds.extend(make_cached_credentials(nodes, tid))

    if not all_creds:
        all_creds = make_cached_credentials(nodes, node_id)
        if not all_creds:
            return

    vulns[tmpl['name']] = VulnerabilityInfo(
        description=tmpl['description'],
        type=VulnerabilityType.LOCAL,
        outcome=LeakedCredentials(credentials=all_creds),
        precondition=precondition_from_properties(match_props),
        reward_string=tmpl.get('reward', 'Exploit successful'),
        cost=get_vulnerability_cost_fn(tmpl),
        rates=Rates(successRate=tmpl['success_rate'])
    )
    node.vulnerabilities = vulns
    fixes_applied.append(f"Added cred dump ({tmpl['name']}) to {node_id}")


def _select_targets(candidates: List[str], template: Dict) -> List[str]:
    """Pick a random subset of target nodes based on template's
    target_coverage and min_targets. Prevents leaking the entire network."""
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


def ensure_credential_chain(
    nodes: Dict,
    config: Dict,
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
    rules = config.get('solvability_rules', {})
    lateral = rules.get('lateral_movement_requirements', {})
    min_ratio = lateral.get('min_credential_leaking_nodes', C.DEFAULT_MIN_CREDENTIAL_LEAKING_NODES_RATIO)
    # max_credential_leaking_nodes caps the probabilistic phase to prevent
    # over-saturation (density > 0.40).  Defaults to 1.5× the minimum so
    # existing configs without the key are unaffected.
    max_ratio = lateral.get('max_credential_leaking_nodes',
                            min(min_ratio * C.DEFAULT_MAX_CREDENTIAL_LEAKING_NODES_MULTIPLIER, 1.0))

    non_start = [nid for nid in nodes if nid != 'start']
    total = len(non_start)
    target_count = max(1, int(total * min_ratio))
    max_count = max(target_count, int(total * max_ratio))

    # Phase 1: Probabilistic pass — each node rolls independently,
    # but stops once max_count is reached.
    placed = sum(1 for nid in non_start if has_credential_leak(nodes[nid]))
    for node_id in non_start:
        if placed >= max_count:
            break
        node = nodes[node_id]
        if has_credential_leak(node):
            continue

        is_critical = node_id in entry_node_ids or node_id in goal_node_ids
        tmpl = get_cred_leak_template(cred_leak_templates)
        if tmpl and should_place_fn(tmpl, force=is_critical):
            add_credential_leak_vulnerability(
                nodes, node, node_id, cred_leak_templates, attack_flow, reachable_cache,
                should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                force=True,
            )
            placed += 1

    # Phase 2: Enforce minimum ratio (deterministic top-up if needed)
    current = sum(1 for nid in non_start if has_credential_leak(nodes[nid]))
    if current < target_count:
        needed = target_count - current
        candidates = [nid for nid in non_start if not has_credential_leak(nodes[nid])]
        random.shuffle(candidates)
        for nid in candidates[:needed]:
            add_credential_leak_vulnerability(
                nodes, nodes[nid], nid, cred_leak_templates, attack_flow, reachable_cache,
                should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                force=True,
            )
