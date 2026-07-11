"""
Solvability rule validation + the remote-vuln adder used by entry-point
validation (SolvabilityConstraintProcessor). Extracted verbatim from
solvability_constraint_processor.py.
"""

import random
from typing import Dict, List

from cyberbattle.simulation.vulenrabilites import VulnerabilityInfo, VulnerabilityType, LeakedCredentials
from cyberbattle.simulation.rate import Rates
from pipeline import constants as C
from pipeline.cbsim.components.precondition_utils import precondition_from_properties
from pipeline.cbsim.components.solvability.shared.template_selection import pick_remote_template
from pipeline.cbsim.components.solvability.constraint_processor.credential_flows import (
    add_credential_leak_for_node,
)


def add_remote_vuln(
    node,
    node_id: str,
    remote_templates: List[Dict],
    make_cached_credentials_for_targets_fn,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    get_attr_fn,
    set_attr_fn,
    force: bool = False,
) -> None:
    tmpl = pick_remote_template(remote_templates, set(get_attr_fn(node, 'properties', [])))
    if not tmpl:
        return
    if not check_planned_fn(tmpl, 'remote_access'):
        return
    if not should_place_fn(tmpl, force=force):
        return

    real_creds = make_cached_credentials_for_targets_fn([node_id])
    if not real_creds:
        return

    vulns = get_attr_fn(node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        vulns = {}

    vulns[tmpl['name']] = VulnerabilityInfo(
        description=tmpl['description'],
        type=VulnerabilityType.REMOTE,
        outcome=LeakedCredentials(credentials=real_creds),
        precondition=precondition_from_properties(tmpl.get('match_properties', [])),
        reward_string=tmpl.get('reward', 'Exploit successful'),
        cost=get_vulnerability_cost_fn(tmpl),
        rates=Rates(successRate=tmpl['success_rate'])
    )
    set_attr_fn(node, 'vulnerabilities', vulns)
    fixes_applied.append(f"Added REMOTE vuln ({tmpl['name']}) to {node_id}")


def validate_entry_points(
    nodes: Dict,
    config: Dict,
    remote_templates: List[Dict],
    cred_leak_templates: List[Dict],
    attack_flow: List[Dict],
    rules: Dict,
    auto_fix: bool,
    find_node_fn,
    make_cached_credentials_for_targets_fn,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    get_attr_fn,
    set_attr_fn,
) -> None:
    entry_reqs = rules.get('entry_point_requirements', {})
    min_remote = entry_reqs.get('min_remote_vulnerabilities', 1)
    min_cred_leak = entry_reqs.get('min_credential_leaking_vulnerabilities', 1)

    for ep in config.get('entry_points', []):
        node_name = ep.get('node')
        node = find_node_fn(node_name)
        if not node:
            continue

        vulns = get_attr_fn(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            continue

        def _count_remote(v_dict):
            return sum(1 for v in v_dict.values()
                       if get_attr_fn(v, 'type') == VulnerabilityType.REMOTE
                       and isinstance(get_attr_fn(v, 'outcome', None), LeakedCredentials))

        def _count_local_cred_leak(v_dict):
            # Only LOCAL LeakedCredentials — post-compromise dumps.
            # REMOTE access is tracked separately via remote_count.
            return sum(1 for v in v_dict.values()
                       if get_attr_fn(v, 'type') == VulnerabilityType.LOCAL
                       and isinstance(get_attr_fn(v, 'outcome', None), LeakedCredentials))

        remote_count = _count_remote(vulns)
        cred_leak_count = _count_local_cred_leak(vulns)

        if auto_fix:
            node_id = get_attr_fn(node, 'name', '')

            # Inject REMOTE vulns; re-count after each attempt to detect failures
            for _ in range(min_remote - remote_count):
                prev = remote_count
                add_remote_vuln(
                    node, node_id, remote_templates, make_cached_credentials_for_targets_fn,
                    should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                    get_attr_fn, set_attr_fn, force=True,
                )
                remote_count = _count_remote(get_attr_fn(node, 'vulnerabilities', {}))
                if remote_count == prev:
                    print(f"[Constraints] Warning: could not inject remote vuln "
                          f"into {node_id} — no template or credentials available")
                    break

            # Inject LOCAL cred-leak vulns; re-count to detect failures
            for _ in range(min_cred_leak - cred_leak_count):
                prev = cred_leak_count
                add_credential_leak_for_node(
                    nodes, node, node_id, cred_leak_templates, attack_flow,
                    make_cached_credentials_for_targets_fn,
                    should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                    get_attr_fn, set_attr_fn, force=True,
                )
                cred_leak_count = _count_local_cred_leak(get_attr_fn(node, 'vulnerabilities', {}))
                if cred_leak_count == prev:
                    print(f"[Constraints] Warning: could not inject cred-leak vuln "
                          f"into {node_id} — no template or credentials available")
                    break


def validate_lateral_movement(
    nodes: Dict,
    rules: Dict,
    auto_fix: bool,
    cred_leak_templates: List[Dict],
    attack_flow: List[Dict],
    make_cached_credentials_for_targets_fn,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    get_attr_fn,
    set_attr_fn,
) -> None:
    lateral_reqs = rules.get('lateral_movement_requirements', {})
    min_ratio = lateral_reqs.get('min_credential_leaking_nodes', C.DEFAULT_MIN_CREDENTIAL_LEAKING_NODES_RATIO)

    if not isinstance(nodes, dict):
        return

    non_start = [nid for nid in nodes if nid != 'start']
    total = len(non_start)
    leak_count = sum(1 for nid in non_start
                     if any(isinstance(get_attr_fn(v, 'outcome', None), LeakedCredentials)
                            for v in get_attr_fn(nodes[nid], 'vulnerabilities', {}).values()))

    ratio = leak_count / total if total > 0 else 0

    if ratio < min_ratio and auto_fix:
        needed = int(total * min_ratio) - leak_count
        # Shuffle to avoid always fixing the same nodes
        candidates = [nid for nid in non_start
                      if isinstance(get_attr_fn(nodes[nid], 'vulnerabilities', {}), dict)
                      and not any(isinstance(get_attr_fn(v, 'outcome', None), LeakedCredentials)
                                  for v in get_attr_fn(nodes[nid], 'vulnerabilities', {}).values())]
        random.shuffle(candidates)
        for nid in candidates[:needed]:
            add_credential_leak_for_node(
                nodes, nodes[nid], nid, cred_leak_templates, attack_flow,
                make_cached_credentials_for_targets_fn,
                should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                get_attr_fn, set_attr_fn, force=True,
            )


def validate_goals(
    nodes: Dict,
    rules: Dict,
    auto_fix: bool,
    set_attr_fn,
    get_attr_fn,
) -> None:
    if not isinstance(nodes, dict):
        return
    goal_nodes = [(nid, n) for nid, n in nodes.items()
                  if nid != 'start' and get_attr_fn(n, 'is_goal')]
    if not goal_nodes and auto_fix:
        # NOTE: hardcoded 3 here, matching current main behavior exactly.
        # This does not read config.goal_config.num_goals — a real bug,
        # deliberately not fixed as part of this behavior-preserving
        # refactor (tracked as a separate follow-up).
        candidates = [nid for nid in nodes if nid != 'start']
        random.shuffle(candidates)
        for nid in candidates[:3]:
            set_attr_fn(nodes[nid], 'is_goal', True)


def validate_solvability(
    nodes: Dict,
    config: Dict,
    remote_templates: List[Dict],
    cred_leak_templates: List[Dict],
    attack_flow: List[Dict],
    find_node_fn,
    make_cached_credentials_for_targets_fn,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    get_attr_fn,
    set_attr_fn,
) -> None:
    rules = config.get('solvability_rules', {})
    if not rules:
        return
    auto_fix = rules.get('auto_fix_enabled', False)
    print(f"\n  [Validation] Validating solvability rules (auto-fix: {auto_fix})...")
    validate_entry_points(
        nodes, config, remote_templates, cred_leak_templates, attack_flow, rules, auto_fix,
        find_node_fn, make_cached_credentials_for_targets_fn,
        should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
        get_attr_fn, set_attr_fn,
    )
    validate_lateral_movement(
        nodes, rules, auto_fix, cred_leak_templates, attack_flow,
        make_cached_credentials_for_targets_fn,
        should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
        get_attr_fn, set_attr_fn,
    )
    validate_goals(nodes, rules, auto_fix, set_attr_fn, get_attr_fn)
