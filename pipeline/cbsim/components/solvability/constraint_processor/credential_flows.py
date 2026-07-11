"""
Credential-flow constraint processing and credential-leak vulnerability
placement (SolvabilityConstraintProcessor). Extracted verbatim from
solvability_constraint_processor.py.
"""

import random
import math
from typing import Dict, List

from cyberbattle.simulation.vulenrabilites import VulnerabilityInfo, VulnerabilityType, LeakedCredentials, CachedCredential
from cyberbattle.simulation.rate import Rates
from pipeline.cbsim.components.precondition_utils import precondition_from_properties
from pipeline.cbsim.components.solvability.shared.template_selection import get_cred_leak_template
from pipeline.cbsim.components.solvability.shared.reachability import find_reachable_targets


def select_targets(candidates: List[str], template: Dict) -> List[str]:
    """Pick a random subset based on target_coverage + min_targets from template."""
    if not candidates:
        return []
    coverage = template.get('target_coverage', 1.0)
    min_targets = template.get('min_targets', 1)

    if coverage >= 1.0:
        return list(candidates)

    n = max(min_targets, math.ceil(len(candidates) * coverage))
    n = min(n, len(candidates))
    return random.sample(candidates, n)


def add_credential_leak_vuln(
    node,
    cached_creds: List[CachedCredential],
    cred_leak_templates: List[Dict],
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    get_attr_fn,
    set_attr_fn,
    force: bool = False,
) -> None:
    tmpl = get_cred_leak_template(cred_leak_templates)
    if not tmpl:
        return
    if not check_planned_fn(tmpl, 'credential_leak'):
        return
    if not should_place_fn(tmpl, force=force):
        return

    vulns = get_attr_fn(node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        vulns = {}

    vulns[tmpl['name']] = VulnerabilityInfo(
        description=tmpl['description'],
        type=VulnerabilityType.LOCAL,
        outcome=LeakedCredentials(credentials=cached_creds),
        precondition=precondition_from_properties(tmpl.get('match_properties', [])),
        reward_string=tmpl.get('reward', 'Exploit successful'),
        cost=get_vulnerability_cost_fn(tmpl),
        rates=Rates(successRate=tmpl['success_rate'])
    )
    set_attr_fn(node, 'vulnerabilities', vulns)
    fixes_applied.append(f"Added credential leak ({tmpl['name']}) to {get_attr_fn(node, 'name', '?')}")


def add_credential_leak_for_node(
    nodes: Dict,
    node,
    node_id: str,
    cred_leak_templates: List[Dict],
    attack_flow: List[Dict],
    make_cached_credentials_for_targets_fn,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    get_attr_fn,
    set_attr_fn,
    force: bool = False,
) -> None:
    targets = find_reachable_targets(nodes, attack_flow, node_id)

    # Pick a SUBSET based on YAML target_coverage
    tmpl = get_cred_leak_template(cred_leak_templates)
    selected = select_targets(targets, tmpl) if tmpl else targets[:1]
    cached = make_cached_credentials_for_targets_fn(selected)

    # If forced but random subset had no creds, try all targets
    if not cached and force and len(selected) < len(targets):
        cached = make_cached_credentials_for_targets_fn(targets)

    if cached:
        add_credential_leak_vuln(
            node, cached, cred_leak_templates,
            should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
            get_attr_fn, set_attr_fn, force=force,
        )


def process_credential_flows(
    nodes: Dict,
    domain_def: Dict,
    domain_name: str,
    get_node_ids_in_group_fn,
    make_cached_credentials_for_targets_fn,
    cred_leak_templates: List[Dict],
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    get_attr_fn,
    set_attr_fn,
) -> None:
    cred_flows = domain_def.get('credential_flows', [])
    for flow in cred_flows:
        from_group = flow.get('from')
        to_group = flow.get('to')
        reuse_prob = flow.get('reuse_probability', 0.8)

        source_ids = get_node_ids_in_group_fn(domain_name, from_group)
        target_ids = get_node_ids_in_group_fn(domain_name, to_group)

        if not source_ids or not target_ids:
            continue

        target_creds = make_cached_credentials_for_targets_fn(target_ids)
        if reuse_prob < 1.0:
            target_creds = [c for c in target_creds if random.random() < reuse_prob]

        if target_creds:
            for sid in source_ids:
                if isinstance(nodes, dict) and sid in nodes:
                    add_credential_leak_vuln(
                        nodes[sid], target_creds, cred_leak_templates,
                        should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                        get_attr_fn, set_attr_fn,
                    )
