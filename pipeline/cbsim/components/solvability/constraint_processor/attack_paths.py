"""
Attack-path constraint processing (SolvabilityConstraintProcessor).
Extracted verbatim from solvability_constraint_processor.py::_process_attack_paths.
"""

from typing import Dict
from pipeline.cbsim.components.solvability.constraint_processor.credential_flows import (
    add_credential_leak_vuln,
)


def process_attack_paths(
    nodes: Dict,
    domain_def: Dict,
    domain_name: str,
    get_node_ids_in_group_fn,
    make_cached_credentials_for_targets_fn,
    cred_leak_templates,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied,
    get_attr_fn,
    set_attr_fn,
) -> None:
    attack_paths = domain_def.get('attack_paths', [])
    for attack_path in attack_paths:
        path_steps = attack_path.get('path', [])
        for step in path_steps:
            source_group = step.get('source')
            target_group = step.get('target')
            credential_leakage = step.get('credential_leakage', False)

            source_ids = get_node_ids_in_group_fn(domain_name, source_group)
            target_ids = get_node_ids_in_group_fn(domain_name, target_group)

            if not source_ids or not target_ids:
                continue

            if credential_leakage:
                target_creds = make_cached_credentials_for_targets_fn(target_ids)
                if target_creds:
                    for sid in source_ids:
                        if isinstance(nodes, dict) and sid in nodes:
                            add_credential_leak_vuln(
                                nodes[sid], target_creds, cred_leak_templates,
                                should_place_fn, check_planned_fn, get_vulnerability_cost_fn,
                                fixes_applied, get_attr_fn, set_attr_fn,
                            )
