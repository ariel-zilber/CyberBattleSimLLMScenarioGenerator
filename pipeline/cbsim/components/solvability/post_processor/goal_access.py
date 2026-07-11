"""
Goal-access enforcement: every goal node always gets privilege escalation
+ a credential dump, regardless of probability (SolvabilityPostProcessor).
Extracted verbatim from solvability_post_processor.py.
"""

from typing import Dict, List

from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, LeakedCredentials,
    PrivilegeEscalation, PrivilegeLevel,
)
from cyberbattle.simulation.rate import Rates
from pipeline.cbsim.components.precondition_utils import precondition_from_properties
from pipeline.cbsim.components.solvability.shared.template_selection import pick_goal_template
from pipeline.cbsim.components.solvability.post_processor.credential_chain import (
    add_credential_dump_vulnerability,
)


def add_privilege_escalation_vulnerability(
    node: object,
    node_id: str,
    goal_templates: List[Dict],
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
    tmpl = pick_goal_template(goal_templates, properties, 'privesc')
    if not tmpl:
        # No privesc-specific template in this config — fall back to any
        # property-matching goal template and force PrivilegeEscalation outcome.
        tmpl = pick_goal_template(goal_templates, properties, None)
    if not tmpl or not check_planned_fn(tmpl, 'privesc'):
        return

    if not should_place_fn(tmpl, force=force):
        return

    # Privesc vulns always produce PrivilegeEscalation (not cred-leak).
    outcome = PrivilegeEscalation(level=PrivilegeLevel.Admin)

    vulns[tmpl['name']] = VulnerabilityInfo(
        description=tmpl['description'],
        type=VulnerabilityType.LOCAL,
        outcome=outcome,
        precondition=precondition_from_properties(tmpl.get('match_properties', [])),
        reward_string=tmpl.get('reward', 'Exploit successful'),
        cost=get_vulnerability_cost_fn(tmpl),
        rates=Rates(successRate=tmpl['success_rate'])
    )
    node.vulnerabilities = vulns
    fixes_applied.append(f"Added privesc ({tmpl['name']}) to {node_id}")


def ensure_goal_access(
    nodes: Dict,
    goal_templates: List[Dict],
    attack_flow: List[Dict],
    reachable_cache: Dict,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
) -> None:
    for node_id, node in nodes.items():
        if node_id == 'start':
            continue
        if not getattr(node, 'is_goal', False):
            continue

        vulns = getattr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            vulns = {}

        has_privesc = any(
            isinstance(getattr(v, 'outcome', None), PrivilegeEscalation)
            for v in vulns.values()
        )
        has_cred_dump = any(
            isinstance(getattr(v, 'outcome', None), LeakedCredentials)
            and getattr(v, 'type', None) == VulnerabilityType.LOCAL
            for v in vulns.values()
        )

        # Goal nodes ALWAYS get these — ignore probability
        if not has_privesc:
            add_privilege_escalation_vulnerability(
                node, node_id, goal_templates,
                should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                force=True,
            )
        if not has_cred_dump:
            add_credential_dump_vulnerability(
                nodes, node, node_id, goal_templates, attack_flow, reachable_cache,
                should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                force=True,
            )
