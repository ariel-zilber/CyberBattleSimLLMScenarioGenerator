"""
Discovery-chain constraint processing (SolvabilityConstraintProcessor).
Extracted verbatim from solvability_constraint_processor.py.
"""

from typing import Dict, List

from cyberbattle.simulation.vulenrabilites import VulnerabilityInfo, VulnerabilityType, LeakedNodesId
from cyberbattle.simulation.rate import Rates
from pipeline.cbsim.components.solvability.shared.template_selection import get_discovery_template


def ensure_discovery_vulnerability(
    node,
    resolved_ids: List[str],
    mechanisms: List[str],
    discovery_templates: List[Dict],
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    get_attr_fn,
    set_attr_fn,
    force: bool = False,
) -> None:
    vulns = get_attr_fn(node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        vulns = {}

    has_discovery = any(isinstance(get_attr_fn(v, 'outcome', None), LeakedNodesId)
                        for v in vulns.values())
    if has_discovery:
        return

    tmpl = get_discovery_template(discovery_templates)
    if not tmpl:
        return
    if not check_planned_fn(tmpl, 'discovery'):
        return
    if not should_place_fn(tmpl, force=force):
        return

    desc = tmpl['description']
    if mechanisms:
        desc = f"{desc} via {', '.join(mechanisms)}"

    vulns[tmpl['name']] = VulnerabilityInfo(
        description=desc,
        type=VulnerabilityType.LOCAL,
        outcome=LeakedNodesId(nodes=resolved_ids),
        reward_string=tmpl.get('reward', 'Exploit successful'),
        cost=get_vulnerability_cost_fn(tmpl),
        rates=Rates(successRate=tmpl['success_rate'])
    )
    set_attr_fn(node, 'vulnerabilities', vulns)
    fixes_applied.append(f"Added discovery ({tmpl['name']}) to {get_attr_fn(node, 'name', '?')}")


def process_discovery_chains(
    nodes: Dict,
    domain_def: Dict,
    domain_name: str,
    get_node_ids_in_group_fn,
    discovery_templates: List[Dict],
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    get_attr_fn,
    set_attr_fn,
) -> None:
    chains = domain_def.get('discovery_chains', [])
    for chain in chains:
        discoverer_group = chain.get('discoverer')
        discoverable_groups = chain.get('discoverable', [])
        mechanisms = chain.get('mechanisms', [])

        discoverer_ids = get_node_ids_in_group_fn(domain_name, discoverer_group)
        resolved_ids = []
        for group in discoverable_groups:
            resolved_ids.extend(get_node_ids_in_group_fn(domain_name, group))

        for did in discoverer_ids:
            if isinstance(nodes, dict) and did in nodes and resolved_ids:
                ensure_discovery_vulnerability(
                    nodes[did], resolved_ids, mechanisms, discovery_templates,
                    should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
                    get_attr_fn, set_attr_fn,
                )
