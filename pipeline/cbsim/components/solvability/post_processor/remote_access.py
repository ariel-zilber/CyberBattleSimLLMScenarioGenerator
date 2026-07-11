"""
Remote-access vulnerability placement (SolvabilityPostProcessor).
Extracted verbatim from solvability_post_processor.py::_add_remote_vulnerability.
"""

from typing import Dict, List

from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, LeakedCredentials,
)
from cyberbattle.simulation.rate import Rates
from pipeline.cbsim.components.precondition_utils import precondition_from_properties
from pipeline.cbsim.components.solvability.shared.template_selection import pick_remote_template
from pipeline.cbsim.components.solvability.shared.credential_helpers import make_cached_credentials


def add_remote_vulnerability(
    nodes: Dict,
    node: object,
    node_id: str,
    remote_templates: List[Dict],
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
    force: bool = False,
) -> None:
    vulns = getattr(node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        vulns = {}

    has_exploitable_remote = any(
        getattr(v, 'type', None) == VulnerabilityType.REMOTE
        and isinstance(getattr(v, 'outcome', None), LeakedCredentials)
        for v in vulns.values()
    )
    if has_exploitable_remote:
        return

    real_creds = make_cached_credentials(nodes, node_id)
    if not real_creds:
        return

    tmpl = pick_remote_template(remote_templates, set(getattr(node, 'properties', [])))
    if not tmpl or not check_planned_fn(tmpl, 'remote'):
        return

    if not should_place_fn(tmpl, force=force):
        return

    vulns[tmpl['name']] = VulnerabilityInfo(
        description=tmpl['description'],
        type=VulnerabilityType.REMOTE,
        outcome=LeakedCredentials(credentials=real_creds),
        precondition=precondition_from_properties(tmpl.get('match_properties', [])),
        reward_string=tmpl.get('reward', 'Exploit successful'),
        cost=get_vulnerability_cost_fn(tmpl),
        rates=Rates(successRate=tmpl['success_rate'])
    )
    node.vulnerabilities = vulns
    fixes_applied.append(f"Added REMOTE ({tmpl['name']}) to {node_id}")
