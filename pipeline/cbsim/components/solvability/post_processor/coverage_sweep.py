"""
Full-coverage sweep (SolvabilityPostProcessor). Runs last, after every other
probabilistic/deterministic placement pass.

Root cause this addresses: none of the earlier passes guarantee every
Solvability.* slot DECLARED in a config's solvability_vulnerabilities
section actually gets INSTANTIATED onto a node. Measured on generated
datasets: coverage as low as 12-20%, flat regardless of sample size (5 vs 50
scenarios) — confirming it's structural, not a sampling gap. Three concrete
causes, all upstream of this module:

  1. get_cred_leak_template()/get_discovery_template() (shared/template_selection.py)
     are blind index-[0] — every credential-leak placement anywhere in the
     codebase always picks the SAME first-listed template, regardless of
     which node it's placed on. The other declared credential_leak templates
     are structurally unreachable.
  2. add_remote_vulnerability() only fires once per scenario (entry_point.py,
     entry node only) — with e.g. 21 declared remote_access templates but a
     single placement opportunity, only whichever template happens to match
     that one node's properties can ever appear.
  3. Templates sharing identical match_properties within a pick_goal_template
     category collide — the first one in YAML order always wins, so a
     duplicate-match_properties sibling (e.g. NTDS_Dump next to DCSync) is
     permanently unreachable regardless of how many scenarios are generated.
  4. The lateral_movement category has no placement function at all anywhere
     in the runtime generator — it's referenced only by identifier-usage
     bookkeeping and a static config validator, never instantiated.

This sweep is deliberately a coverage safety net, not a fix for the above —
it force-places any slot left at zero instances after everything else has
run, giving the DRL agent a gradient signal for every action-slot the config
declares. It does not change how often each existing mechanism naturally
fires; it only tops up what would otherwise be permanently absent.
"""

from typing import Callable, Dict, List

from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, LeakedCredentials, LeakedNodesId,
    LateralMove, PrivilegeEscalation, PrivilegeLevel,
)
from cyberbattle.simulation.rate import Rates
from pipeline.cbsim.components.precondition_utils import precondition_from_properties
from pipeline.cbsim.components.solvability.shared.credential_helpers import make_cached_credentials
from pipeline.cbsim.components.solvability.post_processor.credential_chain import has_credential_leak
from pipeline.cbsim.components.solvability.post_processor.discovery import has_discovery_capability


def _has_remote_lateral_move(node) -> bool:
    vulns = getattr(node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        return False
    return any(
        getattr(v, 'type', None) == VulnerabilityType.REMOTE
        and isinstance(getattr(v, 'outcome', None), LateralMove)
        for v in vulns.values()
    )


def ensure_full_coverage(
    nodes: Dict,
    config: Dict,
    get_vulnerability_cost_fn: Callable,
    fixes_applied: List[str],
) -> None:
    solv = config.get('solvability_vulnerabilities', {})
    defined: Dict[str, tuple] = {}  # name -> (template, category)
    for category, entries in solv.items():
        if not isinstance(entries, list):
            continue
        for tmpl in entries:
            if not isinstance(tmpl, dict):
                continue
            name = tmpl.get('name', '')
            if name.startswith('Solvability.') and name not in defined:
                defined[name] = (tmpl, category)

    if not defined:
        return

    placed: set = set()
    for node in nodes.values():
        vulns = getattr(node, 'vulnerabilities', {})
        if isinstance(vulns, dict):
            placed.update(k for k in vulns if k.startswith('Solvability.'))

    missing = set(defined.keys()) - placed
    if not missing:
        print(f"[Coverage] All {len(defined)} slots placed — no sweep needed.")
        return

    print(f"[Coverage] Sweep: {len(missing)}/{len(defined)} slots unplaced — force-placing")

    swept = 0
    for name in sorted(missing):
        tmpl, category = defined[name]
        match_props = tmpl.get('match_properties', [])

        eligible = [
            nid for nid, node in nodes.items()
            if nid != 'start'
            and name not in (getattr(node, 'vulnerabilities', {}) or {})
            and (
                not match_props
                or any(p in set(getattr(node, 'properties', []) or []) for p in match_props)
            )
        ]

        if not eligible:
            print(f"[Coverage]   SKIP {name} — no eligible node (match_props={match_props})")
            continue

        # Coverage and topology density are separate concerns: prefer reusing
        # a node that already exercises the same capability, so a coverage
        # top-up doesn't turn every node into a credential/discovery source.
        preferred = eligible
        if category == 'credential_leak':
            same_capability = [nid for nid in eligible if has_credential_leak(nodes[nid])]
            preferred = same_capability or eligible
        elif 'discovery' in category or 'probe' in category:
            same_capability = [nid for nid in eligible if has_discovery_capability(nodes[nid])]
            preferred = same_capability or eligible
        elif category == 'remote_access':
            same_capability = [nid for nid in eligible if _has_remote_lateral_move(nodes[nid])]
            preferred = same_capability or eligible

        target_id = min(preferred, key=lambda nid: len(getattr(nodes[nid], 'vulnerabilities', {}) or {}))
        target_node = nodes[target_id]
        vulns = getattr(target_node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            vulns = {}

        vuln_type_str = tmpl.get('type', 'LOCAL')
        vuln_type = VulnerabilityType.REMOTE if vuln_type_str == 'REMOTE' else VulnerabilityType.LOCAL

        if vuln_type == VulnerabilityType.REMOTE or category == 'remote_access':
            outcome = LateralMove()
        elif 'discovery' in category or 'probe' in category:
            others = [n for n in nodes if n not in (target_id, 'start')]
            outcome = LeakedNodesId(nodes=others[:3])
        elif any(k in category for k in ('goal', 'privesc', 'lateral', 'escalat')):
            outcome = PrivilegeEscalation(level=PrivilegeLevel.System)
        else:
            creds = make_cached_credentials(nodes, target_id)
            if creds:
                outcome = LeakedCredentials(credentials=creds)
            else:
                others = [n for n in nodes if n not in (target_id, 'start')]
                outcome = LeakedNodesId(nodes=others[:1])

        vulns[name] = VulnerabilityInfo(
            description=tmpl.get('description', f'Coverage sweep: {name}'),
            type=vuln_type,
            outcome=outcome,
            precondition=precondition_from_properties(match_props),
            reward_string=tmpl.get('reward', f'{name} exploited'),
            cost=get_vulnerability_cost_fn(tmpl),
            rates=Rates(successRate=tmpl.get('success_rate', 0.7)),
        )
        target_node.vulnerabilities = vulns
        swept += 1
        fixes_applied.append(f"Coverage sweep: {name} -> {target_id}")

    skipped = len(missing) - swept
    print(f"[Coverage] Sweep complete: {swept}/{len(missing)} slots placed"
          + (f" ({skipped} skipped — no matching node)" if skipped else ""))
