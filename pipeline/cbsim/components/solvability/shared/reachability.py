"""
Reachable-target computation, shared by SolvabilityPostProcessor and
SolvabilityConstraintProcessor. Plain functions — no class/self state.

This is the ONE canonical implementation of "which nodes can a given source
node's credential-leak/discovery vulnerability target" — previously
duplicated (and independently drifting) across both processors as
_find_reachable_target_nodes / _find_reachable_targets.
"""

from typing import Dict, List, Optional

from pipeline.cbsim.components.solvability.shared.node_lookup import id_matches


def find_reachable_targets(
    nodes: Dict,
    attack_flow: List[Dict],
    source_node_id: str,
    cache: Optional[Dict[str, List[str]]] = None,
) -> List[str]:
    """Resolve which nodes source_node_id's attack_flow rule (if any) targets.

    Falls back to every non-start node in the network when no attack_flow
    source_pattern matches source_node_id. This fallback is intentionally
    unrestricted for now (matches current main behavior exactly) — goal-node
    exclusion is a deliberate follow-up change, not part of this refactor.
    """
    if cache is not None and source_node_id in cache:
        return cache[source_node_id]

    target_patterns = []
    for rule in attack_flow:
        pattern = rule.get('source_pattern', '')
        if pattern and id_matches(pattern, source_node_id):
            target_patterns = rule.get('targets', [])
            break

    targets = []
    if isinstance(nodes, dict):
        for nid in nodes:
            if nid == source_node_id or nid == 'start':
                continue
            for pattern in target_patterns:
                if id_matches(pattern, nid):
                    targets.append(nid)
                    break

    if not targets and isinstance(nodes, dict):
        targets = [nid for nid in nodes if nid != source_node_id and nid != 'start']

    if cache is not None:
        cache[source_node_id] = targets
    return targets
