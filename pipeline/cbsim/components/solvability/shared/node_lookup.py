"""
Node lookup helpers shared by SolvabilityPostProcessor and
SolvabilityConstraintProcessor. Plain functions — no class/self state.

Note: each processor also has its OWN _find_node with genuinely different
semantics (SPP matches dict keys and returns an id string; SCP matches
node.name attributes across dict-or-list storage and returns a node object)
- those are NOT duplicated here, they stay processor-specific.
"""

from typing import Dict, List
import re


def id_matches(pattern: str, node_id: str) -> bool:
    """True when pattern is a complete underscore-delimited token in node_id."""
    if not pattern:
        return False
    return bool(re.search(r'(?:^|_)' + re.escape(pattern) + r'(?:_|$)', node_id))


def get_nodes_by_group_pattern(nodes: Dict, pattern: str) -> List[str]:
    return [nid for nid in nodes
            if nid != 'start' and id_matches(pattern, nid)]
