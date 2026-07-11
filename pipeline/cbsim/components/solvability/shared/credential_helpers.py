"""
Real-credential lookup helpers, shared by SolvabilityPostProcessor and
SolvabilityConstraintProcessor. Plain functions — no class/self state.
"""

from typing import Dict, List, Tuple

from cyberbattle.simulation.vulenrabilites import CachedCredential


def get_real_credentials(nodes: Dict, node_id: str) -> List[Tuple[str, str, str]]:
    if not isinstance(nodes, dict) or node_id not in nodes:
        return []
    node = nodes[node_id]
    results = []
    for svc in getattr(node, 'services', []):
        for cred in getattr(svc, 'allowedCredentials', []):
            results.append((node_id, svc.name, cred))
    return results


def make_cached_credentials(nodes: Dict, node_id: str) -> List[CachedCredential]:
    """Cached credentials for a single node (SolvabilityPostProcessor's shape)."""
    return [CachedCredential(node=n, port=p, credential=c)
            for n, p, c in get_real_credentials(nodes, node_id)]


def make_cached_credentials_for_targets(nodes: Dict, target_ids: List[str]) -> List[CachedCredential]:
    """Cached credentials across multiple target nodes (SolvabilityConstraintProcessor's shape)."""
    cached = []
    for tid in target_ids:
        for nid, port, cred in get_real_credentials(nodes, tid):
            cached.append(CachedCredential(node=nid, port=port, credential=cred))
    return cached
