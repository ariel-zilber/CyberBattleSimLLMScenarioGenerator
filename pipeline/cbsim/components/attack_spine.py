"""
Certified attack spine construction (path-first depth-diversity fix).

Runs as the LAST step of generation, after SolvabilityPostProcessor and
GoalNormalizer have already made the scenario solvable and finalized the
goal set. For each goal node:

  1. Sample a target hop-depth D from `target_depths`.
  2. Build a concrete D-hop path from `start` to the goal through D-1
     distinct intermediate nodes, injecting a real credential-leak edge for
     every hop (deterministic target selection — not the probabilistic
     `find_reachable_targets` fallback used elsewhere).
  3. Mark every spine edge "protected".
  4. Shortcut-guard: while BFS(start, goal) < D, find the current shortest
     path and remove one non-protected edge on it (the same live-verified
     removal semantics as a pure de-shortcut pass — an edge is only ever
     removed, never fabricated).
  5. Emit a depth certificate recording target depth, verified depth, the
     path, and per-hop mechanism.

This module does not modify `find_reachable_targets()` or any existing
solvability-guarantee pass. It only adds edges (deterministically, to
existing credential-leak vulnerability templates already declared in the
YAML config) and removes edges that are provably redundant for reachability.
"""

import random
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, LeakedCredentials, LeakedNodesId,
    LateralMove, PrivilegeEscalation, CustomerData,
)
from cyberbattle.simulation.rate import Rates
from pipeline.cbsim.components.precondition_utils import precondition_from_properties
from pipeline.cbsim.components.solvability.shared.vuln_registry import (
    collect_planned_vuln_names, check_planned,
)
from pipeline.cbsim.components.solvability.shared.template_selection import (
    get_cred_leak_template, get_discovery_template,
)
from pipeline.cbsim.components.solvability.shared.credential_helpers import make_cached_credentials
from pipeline.cbsim.components.solvability.shared.firewall_helpers import open_firewall_for_cred

# Matches pipeline/phase2/evaluator.py's _REMOTE_OWNING_OUTCOMES (the
# serialized-string equivalents), for the live in-memory ownership fixed
# point in _compute_owned_live below.
_REMOTE_OWNING_TYPES = (LateralMove, PrivilegeEscalation, LeakedCredentials, LeakedNodesId, CustomerData)


# ---------------------------------------------------------------------------
# Graph helpers (same edge semantics as pipeline/phase2/evaluator.py's
# _build_attack_edges / _bfs_depth, adapted to live NodeInfo objects instead
# of serialized YAML dicts).
# ---------------------------------------------------------------------------

def _build_attack_graph(nodes: Dict) -> Dict[str, Set[str]]:
    remote_capable = set()
    for nid, node in nodes.items():
        vulns = getattr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            continue
        if any(getattr(v, 'type', None) == VulnerabilityType.REMOTE for v in vulns.values()):
            remote_capable.add(nid)

    adj: Dict[str, Set[str]] = {nid: set() for nid in nodes}
    for nid, node in nodes.items():
        vulns = getattr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            continue
        edges = adj[nid]
        for v in vulns.values():
            outcome = getattr(v, 'outcome', None)
            if isinstance(outcome, LeakedCredentials):
                for cred in outcome.credentials:
                    tgt = getattr(cred, 'node', None)
                    if tgt and tgt in nodes:
                        edges.add(tgt)
            elif isinstance(outcome, LeakedNodesId):
                for tgt in outcome.nodes:
                    if tgt in nodes and tgt in remote_capable:
                        edges.add(tgt)
    return adj


def _bfs_depth(adj: Dict[str, Set[str]], start: str, target: str) -> int:
    if start == target:
        return 0
    visited = {start}
    queue = deque([(start, 0)])
    while queue:
        node, depth = queue.popleft()
        for nbr in adj.get(node, set()):
            if nbr == target:
                return depth + 1
            if nbr not in visited:
                visited.add(nbr)
                queue.append((nbr, depth + 1))
    return -1


def _bfs_path(adj: Dict[str, Set[str]], start: str, target: str) -> Optional[List[str]]:
    if start == target:
        return [start]
    visited = {start}
    queue = deque([[start]])
    while queue:
        path = queue.popleft()
        for nbr in adj.get(path[-1], set()):
            if nbr in visited:
                continue
            new_path = path + [nbr]
            if nbr == target:
                return new_path
            visited.add(nbr)
            queue.append(new_path)
    return None


def _compute_owned_live(nodes: Dict) -> Set[str]:
    """Fixed-point ownership simulation — the actual solvability oracle,
    ported from pipeline/phase2/evaluator.py::_compute_owned (which is what
    `--require-solvable` / evaluate_scenario really gate on, as opposed to
    the more permissive node-to-node adjacency in _build_attack_graph above).

    Critically: holding credentials for a node is NOT enough to own it —
    that node must ALSO be independently *discovered* (via some LeakedNodesId
    outcome) before "lateral move via credential match" applies. Credentials
    are tracked as a shared wallet of raw strings, not per-target edges.
    This is why every spine hop needs both a credential leak AND a discovery
    entry for the same target — see _inject_credential_edge /
    _inject_discovery_edge below.
    """
    if 'start' not in nodes:
        return set()

    owned: Set[str] = {'start'}
    discovered: Set[str] = {'start'}
    credentials: Set[str] = set()

    changed = True
    while changed:
        changed = False

        for node_id in list(owned):
            node = nodes.get(node_id)
            vulns = getattr(node, 'vulnerabilities', {}) if node else {}
            if not isinstance(vulns, dict):
                continue
            for v in vulns.values():
                if getattr(v, 'type', None) != VulnerabilityType.LOCAL:
                    continue
                outcome = getattr(v, 'outcome', None)
                if isinstance(outcome, LeakedCredentials):
                    for cred in outcome.credentials:
                        cred_str = getattr(cred, 'credential', '')
                        if cred_str and cred_str not in credentials:
                            credentials.add(cred_str)
                            changed = True
                elif isinstance(outcome, LeakedNodesId):
                    for n in outcome.nodes:
                        if n and n not in discovered:
                            discovered.add(n)
                            changed = True

        for tgt_id in list(discovered):
            if tgt_id in owned or tgt_id not in nodes:
                continue
            vulns = getattr(nodes[tgt_id], 'vulnerabilities', {})
            if not isinstance(vulns, dict):
                continue
            for v in vulns.values():
                if getattr(v, 'type', None) != VulnerabilityType.REMOTE:
                    continue
                if isinstance(getattr(v, 'outcome', None), _REMOTE_OWNING_TYPES):
                    owned.add(tgt_id)
                    changed = True
                    break

        for node_id in list(discovered):
            if node_id in owned or node_id not in nodes:
                continue
            for svc in getattr(nodes[node_id], 'services', []):
                allowed = set(getattr(svc, 'allowedCredentials', []) or [])
                if credentials & allowed:
                    owned.add(node_id)
                    changed = True
                    break

    return owned


# ---------------------------------------------------------------------------
# Edge injection / removal
# ---------------------------------------------------------------------------

def _inject_credential_edge(
    nodes: Dict, src_id: str, dst_id: str,
    cred_leak_templates: List[Dict], planned_vuln_names: set,
    fixes_applied: List[str],
) -> bool:
    """Deterministically add/extend a LOCAL LeakedCredentials vuln on src_id
    so it includes dst_id's real credentials. Returns True on success."""
    dst_creds = make_cached_credentials(nodes, dst_id)
    if not dst_creds:
        return False

    tmpl = get_cred_leak_template(cred_leak_templates)
    if not tmpl or not check_planned(tmpl, planned_vuln_names, 'AttackSpine', 'cred_leak'):
        return False

    src_node = nodes[src_id]
    vulns = getattr(src_node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        vulns = {}

    existing = vulns.get(tmpl['name'])
    if existing is not None and isinstance(getattr(existing, 'outcome', None), LeakedCredentials):
        existing_targets = {getattr(c, 'node', None) for c in existing.outcome.credentials}
        for c in dst_creds:
            if c.node not in existing_targets:
                existing.outcome.credentials.append(c)
    else:
        vulns[tmpl['name']] = VulnerabilityInfo(
            description=tmpl['description'],
            type=VulnerabilityType.LOCAL,
            outcome=LeakedCredentials(credentials=dst_creds),
            precondition=precondition_from_properties(tmpl.get('match_properties', [])),
            reward_string=tmpl.get('reward', 'Exploit successful'),
            cost=tmpl.get('cost', 1.0),
            rates=Rates(successRate=tmpl.get('success_rate', 0.8)),
        )
        src_node.vulnerabilities = vulns

    open_firewall_for_cred(nodes, src_id, dst_id)
    fixes_applied.append(f"[AttackSpine] Injected credential edge {src_id} -> {dst_id}")
    return True


def _inject_discovery_edge(
    nodes: Dict, src_id: str, dst_id: str,
    discovery_templates: List[Dict], planned_vuln_names: set,
    fixes_applied: List[str],
) -> bool:
    """Deterministically add/extend a LOCAL LeakedNodesId vuln on src_id so
    it lists dst_id. Required alongside _inject_credential_edge: per
    _compute_owned_live (and the real evaluator/simulation semantics),
    holding a credential for a node does not grant ownership unless that
    node has also been independently discovered."""
    tmpl = get_discovery_template(discovery_templates)
    if not tmpl or not check_planned(tmpl, planned_vuln_names, 'AttackSpine', 'discovery'):
        return False

    src_node = nodes[src_id]
    vulns = getattr(src_node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        vulns = {}

    existing = vulns.get(tmpl['name'])
    if existing is not None and isinstance(getattr(existing, 'outcome', None), LeakedNodesId):
        if dst_id not in existing.outcome.nodes:
            existing.outcome.nodes.append(dst_id)
    else:
        vulns[tmpl['name']] = VulnerabilityInfo(
            description=tmpl['description'],
            type=VulnerabilityType.LOCAL,
            outcome=LeakedNodesId(nodes=[dst_id]),
            precondition=precondition_from_properties(tmpl.get('match_properties', [])),
            reward_string=tmpl.get('reward', 'Exploit successful'),
            cost=tmpl.get('cost', 1.0),
            rates=Rates(successRate=tmpl.get('success_rate', 0.8)),
        )
        src_node.vulnerabilities = vulns

    fixes_applied.append(f"[AttackSpine] Injected discovery edge {src_id} -> {dst_id}")
    return True


def _remove_hop_edge(nodes: Dict, src_id: str, dst_id: str) -> List[Tuple[str, object, object]]:
    """Remove every instance of the src_id -> dst_id edge (every credential
    entry across every vuln on src_id that targets dst_id, plus dst_id from
    any discovery outcome) in one shot, so a node with several services (and
    therefore several CachedCredential entries to the same target) is fully
    severed in a single guard iteration instead of one instance at a time.
    Returns the removed instances (for restoration if this breaks solvability).
    """
    removed: List[Tuple[str, object, object]] = []
    node = nodes.get(src_id)
    if node is None:
        return removed
    vulns = getattr(node, 'vulnerabilities', {})
    if not isinstance(vulns, dict):
        return removed
    for v in vulns.values():
        outcome = getattr(v, 'outcome', None)
        if isinstance(outcome, LeakedCredentials):
            matching = [c for c in outcome.credentials if getattr(c, 'node', None) == dst_id]
            for cred in matching:
                outcome.credentials.remove(cred)
                removed.append(('cred', outcome, cred))
        elif isinstance(outcome, LeakedNodesId):
            if dst_id in outcome.nodes:
                outcome.nodes.remove(dst_id)
                removed.append(('disc', outcome, dst_id))
    return removed


def _restore_hop_edge(removed: List[Tuple[str, object, object]]) -> None:
    for kind, outcome, ref in removed:
        if kind == 'cred':
            outcome.credentials.append(ref)
        else:
            outcome.nodes.append(ref)


# ---------------------------------------------------------------------------
# Certified attack spine builder
# ---------------------------------------------------------------------------

class CertifiedAttackSpineBuilder:
    """Mutates `nodes` in place to give each goal a certified, deterministic
    minimum attack depth. See module docstring for the algorithm."""

    def __init__(self, nodes: Dict, config: Dict, seed: int = None,
                 target_depths: Tuple[int, ...] = (3, 4, 5, 6)):
        self.nodes = nodes
        self.config = config
        self.target_depths = target_depths
        self.fixes_applied: List[str] = []

        if seed is not None:
            random.seed(seed)

        solv = config.get('solvability_vulnerabilities', {})
        self.cred_leak_templates = solv.get('credential_leak', [])
        self.discovery_templates = solv.get('discovery', [])
        self._planned_vuln_names = collect_planned_vuln_names(config)

    def _entry_node_ids(self) -> List[str]:
        """Nodes 'start' already leaks real credentials for (the network's
        actual entry points) — reused as-is, never re-injected."""
        start = self.nodes.get('start')
        entries: List[str] = []
        if start:
            vulns = getattr(start, 'vulnerabilities', {})
            if isinstance(vulns, dict):
                for v in vulns.values():
                    outcome = getattr(v, 'outcome', None)
                    if isinstance(outcome, LeakedCredentials):
                        for cred in outcome.credentials:
                            tgt = getattr(cred, 'node', None)
                            if tgt and tgt in self.nodes and tgt not in entries:
                                entries.append(tgt)
        return entries

    def _goal_node_ids(self) -> List[str]:
        return [nid for nid, n in self.nodes.items()
                if nid != 'start' and getattr(n, 'is_goal', False)]

    def apply(self) -> dict:
        goals = self._goal_node_ids()
        entries = self._entry_node_ids()
        certificates = []

        used_intermediates: Set[str] = set(entries) | set(goals) | {'start'}
        all_goal_ids = set(goals)

        for goal_id in goals:
            cert = self._build_spine_for_goal(goal_id, entries, used_intermediates, all_goal_ids)
            certificates.append(cert)

        result = {
            'goals': certificates,
            'all_certified': all(c['certificate_valid'] for c in certificates) if certificates else True,
        }
        return result

    def _build_spine_for_goal(self, goal_id: str, entries: List[str],
                               used_intermediates: Set[str],
                               all_goal_ids: Set[str]) -> dict:
        if not entries:
            return {
                'goal': goal_id, 'target_depth': None, 'verified_bfs_depth': -1,
                'path': [], 'edge_mechanisms': [], 'certificate_valid': False,
                'note': 'no entry node available — cannot build a spine',
            }

        entry_id = random.choice(entries)

        # Eligible intermediates: any node not already used by another
        # goal's spine, not start/entry/goal, and with real credentials
        # (required for the credential-edge mechanism).
        pool = [
            nid for nid in self.nodes
            if nid not in used_intermediates and nid != entry_id
            and make_cached_credentials(self.nodes, nid)
        ]
        random.shuffle(pool)

        feasible_depths = [d for d in self.target_depths if d - 2 <= len(pool)]
        # Sample, don't always take the max — the point is depth *variance*,
        # not trading a uniform depth-2 collapse for a uniform depth-6 one.
        target_depth = random.choice(feasible_depths) if feasible_depths else max(2, min(self.target_depths))
        target_depth = max(2, target_depth)

        n_mid = max(0, target_depth - 2)
        intermediates = pool[:n_mid]
        target_depth = 2 + len(intermediates)  # honest depth given what's actually available

        path = ['start', entry_id] + intermediates + [goal_id]
        used_intermediates.update(intermediates)
        used_intermediates.add(entry_id)

        edge_mechanisms = []
        protected_edges: Set[Tuple[str, str]] = set()
        for src, dst in zip(path[1:-1], path[2:]):  # skip start->entry (already real)
            # Both mechanisms are required: _compute_owned_live only grants
            # ownership via credential match on a node that's ALSO been
            # independently discovered (see _compute_owned_live docstring).
            # A credential-only hop is invisible to the real solvability
            # oracle even though it looks like a valid edge in the simpler
            # adjacency graph used for depth reporting.
            cred_ok = _inject_credential_edge(
                self.nodes, src, dst, self.cred_leak_templates,
                self._planned_vuln_names, self.fixes_applied,
            )
            disc_ok = _inject_discovery_edge(
                self.nodes, src, dst, self.discovery_templates,
                self._planned_vuln_names, self.fixes_applied,
            )
            if cred_ok and disc_ok:
                protected_edges.add((src, dst))
                edge_mechanisms.append('credential+discovery')
            else:
                edge_mechanisms.append('failed')
        protected_edges.add((path[0], path[1]))  # start->entry, always protected

        shortcut_violation = self._shortcut_guard(
            path[0], goal_id, target_depth, protected_edges, all_goal_ids)

        adj = _build_attack_graph(self.nodes)
        verified_depth = _bfs_depth(adj, 'start', goal_id)
        actually_owned = goal_id in _compute_owned_live(self.nodes)

        return {
            'goal': goal_id,
            'target_depth': target_depth,
            'verified_bfs_depth': verified_depth,
            'path': path,
            'edge_mechanisms': edge_mechanisms,
            'certificate_valid': (
                verified_depth == target_depth
                and not shortcut_violation
                and actually_owned
            ),
            'shortcut_violation': shortcut_violation,
            'solvable': actually_owned,
        }

    def _shortcut_guard(self, start_id: str, goal_id: str, target_depth: int,
                         protected_edges: Set[Tuple[str, str]],
                         all_goal_ids: Set[str]) -> bool:
        """While BFS(start, goal) < target_depth, remove one non-protected
        edge on the current shortest path. Returns True if it gets stuck
        (a shortcut survives that can't be safely removed).

        Safety check on every removal covers EVERY goal in the scenario, not
        just this one — an edge that looks redundant for `goal_id` can still
        be another goal's only path in, and removing it would silently
        strand that other goal. (Found via real generation: a shared-edge
        removal made one goal in a 3-goal scenario permanently unreachable
        while this goal's own certificate still validated.)
        """
        guard_iterations = 0
        # Each iteration fully severs one (u, v) hop (every credential/discovery
        # instance behind it at once — see _remove_hop_edge). Bounded by total
        # possible directed pairs, generous but not unbounded.
        max_iterations = len(self.nodes) * len(self.nodes)
        while guard_iterations < max_iterations:
            guard_iterations += 1
            adj = _build_attack_graph(self.nodes)
            depth = _bfs_depth(adj, start_id, goal_id)
            if depth < 0:
                # Should not happen — solvability guarantees already ran.
                return True
            if depth >= target_depth:
                return False

            shortest = _bfs_path(adj, start_id, goal_id)
            if not shortest:
                return True

            removed_one = False
            for u, v in zip(shortest[:-1], shortest[1:]):
                if (u, v) in protected_edges:
                    continue
                removed = _remove_hop_edge(self.nodes, u, v)
                if not removed:
                    continue
                # Safety oracle: real ownership fixed point, not the looser
                # adjacency BFS (which can't see the discovery-gating rule —
                # see _compute_owned_live). This is what --require-solvable
                # actually checks, so it's what must never regress.
                owned_after = _compute_owned_live(self.nodes)
                all_still_reachable = all_goal_ids.issubset(owned_after)
                if all_still_reachable:
                    self.fixes_applied.append(
                        f"[AttackSpine] Severed shortcut edge {u} -> {v} "
                        f"({len(removed)} instance(s), collapsed depth below target {target_depth})")
                    removed_one = True
                else:
                    _restore_hop_edge(removed)
                break  # re-derive the shortest path fresh next iteration

            if not removed_one:
                # Every edge on the current shortest path is protected (or
                # its only instance is load-bearing) — cannot shorten this
                # further without breaking solvability. Give up honestly.
                return True

        return True  # iteration bound hit — treat as unresolved, not silently valid
