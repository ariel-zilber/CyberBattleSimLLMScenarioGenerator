"""
Goal Normalizer — Ensures constant goal count across all scenarios
===================================================================
Plugs into the generation pipeline AFTER SolvabilityPostProcessor.

Problem:  Different YAML scenarios define different numbers of is_goal=True
          services, and each service can have variable instance counts
          (min_count/max_count). This makes the win condition inconsistent
          across scenarios, breaking meta-agent training.

Solution: After all nodes are generated and solvability is ensured, this
          normalizer adjusts goal assignments so that exactly `num_goals`
          nodes have is_goal=True.

Strategy:
  - If too many goals  → demote lowest-priority ones
  - If too few goals   → promote highest-priority non-goal nodes
  - Priority is based on: node value, depth from entry, domain diversity
  - After adjustment, re-validates solvability of remaining goals

Usage in universal_generator.py:
    from goal_normalizer import GoalNormalizer

    # After SolvabilityPostProcessor.ensure_solvability()
    normalizer = GoalNormalizer(
        nodes=self.all_nodes,
        config=self.config,
        num_goals=4  # or from config: self.config['goal_config']['num_goals']
    )
    normalizer.normalize()

YAML schema addition (in config section):
    goal_config:
      num_goals: 4                    # Exact number of goal nodes desired
      selection_strategy: diverse     # diverse | highest_value | deepest
      allow_promote: true             # Allow promoting non-goal nodes
      allow_demote: true              # Allow demoting existing goal nodes
      min_goal_value: 500             # Minimum node value to be promotable
"""

import re
import random
from typing import Dict, List, Set, Optional
from collections import defaultdict

from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, LeakedCredentials,
    LeakedNodesId, PrivilegeEscalation, PrivilegeLevel, CachedCredential
)
from cyberbattle.simulation.rate import Rates


class GoalNormalizer:

    def __init__(self, nodes: Dict, config: Dict, num_goals: int = None,
                 seed: int = None):
        """
        Args:
            nodes:     The generated node dict (same object as all_nodes).
            config:    Full YAML config dict.
            num_goals: Override — if given, takes precedence over config.
                       Otherwise reads from config['goal_config']['num_goals'].
        """
        self.nodes = nodes
        self.config = config
        self.adjustments: List[str] = []

        if seed is not None:
            random.seed(seed)

        # Read goal config from YAML or use defaults
        goal_cfg = config.get('goal_config', {})
        self.num_goals = num_goals if num_goals is not None else goal_cfg.get('num_goals', 4)
        self.strategy = goal_cfg.get('selection_strategy', 'diverse')
        self.allow_promote = goal_cfg.get('allow_promote', True)
        self.allow_demote = goal_cfg.get('allow_demote', True)
        self.min_goal_value = goal_cfg.get('min_goal_value', 500)

        # Scoring weights — all overridable via goal_config in YAML
        self._w_value_norm       = goal_cfg.get('value_normalizer',         1000.0)
        self._w_domain_diversity = goal_cfg.get('domain_diversity_weight',    15.0)
        self._w_service_unique   = goal_cfg.get('service_uniqueness_weight',   8.0)
        self._w_depth_cap        = goal_cfg.get('depth_bonus_cap',             5.0)
        self._w_depth_scale      = goal_cfg.get('depth_bonus_scale',           0.5)
        self._w_secondary_value  = goal_cfg.get('secondary_value_scale',     500.0)
        self._max_cred_targets   = goal_cfg.get('max_cred_dump_targets',       3)
        # Properties that mark a node as a decoy — not eligible for promotion
        self._decoy_markers: Set[str] = set(goal_cfg.get('decoy_properties', [
            'Decoy', 'Honeypot', 'Canary', 'TripWire',
            'FakeDB', 'FakeShare', 'DeadEnd', 'IDSDecoy',
        ]))

        # Solvability templates (for adding goal vulns to promoted nodes)
        solv = config.get('solvability_vulnerabilities', {})
        self.goal_templates = solv.get('goal_access', [])
        self.attack_flow = config.get('attack_flow', [])

        # Registry: only names declared in YAML may be injected
        from cbsim.components.solvability_post_processor import _collect_planned_vuln_names
        self._planned_vuln_names: Set[str] = _collect_planned_vuln_names(config)

        # Pre-build depth graph — immutable after init, no need to rebuild per call
        self._depth_adj: Dict[str, List[str]] = defaultdict(list)
        for rule in self.attack_flow:
            src = rule.get('source_pattern', '')
            for tgt in rule.get('targets', []):
                self._depth_adj[src].append(tgt)
        self._entry_patterns: Set[str] = {
            ep.get('node', '') for ep in config.get('entry_points', [])
        }

    # =====================================================================
    # MAIN ENTRY POINT
    # =====================================================================

    def normalize(self) -> Dict:
        """
        Normalize goal count to exactly self.num_goals.
        Returns a summary dict.
        """
        current_goals = self._get_goal_nodes()
        current_count = len(current_goals)
        target = self.num_goals

        print(f"\n[GoalNormalizer] Current goals: {current_count}, Target: {target}")
        print(f"[GoalNormalizer] Strategy: {self.strategy}")

        if current_count == target:
            print("[GoalNormalizer] Already at target — no changes needed.")
            return self._summary(current_goals, [], [])

        demoted = []
        promoted = []

        if current_count > target:
            # Too many goals — demote the excess
            if not self.allow_demote:
                print("[GoalNormalizer] WARNING: Too many goals but demote disabled.")
                return self._summary(current_goals, [], [])

            keep = self._greedy_select(current_goals, target)
            keep_set = set(keep)
            demote = [g for g in current_goals if g not in keep_set]
            for node_id in demote:
                self._demote_goal(node_id)
                demoted.append(node_id)

            # Demotion can remove the only credential source for a retained goal.
            # Re-validate each kept goal's reachability now that the graph changed.
            for gid in keep:
                self._ensure_promoted_goal_reachable(gid)

        elif current_count < target:
            # Too few goals — promote additional nodes
            needed = target - current_count
            if not self.allow_promote:
                print(f"[GoalNormalizer] WARNING: Need {needed} more goals but promote disabled.")
                return self._summary(current_goals, [], [])

            candidates = self._get_promotion_candidates(current_goals)
            to_promote = self._greedy_select(candidates, needed, seed=current_goals)
            for node_id in to_promote:
                self._promote_to_goal(node_id)
                promoted.append(node_id)

        # Verify final count
        final_goals = self._get_goal_nodes()
        print(f"[GoalNormalizer] Final goals: {len(final_goals)}")
        if len(final_goals) != target:
            print(f"[GoalNormalizer] WARNING: Could only achieve {len(final_goals)}/{target} goals")
        for gid in final_goals:
            print(f"  → {gid} (value={self.nodes[gid].value})")

        return self._summary(final_goals, demoted, promoted)

    # =====================================================================
    # GOAL NODE COLLECTION
    # =====================================================================

    def _get_goal_nodes(self) -> List[str]:
        """Return all node IDs with is_goal=True."""
        return [nid for nid, node in self.nodes.items()
                if nid != 'start' and getattr(node, 'is_goal', False)]

    def _get_node_domain(self, node_id: str) -> str:
        """Extract domain name from node_id (convention: Domain_Group_N)."""
        return getattr(self.nodes[node_id], 'domain', node_id.split('_')[0])

    def _get_node_service_type(self, node_id: str) -> str:
        """Extract service/group type from node_id."""
        return getattr(self.nodes[node_id], 'group', '_'.join(node_id.split('_')[1:-1]))

    # =====================================================================
    # PRIORITY SCORING
    # =====================================================================

    def _score_goal_priority(self, node_id: str, existing_selected: Set[str] = None) -> float:
        """
        Score a node's priority as a goal. Higher = more desirable to keep.
        Factors:
          1. Node value (from YAML service definition)
          2. Domain diversity bonus (if strategy=diverse)
          3. Service type uniqueness bonus
          4. Depth from entry (deeper = higher priority as goal)
        """
        node = self.nodes[node_id]
        score = 0.0

        # Factor 1: Raw value (normalized to 0-10 range)
        score += min(10.0, node.value / self._w_value_norm)

        # Factor 2: Domain diversity
        if self.strategy == 'diverse' and existing_selected:
            selected_domains = {self._get_node_domain(nid) for nid in existing_selected}
            if self._get_node_domain(node_id) not in selected_domains:
                score += self._w_domain_diversity

        # Factor 3: Service type uniqueness
        if existing_selected:
            selected_types = {self._get_node_service_type(nid) for nid in existing_selected}
            if self._get_node_service_type(node_id) not in selected_types:
                score += self._w_service_unique

        # Factor 4: Depth proxy — use attack_flow to estimate depth
        depth = self._estimate_depth(node_id)
        score += min(self._w_depth_cap, depth * self._w_depth_scale)

        # Factor 5: Strategy-specific boost
        if self.strategy == 'highest_value':
            score += node.value / self._w_secondary_value
        elif self.strategy == 'deepest':
            score += depth * 2.0

        return score

    def _estimate_depth(self, node_id: str) -> int:
        """BFS over the cached attack_flow graph; return deepest pattern that matches node_id."""
        visited: Dict[str, int] = {}
        queue = [(p, 0) for p in self._entry_patterns]
        for p, d in queue:
            if p in visited:
                continue
            visited[p] = d
            for neighbor in self._depth_adj.get(p, []):
                if neighbor not in visited:
                    queue.append((neighbor, d + 1))
        return max((d for p, d in visited.items() if self._id_matches(p, node_id)), default=0)

    # =====================================================================
    # GOAL SELECTION
    # =====================================================================

    def _greedy_select(self, pool: List[str], n: int,
                       seed: List[str] = None) -> List[str]:
        """
        Greedily pick the top-N items from pool by diversity-aware score.
        seed primes the diversity context (used when promoting, so existing
        goals influence which candidates score highest).
        O(n·m) — uses max() + set.discard() instead of sort + remove.
        """
        remaining: Set[str] = set(pool)
        selected_set: Set[str] = set(seed) if seed else set()
        picked: List[str] = []

        for _ in range(n):
            if not remaining:
                break
            best = max(remaining,
                       key=lambda nid: self._score_goal_priority(nid, selected_set))
            picked.append(best)
            selected_set.add(best)
            remaining.discard(best)

        return picked

    # =====================================================================
    # PROMOTION CANDIDATES (when too few goals)
    # =====================================================================

    def _get_promotion_candidates(self, current_goals: List[str]) -> List[str]:
        """Non-goal nodes eligible for promotion: meet min_value, have services, not decoys."""
        goal_set = set(current_goals)
        return [
            nid for nid, node in self.nodes.items()
            if nid != 'start'
            and nid not in goal_set
            and node.value >= self.min_goal_value
            and getattr(node, 'services', [])
            and not (set(getattr(node, 'properties', [])) & self._decoy_markers)
        ]

    # =====================================================================
    # DEMOTE: Remove goal status from a node
    # =====================================================================

    def _demote_goal(self, node_id: str):
        """Remove is_goal flag. Optionally strip goal-specific vulns."""
        node = self.nodes[node_id]
        node.is_goal = False
        self.adjustments.append(f"DEMOTED {node_id} (value={node.value})")
        # Note: We do NOT remove vulns from demoted nodes — they still exist
        # in the network as intermediate nodes. The agent can still exploit
        # them for credentials, just won't need to "own" them to win.

    # =====================================================================
    # PROMOTE: Add goal status to a non-goal node
    # =====================================================================

    def _promote_to_goal(self, node_id: str):
        """
        Set is_goal=True and ensure the node has appropriate goal vulns
        (privilege escalation + credential dump), is discoverable, and
        has a credential path leading to it so a path actually exists.
        """
        node = self.nodes[node_id]
        node.is_goal = True
        self.adjustments.append(f"PROMOTED {node_id} (value={node.value})")

        # Ensure goal-appropriate vulnerabilities exist on the node
        self._ensure_promoted_goal_vulns(node, node_id)

        # Ensure the promoted goal can actually be reached:
        #  1. Some node discovers it (LeakedNodesId)
        #  2. Some node leaks credentials for it (LeakedCredentials)
        self._ensure_promoted_goal_discoverable(node_id)
        self._ensure_promoted_goal_reachable(node_id)

    def _ensure_promoted_goal_discoverable(self, node_id: str):
        """
        Ensure the promoted goal node appears in at least one LeakedNodesId
        outcome so the attacker can discover it.  Prefer entry-point nodes,
        then any node that already has a discovery vuln.
        """
        # Check if already discoverable
        for nid, node in self.nodes.items():
            if nid == 'start':
                continue
            for v in getattr(node, 'vulnerabilities', {}).values():
                outcome = getattr(v, 'outcome', None)
                if isinstance(outcome, LeakedNodesId) and node_id in outcome.nodes:
                    return  # Already discoverable

        # Not discoverable — inject into an existing discovery vuln
        # Prefer entry-point nodes, then any node with discovery
        entry_nodes = [nid for nid in self.nodes
                       if nid != 'start' and nid != node_id
                       and any(self._id_matches(p, nid) for p in self._entry_patterns if p)]
        all_discovery_nodes = [(nid, v)
                               for nid, node in self.nodes.items()
                               if nid != 'start' and nid != node_id
                               for v in getattr(node, 'vulnerabilities', {}).values()
                               if isinstance(getattr(v, 'outcome', None), LeakedNodesId)]

        # Try entry nodes first
        for nid in entry_nodes:
            node = self.nodes[nid]
            for v in getattr(node, 'vulnerabilities', {}).values():
                outcome = getattr(v, 'outcome', None)
                if isinstance(outcome, LeakedNodesId):
                    if node_id not in outcome.nodes:
                        outcome.nodes.append(node_id)
                    self.adjustments.append(
                        f"  + Injected {node_id} into {nid}'s discovery (entry node)")
                    return

        # Fallback: any node with discovery
        if all_discovery_nodes:
            nid, v = all_discovery_nodes[0]
            outcome = v.outcome
            if node_id not in outcome.nodes:
                outcome.nodes.append(node_id)
            self.adjustments.append(
                f"  + Injected {node_id} into {nid}'s discovery (fallback)")
            return

        print(f"[GoalNormalizer] WARNING: {node_id} has no discoverable path — "
              f"no LeakedNodesId vulns exist in the network to inject into.")

    def _ensure_promoted_goal_reachable(self, node_id: str):
        """
        Ensure at least one node leaks credentials that allow reaching the
        promoted goal node (LeakedCredentials with cred.node == node_id).
        If no such path exists, inject the goal's own credentials into the
        nearest node that already has a credential-leak vuln.
        """
        goal_node = self.nodes.get(node_id)
        if not goal_node:
            return

        # Collect the goal's own credentials
        goal_creds = self._make_cached_credentials(node_id)
        if not goal_creds:
            print(f"[GoalNormalizer] WARNING: {node_id} has no credentials to inject "
                  f"— node has services but no allowedCredentials. Goal may be unreachable.")
            return

        # Check if already reachable via any node's LeakedCredentials
        for nid, node in self.nodes.items():
            if nid == node_id or nid == 'start':
                continue
            for v in getattr(node, 'vulnerabilities', {}).values():
                outcome = getattr(v, 'outcome', None)
                if isinstance(outcome, LeakedCredentials):
                    for cred in outcome.credentials:
                        if getattr(cred, 'node', None) == node_id:
                            return  # Already reachable

        # Also check if the goal itself has a REMOTE LeakedCredentials exploit
        for v in getattr(goal_node, 'vulnerabilities', {}).values():
            if (getattr(v, 'type', None) == VulnerabilityType.REMOTE
                    and isinstance(getattr(v, 'outcome', None), LeakedCredentials)):
                return

        # Not reachable — inject goal's creds into an existing cred-leak vuln.
        # Prefer entry nodes, then any node with a credential-leak.
        entry_nodes = [nid for nid in self.nodes
                       if nid != 'start' and nid != node_id
                       and any(self._id_matches(p, nid) for p in self._entry_patterns if p)]
        cred_leak_nodes = [nid for nid, node in self.nodes.items()
                           if nid != 'start' and nid != node_id
                           and any(isinstance(getattr(v, 'outcome', None), LeakedCredentials)
                                   for v in getattr(node, 'vulnerabilities', {}).values())]

        # Try entry nodes first, then any cred-leak node not already in entry_nodes
        entry_set = set(entry_nodes)
        candidates = entry_nodes + [n for n in cred_leak_nodes if n not in entry_set]

        for nid in candidates:
            node = self.nodes[nid]
            for v in getattr(node, 'vulnerabilities', {}).values():
                outcome = getattr(v, 'outcome', None)
                if isinstance(outcome, LeakedCredentials):
                    existing_targets = {getattr(c, 'node', None) for c in outcome.credentials}
                    for gc in goal_creds:
                        if gc.node not in existing_targets:
                            outcome.credentials.append(gc)
                    self.adjustments.append(
                        f"  + Injected {node_id} creds into {nid}'s cred leak")
                    return

        # Last resort: no cred-leak node found — create one using a goal template
        if cred_leak_nodes or entry_nodes:
            nid = (entry_nodes or cred_leak_nodes)[0]
            node = self.nodes[nid]
            tmpl = self._pick_goal_template(set(getattr(node, 'properties', [])), 'dump')
            if not tmpl:
                tmpl_list = self.config.get('solvability_vulnerabilities', {}).get(
                    'credential_leak', [])
                tmpl = tmpl_list[0] if tmpl_list else None
            if tmpl and self._check_planned(tmpl, f'last-resort cred-leak on {nid} for goal {node_id}'):
                vulns = getattr(node, 'vulnerabilities', {})
                if not isinstance(vulns, dict):
                    vulns = {}
                vulns[tmpl['name']] = VulnerabilityInfo(
                    description=tmpl['description'],
                    type=VulnerabilityType.LOCAL,
                    outcome=LeakedCredentials(credentials=goal_creds),
                    reward_string=tmpl['reward'],
                    cost=tmpl['cost'],
                    rates=Rates(successRate=tmpl['success_rate'])
                )
                node.vulnerabilities = vulns
                self.adjustments.append(
                    f"  + Created cred leak on {nid} pointing to promoted goal {node_id}")
                return

        print(f"[GoalNormalizer] WARNING: could not establish any credential path to {node_id} "
              f"— no injection candidate found. Goal may be unreachable.")

    def _ensure_promoted_goal_vulns(self, node, node_id: str):
        """Add privesc and credential dump vulns if missing on a newly promoted goal."""
        vulns = getattr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            vulns = {}
            node.vulnerabilities = vulns

        has_privesc = any(
            isinstance(getattr(v, 'outcome', None), PrivilegeEscalation)
            for v in vulns.values()
        )
        has_cred_dump = any(
            isinstance(getattr(v, 'outcome', None), LeakedCredentials)
            and getattr(v, 'type', None) == VulnerabilityType.LOCAL
            for v in vulns.values()
        )

        properties = set(getattr(node, 'properties', []))

        if not has_privesc:
            tmpl = self._pick_goal_template(properties, 'privesc')
            if tmpl and self._check_planned(tmpl, f'privesc on {node_id}'):
                real_creds = self._make_cached_credentials(node_id)
                outcome = (LeakedCredentials(credentials=real_creds) if real_creds
                           else PrivilegeEscalation(level=PrivilegeLevel.Admin))
                vulns[tmpl['name']] = VulnerabilityInfo(
                    description=tmpl['description'],
                    type=VulnerabilityType.LOCAL,
                    outcome=outcome,
                    reward_string=tmpl['reward'],
                    cost=tmpl['cost'],
                    rates=Rates(successRate=tmpl['success_rate'])
                )
                self.adjustments.append(f"  + Added privesc ({tmpl['name']}) to {node_id}")

        if not has_cred_dump:
            tmpl = self._pick_goal_template(properties, 'dump')
            if tmpl and self._check_planned(tmpl, f'cred_dump on {node_id}'):
                all_creds = list(self._make_cached_credentials(node_id))
                # Also add creds from reachable targets
                reachable = self._find_reachable_targets(node_id)
                for tid in reachable[:self._max_cred_targets]:
                    all_creds.extend(self._make_cached_credentials(tid))
                if all_creds:
                    vulns[tmpl['name']] = VulnerabilityInfo(
                        description=tmpl['description'],
                        type=VulnerabilityType.LOCAL,
                        outcome=LeakedCredentials(credentials=all_creds),
                        reward_string=tmpl['reward'],
                        cost=tmpl['cost'],
                        rates=Rates(successRate=tmpl['success_rate'])
                    )
                    self.adjustments.append(f"  + Added cred dump ({tmpl['name']}) to {node_id}")

    # =====================================================================
    # HELPERS (mirrors from SolvabilityPostProcessor)
    # =====================================================================

    def _check_planned(self, tmpl: Dict, context: str = '') -> bool:
        """Return True only if tmpl['name'] is in the planned-vuln registry."""
        name = tmpl.get('name', '') if isinstance(tmpl, dict) else ''
        if not name:
            print(f"[GoalNormalizer] ERROR: injection template missing 'name'"
                  f"{' — ' + context if context else ''}. Refusing injection.")
            return False
        if self._planned_vuln_names and name not in self._planned_vuln_names:
            print(f"[GoalNormalizer] ERROR: refusing to inject unplanned vulnerability '{name}'"
                  f"{' — ' + context if context else ''}. Add it to YAML first.")
            return False
        return True

    def _pick_goal_template(self, node_properties: set, category: str) -> Optional[Dict]:
        fallback = None
        for tmpl in self.goal_templates:
            tmpl_category = tmpl.get('goal_category', '')
            if tmpl_category and tmpl_category != category:
                continue
            match_props = tmpl.get('match_properties', [])
            if not match_props:
                fallback = tmpl
                continue
            if any(p in node_properties for p in match_props):
                return tmpl
        return fallback

    def _make_cached_credentials(self, node_id: str) -> List[CachedCredential]:
        if node_id not in self.nodes:
            return []
        node = self.nodes[node_id]
        results = []
        for svc in getattr(node, 'services', []):
            for cred in getattr(svc, 'allowedCredentials', []):
                results.append(CachedCredential(node=node_id, port=svc.name, credential=cred))
        return results

    def _find_reachable_targets(self, source_node_id: str) -> List[str]:
        # Collect target patterns from ALL matching rules (not just the first)
        target_patterns: Set[str] = set()
        for rule in self.attack_flow:
            pattern = rule.get('source_pattern', '')
            if pattern and self._id_matches(pattern, source_node_id):
                target_patterns.update(rule.get('targets', []))
        targets = []
        for nid in self.nodes:
            if nid == source_node_id or nid == 'start':
                continue
            for pattern in target_patterns:
                if self._id_matches(pattern, nid):
                    targets.append(nid)
                    break
        return targets

    @staticmethod
    def _id_matches(pattern: str, node_id: str) -> bool:
        """True when pattern appears as a complete underscore-delimited token
        in node_id.  Prevents partial matches (e.g. 'DB' matching 'WebDB')."""
        if not pattern:
            return False
        return bool(re.search(r'(?:^|_)' + re.escape(pattern) + r'(?:_|$)', node_id))

    # =====================================================================
    # SUMMARY
    # =====================================================================

    def _summary(self, final_goals, demoted, promoted) -> Dict:
        return {
            'final_goal_count': len(final_goals),
            'target_goal_count': self.num_goals,
            'goal_nodes': final_goals,
            'demoted': demoted,
            'promoted': promoted,
            'adjustments': self.adjustments,
            'domains_represented': list({self._get_node_domain(g) for g in final_goals})
        }
