"""
Solvability Post-Processor — PROBABILISTIC + YAML-DRIVEN
==========================================================
All vulnerability names, costs, descriptions, rates come from YAML config.
Each template has a `probability` field (0.0-1.0) for variance.

Placement rules:
  - Entry point nodes: ALWAYS get vulns (probability ignored) → solvability
  - Goal nodes: ALWAYS get privesc/dump (probability ignored) → capturable
  - All other nodes: use probability for random placement → variance per run
  - Credential chain minimum ratio is enforced AFTER probabilistic pass
"""

import math
import re
import random
from typing import Dict, List, Tuple, Optional

from cyberbattle.simulation.firewall import FirewallRule, RulePermission
from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, LeakedCredentials, CachedCredential,
    PrivilegeEscalation, LeakedNodesId, PrivilegeLevel
)
from cyberbattle.simulation.rate import Rates


def _collect_planned_vuln_names(config: dict) -> set:
    """Return the set of all vulnerability names declared anywhere in the YAML config.

    Covers: solvability_vulnerabilities, vulnerability_patterns,
    probe_vulnerabilities, constraint_vulnerabilities, start_node.vulnerabilities.
    Any vulnerability injected at runtime must appear here.
    """
    names: set = set()
    for item in config.get('vulnerability_patterns', []):
        if isinstance(item, dict) and item.get('name'):
            names.add(item['name'])
    for item in config.get('probe_vulnerabilities', []):
        if isinstance(item, dict) and item.get('name'):
            names.add(item['name'])
    for group in config.get('solvability_vulnerabilities', {}).values():
        for item in (group if isinstance(group, list) else []):
            if isinstance(item, dict) and item.get('name'):
                names.add(item['name'])
    for vdef in config.get('constraint_vulnerabilities', {}).values():
        if isinstance(vdef, dict) and vdef.get('name'):
            names.add(vdef['name'])
    for vdef in config.get('start_node', {}).get('vulnerabilities', {}).values():
        if isinstance(vdef, dict) and vdef.get('name'):
            names.add(vdef['name'])
    return names


class SolvabilityPostProcessor:

    def __init__(self, nodes: Dict, config: Dict, seed: int = None):
        self.nodes = nodes
        self.config = config
        self.fixes_applied = []
        self.entry_node_ids = set()  # Track which nodes are entry points
        self.goal_node_ids = set()   # Track which nodes are goals

        # Optional seed for reproducibility
        if seed is not None:
            random.seed(seed)

        # Load from YAML
        solv = config.get('solvability_vulnerabilities', {})
        self.remote_templates = solv.get('remote_access', [])
        self.cred_leak_templates = solv.get('credential_leak', [])
        self.discovery_templates = solv.get('discovery', [])
        self.goal_templates = solv.get('goal_access', [])
        self.attack_flow = config.get('attack_flow', [])
        # Cache for _find_reachable_target_nodes (avoids repeated O(n) scans)
        self._reachable_cache: Dict[str, List[str]] = {}

        # Registry of every vulnerability name declared in the YAML config.
        # Any injection attempt using a name absent from this set is refused.
        self._planned_vuln_names: set = _collect_planned_vuln_names(config)

        # Identify entry and goal nodes
        self._identify_critical_nodes()

    def _identify_critical_nodes(self):
        """
        Pre-identify entry points and goal nodes.
        Entry points = the SPECIFIC nodes the start node leaks creds for
        (extracted from start node's LeakedCredentials outcomes),
        NOT the entire YAML entry_points group.
        """
        # Extract actual entry targets from start node's credential leak
        start = self.nodes.get('start')
        if start:
            start_vulns = getattr(start, 'vulnerabilities', {})
            if isinstance(start_vulns, dict):
                for v in start_vulns.values():
                    outcome = getattr(v, 'outcome', None)
                    if isinstance(outcome, LeakedCredentials):
                        for cred in outcome.credentials:
                            target_node = getattr(cred, 'node', None)
                            if target_node and target_node in self.nodes:
                                self.entry_node_ids.add(target_node)

        # If start node didn't exist yet or had no cred leaks, fall back
        # to first node matching YAML entry_points (just 1, not all)
        if not self.entry_node_ids:
            for ep in self.config.get('entry_points', []):
                node_name = ep.get('node', '')
                for nid in self.nodes:
                    if node_name and self._id_matches(node_name, nid) and nid != 'start':
                        self.entry_node_ids.add(nid)
                        break  # Only first match, not entire group

        for nid, node in self.nodes.items():
            if nid == 'start':
                continue
            if getattr(node, 'is_goal', False):
                self.goal_node_ids.add(nid)

    def _should_place(self, template: Dict, force: bool = False) -> bool:
        """
        Probabilistic placement check.
        force=True bypasses probability (used for entry points and goal nodes).
        """
        if force:
            return True
        prob = template.get('probability', 1.0)
        return random.random() < prob

    def _select_targets(self, candidates: List[str], template: Dict) -> List[str]:
        """
        Pick a random subset of target nodes based on template's
        target_coverage and min_targets. Prevents leaking the entire network.
        """
        coverage = template.get('target_coverage', 1.0)
        min_targets = template.get('min_targets', 1)

        if coverage >= 1.0:
            return list(candidates)
        if not candidates:
            return []

        n = max(min_targets, math.ceil(len(candidates) * coverage))
        n = min(n, len(candidates))
        return random.sample(candidates, n)

    def ensure_solvability(self):
        self._reachable_cache.clear()  # Invalidate stale entries from any prior call
        print("\n[Solvability] Ensuring scenario is solvable...")
        self._ensure_entry_point_access()
        self._ensure_credential_chain()
        self._ensure_discovery()
        self._ensure_goal_access()
        self._ensure_goal_reachable()

        stats = self._compute_stats()
        print(f"[Solvability] Applied {len(self.fixes_applied)} fixes")
        print(f"[Solvability] Stats: {stats}")
        return {
            'fixes_applied': len(self.fixes_applied),
            'fixes': self.fixes_applied,
            'stats': stats
        }

    def _compute_stats(self) -> Dict:
        """Compute placement stats for debugging/analysis."""
        total = len([n for n in self.nodes if n != 'start'])
        remote_count = 0
        cred_leak_count = 0
        discovery_count = 0

        for nid, node in self.nodes.items():
            if nid == 'start':
                continue
            vulns = getattr(node, 'vulnerabilities', {})
            if not isinstance(vulns, dict):
                continue
            for v in vulns.values():
                outcome = getattr(v, 'outcome', None)
                vtype = getattr(v, 'type', None)
                if vtype == VulnerabilityType.REMOTE and isinstance(outcome, LeakedCredentials):
                    remote_count += 1
                if isinstance(outcome, LeakedCredentials) and vtype == VulnerabilityType.LOCAL:
                    cred_leak_count += 1
                if isinstance(outcome, LeakedNodesId):
                    discovery_count += 1

        return {
            'total_nodes': total,
            'nodes_with_remote_exploit': remote_count,
            'nodes_with_cred_leak': cred_leak_count,
            'nodes_with_discovery': discovery_count,
            'cred_leak_ratio': round(cred_leak_count / total, 2) if total > 0 else 0
        }

    # =========================================================================
    # FIREWALL HELPER — ensures movement paths are open
    # =========================================================================

    def _prune_orphaned_identifiers(self):
        """Automatically remove properties declared in identifiers but never used (Q25)."""
        id_config = self.config.get('identifiers', {})
        base_props = id_config.get('base_properties', [])
        if not base_props:
            return

        used_props: set[str] = set()
        
        # 1. Check Services
        services = self.config.get('services', {})
        for svc in services.values():
            used_props.update(svc.get('default_properties', []))
            
        # 2. Check Domains/Groups
        for domain in self.config.get('domains', []):
            for group in domain.get('groups', []):
                used_props.update(group.get('properties', []))
                
        # 3. Check Vulnerabilities (Planned)
        for category in ['remote_access', 'credential_leak', 'discovery', 'goal_access', 'lateral_movement']:
            vulns = self.config.get('solvability_vulnerabilities', {}).get(category, [])
            if isinstance(vulns, list):
                for v in vulns:
                    used_props.update(v.get('match_properties', []))
        
        # 4. Check Start Node
        used_props.update(self.config.get('start_node', {}).get('properties', []))

        # Identify orphans
        orphans = [p for p in base_props if p not in used_props and p != 'breach_node']
        
        if orphans:
            new_props = [p for p in base_props if p not in orphans]
            id_config['base_properties'] = new_props
            self.fixes_applied.append(f"Pruned {len(orphans)} orphaned properties: {orphans}")

    def _open_firewall_for_cred(self, src_id: str, dst_id: str):
        """Add bidirectional firewall rules so src can reach dst via its services.

        Called whenever a credential leak is placed so agents can actually use
        the leaked credentials.  Rules are added only if not already present.
        """
        if src_id not in self.nodes or dst_id not in self.nodes:
            return
        src_node = self.nodes[src_id]
        dst_node = self.nodes[dst_id]
        src_ni = getattr(src_node, 'network_info', [])
        dst_ni = getattr(dst_node, 'network_info', [])
        if not src_ni or not dst_ni:
            return
        src_subnet = src_ni[0].subnet
        dst_subnet = dst_ni[0].subnet

        def _existing_ports(rules):
            return {str(getattr(r, 'port', '')) for r in rules}

        src_out_ports = _existing_ports(getattr(src_node.firewall, 'outgoing', []))
        dst_in_ports  = _existing_ports(getattr(dst_node.firewall, 'incoming', []))

        for svc in getattr(dst_node, 'services', []):
            port = getattr(svc, 'name', None)
            if not port or port in ('*', 'any'):
                continue
            if port not in src_out_ports:
                src_node.firewall.outgoing.append(FirewallRule(
                    port=port, permission=RulePermission.ALLOW,
                    subnet=dst_subnet, reason=""
                ))
                src_out_ports.add(port)
            if port not in dst_in_ports:
                dst_node.firewall.incoming.append(FirewallRule(
                    port=port, permission=RulePermission.ALLOW,
                    subnet=src_subnet, reason=""
                ))
                dst_in_ports.add(port)

    # =========================================================================
    # REAL CREDENTIAL HELPERS
    # =========================================================================

    def _get_real_credentials(self, node_id: str) -> List[Tuple[str, str, str]]:
        if node_id not in self.nodes:
            return []
        node = self.nodes[node_id]
        results = []
        for svc in getattr(node, 'services', []):
            for cred in getattr(svc, 'allowedCredentials', []):
                results.append((node_id, svc.name, cred))
        return results

    def _make_cached_credentials(self, node_id: str) -> List[CachedCredential]:
        return [CachedCredential(node=n, port=p, credential=c)
                for n, p, c in self._get_real_credentials(node_id)]

    # =========================================================================
    # ATTACK FLOW — FROM YAML
    # =========================================================================

    def _find_reachable_target_nodes(self, source_node_id: str) -> List[str]:
        if source_node_id in self._reachable_cache:
            return self._reachable_cache[source_node_id]

        target_patterns = []
        for rule in self.attack_flow:
            pattern = rule.get('source_pattern', '')
            if pattern and self._id_matches(pattern, source_node_id):
                target_patterns = rule.get('targets', [])
                break

        targets = []
        for nid in self.nodes:
            if nid == source_node_id or nid == 'start':
                continue
            for pattern in target_patterns:
                if self._id_matches(pattern, nid):
                    targets.append(nid)
                    break

        if not targets:
            targets = [nid for nid in self.nodes if nid != source_node_id and nid != 'start']

        self._reachable_cache[source_node_id] = targets
        return targets

    def _get_nodes_by_group_pattern(self, pattern: str) -> List[str]:
        return [nid for nid in self.nodes
                if nid != 'start' and self._id_matches(pattern, nid)]

    @staticmethod
    def _id_matches(pattern: str, node_id: str) -> bool:
        """True when pattern is a complete underscore-delimited token in node_id."""
        if not pattern:
            return False
        return bool(re.search(r'(?:^|_)' + re.escape(pattern) + r'(?:_|$)', node_id))

    # =========================================================================
    # PLANNED-VULNERABILITY GUARD
    # =========================================================================

    def _check_planned(self, tmpl: Dict, context: str = '') -> bool:
        """Return False and print an error if the template name is not declared
        in the YAML config.  Prevents injecting unplanned vulnerabilities that
        would be absent from the CyberBattleSim action space."""
        name = tmpl.get('name', '') if isinstance(tmpl, dict) else ''
        if not name:
            print(f"[Solvability] ERROR: injection template missing 'name'"
                  f"{' (' + context + ')' if context else ''} — skipping")
            return False
        if self._planned_vuln_names and name not in self._planned_vuln_names:
            print(f"[Solvability] ERROR: refusing to inject unplanned vulnerability "
                  f"'{name}' — not declared in any YAML config section. "
                  f"Add it to solvability_vulnerabilities or vulnerability_patterns.")
            return False
        return True

    # =========================================================================
    # YAML TEMPLATE HELPERS
    # =========================================================================

    def _pick_remote_template(self, node_properties: set) -> Optional[Dict]:
        fallback = None
        for tmpl in self.remote_templates:
            match_props = tmpl.get('match_properties', [])
            if not match_props:
                fallback = tmpl
                continue
            if any(p in node_properties for p in match_props):
                return tmpl
        return fallback

    def _pick_goal_template(self, node_properties: set, category) -> Optional[Dict]:
        """Return the best-matching goal template for the given category.

        category=None means "accept any category" (used as a cross-category fallback).
        """
        fallback = None
        for tmpl in self.goal_templates:
            tmpl_category = tmpl.get('goal_category', '')
            if category is not None and tmpl_category and tmpl_category != category:
                continue

            match_props = tmpl.get('match_properties', [])
            if not match_props:
                fallback = tmpl
                continue
            if any(p in node_properties for p in match_props):
                return tmpl
        return fallback

    def _get_cred_leak_template(self) -> Optional[Dict]:
        return self.cred_leak_templates[0] if self.cred_leak_templates else None

    def _get_discovery_template(self) -> Optional[Dict]:
        return self.discovery_templates[0] if self.discovery_templates else None

    # =========================================================================
    # ENSURE ENTRY POINT ACCESS (FORCED — probability ignored)
    # =========================================================================

    def _ensure_entry_point_access(self):
        """Ensure the ACTUAL entry nodes (the ones start node targets) have
        remote access + discovery + credential leak vulns. Uses entry_node_ids
        derived from the start node's leaked credentials."""

        # Use the actual entry nodes identified from start node
        targets = list(self.entry_node_ids)

        # Fallback if none identified (start node hasn't been created yet)
        if not targets:
            entry_points = self.config.get('entry_points', [])
            if entry_points:
                ep = entry_points[0]
                node_name = ep.get('node')
                nid = (self._find_node(node_name) if node_name
                       else self._find_first_node_in_domain(ep.get('domain')))
                if nid:
                    targets = [nid]

        # Ultimate fallback: first non-start node
        if not targets:
            for nid in self.nodes:
                if nid != 'start':
                    targets = [nid]
                    break

        for node_id in targets:
            if node_id not in self.nodes:
                continue
            node = self.nodes[node_id]
            # Entry points ALWAYS get these — ignore probability
            self._add_remote_vulnerability(node, node_id, force=True)
            self._add_discovery_vulnerability(node, node_id, force=True)
            self._add_credential_leak_vulnerability(node, node_id, force=True)

    # =========================================================================
    # ENSURE CREDENTIAL CHAIN (probabilistic + enforced minimum)
    # =========================================================================

    def _ensure_credential_chain(self):
        rules = self.config.get('solvability_rules', {})
        lateral = rules.get('lateral_movement_requirements', {})
        min_ratio = lateral.get('min_credential_leaking_nodes', C.DEFAULT_MIN_CREDENTIAL_LEAKING_NODES_RATIO)
        # max_credential_leaking_nodes caps the probabilistic phase to prevent
        # over-saturation (density > 0.40).  Defaults to 1.5× the minimum so
        # existing configs without the key are unaffected.
        max_ratio = lateral.get('max_credential_leaking_nodes',
                                min(min_ratio * C.DEFAULT_MAX_CREDENTIAL_LEAKING_NODES_MULTIPLIER, 1.0))

        non_start = [nid for nid in self.nodes if nid != 'start']
        total = len(non_start)
        target_count = max(1, int(total * min_ratio))
        max_count    = max(target_count, int(total * max_ratio))

        # Phase 1: Probabilistic pass — each node rolls independently,
        # but stops once max_count is reached.
        placed = sum(1 for nid in non_start
                     if self._has_credential_leak(self.nodes[nid]))
        for node_id in non_start:
            if placed >= max_count:
                break
            node = self.nodes[node_id]
            if self._has_credential_leak(node):
                continue

            is_critical = node_id in self.entry_node_ids or node_id in self.goal_node_ids
            tmpl = self._get_cred_leak_template()
            if tmpl and self._should_place(tmpl, force=is_critical):
                self._add_credential_leak_vulnerability(node, node_id, force=True)
                placed += 1

        # Phase 2: Enforce minimum ratio (deterministic top-up if needed)
        current = sum(1 for nid in non_start
                      if self._has_credential_leak(self.nodes[nid]))
        if current < target_count:
            needed = target_count - current
            candidates = [nid for nid in non_start
                          if not self._has_credential_leak(self.nodes[nid])]
            random.shuffle(candidates)
            for nid in candidates[:needed]:
                self._add_credential_leak_vulnerability(self.nodes[nid], nid, force=True)

    # =========================================================================
    # ENSURE DISCOVERY (probabilistic)
    # =========================================================================

    def _ensure_discovery(self):
        for node_id, node in self.nodes.items():
            if node_id == 'start':
                continue
            if self._has_discovery_capability(node):
                continue

            is_critical = node_id in self.entry_node_ids
            tmpl = self._get_discovery_template()
            if tmpl and self._should_place(tmpl, force=is_critical):
                self._add_discovery_vulnerability(node, node_id, force=True)

        # After probabilistic placement, verify goal nodes are reachable
        self._ensure_goal_discoverable()

    def _ensure_goal_discoverable(self):
        """
        Verify every goal node appears in at least one node's LeakedNodesId.
        Pre-computes a ``goal → discoverers`` mapping so each goal lookup is
        O(1) instead of re-scanning the full node set per goal.
        """
        # Build mapping: goal_id → True/False (already discoverable)
        discovered_anywhere: set = set()
        nodes_with_discovery = []  # (nid, vuln) pairs

        for nid, node in self.nodes.items():
            if nid == 'start':
                continue
            vulns = getattr(node, 'vulnerabilities', {})
            if not isinstance(vulns, dict):
                continue
            for v in vulns.values():
                outcome = getattr(v, 'outcome', None)
                if isinstance(outcome, LeakedNodesId):
                    discovered_anywhere.update(outcome.nodes)
                    nodes_with_discovery.append((nid, v))

        start = self.nodes.get('start')
        if start:
            start_vulns = getattr(start, 'vulnerabilities', {})
            if isinstance(start_vulns, dict):
                for v in start_vulns.values():
                    outcome = getattr(v, 'outcome', None)
                    if isinstance(outcome, LeakedNodesId):
                        discovered_anywhere.update(outcome.nodes)

        # Shuffle once before iterating goals (not per-goal)
        random.shuffle(nodes_with_discovery)

        for goal_id in list(self.goal_node_ids):
            if goal_id in discovered_anywhere:
                continue

            injected = False
            for nid in self.entry_node_ids:
                if nid == goal_id:
                    continue
                node = self.nodes.get(nid)
                if not node:
                    continue
                vulns = getattr(node, 'vulnerabilities', {})
                if isinstance(vulns, dict):
                    for v in vulns.values():
                        outcome = getattr(v, 'outcome', None)
                        if isinstance(outcome, LeakedNodesId):
                            outcome.nodes.append(goal_id)
                            discovered_anywhere.add(goal_id)
                            injected = True
                            self.fixes_applied.append(
                                f"Injected goal {goal_id} into {nid}'s discovery")
                            break
                if injected:
                    break

            if not injected:
                for nid, v in nodes_with_discovery:
                    if nid == goal_id:
                        continue
                    outcome = getattr(v, 'outcome', None)
                    if isinstance(outcome, LeakedNodesId):
                        outcome.nodes.append(goal_id)
                        discovered_anywhere.add(goal_id)
                        self.fixes_applied.append(
                            f"Injected goal {goal_id} into {nid}'s discovery (fallback)")
                        break

    # =========================================================================
    # ENSURE GOAL ACCESS (FORCED — probability ignored)
    # =========================================================================

    def _ensure_goal_access(self):
        for node_id, node in self.nodes.items():
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
                self._add_privilege_escalation_vulnerability(node, node_id, force=True)
            if not has_cred_dump:
                self._add_credential_dump_vulnerability(node, node_id, force=True)

    # =========================================================================
    # ENSURE GOAL REACHABLE — credential path to each goal exists
    # =========================================================================

    def _ensure_goal_reachable(self):
        """
        Verify each goal node can be REACHED (not just discovered).
        A goal is reachable if:
          (a) it has a REMOTE vuln with LeakedCredentials → attackable from afar, OR
          (b) at least one other node's credential leak includes creds for it

        If neither, inject the goal's credentials into the nearest node's
        credential leak. Without this, partial target_coverage can create
        goals that are visible but inaccessible.
        """
        for goal_id in list(self.goal_node_ids):
            goal_node = self.nodes.get(goal_id)
            if not goal_node:
                continue

            # Check (a): goal has a REMOTE LeakedCredentials vuln
            goal_vulns = getattr(goal_node, 'vulnerabilities', {})
            has_remote_cred = False
            if isinstance(goal_vulns, dict):
                has_remote_cred = any(
                    getattr(v, 'type', None) == VulnerabilityType.REMOTE
                    and isinstance(getattr(v, 'outcome', None), LeakedCredentials)
                    for v in goal_vulns.values()
                )
            if has_remote_cred:
                continue

            # Check (b): any node's credential leak targets this goal
            has_cred_path = False
            for nid, node in self.nodes.items():
                if nid == goal_id or nid == 'start':
                    continue
                vulns = getattr(node, 'vulnerabilities', {})
                if not isinstance(vulns, dict):
                    continue
                for v in vulns.values():
                    outcome = getattr(v, 'outcome', None)
                    if isinstance(outcome, LeakedCredentials):
                        for cred in outcome.credentials:
                            if getattr(cred, 'node', None) == goal_id:
                                has_cred_path = True
                                break
                    if has_cred_path:
                        break
                if has_cred_path:
                    break

            if has_cred_path:
                continue

            # Neither — inject goal's creds into nearest node's credential leak
            goal_creds = self._make_cached_credentials(goal_id)
            if not goal_creds:
                print(f"[Solvability] WARNING: goal {goal_id} has no services/credentials "
                      f"— cannot establish a credential path. Scenario may be unsolvable.")
                continue

            injected = False
            # Prefer entry nodes or nodes with existing credential leaks
            candidates = list(self.entry_node_ids)
            if not candidates:
                candidates = [nid for nid in self.nodes
                              if nid != goal_id and nid != 'start'
                              and self._has_credential_leak(self.nodes[nid])]
            random.shuffle(candidates)

            for nid in candidates:
                node = self.nodes.get(nid)
                if not node:
                    continue
                vulns = getattr(node, 'vulnerabilities', {})
                if not isinstance(vulns, dict):
                    continue
                for _vname, v in vulns.items():
                    outcome = getattr(v, 'outcome', None)
                    if isinstance(outcome, LeakedCredentials):
                        existing_targets = {getattr(c, 'node', None)
                                            for c in outcome.credentials}
                        for gc in goal_creds:
                            if gc.node not in existing_targets:
                                outcome.credentials.append(gc)
                        self._open_firewall_for_cred(nid, goal_id)
                        injected = True
                        self.fixes_applied.append(
                            f"Injected goal {goal_id} creds into {nid}'s credential leak")
                        break
                if injected:
                    break

            if not injected:
                if candidates:
                    nid = candidates[0]
                    node = self.nodes[nid]
                    self._add_credential_leak_vulnerability(node, nid, force=True)
                    self.fixes_applied.append(
                        f"Created credential leak on {nid} for goal {goal_id}")
                else:
                    print(f"[Solvability] WARNING: goal {goal_id} has no reachable "
                          f"credential path and no injection candidate. "
                          f"Scenario may be unsolvable.")

    # =========================================================================
    # VULNERABILITY ADDERS — YAML TEMPLATES + REAL CREDENTIALS + PROBABILITY
    # =========================================================================

    def _add_remote_vulnerability(self, node, node_id: str, force: bool = False):
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

        real_creds = self._make_cached_credentials(node_id)
        if not real_creds:
            return

        tmpl = self._pick_remote_template(set(getattr(node, 'properties', [])))
        if not tmpl or not self._check_planned(tmpl, 'remote'):
            return

        if not self._should_place(tmpl, force=force):
            return

        vulns[tmpl['name']] = VulnerabilityInfo(
            description=tmpl['description'],
            type=VulnerabilityType.REMOTE,
            outcome=LeakedCredentials(credentials=real_creds),
            reward_string=tmpl['reward'],
            cost=self._get_vulnerability_cost(tmpl),
            rates=Rates(successRate=tmpl['success_rate'])
        )
        node.vulnerabilities = vulns
        self.fixes_applied.append(f"Added REMOTE ({tmpl['name']}) to {node_id}")

    def _add_credential_leak_vulnerability(self, node, node_id: str, force: bool = False):
        vulns = getattr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            vulns = {}

        tmpl = self._get_cred_leak_template()
        if not tmpl or not self._check_planned(tmpl, 'cred_leak'):
            return

        if not self._should_place(tmpl, force=force):
            return

        targets = self._find_reachable_target_nodes(node_id)
        # Pick a SUBSET of reachable targets based on YAML target_coverage
        selected = self._select_targets(targets, tmpl)
        all_cached = []
        for tid in selected:
            all_cached.extend(self._make_cached_credentials(tid))

        # If forced placement but random subset had no creds, try all targets
        if not all_cached and force and len(selected) < len(targets):
            for tid in targets:
                if tid not in selected:
                    all_cached.extend(self._make_cached_credentials(tid))

        if not all_cached:
            return

        vulns[tmpl['name']] = VulnerabilityInfo(
            description=tmpl['description'],
            type=VulnerabilityType.LOCAL,
            outcome=LeakedCredentials(credentials=all_cached),
            reward_string=tmpl['reward'],
            cost=self._get_vulnerability_cost(tmpl),
            rates=Rates(successRate=tmpl['success_rate'])
        )
        node.vulnerabilities = vulns

        # Ensure the firewall allows credential-based lateral movement for each
        # credential we just leaked.  Without matching rules the simulation
        # blocks the connection even when the agent has valid credentials.
        target_ids = {cred.node for cred in all_cached}
        for tid in target_ids:
            self._open_firewall_for_cred(node_id, tid)

        self.fixes_applied.append(f"Added cred leak ({tmpl['name']}) to {node_id}")

    def _add_discovery_vulnerability(self, node, node_id: str, force: bool = False):
        vulns = getattr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            vulns = {}

        tmpl = self._get_discovery_template()
        if not tmpl or not self._check_planned(tmpl, 'discovery'):
            return

        if not self._should_place(tmpl, force=force):
            return

        all_others = [n for n in self.nodes if n != node_id and n != 'start']
        # Pick a SUBSET based on YAML target_coverage
        discovered = self._select_targets(all_others, tmpl)

        vulns[tmpl['name']] = VulnerabilityInfo(
            description=tmpl['description'],
            type=VulnerabilityType.LOCAL,
            outcome=LeakedNodesId(nodes=discovered),
            reward_string=tmpl['reward'],
            cost=self._get_vulnerability_cost(tmpl),
            rates=Rates(successRate=tmpl['success_rate'])
        )
        node.vulnerabilities = vulns
        self.fixes_applied.append(f"Added discovery ({tmpl['name']}) to {node_id}")

    def _add_privilege_escalation_vulnerability(self, node, node_id: str, force: bool = False):
        vulns = getattr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            vulns = {}

        properties = set(getattr(node, 'properties', []))
        tmpl = self._pick_goal_template(properties, 'privesc')
        if not tmpl:
            # No privesc-specific template in this config — fall back to any
            # property-matching goal template and force PrivilegeEscalation outcome.
            tmpl = self._pick_goal_template(properties, None)
        if not tmpl or not self._check_planned(tmpl, 'privesc'):
            return

        if not self._should_place(tmpl, force=force):
            return

        # Privesc vulns always produce PrivilegeEscalation (not cred-leak).
        outcome = PrivilegeEscalation(level=PrivilegeLevel.Admin)

        vulns[tmpl['name']] = VulnerabilityInfo(
            description=tmpl['description'],
            type=VulnerabilityType.LOCAL,
            outcome=outcome,
            reward_string=tmpl['reward'],
            cost=self._get_vulnerability_cost(tmpl),
            rates=Rates(successRate=tmpl['success_rate'])
        )
        node.vulnerabilities = vulns
        self.fixes_applied.append(f"Added privesc ({tmpl['name']}) to {node_id}")

    def _add_credential_dump_vulnerability(self, node, node_id: str, force: bool = False):
        vulns = getattr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            vulns = {}

        properties = set(getattr(node, 'properties', []))
        tmpl = self._pick_goal_template(properties, 'dump')
        if not tmpl or not self._check_planned(tmpl, 'dump'):
            return

        if not self._should_place(tmpl, force=force):
            return

        # Start with self-creds (the node's own credentials)
        all_creds = list(self._make_cached_credentials(node_id))

        # Find reachable targets, then pick a SUBSET via target_coverage
        match_props = tmpl.get('match_properties', [])
        if match_props and any(p in properties for p in match_props):
            # DC-style dump: targets from attack flow
            reachable = []
            for rule in self.attack_flow:
                sp = rule.get('source_pattern', '')
                if sp and sp in node_id:
                    for pattern in rule.get('targets', []):
                        for other_id in self._get_nodes_by_group_pattern(pattern):
                            if other_id != node_id:
                                reachable.append(other_id)
                    break
            selected = self._select_targets(reachable, tmpl)
        else:
            # Generic dump: targets from reachability
            reachable = self._find_reachable_target_nodes(node_id)
            selected = self._select_targets(reachable, tmpl)

        for tid in selected:
            all_creds.extend(self._make_cached_credentials(tid))

        if not all_creds:
            all_creds = self._make_cached_credentials(node_id)
            if not all_creds:
                return

        vulns[tmpl['name']] = VulnerabilityInfo(
            description=tmpl['description'],
            type=VulnerabilityType.LOCAL,
            outcome=LeakedCredentials(credentials=all_creds),
            reward_string=tmpl['reward'],
            cost=self._get_vulnerability_cost(tmpl),
            rates=Rates(successRate=tmpl['success_rate'])
        )
        node.vulnerabilities = vulns
        self.fixes_applied.append(f"Added cred dump ({tmpl['name']}) to {node_id}")

    # =========================================================================
    # CHECKERS
    # =========================================================================

    def _has_credential_leak(self, node) -> bool:
        vulns = getattr(node, 'vulnerabilities', {})
        if isinstance(vulns, dict):
            return any(isinstance(getattr(v, 'outcome', None), LeakedCredentials)
                       for v in vulns.values())
        return False

    def _has_discovery_capability(self, node) -> bool:
        vulns = getattr(node, 'vulnerabilities', {})
        if isinstance(vulns, dict):
            return any(isinstance(getattr(v, 'outcome', None), LeakedNodesId)
                       for v in vulns.values())
        return False

    def _find_node(self, node_name: str):
        for nid in self.nodes:
            if self._id_matches(node_name, nid):
                return nid
        return None

    def _find_first_node_in_domain(self, domain_name: str):
        for nid in self.nodes:
            if nid.startswith(domain_name):
                return nid
        return None

    def _get_vulnerability_cost(self, tmpl: dict) -> float:
        """Apply Q10 cost normalization if enabled."""
        cost = tmpl.get('cost', C.DEFAULT_CVE_COST)
        if C.ENABLE_TECHNIQUE_COST_SCALING:
            # A "technique" is defined as a template without an explicit exploit_cve
            # or one that includes protocol-abuse identifiers (ShadowCredentials, DCSync, etc.)
            has_cve = 'exploit_cve' in tmpl or 'CVE-' in tmpl.get('name', '')
            if not has_cve:
                return C.DEFAULT_TECHNIQUE_COST
        return cost