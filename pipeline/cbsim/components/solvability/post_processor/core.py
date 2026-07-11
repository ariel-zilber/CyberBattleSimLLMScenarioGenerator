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

This is a thin orchestrator: it holds the processor's state (nodes, config,
caches, entry/goal node ids) and delegates each concern to the plain
functions in the sibling submodules (entry_point, credential_chain,
discovery, goal_access, goal_reachable). See docstrings in each submodule
for the extracted logic.
"""

import random
from typing import Dict, List, Optional

from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityType, LeakedCredentials, LeakedNodesId,
)
from pipeline import constants as C
from pipeline.cbsim.components.solvability.shared.vuln_registry import (
    collect_planned_vuln_names, check_planned,
)
from pipeline.cbsim.components.solvability.shared.node_lookup import id_matches
from pipeline.cbsim.components.solvability.post_processor.entry_point import (
    ensure_external_routing, ensure_entry_point_access,
)
from pipeline.cbsim.components.solvability.post_processor.credential_chain import (
    ensure_credential_chain,
)
from pipeline.cbsim.components.solvability.post_processor.discovery import ensure_discovery
from pipeline.cbsim.components.solvability.post_processor.goal_access import ensure_goal_access
from pipeline.cbsim.components.solvability.post_processor.goal_reachable import ensure_goal_reachable
# ensure_full_coverage is intentionally NOT wired in here — see the call
# site in ensure_solvability()'s docstring/comment and pipeline/cbsim/generator.py.

# Re-exported so `from ...solvability_post_processor import _collect_planned_vuln_names`
# (used by SolvabilityConstraintProcessor) keeps working unchanged.
_collect_planned_vuln_names = collect_planned_vuln_names


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
        # Cache for find_reachable_targets (avoids repeated O(n) scans)
        self._reachable_cache: Dict[str, List[str]] = {}

        # Registry of every vulnerability name declared in the YAML config.
        # Any injection attempt using a name absent from this set is refused.
        self._planned_vuln_names: set = collect_planned_vuln_names(config)

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
                    if node_name and id_matches(node_name, nid) and nid != 'start':
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

    def _check_planned(self, tmpl: Dict, context: str = '') -> bool:
        return check_planned(tmpl, self._planned_vuln_names, 'Solvability', context)

    def _find_node(self, node_name: str):
        for nid in self.nodes:
            if id_matches(node_name, nid):
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

    def ensure_solvability(self):
        self._reachable_cache.clear()  # Invalidate stale entries from any prior call
        print("\n[Solvability] Ensuring scenario is solvable...")
        ensure_external_routing(self.nodes, self.fixes_applied)  # must run first: bridges start→internal subnets (Q38)
        ensure_entry_point_access(
            self.nodes, self.config, self.entry_node_ids,
            self.remote_templates, self.discovery_templates, self.cred_leak_templates,
            self.attack_flow, self._reachable_cache,
            self._find_node, self._find_first_node_in_domain,
            self._should_place, self._check_planned, self._get_vulnerability_cost,
            self.fixes_applied,
        )
        ensure_credential_chain(
            self.nodes, self.config, self.entry_node_ids, self.goal_node_ids,
            self.cred_leak_templates, self.attack_flow, self._reachable_cache,
            self._should_place, self._check_planned, self._get_vulnerability_cost,
            self.fixes_applied,
        )
        ensure_discovery(
            self.nodes, self.entry_node_ids, self.goal_node_ids, self.discovery_templates,
            self._should_place, self._check_planned, self._get_vulnerability_cost,
            self.fixes_applied,
        )
        ensure_goal_access(
            self.nodes, self.goal_templates, self.attack_flow, self._reachable_cache,
            self._should_place, self._check_planned, self._get_vulnerability_cost,
            self.fixes_applied,
        )
        ensure_goal_reachable(
            self.nodes, self.entry_node_ids, self.goal_node_ids,
            self.cred_leak_templates, self.attack_flow, self._reachable_cache,
            self._should_place, self._check_planned, self._get_vulnerability_cost,
            self.fixes_applied,
        )
        # NOTE: the full-coverage sweep does NOT run here. It must run after
        # CertifiedAttackSpineBuilder's shortcut guard (generator.py, later in
        # the pipeline) has finished pruning edges — pruning only guarantees
        # goal reachability, not reachability of whatever node a coverage
        # placement landed on, so running the sweep here let ~1% of force-
        # placed slots get orphaned by a later prune. See
        # pipeline/cbsim/generator.py for the call site.

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
