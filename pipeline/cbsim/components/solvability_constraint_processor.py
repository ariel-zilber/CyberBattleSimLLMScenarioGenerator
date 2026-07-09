"""
Solvability Constraint Processor — PROBABILISTIC + YAML-DRIVEN
================================================================
All vulnerability names, costs, descriptions, rates come from YAML.
Probability field on templates creates variance between runs.
Validation auto-fix is forced (ignores probability) to guarantee solvability.
"""

import re
from typing import Dict, List, Any, Tuple
import math
import random

from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, LeakedCredentials,
    CachedCredential, LeakedNodesId
)
from cyberbattle.simulation.rate import Rates
from pipeline import constants as C
from pipeline.cbsim.components.precondition_utils import precondition_from_properties


class SolvabilityConstraintProcessor:

    def __init__(self, config: Dict, nodes: Any, domain_map: Dict, group_map: Dict = None,
                 seed: int = None):
        self.config = config
        self.nodes = nodes
        self.domain_map = domain_map
        self.group_map = group_map or {}
        self.fixes_applied = []

        if seed is not None:
            random.seed(seed)

        # Load from YAML
        solv = config.get('solvability_vulnerabilities', {})
        self.remote_templates = solv.get('remote_access', [])
        self.cred_leak_templates = solv.get('credential_leak', [])
        self.discovery_templates = solv.get('discovery', [])
        self.attack_flow = config.get('attack_flow', [])

        # Registry of all vulnerability names declared in the YAML config.
        from pipeline.cbsim.components.solvability_post_processor import _collect_planned_vuln_names
        self._planned_vuln_names: set = _collect_planned_vuln_names(config)

    def _check_planned(self, tmpl: Dict, context: str = '') -> bool:
        """Return True only if tmpl['name'] is in the planned-vuln registry."""
        name = tmpl.get('name', '') if isinstance(tmpl, dict) else ''
        if not name:
            print(f"[Constraints] ERROR: injection template missing 'name'{' — ' + context if context else ''}. Refusing injection.")
            return False
        if self._planned_vuln_names and name not in self._planned_vuln_names:
            print(f"[Constraints] ERROR: refusing to inject unplanned vulnerability '{name}'"
                  f"{' — ' + context if context else ''}. Add it to YAML first.")
            return False
        return True

    def _should_place(self, template: Dict, force: bool = False) -> bool:
        """Probabilistic placement. force=True bypasses probability."""
        if force:
            return True
        prob = template.get('probability', 1.0)
        return random.random() < prob

    # =========================================================================
    # REAL CREDENTIAL HELPERS
    # =========================================================================

    def _get_real_credentials(self, node_id: str) -> List[Tuple[str, str, str]]:
        if not isinstance(self.nodes, dict) or node_id not in self.nodes:
            return []
        node = self.nodes[node_id]
        results = []
        for svc in self._get_attr(node, 'services', []):
            for cred in self._get_attr(svc, 'allowedCredentials', []):
                results.append((node_id, svc.name, cred))
        return results

    def _make_cached_credentials_for_targets(self, target_ids: List[str]) -> List[CachedCredential]:
        cached = []
        for tid in target_ids:
            for nid, port, cred in self._get_real_credentials(tid):
                cached.append(CachedCredential(node=nid, port=port, credential=cred))
        return cached

    def _get_node_ids_in_group(self, domain_name: str, group_name: str) -> List[str]:
        if self.group_map and group_name in self.group_map:
            return list(self.group_map[group_name])
        if isinstance(self.nodes, dict):
            return [nid for nid in self.nodes
                    if nid != 'start' and self._id_matches(group_name, nid)
                    and (not domain_name or nid.startswith(domain_name))]
        return []

    # =========================================================================
    # ATTACK FLOW — FROM YAML
    # =========================================================================

    def _find_reachable_targets(self, node_id: str) -> List[str]:
        target_patterns = []
        for rule in self.attack_flow:
            pattern = rule.get('source_pattern', '')
            if pattern and self._id_matches(pattern, node_id):
                target_patterns = rule.get('targets', [])
                break

        targets = []
        if isinstance(self.nodes, dict):
            for nid in self.nodes:
                if nid == node_id or nid == 'start':
                    continue
                for pattern in target_patterns:
                    if self._id_matches(pattern, nid):
                        targets.append(nid)
                        break
        return targets

    @staticmethod
    def _id_matches(pattern: str, node_id: str) -> bool:
        """True when pattern is a complete underscore-delimited token in node_id."""
        if not pattern:
            return False
        return bool(re.search(r'(?:^|_)' + re.escape(pattern) + r'(?:_|$)', node_id))

    # =========================================================================
    # YAML TEMPLATE HELPERS
    # =========================================================================

    def _get_cred_leak_template(self):
        return self.cred_leak_templates[0] if self.cred_leak_templates else None

    def _get_discovery_template(self):
        return self.discovery_templates[0] if self.discovery_templates else None

    def _pick_remote_template(self, node_properties: set):
        fallback = None
        for tmpl in self.remote_templates:
            match_props = tmpl.get('match_properties', [])
            if not match_props:
                fallback = tmpl
                continue
            if any(p in node_properties for p in match_props):
                return tmpl
        return fallback

    # =========================================================================
    # MAIN PROCESSING
    # =========================================================================

    def process_all_constraints(self):
        self.fixes_applied = []  # Reset so re-runs don't accumulate stale entries
        print("\n[Constraints] Processing solvability constraints...")

        for domain_def in self.config.get('domains', []):
            domain_name = domain_def.get('name')
            print(f"[Constraints] Processing domain: {domain_name}")
            self._process_attack_paths(domain_def, domain_name)
            self._process_credential_flows(domain_def, domain_name)
            self._process_discovery_chains(domain_def, domain_name)

        self._validate_solvability()
        print(f"[Constraints] Applied {len(self.fixes_applied)} solvability fixes")

    # =========================================================================
    # ATTACK PATHS
    # =========================================================================

    def _process_attack_paths(self, domain_def: Dict, domain_name: str):
        attack_paths = domain_def.get('attack_paths', [])
        for attack_path in attack_paths:
            path_steps = attack_path.get('path', [])
            for step in path_steps:
                source_group = step.get('source')
                target_group = step.get('target')
                credential_leakage = step.get('credential_leakage', False)

                source_ids = self._get_node_ids_in_group(domain_name, source_group)
                target_ids = self._get_node_ids_in_group(domain_name, target_group)

                if not source_ids or not target_ids:
                    continue

                if credential_leakage:
                    target_creds = self._make_cached_credentials_for_targets(target_ids)
                    if target_creds:
                        for sid in source_ids:
                            if isinstance(self.nodes, dict) and sid in self.nodes:
                                self._add_credential_leak_vuln(self.nodes[sid], target_creds)

    # =========================================================================
    # CREDENTIAL FLOWS
    # =========================================================================

    def _process_credential_flows(self, domain_def: Dict, domain_name: str):
        cred_flows = domain_def.get('credential_flows', [])
        for flow in cred_flows:
            from_group = flow.get('from')
            to_group = flow.get('to')
            reuse_prob = flow.get('reuse_probability', 0.8)

            source_ids = self._get_node_ids_in_group(domain_name, from_group)
            target_ids = self._get_node_ids_in_group(domain_name, to_group)

            if not source_ids or not target_ids:
                continue

            target_creds = self._make_cached_credentials_for_targets(target_ids)
            if reuse_prob < 1.0:
                target_creds = [c for c in target_creds if random.random() < reuse_prob]

            if target_creds:
                for sid in source_ids:
                    if isinstance(self.nodes, dict) and sid in self.nodes:
                        self._add_credential_leak_vuln(self.nodes[sid], target_creds)

    # =========================================================================
    # DISCOVERY CHAINS
    # =========================================================================

    def _process_discovery_chains(self, domain_def: Dict, domain_name: str):
        chains = domain_def.get('discovery_chains', [])
        for chain in chains:
            discoverer_group = chain.get('discoverer')
            discoverable_groups = chain.get('discoverable', [])
            mechanisms = chain.get('mechanisms', [])

            discoverer_ids = self._get_node_ids_in_group(domain_name, discoverer_group)
            resolved_ids = []
            for group in discoverable_groups:
                resolved_ids.extend(self._get_node_ids_in_group(domain_name, group))

            for did in discoverer_ids:
                if isinstance(self.nodes, dict) and did in self.nodes and resolved_ids:
                    self._ensure_discovery_vulnerability(self.nodes[did], resolved_ids, mechanisms)

    def _ensure_discovery_vulnerability(self, node, resolved_ids: List[str],
                                         mechanisms: List[str], force: bool = False):
        vulns = self._get_attr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            vulns = {}

        has_discovery = any(isinstance(self._get_attr(v, 'outcome', None), LeakedNodesId)
                            for v in vulns.values())
        if has_discovery:
            return

        tmpl = self._get_discovery_template()
        if not tmpl:
            return
        if not self._check_planned(tmpl, 'discovery'):
            return
        if not self._should_place(tmpl, force=force):
            return

        desc = tmpl['description']
        if mechanisms:
            desc = f"{desc} via {', '.join(mechanisms)}"

        vulns[tmpl['name']] = VulnerabilityInfo(
            description=desc,
            type=VulnerabilityType.LOCAL,
            outcome=LeakedNodesId(nodes=resolved_ids),
            reward_string=tmpl.get('reward', 'Exploit successful'),
            cost=self._get_vulnerability_cost(tmpl),
            rates=Rates(successRate=tmpl['success_rate'])
        )
        self._set_attr(node, 'vulnerabilities', vulns)
        self.fixes_applied.append(f"Added discovery ({tmpl['name']}) to {self._get_attr(node, 'name', '?')}")

    # =========================================================================
    # SOLVABILITY VALIDATION
    # =========================================================================

    def _validate_solvability(self):
        rules = self.config.get('solvability_rules', {})
        if not rules:
            return
        auto_fix = rules.get('auto_fix_enabled', False)
        print(f"\n  [Validation] Validating solvability rules (auto-fix: {auto_fix})...")
        self._validate_entry_points(rules, auto_fix)
        self._validate_lateral_movement(rules, auto_fix)
        self._validate_goals(rules, auto_fix)

    def _validate_entry_points(self, rules: Dict, auto_fix: bool):
        entry_reqs = rules.get('entry_point_requirements', {})
        min_remote = entry_reqs.get('min_remote_vulnerabilities', 1)
        min_cred_leak = entry_reqs.get('min_credential_leaking_vulnerabilities', 1)

        for ep in self.config.get('entry_points', []):
            node_name = ep.get('node')
            node = self._find_node(node_name)
            if not node:
                continue

            vulns = self._get_attr(node, 'vulnerabilities', {})
            if not isinstance(vulns, dict):
                continue

            def _count_remote(v_dict):
                return sum(1 for v in v_dict.values()
                           if self._get_attr(v, 'type') == VulnerabilityType.REMOTE
                           and isinstance(self._get_attr(v, 'outcome', None), LeakedCredentials))

            def _count_local_cred_leak(v_dict):
                # Only LOCAL LeakedCredentials — post-compromise dumps.
                # REMOTE access is tracked separately via remote_count.
                return sum(1 for v in v_dict.values()
                           if self._get_attr(v, 'type') == VulnerabilityType.LOCAL
                           and isinstance(self._get_attr(v, 'outcome', None), LeakedCredentials))

            remote_count = _count_remote(vulns)
            cred_leak_count = _count_local_cred_leak(vulns)

            if auto_fix:
                node_id = self._get_attr(node, 'name', '')

                # Inject REMOTE vulns; re-count after each attempt to detect failures
                for _ in range(min_remote - remote_count):
                    prev = remote_count
                    self._add_remote_vuln(node, node_id, force=True)
                    remote_count = _count_remote(
                        self._get_attr(node, 'vulnerabilities', {}))
                    if remote_count == prev:
                        print(f"[Constraints] Warning: could not inject remote vuln "
                              f"into {node_id} — no template or credentials available")
                        break

                # Inject LOCAL cred-leak vulns; re-count to detect failures
                for _ in range(min_cred_leak - cred_leak_count):
                    prev = cred_leak_count
                    self._add_credential_leak_for_node(node, node_id, force=True)
                    cred_leak_count = _count_local_cred_leak(
                        self._get_attr(node, 'vulnerabilities', {}))
                    if cred_leak_count == prev:
                        print(f"[Constraints] Warning: could not inject cred-leak vuln "
                              f"into {node_id} — no template or credentials available")
                        break

    def _validate_lateral_movement(self, rules: Dict, auto_fix: bool):
        lateral_reqs = rules.get('lateral_movement_requirements', {})
        min_ratio = lateral_reqs.get('min_credential_leaking_nodes', C.DEFAULT_MIN_CREDENTIAL_LEAKING_NODES_RATIO)

        if not isinstance(self.nodes, dict):
            return

        non_start = [nid for nid in self.nodes if nid != 'start']
        total = len(non_start)
        leak_count = sum(1 for nid in non_start
                         if any(isinstance(self._get_attr(v, 'outcome', None), LeakedCredentials)
                                for v in self._get_attr(self.nodes[nid], 'vulnerabilities', {}).values()))

        ratio = leak_count / total if total > 0 else 0

        if ratio < min_ratio and auto_fix:
            needed = int(total * min_ratio) - leak_count
            # Shuffle to avoid always fixing the same nodes
            candidates = [nid for nid in non_start
                          if isinstance(self._get_attr(self.nodes[nid], 'vulnerabilities', {}), dict)
                          and not any(isinstance(self._get_attr(v, 'outcome', None), LeakedCredentials)
                                      for v in self._get_attr(self.nodes[nid], 'vulnerabilities', {}).values())]
            random.shuffle(candidates)
            for nid in candidates[:needed]:
                self._add_credential_leak_for_node(self.nodes[nid], nid, force=True)

    def _validate_goals(self, rules: Dict, auto_fix: bool):
        if not isinstance(self.nodes, dict):
            return
        goal_nodes = [(nid, n) for nid, n in self.nodes.items()
                      if nid != 'start' and self._get_attr(n, 'is_goal')]
        if not goal_nodes and auto_fix:
            candidates = [nid for nid in self.nodes if nid != 'start']
            random.shuffle(candidates)
            for nid in candidates[:3]:
                self._set_attr(self.nodes[nid], 'is_goal', True)

    # =========================================================================
    # VULNERABILITY ADDERS — ALL FROM YAML + REAL CREDENTIALS
    # =========================================================================

    def _add_credential_leak_vuln(self, node, cached_creds: List[CachedCredential],
                                   force: bool = False):
        tmpl = self._get_cred_leak_template()
        if not tmpl:
            return
        if not self._check_planned(tmpl, 'credential_leak'):
            return
        if not self._should_place(tmpl, force=force):
            return

        vulns = self._get_attr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            vulns = {}

        vulns[tmpl['name']] = VulnerabilityInfo(
            description=tmpl['description'],
            type=VulnerabilityType.LOCAL,
            outcome=LeakedCredentials(credentials=cached_creds),
            precondition=precondition_from_properties(tmpl.get('match_properties', [])),
            reward_string=tmpl.get('reward', 'Exploit successful'),
            cost=self._get_vulnerability_cost(tmpl),
            rates=Rates(successRate=tmpl['success_rate'])
        )
        self._set_attr(node, 'vulnerabilities', vulns)
        self.fixes_applied.append(f"Added credential leak ({tmpl['name']}) to {self._get_attr(node, 'name', '?')}")

    def _add_remote_vuln(self, node, node_id: str, force: bool = False):
        tmpl = self._pick_remote_template(set(self._get_attr(node, 'properties', [])))
        if not tmpl:
            return
        if not self._check_planned(tmpl, 'remote_access'):
            return
        if not self._should_place(tmpl, force=force):
            return

        real_creds = self._make_cached_credentials_for_targets([node_id])
        if not real_creds:
            return

        vulns = self._get_attr(node, 'vulnerabilities', {})
        if not isinstance(vulns, dict):
            vulns = {}

        vulns[tmpl['name']] = VulnerabilityInfo(
            description=tmpl['description'],
            type=VulnerabilityType.REMOTE,
            outcome=LeakedCredentials(credentials=real_creds),
            precondition=precondition_from_properties(tmpl.get('match_properties', [])),
            reward_string=tmpl.get('reward', 'Exploit successful'),
            cost=self._get_vulnerability_cost(tmpl),
            rates=Rates(successRate=tmpl['success_rate'])
        )
        self._set_attr(node, 'vulnerabilities', vulns)
        self.fixes_applied.append(f"Added REMOTE vuln ({tmpl['name']}) to {node_id}")

    def _add_credential_leak_for_node(self, node, node_id: str, force: bool = False):
        targets = self._find_reachable_targets(node_id)
        if not targets:
            if isinstance(self.nodes, dict):
                targets = [nid for nid in self.nodes if nid != node_id and nid != 'start']

        # Pick a SUBSET based on YAML target_coverage
        tmpl = self._get_cred_leak_template()
        selected = self._select_targets(targets, tmpl) if tmpl else targets[:1]
        cached = self._make_cached_credentials_for_targets(selected)

        # If forced but random subset had no creds, try all targets
        if not cached and force and len(selected) < len(targets):
            cached = self._make_cached_credentials_for_targets(targets)

        if cached:
            self._add_credential_leak_vuln(node, cached, force=force)

    def _select_targets(self, candidates: List[str], template: Dict) -> List[str]:
        """Pick a random subset based on target_coverage + min_targets from template."""
        if not candidates:
            return []
        coverage = template.get('target_coverage', 1.0)
        min_targets = template.get('min_targets', 1)

        if coverage >= 1.0:
            return list(candidates)

        n = max(min_targets, math.ceil(len(candidates) * coverage))
        n = min(n, len(candidates))
        return random.sample(candidates, n)

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _get_all_node_objects(self) -> List:
        if isinstance(self.nodes, dict):
            return list(self.nodes.values())
        return [n for n in self.nodes if not isinstance(n, str)]

    def _find_node(self, node_name: str):
        """Find a node by name — uses token-boundary match since entry_points
        use group names like 'Workstations' but node names are like
        'CorporateAD_Workstations_1'."""
        if not node_name:
            return None
        for node in self._get_all_node_objects():
            name = self._get_attr(node, 'name', '')
            if name and self._id_matches(node_name, name):
                return node
        return None

    def _get_attr(self, obj, attr, default=None):
        if isinstance(obj, str):
            return default
        if isinstance(obj, dict):
            return obj.get(attr, default)
        if hasattr(obj, attr):
            return getattr(obj, attr)
        return default

    def _set_attr(self, obj, attr, value):
        if isinstance(obj, str):
            return
        if isinstance(obj, dict):
            obj[attr] = value
        else:
            setattr(obj, attr, value)

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