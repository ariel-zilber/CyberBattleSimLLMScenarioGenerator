"""
Solvability Constraint Processor — PROBABILISTIC + YAML-DRIVEN
================================================================
All vulnerability names, costs, descriptions, rates come from YAML.
Probability field on templates creates variance between runs.
Validation auto-fix is forced (ignores probability) to guarantee solvability.

This is a thin orchestrator: it holds the processor's state (nodes, config,
templates) and delegates each concern to the plain functions in the
sibling submodules (attack_paths, credential_flows, discovery_chains,
validation). See docstrings in each submodule for the extracted logic.
"""

import random
from typing import Dict, Any, List, Tuple

from pipeline.cbsim.components.solvability.shared.vuln_registry import check_planned
from pipeline.cbsim.components.solvability.shared.node_lookup import id_matches
from pipeline.cbsim.components.solvability.post_processor.core import _collect_planned_vuln_names
from pipeline.cbsim.components.solvability.constraint_processor.attack_paths import process_attack_paths
from pipeline.cbsim.components.solvability.constraint_processor.credential_flows import (
    process_credential_flows, select_targets,
)
from pipeline.cbsim.components.solvability.constraint_processor.discovery_chains import (
    process_discovery_chains,
)
from pipeline.cbsim.components.solvability.constraint_processor.validation import validate_solvability
from pipeline import constants as C


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
        self._planned_vuln_names: set = _collect_planned_vuln_names(config)

    def _check_planned(self, tmpl: Dict, context: str = '') -> bool:
        return check_planned(tmpl, self._planned_vuln_names, 'Constraints', context)

    def _should_place(self, template: Dict, force: bool = False) -> bool:
        """Probabilistic placement. force=True bypasses probability."""
        if force:
            return True
        prob = template.get('probability', 1.0)
        return random.random() < prob

    def _get_real_credentials(self, node_id: str) -> List[Tuple[str, str, str]]:
        if not isinstance(self.nodes, dict) or node_id not in self.nodes:
            return []
        node = self.nodes[node_id]
        results = []
        for svc in self._get_attr(node, 'services', []):
            for cred in self._get_attr(svc, 'allowedCredentials', []):
                results.append((node_id, svc.name, cred))
        return results

    def _make_cached_credentials_for_targets(self, target_ids: List[str]):
        from cyberbattle.simulation.vulenrabilites import CachedCredential
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
                    if nid != 'start' and id_matches(group_name, nid)
                    and (not domain_name or nid.startswith(domain_name))]
        return []

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
            if name and id_matches(node_name, name):
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
            has_cve = 'exploit_cve' in tmpl or 'CVE-' in tmpl.get('name', '')
            if not has_cve:
                return C.DEFAULT_TECHNIQUE_COST
        return cost

    def process_all_constraints(self):
        self.fixes_applied = []  # Reset so re-runs don't accumulate stale entries
        print("\n[Constraints] Processing solvability constraints...")

        for domain_def in self.config.get('domains', []):
            domain_name = domain_def.get('name')
            print(f"[Constraints] Processing domain: {domain_name}")
            process_attack_paths(
                self.nodes, domain_def, domain_name, self._get_node_ids_in_group,
                self._make_cached_credentials_for_targets, self.cred_leak_templates,
                self._should_place, self._check_planned, self._get_vulnerability_cost,
                self.fixes_applied, self._get_attr, self._set_attr,
            )
            process_credential_flows(
                self.nodes, domain_def, domain_name, self._get_node_ids_in_group,
                self._make_cached_credentials_for_targets, self.cred_leak_templates,
                self._should_place, self._check_planned, self._get_vulnerability_cost,
                self.fixes_applied, self._get_attr, self._set_attr,
            )
            process_discovery_chains(
                self.nodes, domain_def, domain_name, self._get_node_ids_in_group,
                self.discovery_templates,
                self._should_place, self._check_planned, self._get_vulnerability_cost,
                self.fixes_applied, self._get_attr, self._set_attr,
            )

        validate_solvability(
            self.nodes, self.config, self.remote_templates, self.cred_leak_templates,
            self.attack_flow, self._find_node, self._make_cached_credentials_for_targets,
            self._should_place, self._check_planned, self._get_vulnerability_cost,
            self.fixes_applied, self._get_attr, self._set_attr,
        )
        print(f"[Constraints] Applied {len(self.fixes_applied)} solvability fixes")
