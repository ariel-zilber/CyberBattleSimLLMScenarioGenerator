"""
Constraint Engine — BATCHED, PROBABILISTIC, YAML-DRIVEN
=========================================================
All vulnerability names, descriptions, costs come from YAML.

Placement is controlled per constraint_vulnerability template:
  node_probability: fraction of source nodes that get the vuln at all
  target_coverage:  fraction of targets each source node leaks creds for
  min_targets:      minimum targets per node (ensures at least 1 path)

This means NOT every node gets Local.Credentials.Leak — only a random
subset does, and each of those only caches creds for a random subset
of targets. This creates meaningful variance between runs.

Supported relations:
  MUST_CONNECT / MUST_REACH      → Firewall (always applied, no probability)
  CLIENT_OF / LEAK_KNOWN_CREDENTIALS → Credential leak (probabilistic)
  KNOWS                          → Discovery (probabilistic)
  MUST_HAVE / MUST_NOT_HAVE      → Property mutation (always applied)
"""

import math
import random
from typing import Dict, List, Optional, Set

from cyberbattle.simulation.nodes import NodeInfo
from cyberbattle.simulation.firewall import FirewallRule, RulePermission
from cyberbattle.simulation.vulenrabilites import (
    CachedCredential, LeakedCredentials, VulnerabilityInfo,
    VulnerabilityType, LeakedNodesId
)
from cyberbattle.simulation.rate import Rates


class ConstraintEngine:

    def __init__(self, nodes: Dict[str, NodeInfo], domain_map: Dict[str, List[str]],
                 group_map: Dict[str, List[str]], gateways: Dict[str, str],
                 vulnerability_templates: List[Dict],
                 config: Dict = None, seed: int = None):
        self.nodes = nodes
        self.domain_map = domain_map
        self.group_map = group_map
        self.gateways = gateways
        self.templates = vulnerability_templates or []
        self.config = config or {}

        if seed is not None:
            random.seed(seed)

        # Pre-build service-name → node-ids index per domain for O(1) resolution
        # (replaces O(n·services) linear scan in _resolve_nodes)
        self._service_index: Dict[str, Dict[str, List[str]]] = {}
        self._build_service_index()

        # Track already-added firewall edges for O(1) deduplication
        # (replaces O(m) list membership check in _add_connectivity)
        self._fw_seen: Set[tuple] = set()

        cv = self.config.get('constraint_vulnerabilities', {})
        self.cred_leak_template = cv.get('leak_known_credentials', {})
        self.discovery_template = cv.get('leak_neighbors', {})
        self.os_mgmt_ports = self.config.get('os_management_ports', {})

        # Track which source nodes were selected/rejected for each relation.
        # Cached so a node's roll is consistent across multiple constraints.
        self._cred_leak_selected: Set[str] = set()
        self._cred_leak_rejected: Set[str] = set()
        self._discovery_selected: Set[str] = set()
        self._discovery_rejected: Set[str] = set()

    # --------------------------------------------------------------------------
    # INDEX BUILDERS
    # --------------------------------------------------------------------------

    def _build_service_index(self):
        """Build domain → service_name → [node_ids] for fast _resolve_nodes."""
        for domain, node_ids in self.domain_map.items():
            domain_idx: Dict[str, List[str]] = {}
            for node_id in node_ids:
                if node_id not in self.nodes:
                    continue
                for svc in self.nodes[node_id].services:
                    domain_idx.setdefault(svc.name, []).append(node_id)
            self._service_index[domain] = domain_idx

    # --------------------------------------------------------------------------
    # TEMPLATE HELPERS
    # --------------------------------------------------------------------------

    def _get_default_port(self, template: Dict) -> str:
        port = template.get('default_port')
        if port:
            return port
        default = self.os_mgmt_ports.get('default')
        if default:
            return default
        vals = list(self.os_mgmt_ports.values())
        return vals[0] if vals else ''

    def _select_source_nodes(self, source_ids: List[str], template: Dict,
                             selected_set: Set[str], rejected_set: Set[str]) -> List[str]:
        """
        Decide which source nodes get this vulnerability at all.
        Rolls once per node; result is cached so the same node gives
        the same answer if hit by multiple constraints.
        """
        node_prob = template.get('node_probability', 1.0)
        chosen = []
        for sid in source_ids:
            if sid in selected_set:
                chosen.append(sid)
            elif sid in rejected_set:
                continue
            else:
                if random.random() < node_prob:
                    selected_set.add(sid)
                    chosen.append(sid)
                else:
                    rejected_set.add(sid)
        return chosen

    def _select_targets(self, target_ids: List[str], template: Dict) -> List[str]:
        """Pick a random subset of targets based on target_coverage + min_targets."""
        if not target_ids:
            return []
        coverage = template.get('target_coverage', 1.0)
        min_targets = template.get('min_targets', 1)

        if coverage >= 1.0:
            return list(target_ids)

        n = max(min_targets, math.ceil(len(target_ids) * coverage))
        n = min(n, len(target_ids))

        return random.sample(target_ids, n)

    # --------------------------------------------------------------------------
    # MAIN DISPATCH
    # --------------------------------------------------------------------------

    def apply_constraints(self, context_domain: Optional[str], constraints: List[Dict],
                          is_inter_domain: bool = False):
        if not constraints:
            return

        for constraint in constraints:
            if is_inter_domain:
                source_domain = constraint.source_domain
                target_domain = constraint.target_domain
            else:
                source_domain = context_domain
                target_domain = context_domain

            if type(constraint) != dict:
                constraint = constraint.to_dict()

            self._apply_single_constraint(constraint, source_domain, target_domain)

    def _apply_single_constraint(self, constraint: Dict, source_domain: str, target_domain: str):
        relation = constraint['relation']
        protocol = constraint.get('protocol')

        # --- PROPERTY MUTATION (always applied) ---
        if relation in ("MUST_HAVE", "MUST_NOT_HAVE"):
            target_property = constraint['target']
            source_nodes = self._resolve_nodes(constraint['source'], source_domain)
            for source_id in source_nodes:
                if relation == "MUST_HAVE":
                    self._add_property(source_id, target_property)
                else:
                    self._remove_property(source_id, target_property)
            return

        # --- NODE-TO-NODE RELATIONS ---
        source_nodes = self._resolve_nodes(constraint['source'], source_domain)
        target_nodes = self._resolve_nodes(constraint['target'], target_domain)

        if not source_nodes or not target_nodes:
            return

        # --- FIREWALL (always applied, no probability) ---
        if relation in ("MUST_CONNECT", "MUST_REACH"):
            proto = "ALL" if relation == "MUST_REACH" else protocol
            for source_id in source_nodes:
                for target_id in target_nodes:
                    if source_id != target_id:
                        self._add_connectivity(source_id, target_id, proto)
            return

        # --- CREDENTIAL LEAK (probabilistic per-node, partial per-target) ---
        if relation in ("CLIENT_OF", "LEAK_KNOWN_CREDENTIALS"):
            self._apply_credential_leak_batched(source_nodes, target_nodes, protocol)
            return

        # --- DISCOVERY (probabilistic per-node, partial per-target) ---
        if relation == "KNOWS":
            self._apply_discovery_batched(source_nodes, target_nodes)
            return

    # --------------------------------------------------------------------------
    # BATCHED CREDENTIAL LEAK
    # --------------------------------------------------------------------------

    def _apply_credential_leak_batched(self, source_ids: List[str],
                                        target_ids: List[str], protocol: str):
        """
        For each source node:
          1. Roll node_probability → skip entirely if rejected
          2. Pick a subset of targets (target_coverage)
          3. Create/aggregate Local.Credentials.Leak for those targets only
        """
        tmpl = self.cred_leak_template
        if not tmpl or not tmpl.get('name'):
            legacy = self._find_vulnerability_template("LOCAL", "LEAK_KNOWN_CREDENTIALS")
            if not legacy:
                return
            tmpl = legacy

        vuln_name = tmpl['name']
        description = tmpl.get('description', '')
        cost = tmpl.get('cost', 1.0)
        success_rate = tmpl.get('success_rate', 1.0)
        default_port = self._get_default_port(tmpl)

        # Step 1: Select which source nodes participate
        chosen_sources = self._select_source_nodes(
            source_ids, tmpl, self._cred_leak_selected, self._cred_leak_rejected
        )

        if not chosen_sources:
            return

        # Step 2: For each chosen source, pick target subset and build vuln
        for source_id in chosen_sources:
            if source_id not in self.nodes:
                continue
            source_info = self.nodes[source_id]

            my_targets = self._select_targets(target_ids, tmpl)

            for target_id in my_targets:
                if target_id == source_id or target_id not in self.nodes:
                    continue

                target_info = self.nodes[target_id]

                creds_to_leak, target_port = self._find_creds(target_info, protocol)
                if not creds_to_leak:
                    continue
                if not target_port:
                    target_port = default_port

                reward = tmpl.get('reward', 'Leaked credentials')
                reward = reward.replace('{target}', target_id)

                # Aggregate or create
                if vuln_name in source_info.vulnerabilities:
                    existing = source_info.vulnerabilities[vuln_name]
                    if isinstance(existing.outcome, LeakedCredentials):
                        existing_cred_set = {c.credential for c in existing.outcome.credentials}
                        for c in creds_to_leak:
                            if c not in existing_cred_set:
                                existing.outcome.credentials.append(
                                    CachedCredential(node=target_id, port=target_port, credential=c)
                                )
                else:
                    source_info.vulnerabilities[vuln_name] = VulnerabilityInfo(
                        description=description,
                        type=VulnerabilityType.LOCAL,
                        outcome=LeakedCredentials(credentials=[
                            CachedCredential(node=target_id, port=target_port, credential=c)
                            for c in creds_to_leak
                        ]),
                        reward_string=reward,
                        cost=cost,
                        rates=Rates(successRate=success_rate)
                    )

    # --------------------------------------------------------------------------
    # BATCHED DISCOVERY
    # --------------------------------------------------------------------------

    def _apply_discovery_batched(self, source_ids: List[str], target_ids: List[str]):
        """
        For each source node:
          1. Roll node_probability → skip if rejected
          2. Pick a subset of targets (target_coverage)
          3. Create/aggregate Local.Network.Discovery for those targets
        """
        tmpl = self.discovery_template
        if not tmpl or not tmpl.get('name'):
            legacy = self._find_vulnerability_template("LOCAL", "LEAK_NEIGHBORS")
            if not legacy:
                return
            tmpl = legacy

        vuln_name = tmpl['name']
        description = tmpl.get('description', '')
        cost = tmpl.get('cost', 0.5)
        success_rate = tmpl.get('success_rate', 1.0)

        chosen_sources = self._select_source_nodes(
            source_ids, tmpl, self._discovery_selected, self._discovery_rejected
        )

        if not chosen_sources:
            return

        for source_id in chosen_sources:
            if source_id not in self.nodes:
                continue
            source_info = self.nodes[source_id]

            my_targets = self._select_targets(target_ids, tmpl)

            for target_id in my_targets:
                if target_id == source_id:
                    continue

                reward = tmpl.get('reward', 'Discovered neighbor')
                reward = reward.replace('{target}', target_id)

                if vuln_name in source_info.vulnerabilities:
                    existing = source_info.vulnerabilities[vuln_name]
                    if isinstance(existing.outcome, LeakedNodesId):
                        if target_id not in existing.outcome.nodes:
                            existing.outcome.nodes.append(target_id)
                else:
                    source_info.vulnerabilities[vuln_name] = VulnerabilityInfo(
                        description=description,
                        type=VulnerabilityType.LOCAL,
                        outcome=LeakedNodesId(nodes=[target_id]),
                        reward_string=reward,
                        cost=cost,
                        rates=Rates(successRate=success_rate)
                    )

    # --------------------------------------------------------------------------
    # CREDENTIAL FINDER
    # --------------------------------------------------------------------------

    def _find_creds(self, target_info: NodeInfo, protocol: str):
        """Find credentials to leak from target. Returns (creds_list, port_name)."""
        creds = []
        port_name = protocol

        for svc in target_info.services:
            if protocol is None or svc.name == protocol or str(svc.port) == protocol:
                if svc.allowedCredentials:
                    creds.extend(svc.allowedCredentials)
                    port_name = svc.name

        if not creds and target_info.services:
            first = target_info.services[0]
            if first.allowedCredentials:
                creds.extend(first.allowedCredentials)
                port_name = first.name

        return creds, port_name

    # --------------------------------------------------------------------------
    # CONNECTIVITY (always applied, no probability)
    # --------------------------------------------------------------------------

    def _add_connectivity(self, source_id: str, target_id: str, protocol: str):
        if source_id not in self.nodes or target_id not in self.nodes:
            return

        port = protocol or "ALL"
        src_info = self.nodes[source_id]
        dst_info = self.nodes[target_id]
        dst_subnet = dst_info.network_info[0].subnet
        src_subnet = src_info.network_info[0].subnet

        def _add_rule(p: str):
            key = (source_id, target_id, p)
            if key in self._fw_seen:
                return
            self._fw_seen.add(key)
            src_info.firewall.outgoing.append(FirewallRule(
                port=p, permission=RulePermission.ALLOW, subnet=dst_subnet, reason=""
            ))
            dst_info.firewall.incoming.append(FirewallRule(
                port=p, permission=RulePermission.ALLOW, subnet=src_subnet, reason=""
            ))

        # Add the semantic protocol rule (e.g., Kerberos, SMB, HTTPS)
        _add_rule(port)

        # Also add rules for each service on the destination so agents can
        # use credential-based lateral movement (RDP/SSH etc.) over this path.
        for svc in getattr(dst_info, 'services', []):
            svc_port = getattr(svc, 'name', None)
            if svc_port and svc_port not in ('*', 'any'):
                _add_rule(svc_port)

    # --------------------------------------------------------------------------
    # PROPERTY MUTATION (always applied)
    # --------------------------------------------------------------------------

    def _add_property(self, node_id: str, property_name: str):
        if node_id in self.nodes:
            node = self.nodes[node_id]
            if property_name not in node.properties:
                node.properties.append(property_name)

    def _remove_property(self, node_id: str, property_name: str):
        if node_id in self.nodes:
            node = self.nodes[node_id]
            if property_name in node.properties:
                node.properties.remove(property_name)

    # --------------------------------------------------------------------------
    # LEGACY TEMPLATE SEARCH
    # --------------------------------------------------------------------------

    def _find_vulnerability_template(self, type_str: str, outcome_str: str) -> Optional[Dict]:
        for vuln in self.templates:
            v_type = str(vuln.get('type', '')).upper()
            if v_type != type_str:
                continue
            out_type = str(vuln.get('outcome', {}).get('type', '')).upper()
            if out_type == outcome_str:
                return vuln
        return None

    # --------------------------------------------------------------------------
    # NODE RESOLUTION
    # --------------------------------------------------------------------------

    def _resolve_nodes(self, reference: str, domain_context: str) -> List[str]:
        """
        Resolves a reference string to a list of Node IDs.
        Priority: Group Name → Service Name → Direct Node Match.
        """
        resolved = []

        # 1. Group Map
        if reference in self.group_map:
            for node_id in self.group_map[reference]:
                if node_id.startswith(f"{domain_context}_"):
                    resolved.append(node_id)
            if resolved:
                return resolved

        # 2. Service Name — O(1) index lookup instead of O(n·services) scan
        domain_idx = self._service_index.get(domain_context, {})
        resolved = domain_idx.get(reference, [])
        if resolved:
            return resolved

        # 3. Direct Node Match
        potential = f"{domain_context}_{reference}"
        if potential in self.nodes:
            resolved.append(potential)

        return resolved