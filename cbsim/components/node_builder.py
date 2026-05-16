# domain/components/node_builder.py
# ZERO hardcoded values. Every port name, vulnerability name, property,
# cost, rate, and description is read from self.config (the YAML dict).

import math
import random
from typing import Dict, List, Tuple, Optional
from cyberbattle.simulation.nodes import NodeInfo
from cyberbattle.simulation.services import ListeningService
from cyberbattle.simulation.firewall import FirewallConfiguration, FirewallRule, RulePermission
from cyberbattle.simulation.network import NodeNetworkInfo, Subnet, NetworkInterfaces
from cyberbattle.simulation.vulenrabilites import (
    CachedCredential, LeakedCredentials, VulnerabilityInfo,
    VulnerabilityType, LeakedNodesId, ProbeSucceeded
)
from cyberbattle.simulation.rate import Rates
from .network_utils import NetworkUtils


class NodeBuilder:
    """
    Factory class for creating NodeInfo objects.
    All configuration comes from the YAML config dict.
    """

    def __init__(self, services_config: Dict, config: Dict):
        """
        Args:
            services_config: Dictionary of ServiceProfile objects (from loader.services).
            config: Full YAML config dict.
        """
        self.services = services_config
        self.config = config

        # Caches read from YAML once
        self._os_mgmt_ports = config.get('os_management_ports', {})
        self._probe_config = config.get('probe_vulnerabilities', [])
        self._start_config = config.get('start_node', {})

    # =========================================================================
    # CONFIG LOOKUPS — no hardcoded port names or property strings
    # =========================================================================

    def _get_mgmt_port(self, os_family: str) -> str:
        """Get management port for an OS from YAML os_management_ports."""
        port = self._os_mgmt_ports.get(os_family)
        if port:
            return port
        # Use the 'default' key from YAML, or first available value
        default = self._os_mgmt_ports.get('default')
        if default:
            return default
        # Absolute last resort: first defined port in the mapping
        vals = list(self._os_mgmt_ports.values())
        return vals[0] if vals else os_family

    # =========================================================================
    # DOMAIN NODE CREATION
    # =========================================================================

    def create_node(self, domain_name: str, subnet: str, group_config: Dict,
                    instance_num: int, global_counter: int,
                    gateway_ip: Optional[str] = None) -> Tuple[str, NodeInfo]:
        """Creates a standard domain node based on group configuration."""
        service_name = group_config['service']
        group_name = group_config['name']

        if service_name not in self.services:
            raise ValueError(f"Service '{service_name}' not found in services configuration.")

        service_profile = self.services[service_name]
        node_name = f"{domain_name}_{group_name}_{instance_num}"

        # OS from service profile, management port from YAML mapping
        allowed_os = service_profile.allowed_os
        os_family = allowed_os[0] if allowed_os else list(self._os_mgmt_ports.keys())[0]
        mgmt_port = self._get_mgmt_port(os_family)

        # Unique credentials per node
        mgmt_cred = NetworkUtils.generate_credential_id(node_name, mgmt_port)
        services = [ListeningService(name=mgmt_port, allowedCredentials=[mgmt_cred])]

        if service_name != mgmt_port:
            app_cred = NetworkUtils.generate_credential_id(node_name, service_name)
            services.append(ListeningService(name=service_name, allowedCredentials=[app_cred]))

        properties = list(service_profile.default_properties)
        properties.append(os_family)

        ip_address = NetworkUtils.generate_ip(subnet, global_counter)
        vulnerabilities = self._generate_base_vulnerabilities(node_name, os_family, service_name, mgmt_port)
        firewall = self._create_default_firewall(subnet, domain_name, gateway_ip, os_family=os_family)

        node_info = NodeInfo(
            services=services,
            firewall=firewall,
            value=service_profile.value,
            properties=properties,
            vulnerabilities=vulnerabilities,
            network_info=[NodeNetworkInfo(
                interface=NetworkInterfaces.ETH1,
                ip_address=ip_address,
                subnet=Subnet(subnet)
            )]
        )
        node_info.is_goal = service_profile.is_goal
        return node_name, node_info

    def create_filler_node(self, domain_name: str, subnet: str, service_name: str,
                           global_counter: int, gateway_ip: Optional[str] = None) -> Tuple[str, NodeInfo]:
        """Creates a filler node to meet minimum node counts."""
        service_profile = self.services[service_name]
        node_name = f"{domain_name}_{service_name}_{global_counter}"

        allowed_os = service_profile.allowed_os
        os_family = allowed_os[0] if allowed_os else list(self._os_mgmt_ports.keys())[0]
        mgmt_port = self._get_mgmt_port(os_family)

        mgmt_cred = NetworkUtils.generate_credential_id(node_name, mgmt_port)
        services = [ListeningService(name=mgmt_port, allowedCredentials=[mgmt_cred])]

        if service_name != mgmt_port:
            app_cred = NetworkUtils.generate_credential_id(node_name, service_name)
            services.append(ListeningService(name=service_name, allowedCredentials=[app_cred]))

        properties = list(service_profile.default_properties)
        properties.append(os_family)

        ip_address = NetworkUtils.generate_ip(subnet, global_counter)
        firewall = self._create_default_firewall(subnet, domain_name, gateway_ip, os_family=os_family)
        vulns = self._generate_base_vulnerabilities(node_name, os_family, service_name, mgmt_port)

        node_info = NodeInfo(
            services=services,
            firewall=firewall,
            value=service_profile.value,
            properties=properties,
            vulnerabilities=vulns,
            network_info=[NodeNetworkInfo(
                interface=NetworkInterfaces.ETH1,
                ip_address=ip_address,
                subnet=Subnet(subnet)
            )]
        )
        node_info.is_goal = service_profile.is_goal
        return node_name, node_info

    # =========================================================================
    # ATTACKER (START) NODE — RANDOMIZED ENTRY POINTS FROM YAML
    # =========================================================================

    def create_attacker_node(self, entry_points: List[Dict], all_nodes: Dict[str, NodeInfo],
                             domain_map: Dict[str, List[str]],
                             group_map: Dict[str, List[str]] = None) -> Optional[Dict[str, NodeInfo]]:
        """
        Creates the 'start' node with VARIANCE in:
          - Which node(s) the attacker gets initial creds for (randomized)
          - Which port/credential is leaked (randomized from preferred list)
          - How many group nodes are discovered (partial coverage)

        All controlled from YAML start_node section.
        """
        if not all_nodes:
            return None

        sc = self._start_config
        attacker_subnet = sc.get('subnet')
        attacker_ip = sc.get('ip')
        attacker_props = sc.get('properties', [])
        preferred_ports = sc.get('preferred_entry_ports', [])
        default_port = sc.get('default_entry_port')
        vuln_defs = sc.get('vulnerabilities', {})
        port_selection = sc.get('port_selection', 'first')

        # --- Variance controls ---
        entry_count_cfg = sc.get('entry_node_count', 1)
        leaked_coverage = sc.get('leaked_node_coverage', 1.0)
        min_leaked = sc.get('min_leaked_nodes', 1)

        # Resolve entry_node_count (int or {min, max})
        if isinstance(entry_count_cfg, dict):
            entry_count = random.randint(
                entry_count_cfg.get('min', 1),
                entry_count_cfg.get('max', 1)
            )
        else:
            entry_count = int(entry_count_cfg)

        # --- Resolve candidate nodes from entry_points config ---
        candidates = []

        if entry_points:
            ep_config = entry_points[0]
            target_str = ep_config.get('node')
            domain_str = ep_config.get('domain')

            # Strategy 1: group name in group_map
            if group_map and target_str and target_str in group_map:
                candidates = list(group_map[target_str])
                if domain_str and domain_map and domain_str in domain_map:
                    domain_nodes = set(domain_map[domain_str])
                    candidates = [n for n in candidates if n in domain_nodes]

            # Strategy 2: substring match
            if not candidates and target_str:
                candidates = [n_id for n_id in all_nodes
                              if target_str in n_id and (not domain_str or domain_str in n_id)]

            # Strategy 3: all nodes in domain
            if not candidates and domain_str and domain_str in domain_map:
                candidates = list(domain_map[domain_str])

        # Ultimate fallback
        if not candidates:
            candidates = [n for n in all_nodes if n != 'start']

        # --- RANDOMIZE: pick entry nodes (not always the first!) ---
        random.shuffle(candidates)
        entry_node_ids = candidates[:entry_count]

        # --- RANDOMIZE: pick discovered nodes (partial coverage) ---
        n_leaked = max(min_leaked, math.ceil(len(candidates) * leaked_coverage))
        n_leaked = min(n_leaked, len(candidates))
        # Ensure entry nodes are always in the discovered set
        remaining = [n for n in candidates if n not in entry_node_ids]
        random.shuffle(remaining)
        extra_slots = max(0, n_leaked - len(entry_node_ids))
        leaked_nodes = list(entry_node_ids) + remaining[:extra_slots]

        print(f"[NodeBuilder] Entry nodes: {entry_node_ids}")
        print(f"[NodeBuilder] Discovered nodes ({len(leaked_nodes)}/{len(candidates)}): {leaked_nodes}")

        # --- Build credential leaks for each entry node ---
        cred_leaks = []  # [(node_id, port, credential)]

        for eid in entry_node_ids:
            if eid not in all_nodes:
                continue
            enode = all_nodes[eid]

            port, cred = self._pick_entry_credential(enode, preferred_ports, default_port, port_selection)
            if port and cred:
                cred_leaks.append((eid, port, cred))

            # Open firewall on this entry node
            self._open_entry_firewall(enode, attacker_subnet, port)

        # --- Build start node vulnerabilities from YAML templates ---
        start_vulns = {}

        # Discovery: reveals a SUBSET of group nodes
        disc_def = vuln_defs.get('discovery')
        if disc_def and leaked_nodes:
            start_vulns[disc_def['name']] = VulnerabilityInfo(
                description=disc_def['description'],
                type=VulnerabilityType.LOCAL,
                outcome=LeakedNodesId(nodes=leaked_nodes),
                reward_string=disc_def['reward'],
                cost=disc_def['cost'],
                rates=Rates(successRate=disc_def['success_rate'])
            )

        # Credential leak: creds for the randomly selected entry node(s)
        cred_def = vuln_defs.get('credential_leak')
        if cred_def and cred_leaks:
            cached_creds = [
                CachedCredential(node=nid, port=port, credential=cred)
                for nid, port, cred in cred_leaks
            ]
            start_vulns[cred_def['name']] = VulnerabilityInfo(
                description=cred_def['description'],
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials(credentials=cached_creds),
                reward_string=cred_def['reward'],
                cost=cred_def['cost'],
                rates=Rates(successRate=cred_def['success_rate'])
            )

        # --- Create attacker node ---
        start_node = NodeInfo(
            image='attacker',
            network_info=[NodeNetworkInfo(
                interface=NetworkInterfaces.ETH1,
                ip_address=attacker_ip,
                subnet=Subnet(attacker_subnet)
            )] if attacker_subnet and attacker_ip else [],
            services=[],
            firewall=FirewallConfiguration(
                incoming=[],
                outgoing=[FirewallRule("*", RulePermission.ALLOW, "", Subnet("0.0.0.0/0"))]
            ),
            value=0,
            vulnerabilities=start_vulns,
            agent_installed=True,
            properties=list(attacker_props)
        )

        return {'start': start_node}

    # =========================================================================
    # ENTRY CREDENTIAL SELECTION — RANDOMIZED
    # =========================================================================

    def _pick_entry_credential(self, entry_node: NodeInfo, preferred_ports: List[str],
                               default_port: str, selection_mode: str):
        """
        Pick a port+credential from the entry node.
        selection_mode:
          "random" → shuffle matching services, pick one at random
          "first"  → pick first match (old deterministic behavior)
        """
        # Collect all services that match preferred ports
        matching = []
        for svc in entry_node.services:
            if svc.name in preferred_ports and svc.allowedCredentials:
                matching.append(svc)

        if not matching:
            # Fallback: any service with credentials
            for svc in entry_node.services:
                if svc.allowedCredentials:
                    matching.append(svc)

        if not matching:
            # No credentials at all
            port = entry_node.services[0].name if entry_node.services else default_port
            return port, None

        if selection_mode == "random":
            svc = random.choice(matching)
        else:
            svc = matching[0]

        cred = random.choice(svc.allowedCredentials) if svc.allowedCredentials else None
        return svc.name, cred

    def _open_entry_firewall(self, entry_node: NodeInfo, attacker_subnet: str, entry_port: str):
        """Open firewall on an entry node for the attacker subnet."""
        if not attacker_subnet:
            return

        incoming_exists = any(
            getattr(r, 'subnet', None) and r.subnet.network == attacker_subnet
            for r in entry_node.firewall.incoming
        )
        if not incoming_exists and entry_port:
            entry_node.firewall.incoming.append(FirewallRule(
                port=entry_port,
                permission=RulePermission.ALLOW,
                subnet=Subnet(attacker_subnet),
                reason="Attacker Entry Point (Incoming)"
            ))

        outgoing_exists = any(
            getattr(r, 'subnet', None) and r.subnet.network == attacker_subnet
            for r in entry_node.firewall.outgoing
        )
        if not outgoing_exists and entry_port:
            entry_node.firewall.outgoing.append(FirewallRule(
                port=entry_port,
                permission=RulePermission.ALLOW,
                subnet=Subnet(attacker_subnet),
                reason="Attacker Entry Point (Outgoing)"
            ))

    # =========================================================================
    # FIREWALL
    # =========================================================================

    def _create_default_firewall(self, subnet_str: str, domain_name: str,
                                 gateway_ip: Optional[str],
                                 os_family: str = "Windows") -> FirewallConfiguration:
        """Create a deny-by-default firewall with no wildcard rules.

        No default intra-domain rules are added — all connectivity must be
        explicitly defined via MUST_CONNECT constraints in the YAML.
        This ensures density/diameter metrics reflect the actual security
        design rather than simulator-internal wildcard plumbing.
        """
        return FirewallConfiguration(incoming=[], outgoing=[])

    # =========================================================================
    # PROBE VULNERABILITIES — FROM YAML probe_vulnerabilities
    # =========================================================================

    def _generate_base_vulnerabilities(self, node_name: str, os_family: str,
                                        service_name: str, mgmt_port: str = None) -> Dict:
        """
        Generates probe vulnerabilities entirely from YAML probe_vulnerabilities.
        No fallback names are hardcoded — if YAML has no matching probe, none is added.
        """
        vulns = {}
        discovered = list(set(filter(None, [os_family, service_name, mgmt_port])))

        for probe in self._probe_config:
            if probe.get('os') == os_family:
                vulns[probe['name']] = VulnerabilityInfo(
                    description=probe.get('description', ''),
                    type=VulnerabilityType.REMOTE,
                    outcome=ProbeSucceeded(discovered_properties=discovered),
                    reward_string=probe.get('reward', f"Probed {os_family}"),
                    cost=probe.get('cost', 1.0),
                    rates=Rates(successRate=probe.get('success_rate', 1.0))
                )

        return vulns