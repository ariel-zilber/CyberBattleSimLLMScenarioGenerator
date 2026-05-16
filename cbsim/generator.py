# domain/universal_generator.py
# Network_utils.extract_identifiers() handles all YAML sections.
# get_identifiers() only supplements with VulnerabilityManager-specific entries.

import random
from typing import Dict, List
from cyberbattle.simulation.nodes import NodeInfo
from cyberbattle.simulation.identifiers import Identifiers
from cyberbattlesim_network_gen.generators.network_generator import NetworkGenerator

from cbsim.domain_loader import YamlDomainLoader
from cbsim.components.network_utils import NetworkUtils
from cbsim.components.node_builder import NodeBuilder
from cbsim.components.constraint_engine import ConstraintEngine
from cbsim.components.topology_manager import TopologyManager
from cbsim.components.solvability_constraint_processor import SolvabilityConstraintProcessor
from cbsim.components.vulnerability_manager import VulnerabilityManager
from cbsim.components.solvability_post_processor import SolvabilityPostProcessor
from cbsim.goal_normalizer import GoalNormalizer
from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, ProbeSucceeded, 
    LeakedCredentials, CachedCredential, CustomerData,
    ExploitFailed, PrivilegeEscalation, LateralMove, LeakedNodesId
)
class UniversalNetworkGenerator(NetworkGenerator):

    def __init__(self, domain_config_path: str, gml_file_path: str = None, seed: int = None, **kwargs) -> None:
        super().__init__(**kwargs)

        if seed is not None:
            random.seed(seed)

        self.loader = YamlDomainLoader(domain_config_path)
        self.config = self.loader.data
        self.domain_loader = self.loader  # reuse — no double parse

        self.topology_manager = TopologyManager(gml_file_path, config=self.config.get('config', {}))

        self.all_nodes: Dict[str, NodeInfo] = {}
        self.domain_node_map: Dict[str, List[str]] = {}
        self.group_node_map: Dict[str, List[str]] = {}
        self.node_counter = 1

        self.utils = NetworkUtils()

        # Pass full config to NodeBuilder
        self.builder = NodeBuilder(self.loader.services, config=self.config)

        self.vuln_manager = VulnerabilityManager(
            config=self.config,
            domain_loader=self.domain_loader
        )

        # Build domain subnets: prefer YAML-defined subnets, fall back to auto /16
        yaml_subnets = {
            name: self.loader.get_domain_template(name).subnet
            for name in self.loader.get_all_domains()
            if self.loader.get_domain_template(name)
        }
        self.domain_subnets = self.utils.calculate_domain_subnets(
            self.loader.get_all_domains(), yaml_subnets=yaml_subnets
        )
        backbone_subnets = self.topology_manager.get_backbone_subnets()
        self.domain_subnets.update(backbone_subnets)
        self.domain_gateways = self.utils.calculate_domain_gateways(
            self.loader.get_all_domains(), domain_subnets=self.domain_subnets
        )
        # Per-group subnet mapping: domain → {group_name → subnet}
        self.domain_group_subnets: Dict[str, Dict[str, str]] = {}

    def get_nodes(self) -> Dict[str, NodeInfo]:
        print(f"\n{'='*80}")
        print("UNIVERSAL NETWORK GENERATOR - Starting Generation")
        print(f"{'='*80}")

        print("[Step 1/5] Generating domain nodes...")
        for domain_name in self.loader.get_all_domains():
            template = self.loader.get_domain_template(domain_name)
            self._generate_domain_nodes(domain_name, template)

        print("[Step 2/5] Ensuring minimum node count...")
        self._ensure_minimum_nodes()

        print("[Step 3/5] Applying constraints...")
        vuln_templates = self.domain_loader.config.get('vulnerabilities', [])
        constraint_engine = ConstraintEngine(
            nodes=self.all_nodes,
            domain_map=self.domain_node_map,
            group_map=self.group_node_map,
            gateways=self.domain_gateways,
            vulnerability_templates=vuln_templates,
            config=self.config
        )

        for domain in self.loader.get_all_domains():
            tmpl = self.loader.get_domain_template(domain)
            constraint_engine.apply_constraints(
                context_domain=domain,
                constraints=tmpl.constraints,
                is_inter_domain=False
            )

        constraint_engine.apply_constraints(
            context_domain=None,
            constraints=self.loader.get_inter_domain_constraints(),
            is_inter_domain=True
        )

        print("[Step 4/5] Applying vulnerabilities...")
        self.vuln_manager.apply_vulnerabilities(self.all_nodes, self.domain_node_map)

        print("[Solvability] Processing solvability constraints...")
        constraint_processor = SolvabilityConstraintProcessor(
            config=self.config,
            nodes=self.all_nodes,
            domain_map=self.domain_node_map,
            group_map=self.group_node_map
        )
        constraint_processor.process_all_constraints()

        print("[Step 5/5] Creating attacker node...")
        start_node = self.builder.create_attacker_node(
            self.loader.entry_points,
            self.all_nodes,
            self.domain_node_map,
            self.group_node_map
        )
        if start_node:
            self.all_nodes.update(start_node)

        print(f"{'='*80}")
        print("GENERATION COMPLETE")
        print(f"Total nodes: {len(self.all_nodes)}")
        print(f"{'='*80}\n")

        post_processor = SolvabilityPostProcessor(
            nodes=self.all_nodes,
            config=self.config
        )
        post_processor.ensure_solvability()
        goal_cfg = self.config.get('config', {}).get('goal_config', {})
        if goal_cfg.get('num_goals'):
            normalizer = GoalNormalizer(
                nodes=self.all_nodes,
                config=self.config,
                num_goals=goal_cfg['num_goals']
            )
            normalizer.normalize()
        for node in self.all_nodes.values():
            for vuln_name,vuln in node.vulnerabilities.items():
                try:
                    for prop in vuln.outcome.discovered_properties:
                        if prop not in node.properties:
                            node.properties.append(prop)
                except Exception as e:
                    ...

        return self.all_nodes

    def _generate_domain_nodes(self, domain_name: str, template):
        domain_subnet = self.domain_subnets.get(domain_name)
        if not domain_subnet:
            return
        if domain_name not in self.domain_node_map:
            self.domain_node_map[domain_name] = []
        if not template.groups:
            return

        # Assign per-group /24 subnets carved from the domain block
        group_subnets = self.utils.get_group_subnets(domain_subnet, template.groups)
        self.domain_group_subnets[domain_name] = group_subnets

        print(f"  Generating nodes for domain: {domain_name} ({domain_subnet})")
        for group in template.groups:
            subnet = group_subnets.get(group['name'], domain_subnet)
            count = self.utils.resolve_count(group)
            print(f"    Group '{group['name']}': {count} nodes on {subnet}")
            for i in range(count):
                if self._check_limit():
                    break
                node_id, node_info = self.builder.create_node(
                    domain_name=domain_name,
                    subnet=subnet,
                    group_config=group,
                    instance_num=i + 1,
                    global_counter=self.node_counter,
                    gateway_ip=self.domain_gateways.get(domain_name)
                )
                setattr(node_info, 'domain', domain_name)
                setattr(node_info, 'group', group['name'])
                setattr(node_info, 'name', node_id)
                self._register_node(node_id, node_info, domain_name, group['name'])

    def _ensure_minimum_nodes(self):
        cfg = self.config['config']
        max_nodes = cfg.get('max_total_nodes', 100)
        min_nodes = cfg.get('min_total_nodes', 1)

        # If no domain defines a filler list, node count is determined entirely
        # by the random per-group sampling already done.  Still enforce the hard
        # minimum so we never return 0 nodes.
        has_filler = any(
            self.loader.get_domain_template(d) and self.loader.get_domain_template(d).filler
            for d in self.loader.get_all_domains()
        )
        if not has_filler:
            print(f"  No filler defined — node count determined by group sampling "
                  f"(current: {len(self.all_nodes)})")
            # Still enforce the hard minimum using any available service as filler
            self._enforce_hard_minimum(min_nodes, max_nodes)
            return

        # At least one domain has filler: randomly pick a target between
        # min_total_nodes and max_total_nodes (minus 1 slot for the attacker node).
        current = len(self.all_nodes)
        lo = max(min_nodes - 1, current)
        hi = max_nodes - 1
        target = random.randint(lo, hi) if lo < hi else hi
        print(f"  Filling nodes up to {target} (currently {current})")

        consecutive_failures = 0
        while len(self.all_nodes) < target:
            domain = self.utils.pick_filler_domain(self.loader)
            if not domain:
                break
            service = self.utils.pick_filler_service(self.loader, domain)
            subnet = self._get_filler_subnet(domain, service)
            if not subnet:
                break
            try:
                node_id, node_info = self.builder.create_filler_node(
                    domain_name=domain,
                    subnet=subnet,
                    service_name=service,
                    global_counter=self.node_counter,
                    gateway_ip=self.domain_gateways.get(domain)
                )
            except Exception as e:
                consecutive_failures += 1
                print(f"  [Warning] Filler node creation failed for service "
                      f"'{service}': {e}")
                if consecutive_failures >= 10:
                    print("  [Warning] Too many consecutive filler failures — stopping.")
                    break
                continue
            consecutive_failures = 0
            setattr(node_info, 'domain', domain)
            setattr(node_info, 'group', 'Filler')
            setattr(node_info, 'name', node_id)
            self._register_node(node_id, node_info, domain, "Filler")

        # Hard minimum: even if filler failed partway, ensure we meet min_nodes
        self._enforce_hard_minimum(min_nodes, max_nodes)

    def _get_filler_subnet(self, domain: str, service: str) -> str:
        """Return the subnet for a filler node.

        Looks up which group uses the requested service and returns that
        group's /24 subnet.  Falls back to the first available group subnet,
        then the domain-level block.
        """
        group_subnets = self.domain_group_subnets.get(domain, {})
        template = self.loader.get_domain_template(domain)
        if template and template.groups and group_subnets:
            for group in template.groups:
                if group.get('service') == service:
                    return group_subnets.get(group['name'],
                                             self.domain_subnets.get(domain))
            # Service not matched — use first group's subnet
            return next(iter(group_subnets.values()))
        return self.domain_subnets.get(domain)

    def _enforce_hard_minimum(self, min_nodes: int, max_nodes: int):
        """
        Guarantee at least min_nodes total nodes.  If filler or group sampling
        produced fewer, create additional nodes from whatever services are
        available until the minimum is met.
        """
        if len(self.all_nodes) >= min_nodes:
            return

        print(f"  [Hard minimum] Only {len(self.all_nodes)} nodes — "
              f"forcing up to minimum {min_nodes}")

        domains = self.loader.get_all_domains()
        services = list(self.loader.services.keys())
        if not domains or not services:
            return

        import itertools
        service_cycle = itertools.cycle(services)
        domain_cycle = itertools.cycle(domains)

        while len(self.all_nodes) < min_nodes:
            domain = next(domain_cycle)
            service = next(service_cycle)
            subnet = self._get_filler_subnet(domain, service)
            if not subnet:
                continue
            try:
                node_id, node_info = self.builder.create_filler_node(
                    domain_name=domain,
                    subnet=subnet,
                    service_name=service,
                    global_counter=self.node_counter,
                    gateway_ip=self.domain_gateways.get(domain)
                )
            except Exception:
                continue
            setattr(node_info, 'domain', domain)
            setattr(node_info, 'group', 'Filler')
            setattr(node_info, 'name', node_id)
            self._register_node(node_id, node_info, domain, "Filler")

    def _register_node(self, node_id, node_info, domain, group):
        self.all_nodes[node_id] = node_info
        if domain not in self.domain_node_map:
            self.domain_node_map[domain] = []
        self.domain_node_map[domain].append(node_id)
        if group not in self.group_node_map:
            self.group_node_map[group] = []
        self.group_node_map[group].append(node_id)
        self.node_counter += 1

    def _check_limit(self) -> bool:
        # Reserve 1 slot for the attacker/start node so total reaches exactly max_total_nodes
        max_nodes = self.config['config'].get('max_total_nodes', 100)
        return len(self.all_nodes) >= max_nodes - 1

    def get_vulnerability_library(self):
        return {}

    def get_identifiers(self) -> Identifiers:
        """
        Build identifiers from YAML config.
        extract_identifiers() handles: services, identifiers section,
        vulnerabilities, probes, solvability vulns, start_node vulns.
        This method only supplements with VulnerabilityManager-specific entries.
        """
        identifiers = self.utils.extract_identifiers(self.loader)

        # Supplement with VulnerabilityManager-specific identifiers
        # (these come from vulnerability_patterns or credential_bank config,
        # which are separate from the solvability/probe YAML sections)
        if self.vuln_manager.mode == "library":
            try:
                for vuln in self.vuln_manager.library.vulnerabilities:
                    target = (identifiers.remote_vulnerabilities if vuln.type == "REMOTE"
                              else identifiers.local_vulnerabilities)
                    if vuln.name not in target:
                        target.append(vuln.name)
            except Exception as e:
                print(f"[Identifiers] Warning: {e}")

        elif self.vuln_manager.mode == "credential_bank":
            try:
                local_v, remote_v = self.vuln_manager.get_vulnerability_identifiers()
                for v in local_v:
                    if v not in identifiers.local_vulnerabilities:
                        identifiers.local_vulnerabilities.append(v)
                for v in remote_v:
                    if v not in identifiers.remote_vulnerabilities:
                        identifiers.remote_vulnerabilities.append(v)
            except Exception as e:
                print(f"[Identifiers] Warning: {e}")
        # Use sets for O(1) membership checks instead of O(n) list scans
        props_set   = set(identifiers.properties)
        local_set   = set(identifiers.local_vulnerabilities)
        remote_set  = set(identifiers.remote_vulnerabilities)

        for node in self.all_nodes.values():
            props_set.update(node.properties)
            for vuln_name, vuln in node.vulnerabilities.items():
                if vuln.type == VulnerabilityType.LOCAL:
                    local_set.add(vuln_name)
                if vuln.type == VulnerabilityType.REMOTE:
                    remote_set.add(vuln_name)
                try:
                    props_set.update(vuln.outcome.discovered_properties)
                except Exception:
                    pass
        return Identifiers.from_dict({
            'properties': list(props_set),
            'local_vulnerabilities': list(local_set),
            'remote_vulnerabilities': list(remote_set),
            'ports': identifiers.ports  # ports are already handled by extract_identifiers
        })
        # identifiers.properties              = list(props_set)
        # identifiers.local_vulnerabilities   = list(local_set)
        # identifiers.remote_vulnerabilities  = list(remote_set)
        # return identifiers