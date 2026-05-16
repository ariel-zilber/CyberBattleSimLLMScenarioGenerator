# domain/components/network_utils.py
# ZERO hardcoded identifier lists. All ports, properties, and vulnerability
# names are read from YAML config sections.

import ipaddress
import random
from typing import Dict, List, Set, Optional
from cyberbattle.simulation.identifiers import Identifiers


class NetworkUtils:
    """Utility functions for network generation."""

    @staticmethod
    def generate_credential_id(node_name: str, port_name: str) -> str:
        """Generate a unique credential ID for a node+port combination."""
        return f"{node_name}_{port_name}"

    @staticmethod
    def generate_ip(subnet: str, counter: int) -> str:
        """Generate an IP address within a subnet."""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            # Avoid list(network.hosts()) — O(n) memory for large subnets
            net_int = int(network.network_address)
            bcast_int = int(network.broadcast_address)
            host_int = net_int + 1 + counter
            host_int = min(host_int, bcast_int - 1)
            return str(ipaddress.ip_address(host_int))
        except Exception:
            return f"10.0.0.{counter}"

    @staticmethod
    def calculate_domain_subnets(domain_names: List[str],
                                  yaml_subnets: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Assign subnets to domains.

        Uses YAML-defined subnet when available; falls back to auto-generated
        10.{i}.0.0/16 blocks.
        """
        subnets = {}
        for i, name in enumerate(domain_names):
            if yaml_subnets and name in yaml_subnets and yaml_subnets[name]:
                subnets[name] = yaml_subnets[name]
            else:
                subnets[name] = f"10.{i}.0.0/16"
        return subnets

    @staticmethod
    def calculate_domain_gateways(domain_names: List[str],
                                   domain_subnets: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Assign gateway IPs to domains (first usable host in each subnet)."""
        gateways = {}
        for i, name in enumerate(domain_names):
            subnet_str = (domain_subnets or {}).get(name, f"10.{i}.0.0/16")
            try:
                network = ipaddress.ip_network(subnet_str, strict=False)
                net_int = int(network.network_address)
                bcast_int = int(network.broadcast_address)
                if net_int + 1 < bcast_int:
                    gateways[name] = str(ipaddress.ip_address(net_int + 1))
                else:
                    gateways[name] = f"10.{i}.0.1"
            except Exception:
                gateways[name] = f"10.{i}.0.1"
        return gateways

    @staticmethod
    def get_group_subnets(domain_subnet: str, groups: list) -> Dict[str, str]:
        """Carve per-group /24 subnets from a domain block.

        - Domain /16 (or larger): each group gets its own sequential /24.
        - Domain /24 (or smaller): all groups share the same subnet.
        - Groups may override with an explicit 'subnet' key.
        """
        result: Dict[str, str] = {}
        try:
            network = ipaddress.ip_network(domain_subnet, strict=False)
        except Exception:
            return {g['name']: domain_subnet for g in groups}

        if network.prefixlen >= 24:
            # Already a /24 or smaller — all groups share it
            return {g['name']: domain_subnet for g in groups}

        # Carve /24 blocks; skip index 0 (infrastructure/gateway range)
        try:
            subnets_24 = list(network.subnets(new_prefix=24))
        except Exception:
            return {g['name']: domain_subnet for g in groups}

        for idx, group in enumerate(groups):
            if 'subnet' in group:
                result[group['name']] = group['subnet']
            else:
                subnet_idx = min(idx + 1, len(subnets_24) - 1)
                result[group['name']] = str(subnets_24[subnet_idx])

        return result

    @staticmethod
    def resolve_count(group_config: Dict) -> int:
        """Resolve the node count for a group.

        Supports three YAML formats:
          min_count: 2          # separate top-level keys (preferred)
          max_count: 8
          ---
          count: 5              # scalar
          ---
          count:                # nested dict
            min: 2
            max: 8
        """
        # Preferred format: min_count / max_count as top-level keys
        if 'min_count' in group_config or 'max_count' in group_config:
            lo = int(group_config.get('min_count', 1))
            hi = int(group_config.get('max_count', lo))
            return random.randint(lo, hi)
        # Legacy formats: count: N  or  count: {min: N, max: M}
        count = group_config.get('count', 1)
        if isinstance(count, dict):
            lo = count.get('min', 1)
            hi = count.get('max', lo)
            return random.randint(lo, hi)
        return int(count)

    @staticmethod
    def pick_filler_domain(loader) -> Optional[str]:
        """Pick a random domain that has a non-empty filler list."""
        domains = [
            d for d in loader.get_all_domains()
            if loader.get_domain_template(d) and loader.get_domain_template(d).filler
        ]
        return random.choice(domains) if domains else None

    @staticmethod
    def pick_filler_service(loader, domain: str) -> str:
        """Pick a random service from the domain's filler list."""
        template = loader.get_domain_template(domain)
        filler = template.filler if (template and template.filler) else []
        if filler:
            return random.choice(filler)
        # Fallback: any service (only reached if called with a domain that has no filler)
        services = list(loader.services.keys())
        return random.choice(services) if services else 'Generic'

    @staticmethod
    def extract_identifiers(loader) -> Identifiers:
        """
        Build the global Identifiers object required by CyberBattleSim.
        ALL ports, properties, and vulnerability names come from YAML config.
        Nothing is hardcoded.

        Sources:
          1. services section — port names, service names, default_properties
          2. vulnerabilities section — vuln names and required_properties
          3. domain groups — service profile properties
          4. identifiers.standard_ports — from YAML (replaces hardcoded list)
          5. identifiers.base_properties — from YAML (replaces hardcoded list)
          6. probe_vulnerabilities — from YAML
          7. solvability_vulnerabilities — from YAML (all sub-keys)
          8. start_node.vulnerabilities — from YAML
        """
        # Access the raw YAML config dict
        config = getattr(loader, 'data', None) or getattr(loader, 'config', {})

        ports: Set[str] = set()
        properties: Set[str] = set()
        local_vulns: List[str] = []
        remote_vulns: List[str] = []

        # -----------------------------------------------------------------
        # 1. Scan Services (ServiceProfile objects)
        # -----------------------------------------------------------------
        for name, service in loader.services.items():
            if service.port:
                ports.add(str(service.port))
            # Service name itself is used as a port in CyberBattleSim
            ports.add(name)
            properties.update(service.default_properties)

        # -----------------------------------------------------------------
        # 2. Standard ports FROM YAML identifiers section
        # -----------------------------------------------------------------
        id_config = config.get('identifiers', {})
        for port in id_config.get('standard_ports', []):
            ports.add(str(port))

        # -----------------------------------------------------------------
        # 3. Base properties FROM YAML identifiers section
        # -----------------------------------------------------------------
        for prop in id_config.get('base_properties', []):
            properties.add(str(prop))

        # -----------------------------------------------------------------
        # 4. Scan vulnerabilities section (if present)
        # -----------------------------------------------------------------
        for vuln in getattr(loader, 'vulnerabilities', []) or []:
            properties.update(vuln.get('required_properties', []))
            v_type = str(vuln.get('type', '')).upper()
            v_name = vuln.get('name', '')
            if v_name:
                if v_type == "LOCAL" and v_name not in local_vulns:
                    local_vulns.append(v_name)
                elif v_type == "REMOTE" and v_name not in remote_vulns:
                    remote_vulns.append(v_name)

        # -----------------------------------------------------------------
        # 5. Scan domain groups for additional properties
        # -----------------------------------------------------------------
        for domain_name in loader.get_all_domains():
            template = loader.get_domain_template(domain_name)
            for group in template.groups or []:
                service_name = group.get('service')
                if service_name in loader.services:
                    properties.update(loader.services[service_name].default_properties)

        # -----------------------------------------------------------------
        # 6. Probe vulnerabilities FROM YAML
        # -----------------------------------------------------------------
        for probe in config.get('probe_vulnerabilities', []):
            name = probe.get('name')
            if not name:
                continue
            vtype = probe.get('type', 'REMOTE').upper()
            if vtype == 'REMOTE' and name not in remote_vulns:
                remote_vulns.append(name)
            elif vtype == 'LOCAL' and name not in local_vulns:
                local_vulns.append(name)

        # -----------------------------------------------------------------
        # 7. Solvability vulnerabilities FROM YAML (all sub-keys)
        # -----------------------------------------------------------------
        for _category, vuln_list in config.get('solvability_vulnerabilities', {}).items():
            if not isinstance(vuln_list, list):
                continue
            for vdef in vuln_list:
                name = vdef.get('name')
                if not name:
                    continue
                vtype = vdef.get('type', 'LOCAL').upper()
                if vtype == 'REMOTE' and name not in remote_vulns:
                    remote_vulns.append(name)
                elif name not in local_vulns:
                    local_vulns.append(name)

        # -----------------------------------------------------------------
        # 7b. Constraint vulnerabilities FROM YAML
        #     (leak_known_credentials, leak_neighbors, etc.)
        # -----------------------------------------------------------------
        for _key, vdef in config.get('constraint_vulnerabilities', {}).items():
            if not isinstance(vdef, dict):
                continue
            name = vdef.get('name')
            if not name:
                continue
            vtype = vdef.get('type', 'LOCAL').upper()
            if vtype == 'REMOTE' and name not in remote_vulns:
                remote_vulns.append(name)
            elif name not in local_vulns:
                local_vulns.append(name)

        # -----------------------------------------------------------------
        # 8. Start node vulnerabilities FROM YAML
        # -----------------------------------------------------------------
        for _key, vdef in config.get('start_node', {}).get('vulnerabilities', {}).items():
            if not isinstance(vdef, dict):
                continue
            name = vdef.get('name')
            if not name:
                continue
            vtype = vdef.get('type', 'LOCAL').upper()
            if vtype == 'REMOTE' and name not in remote_vulns:
                remote_vulns.append(name)
            elif name not in local_vulns:
                local_vulns.append(name)

        # -----------------------------------------------------------------
        # 9. OS management ports FROM YAML
        # -----------------------------------------------------------------
        for _os, port in config.get('os_management_ports', {}).items():
            if port and port != 'default':
                ports.add(str(port))

        # -----------------------------------------------------------------
        # 10. Start node properties FROM YAML
        # -----------------------------------------------------------------
        for prop in config.get('start_node', {}).get('properties', []):
            properties.add(str(prop))

        return Identifiers(
            properties=sorted(properties),
            ports=sorted(ports),
            local_vulnerabilities=local_vulns,
            remote_vulnerabilities=remote_vulns
        )