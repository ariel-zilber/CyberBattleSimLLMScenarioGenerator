"""
Entry-point routing and access guarantees (SolvabilityPostProcessor).
Extracted verbatim from solvability_post_processor.py.
"""

from typing import Dict, List

from pipeline.cbsim.components.solvability.post_processor.remote_access import add_remote_vulnerability
from pipeline.cbsim.components.solvability.post_processor.discovery import add_discovery_vulnerability
from pipeline.cbsim.components.solvability.post_processor.credential_chain import (
    add_credential_leak_vulnerability,
)


def ensure_external_routing(nodes: Dict, fixes_applied: List[str]) -> None:
    """
    Ensure the 'start' node (External) can route to all internal subnets.
    Fixes the 0% solve rate caused by disconnected subnets (Q38).
    """
    start_node = nodes.get('start')
    if not start_node:
        return

    # 1. Collect all unique internal subnets
    internal_subnets = set()
    for nid, node in nodes.items():
        if nid == 'start':
            continue
        ni_list = getattr(node, 'network_info', [])
        for ni in ni_list:
            subnet = getattr(ni, 'subnet', None)
            if subnet:
                # networkx/Simulation subnet objects have a 'network' string
                net_str = getattr(subnet, 'network', str(subnet))
                if net_str and net_str != "0.0.0.0/0":
                    internal_subnets.add(net_str)

    if not internal_subnets:
        return

    # 2. Add outgoing wildcard rules to start node for each subnet
    fw = getattr(start_node, 'firewall', None)
    if not fw:
        return

    from cyberbattle.simulation.firewall import RulePermission, FirewallRule
    from cyberbattle.simulation.network import Subnet

    existing_nets = {r.subnet.network for r in fw.outgoing if hasattr(r.subnet, 'network')}

    for net_str in internal_subnets:
        if net_str not in existing_nets:
            fw.outgoing.append(FirewallRule(
                port="*",
                permission=RulePermission.ALLOW,
                subnet=Subnet(net_str)
            ))
            fixes_applied.append(f"Bridged subnet: External → {net_str}")


def ensure_entry_point_access(
    nodes: Dict,
    config: Dict,
    entry_node_ids: set,
    remote_templates: List[Dict],
    discovery_templates: List[Dict],
    cred_leak_templates: List[Dict],
    attack_flow: List[Dict],
    reachable_cache: Dict,
    find_node_fn,
    find_first_node_in_domain_fn,
    should_place_fn,
    check_planned_fn,
    get_vulnerability_cost_fn,
    fixes_applied: List[str],
) -> None:
    """Ensure the ACTUAL entry nodes (the ones start node targets) have
    remote access + discovery + credential leak vulns. Uses entry_node_ids
    derived from the start node's leaked credentials."""

    # Use the actual entry nodes identified from start node
    targets = list(entry_node_ids)

    # Fallback if none identified (start node hasn't been created yet)
    if not targets:
        entry_points = config.get('entry_points', [])
        if entry_points:
            ep = entry_points[0]
            node_name = ep.get('node')
            nid = (find_node_fn(node_name) if node_name
                   else find_first_node_in_domain_fn(ep.get('domain')))
            if nid:
                targets = [nid]

    # Ultimate fallback: first non-start node
    if not targets:
        for nid in nodes:
            if nid != 'start':
                targets = [nid]
                break

    for node_id in targets:
        if node_id not in nodes:
            continue
        node = nodes[node_id]
        # Entry points ALWAYS get these — ignore probability
        add_remote_vulnerability(
            nodes, node, node_id, remote_templates,
            should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
            force=True,
        )
        add_discovery_vulnerability(
            nodes, node, node_id, discovery_templates,
            should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
            force=True,
        )
        add_credential_leak_vulnerability(
            nodes, node, node_id, cred_leak_templates, attack_flow, reachable_cache,
            should_place_fn, check_planned_fn, get_vulnerability_cost_fn, fixes_applied,
            force=True,
        )
