"""
Firewall-rule helpers, shared by SolvabilityPostProcessor and (eventually)
SolvabilityConstraintProcessor. Plain functions — no class/self state.
"""

from typing import Dict

from cyberbattle.simulation.firewall import FirewallRule, RulePermission


def existing_ports(rules) -> set:
    return {str(getattr(r, 'port', '')) for r in rules}


def open_firewall_for_cred(nodes: Dict, src_id: str, dst_id: str) -> None:
    """Add bidirectional firewall rules so src can reach dst via its services.

    Called whenever a credential leak is placed so agents can actually use
    the leaked credentials. Rules are added only if not already present.
    """
    if src_id not in nodes or dst_id not in nodes:
        return
    src_node = nodes[src_id]
    dst_node = nodes[dst_id]
    src_ni = getattr(src_node, 'network_info', [])
    dst_ni = getattr(dst_node, 'network_info', [])
    if not src_ni or not dst_ni:
        return
    src_subnet = src_ni[0].subnet
    dst_subnet = dst_ni[0].subnet

    src_out_ports = existing_ports(getattr(src_node.firewall, 'outgoing', []))
    dst_in_ports = existing_ports(getattr(dst_node.firewall, 'incoming', []))

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
