from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path
from typing import Any

import yaml

from .model import ActionType, FirewallPermission, Privilege, ScenarioSpec, TransitionRole


def _outcome(transition) -> dict[str, Any]:
    if transition.action == ActionType.DISCOVER:
        return {"type": "leaked_nodes_id", "kwargs": {"nodes": [transition.target]}}
    if transition.action == ActionType.PROBE:
        return {
            "type": "probe_succeeded",
            "kwargs": {"discovered_properties": sorted(transition.prerequisites)},
        }
    if transition.action == ActionType.REMOTE_EXPLOIT:
        return {"type": "lateral_move", "kwargs": {}}
    if transition.action == ActionType.LEAK_CREDENTIAL:
        return {
            "type": "leaked_credentials",
            "kwargs": {"credentials": [{
                "type": "cached_credentials",
                "kwargs": {
                    "node": transition.target,
                    "port": transition.service or "",
                    "credential": transition.credential,
                },
            }]},
        }
    if transition.action == ActionType.ESCALATE:
        level = {Privilege.USER: 1, Privilege.ADMIN: 2, Privilege.SYSTEM: 3}[
            transition.grants_privilege
        ]
        return {"type": "privilege_escalation", "kwargs": {"level": level}}
    raise ValueError(f"No vulnerability outcome for {transition.action}")


def _vulnerability(transition) -> dict[str, Any]:
    local = transition.action in {
        ActionType.DISCOVER, ActionType.LEAK_CREDENTIAL, ActionType.ESCALATE,
    }
    return {
        "description": f"Object-generator transition: {transition.source} -> {transition.target}",
        "type": 2 if local else 3,
        "outcome": _outcome(transition),
        "precondition": {
            "expression": "|".join(sorted(transition.prerequisites))
            if transition.prerequisites else "true"
        },
        "rates": {
            "probingDetectionRate": 0.0,
            "exploitDetectionRate": 0.0,
            "successRate": transition.success_rate,
        },
        "URL": "",
        "cost": 1.0,
        "reward_string": transition.vulnerability,
    }


def compile_nodes(spec: ScenarioSpec) -> dict[str, dict[str, Any]]:
    """Compile a validated ScenarioSpec into existing per-node YAML dictionaries."""
    zones = sorted({node.zone for node in spec.nodes.values()})
    subnet_for = {zone: f"10.{index + 1}.0.0/24" for index, zone in enumerate(zones)}
    counters = {zone: 10 for zone in zones}
    compiled: dict[str, dict[str, Any]] = {}

    for node_id, node in spec.nodes.items():
        network = ipaddress.ip_network(subnet_for[node.zone])
        ip = str(network.network_address + counters[node.zone])
        counters[node.zone] += 1
        compiled[node_id] = {
            "services": [
                {"name": svc.name, "port": None,
                 "allowedCredentials": list(svc.credentials), "running": True}
                for svc in node.services.values()
            ],
            "vulnerabilities": {},
            "value": node.value,
            "network_info": [{
                "ip_address": ip,
                "subnet": {"network": subnet_for[node.zone], "name": node.zone},
                "interface": "eth0",
            }],
            "properties": sorted(node.properties),
            "firewall": {"outgoing": [], "incoming": []},
            "agent_installed": False,
            "privilege_level": 0,
            "reimagable": True,
            "owned_string": "",
            "status": 1,
            "last_reimaging": None,
            "sla_weight": 1.0,
            "is_goal": node.is_goal or node_id == spec.goal.node,
            "image": node.template,
        }

    compiled["start"] = {
        "services": [], "vulnerabilities": {}, "value": 0,
        "network_info": [{
            "ip_address": "192.0.2.10",
            "subnet": {"network": "192.0.2.0/24", "name": "external"},
            "interface": "eth0",
        }],
        "properties": ["breach_node"],
        "firewall": {"outgoing": [], "incoming": []},
        "agent_installed": True, "privilege_level": 3, "reimagable": False,
        "owned_string": "Attacker foothold", "status": 1,
        "last_reimaging": None, "sla_weight": 0.0, "is_goal": False, "image": "attacker",
    }

    if spec.initial_state.discovered:
        compiled["start"]["vulnerabilities"]["Initial.Discovery"] = {
            "description": "Initially visible nodes", "type": 2,
            "outcome": {"type": "leaked_nodes_id", "kwargs": {
                "nodes": sorted(spec.initial_state.discovered)
            }},
            "precondition": {"expression": "true"},
            "rates": {"probingDetectionRate": 0.0, "exploitDetectionRate": 0.0, "successRate": 1.0},
            "URL": "", "cost": 0.0, "reward_string": "Initial discovery",
        }

    for index, transition in enumerate(spec.transitions):
        if transition.role == TransitionRole.BLOCKED:
            continue
        if transition.action == ActionType.CONNECT:
            source = compiled[transition.source]
            target = compiled[transition.target]
            source_subnet = source["network_info"][0]["subnet"]
            target_subnet = target["network_info"][0]["subnet"]
            source["firewall"]["outgoing"].append({
                "port": transition.service, "reason": transition.vulnerability,
                "permission": 0, "subnet": target_subnet, "priority": 1,
            })
            target["firewall"]["incoming"].append({
                "port": transition.service, "reason": transition.vulnerability,
                "permission": 0, "subnet": source_subnet, "priority": 1,
            })
            continue
        owner = transition.target if transition.action == ActionType.REMOTE_EXPLOIT else transition.source
        vuln_id = transition.vulnerability
        if vuln_id in compiled[owner]["vulnerabilities"]:
            vuln_id = f"{vuln_id}_{index}"
        compiled[owner]["vulnerabilities"][vuln_id] = _vulnerability(transition)

    # Materialize explicit deny policies. ALLOW policies used by Connect were
    # emitted above with the exact source/target node pair.
    for policy in spec.firewall_policies:
        if policy.permission != FirewallPermission.BLOCK:
            continue
        source_nodes = [n for n in spec.nodes.values() if n.zone == policy.source_zone]
        target_nodes = [n for n in spec.nodes.values() if n.zone == policy.target_zone]
        for source_node in source_nodes:
            for target_node in target_nodes:
                source_subnet = compiled[source_node.id]["network_info"][0]["subnet"]
                compiled[target_node.id]["firewall"]["incoming"].append({
                    "port": policy.service, "reason": "DSL explicit block",
                    "permission": 1, "subnet": source_subnet, "priority": 1,
                })
    return compiled


def compile_identifiers(nodes: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """Derive the exact identifier vocabulary consumed by CyberBattleSim.

    Keeping this derived from the compiled nodes prevents the runtime catalog
    from drifting away from renamed duplicate vulnerabilities or added node
    properties.
    """
    properties: set[str] = set()
    ports: set[str] = set()
    local_vulnerabilities: set[str] = set()
    remote_vulnerabilities: set[str] = set()
    for node in nodes.values():
        properties.update(node.get("properties", ()))
        ports.update(service["name"] for service in node.get("services", ()))
        for vulnerability_id, vulnerability in node.get("vulnerabilities", {}).items():
            if vulnerability.get("type") == 2:
                local_vulnerabilities.add(vulnerability_id)
            elif vulnerability.get("type") == 3:
                remote_vulnerabilities.add(vulnerability_id)
    return {
        "properties": sorted(properties),
        "ports": sorted(ports),
        "local_vulnerabilities": sorted(local_vulnerabilities),
        "remote_vulnerabilities": sorted(remote_vulnerabilities),
    }


def write_compiled_scenario(spec: ScenarioSpec, output_dir: Path) -> Path:
    scenario_dir = output_dir / spec.name
    nodes_dir = scenario_dir / "nodes"
    identifiers_dir = scenario_dir / "identifiers"
    vulnerability_dir = scenario_dir / "vulnerability_library"
    nodes_dir.mkdir(parents=True, exist_ok=True)
    identifiers_dir.mkdir(parents=True, exist_ok=True)
    vulnerability_dir.mkdir(parents=True, exist_ok=True)
    nodes = compile_nodes(spec)
    for node_id, data in nodes.items():
        with (nodes_dir / f"{node_id}.yaml").open("w", encoding="utf-8") as stream:
            yaml.safe_dump(data, stream, sort_keys=False, allow_unicode=False)
    with (identifiers_dir / "identifiers.yaml").open("w", encoding="utf-8") as stream:
        yaml.safe_dump(compile_identifiers(nodes), stream, sort_keys=False, allow_unicode=False)
    with (vulnerability_dir / "vulnerability_library.yaml").open("w", encoding="utf-8") as stream:
        # Object-generator vulnerabilities are node-local, but the runtime
        # loader requires the global library artifact to exist.
        yaml.safe_dump({}, stream, sort_keys=False)
    digest = hashlib.sha256(
        yaml.safe_dump(spec.to_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()
    (scenario_dir / "scenario.sha256").write_text(digest + "\n", encoding="ascii")
    return scenario_dir
