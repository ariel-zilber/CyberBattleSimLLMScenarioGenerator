from __future__ import annotations

from dataclasses import dataclass

from .model import ActionType


@dataclass(frozen=True)
class NodeTemplate:
    name: str
    properties: frozenset[str]
    services: frozenset[str]


@dataclass(frozen=True)
class SpecialistProfile:
    name: str
    actions: frozenset[ActionType]
    services: frozenset[str]
    target_templates: frozenset[str]


NODE_TEMPLATES = {
    t.name: t for t in (
        NodeTemplate("linux_gateway", frozenset({"Linux", "Gateway", "NetworkDevice"}), frozenset({"SSH", "HTTPS"})),
        NodeTemplate("linux_server", frozenset({"Linux", "Server"}), frozenset({"SSH", "HTTPS"})),
        NodeTemplate("windows_workstation", frozenset({"Windows", "Workstation", "DomainJoined"}), frozenset({"RDP", "SMB"})),
        NodeTemplate("windows_server", frozenset({"Windows", "Server", "DomainJoined"}), frozenset({"RDP", "SMB", "WinRM"})),
        NodeTemplate("domain_controller", frozenset({"Windows", "DomainController", "DomainJoined"}), frozenset({"LDAP", "Kerberos", "SMB"})),
        NodeTemplate("database", frozenset({"Linux", "Database"}), frozenset({"SSH", "SQL"})),
        NodeTemplate("firewall", frozenset({"Linux", "Firewall", "NetworkDevice"}), frozenset({"SSH", "HTTPS", "SNMP"})),
        NodeTemplate("router", frozenset({"Linux", "Router", "NetworkDevice"}), frozenset({"SSH", "SNMP"})),
        NodeTemplate("cicd_runner", frozenset({"Linux", "CICDRunner"}), frozenset({"SSH", "HTTPS"})),
        NodeTemplate("cloud_workload", frozenset({"Linux", "CloudWorkload"}), frozenset({"SSH", "HTTPS"})),
    )
}


def _actions(*values: ActionType) -> frozenset[ActionType]:
    return frozenset(values)


SPECIALISTS = {
    p.name: p for p in (
        SpecialistProfile("s_network", _actions(ActionType.DISCOVER, ActionType.PROBE, ActionType.REMOTE_EXPLOIT),
                          frozenset({"SSH", "HTTPS", "SNMP"}), frozenset({"linux_gateway", "firewall", "router"})),
        SpecialistProfile("s_linux", _actions(ActionType.DISCOVER, ActionType.REMOTE_EXPLOIT, ActionType.LEAK_CREDENTIAL,
                                               ActionType.CONNECT, ActionType.ESCALATE),
                          frozenset({"SSH", "HTTPS", "SQL"}),
                          frozenset({"linux_gateway", "linux_server", "database", "cicd_runner", "cloud_workload"})),
        SpecialistProfile("s_windows", _actions(ActionType.DISCOVER, ActionType.REMOTE_EXPLOIT, ActionType.LEAK_CREDENTIAL,
                                                 ActionType.CONNECT, ActionType.ESCALATE),
                          frozenset({"RDP", "SMB", "WinRM"}),
                          frozenset({"windows_workstation", "windows_server", "domain_controller"})),
        SpecialistProfile("s_identity", _actions(ActionType.DISCOVER, ActionType.LEAK_CREDENTIAL,
                                                  ActionType.CONNECT, ActionType.ESCALATE),
                          frozenset({"LDAP", "Kerberos", "SMB", "RDP"}),
                          frozenset({"windows_workstation", "windows_server", "domain_controller"})),
        SpecialistProfile("s_lateral", _actions(ActionType.DISCOVER, ActionType.REMOTE_EXPLOIT,
                                                 ActionType.LEAK_CREDENTIAL, ActionType.CONNECT),
                          frozenset({"SSH", "RDP", "SMB", "WinRM", "LDAP", "Kerberos", "HTTPS"}),
                          frozenset(NODE_TEMPLATES)),
    )
}


def validate_catalogs() -> list[str]:
    errors = []
    for name, profile in SPECIALISTS.items():
        missing = profile.target_templates - NODE_TEMPLATES.keys()
        if missing:
            errors.append(f"{name}: unknown target templates {sorted(missing)}")
        if not profile.actions:
            errors.append(f"{name}: no actions")
    return errors
