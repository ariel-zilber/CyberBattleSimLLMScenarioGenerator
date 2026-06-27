#!/usr/bin/env python3
"""
coverage_fix.py — Patch specialist vocabulary coverage in generated scenarios.

Problem: generated scenarios have avg 9.1 unique vulns / 50 specialist action slots.
Most specialist exploit slots are runtime-invalid (env_idx == -1), so Q-network
receives zero gradient for those actions.

Fix: for each node, check if any specialist vuln's match_properties ⊆ node.properties.
If match and vuln absent → inject vuln into node YAML + add to identifiers.yaml.

After running this script, regenerate PKL files:
  python -m cyberbattle.training.preprocess_scenarios \\
      --meta-root <dataset_root> --workers 4 --overwrite

Usage:
  python coverage_fix.py --dataset output_specialists_final
  python coverage_fix.py --dataset output_specialists_final --dry-run
  python coverage_fix.py --dataset output_specialists_final --report-only
"""

import argparse
import copy
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml


# ── Device-role property tokens (OR semantics in match sets) ─────────────────
# A node matches if it has at least ONE device-role token from the match set
# AND ALL non-device-role tokens from the match set.
DEVICE_ROLE_PROPS: Set[str] = {
    "Router", "Switch", "Firewall", "LoadBalancer", "Workstation",
    "DomainController", "FileServer", "WebServer", "DatabaseServer",
    "MailServer", "AppServer", "AuthServer", "WorkerNode", "PrintServer",
    "MSMQServer", "HyperVHost", "DNSServer", "IISServer",
}

# ── Outcome type heuristic based on vuln name patterns ───────────────────────
CRED_DUMP_KEYWORDS = {
    "Dump", "Creds", "Secret", "NoAuth", "ConfigLeak", "DataSource",
    "AdminCreds", "EnvVar", "PrivKey", "Token", "ConfigBackup", "Exfil",
    "Password", "CommunityDump", "Connections", "AAA", "Backup",
}
DISCOVERY_KEYWORDS = {"Recon", "Enum", "Scan", "Walk", "Neighbors", "ZoneTransfer"}
LATERAL_KEYWORDS   = {"Relay", "Exec_Hash", "Exec_Ticket"}


def _infer_outcome(vuln_name: str) -> Tuple[str, dict]:
    """Return (outcome_type_str, kwargs_dict) for a vuln based on its name."""
    short = vuln_name.replace("Solvability.", "")
    for kw in LATERAL_KEYWORDS:
        if kw in short:
            return "lateral_move", {}
    for kw in DISCOVERY_KEYWORDS:
        if kw in short:
            return "leaked_nodes_id", {"nodes": []}
    for kw in CRED_DUMP_KEYWORDS:
        if kw in short:
            return "leaked_credentials", {"credentials": []}
    # Default: privilege escalation (covers RCE, EOP, Escape, PrivEsc, etc.)
    return "privilege_escalation", {"level": 2}


# ── Per-specialist vuln lists (from global_vocabulary.yaml) ──────────────────
# local/remote keys map to ordered lists matching the specialist's action slots.
SPECIALIST_VULNS: Dict[str, Dict[str, List[str]]] = {
    "S_Network": {
        "local": [
            "Solvability.PanOS_LocalRootEsc",
            "Solvability.CiscoNXOS_LocalBash",
            "Solvability.FortiGate_LocalCmdExec",
            "Solvability.PanOS_ConfigDump",
            "Solvability.EnablePassword_Crack",
            "Solvability.FortiGate_ConfigBackup",
            "Solvability.F5_AdminToken",
            "Solvability.JuniperJunos_ConfigExtract",
            "Solvability.CiscoNXOS_AAA_Secret",
            "Solvability.CiscoNXOS_CMDInject",
            "Solvability.CiscoNXOS_CMDInject2",
            "Solvability.CiscoNXOS_PrivEsc",
            "Solvability.JuniperJunos_AuthBypass",
            "Solvability.CiscoIOS_PhysicalBypass",
            "Solvability.SNMP_CommunityDump",
            "Solvability.NetworkDevice_DefaultCreds",
            "Solvability.ConfigBackup_Exfil",
            "Solvability.VLAN_Hop",
        ],
        "remote": [
            "Solvability.PanOS_CMDInject",
            "Solvability.FortiOS_SSLVPN_RCE",
            "Solvability.FortiOS_AuthBypass",
            "Solvability.CiscoASA_IKE_HeapOvf",
            "Solvability.CiscoASA_SSLVPN_Bypass",
            "Solvability.CiscoIOS_XE_PrivEsc",
            "Solvability.F5_BIGIP_AuthBypass",
            "Solvability.F5_BIGIP_RCE",
            "Solvability.Citrix_Bleed",
            "Solvability.Citrix_ADC_RCE",
            "Solvability.PanOS_TOCTOU",
            "Solvability.CiscoNXOS_LLDP",
            "Solvability.CiscoIOS_RPKI",
            "Solvability.Netgear_RCE",
        ],
    },
    "S_Linux": {
        "local": [
            "Solvability.Docker_Socket_Escape",
            "Solvability.Kubernetes_HostPID_Escape",
            "Solvability.Container_ProcMount_Escape",
            "Solvability.Redis_Noauth_Config_Rewrite",
            "Solvability.Hadoop_FileUtil_Inject",
            "Solvability.Bundler_DNSHijack",
            "Solvability.WordPressDB_Creds",
            "Solvability.Container_EnvVars",
            "Solvability.AWS_CredFile",
            "Solvability.VaultToken_EnvVar",
            "Solvability.KubeServiceAccount",
            "Solvability.MongoDB_NoAuth",
            "Solvability.Redis_NoAuth",
            "Solvability.Keycloak_AdminCreds",
            "Solvability.Kafka_ConfigLeak",
            "Solvability.Grafana_DataSource",
            "Solvability.Vault_Unsealed",
            "Solvability.Airflow_Connections",
            "Solvability.SSH_PrivKey_Theft",
        ],
        "remote": [
            "Solvability.Concourse_ContainerEscape",
            "Solvability.ApacheSpark_PrivEsc",
            "Solvability.SnakeYAML_Deserialization",
            "Solvability.ImageMagick_ShellInject",
            "Solvability.MySQL2_SQLInject_1",
            "Solvability.MySQL2_SQLInject_2",
            "Solvability.JavaDeserialize_RCE_1",
            "Solvability.JavaDeserialize_RCE_2",
            "Solvability.GhostCMS_CSV_Injection",
            "Solvability.ApacheAvro_Deserialization",
            "Solvability.LibSSH_OpenSSL_RCE",
            "Solvability.GoGoProtobuf_Deserialization",
            "Solvability.Zlib_IntOverflow",
            "Solvability.OpenEXR_OOB_Write",
            "Solvability.PgDump_UntrustedData",
            "Solvability.Elasticsearch_Groovy_RCE",
            "Solvability.NodeJS_IP_SSRF",
        ],
    },
    "S_Windows": {
        "local": [
            "Solvability.SeImpersonatePrivEsc",
            "Solvability.AlwaysInstallElevated",
            "Solvability.UnquotedServicePath",
            "Solvability.DLLHijacking_Windows",
            "Solvability.Schtasks_EOP_1",
            "Solvability.Schtasks_EOP_2",
            "Solvability.Schtasks_EOP_3",
            "Solvability.Schtasks_EOP_4",
            "Solvability.Mimikatz_NTLM",
            "Solvability.SAM_Dump",
            "Solvability.LSA_Secrets",
            "Solvability.HiveNightmare",
        ],
        "remote": [
            "Solvability.SMBGhost",
            "Solvability.MS08_067",
            "Solvability.SIGRed",
            "Solvability.BlueKeep",
            "Solvability.DejaBlue",
            "Solvability.RDP_RCE_1226",
            "Solvability.IIS_HTTP_Stack",
            "Solvability.IIS_RCE",
            "Solvability.TCPIP_RCE_1",
            "Solvability.TCPIP_RCE_2",
            "Solvability.NFS_RCE_TCPIP",
            "Solvability.HTTP3_RCE",
            "Solvability.DNS_RCE_1",
            "Solvability.RPC_RCE_2",
            "Solvability.WSD_RCE",
            "Solvability.iSCSI_RCE",
            "Solvability.ProxyShell",
            "Solvability.ProxyLogon",
            "Solvability.QueueJumper",
            "Solvability.HyperV_RCE",
            "Solvability.Follina",
        ],
    },
    "S_Identity": {
        "local": [
            "Solvability.PassTheHash",
            "Solvability.NTLM_Relay_LDAP",
            "Solvability.ZeroLogon",
            "Solvability.ConstrainedDelegation_S4U",
            "Solvability.RBCD_Attack",
            "Solvability.SilverTicket",
            "Solvability.TokenImpersonation",
            "Solvability.DCSync",
            "Solvability.NTDS_Dump",
            "Solvability.GoldenTicket",
            "Solvability.ADCS_ESC1",
            "Solvability.ADCS_ESC6",
            "Solvability.DCShadow",
            "Solvability.DSRM_Abuse",
            "Solvability.ADCS_ESC8",
        ],
        "remote": [
            "Solvability.ASREPRoasting",
            "Solvability.Kerberoasting",
            "Solvability.PrinterBug_Coercion",
            "Solvability.PetitPotam",
            "Solvability.UnconstrainedDelegation",
            "Solvability.ShadowCredentials",
            "Solvability.noPac",
            "Solvability.Certifried",
            "Solvability.ZeroLogon",
            "Solvability.AD_Services_EOP",
            "Solvability.NetNTLMv2_Downgrade",
            "Solvability.Kerberos_EOP_2",
            "Solvability.LSASS_EOP_AD",
            "Solvability.noPac_2",
            "Solvability.Kerberos_EOP",
            "Solvability.MSAA_Priv",
        ],
    },
    "S_Lateral": {
        "local": [
            "Solvability.Mimikatz_LSASS",
            "Solvability.LAPS_Password_Read",
            "Solvability.GPP_Password_Decryption",
            "Solvability.WinRM_Credential_Cache",
            "Solvability.PrintNightmare_LocalPrivEsc",
            "Solvability.PrintNightmare",
            "Solvability.SpoolSample_Coerce",
            "Solvability.Spooler_EOP_1",
            "Solvability.Spooler_RCE",
            "Solvability.Exchange_NTLM_Relay",
            "Solvability.PrivExchange",
            "Solvability.ProxyNotShell_NTLM",
            "Solvability.Exchange_RCE_Lateral_1",
            "Solvability.Exchange_RCE_Lateral_2",
            "Solvability.MSSQL_xpCmdshell",
            "Solvability.MSSQL_LinkedServer",
            "Solvability.MSSQL_RCE_Lateral",
            "Solvability.MSSQL_Privesc_Lateral",
            "Solvability.ShadowCredentials",
            "Solvability.RBCD_Write",
            "Solvability.LDAP_AuthBypass_Lateral",
            "Solvability.CloudIAM_LDAP_Write",
            "Solvability.ADCS_CertSpoof_Lateral",
            "Solvability.ADCS_EOP_Lateral",
            "Solvability.LSA_Relay",
            "Solvability.Outlook_NTLM_Relay",
            "Solvability.PetitPotam_Relay",
            "Solvability.Kerberoasting",
            "Solvability.ASREPRoasting",
            "Solvability.SpoolSample",
            "Solvability.CLFS_Privesc",
            "Solvability.Win_EOP_Cred",
            "Solvability.BloodHound_Recon",
            "Solvability.LDAP_Enum",
        ],
        "remote": [
            "Solvability.NTLM_Relay_SMB",
            "Solvability.NTLM_Relay_LDAP",
            "Solvability.WinRM_Exec_Hash",
            "Solvability.WinRM_Exec_Ticket",
        ],
    },
}

# ── Vulnerability catalog: name → (vuln_type, match_props, success_rate) ─────
# type: 2=LOCAL, 3=REMOTE
# match: set of properties required on node (device-role props use OR semantics)
VULN_CATALOG: Dict[str, Dict] = {
    # ── S_Network local ──────────────────────────────────────────────────────
    "Solvability.PanOS_LocalRootEsc":        {"type": 2, "match": {"PaloAlto", "PANOS"}, "rate": 0.70},
    "Solvability.CiscoNXOS_LocalBash":       {"type": 2, "match": {"Switch", "CiscoNXOS", "NetworkDevice"}, "rate": 0.75},
    "Solvability.FortiGate_LocalCmdExec":    {"type": 2, "match": {"Firewall", "FortiGate", "SSLVPN"}, "rate": 0.75},
    "Solvability.PanOS_ConfigDump":          {"type": 2, "match": {"PaloAlto", "PANOS"}, "rate": 0.70},
    "Solvability.EnablePassword_Crack":      {"type": 2, "match": {"Router", "CiscoIOS", "NetworkDevice"}, "rate": 0.60},
    "Solvability.FortiGate_ConfigBackup":    {"type": 2, "match": {"Firewall", "FortiGate"}, "rate": 0.65},
    "Solvability.F5_AdminToken":             {"type": 2, "match": {"LoadBalancer", "F5BIGIP"}, "rate": 0.70},
    "Solvability.JuniperJunos_ConfigExtract":{"type": 2, "match": {"Router", "JuniperJunos", "NetworkDevice"}, "rate": 0.65},
    "Solvability.CiscoNXOS_AAA_Secret":      {"type": 2, "match": {"Switch", "CiscoNXOS", "NetworkDevice"}, "rate": 0.70},
    "Solvability.CiscoNXOS_CMDInject":       {"type": 2, "match": {"Switch", "CiscoNXOS", "NetworkDevice"}, "rate": 0.75},
    "Solvability.CiscoNXOS_CMDInject2":      {"type": 2, "match": {"Switch", "CiscoNXOS", "NetworkDevice"}, "rate": 0.75},
    "Solvability.CiscoNXOS_PrivEsc":         {"type": 2, "match": {"Switch", "CiscoNXOS", "NetworkDevice"}, "rate": 0.60},
    "Solvability.JuniperJunos_AuthBypass":   {"type": 2, "match": {"Router", "JuniperJunos", "NetworkDevice"}, "rate": 0.65},
    "Solvability.CiscoIOS_PhysicalBypass":   {"type": 2, "match": {"Router", "CiscoIOS", "NetworkDevice"}, "rate": 0.65},
    "Solvability.SNMP_CommunityDump":        {"type": 2, "match": {"SNMP", "NetworkDevice"}, "rate": 0.70},
    "Solvability.NetworkDevice_DefaultCreds":{"type": 2, "match": {"NetworkDevice", "DefaultCredentials"}, "rate": 0.75},
    "Solvability.ConfigBackup_Exfil":        {"type": 2, "match": {"NetworkDevice"}, "rate": 0.65},
    "Solvability.VLAN_Hop":                  {"type": 2, "match": {"Switch", "VLAN", "NetworkDevice"}, "rate": 0.55},
    # ── S_Network remote ─────────────────────────────────────────────────────
    "Solvability.PanOS_CMDInject":           {"type": 3, "match": {"Firewall", "PaloAlto", "PANOS", "GlobalProtect"}, "rate": 0.90},
    "Solvability.FortiOS_SSLVPN_RCE":        {"type": 3, "match": {"Firewall", "FortiGate", "SSLVPN"}, "rate": 0.90},
    "Solvability.FortiOS_AuthBypass":        {"type": 3, "match": {"Firewall", "FortiGate", "SSLVPN"}, "rate": 0.90},
    "Solvability.CiscoASA_IKE_HeapOvf":     {"type": 3, "match": {"Firewall", "CiscoASA", "NetworkDevice"}, "rate": 0.85},
    "Solvability.CiscoASA_SSLVPN_Bypass":   {"type": 3, "match": {"Firewall", "CiscoASA", "NetworkDevice"}, "rate": 0.85},
    "Solvability.CiscoIOS_XE_PrivEsc":      {"type": 3, "match": {"Router", "CiscoIOS", "NetworkDevice"}, "rate": 0.90},
    "Solvability.F5_BIGIP_AuthBypass":       {"type": 3, "match": {"LoadBalancer", "F5BIGIP", "NetworkDevice"}, "rate": 0.90},
    "Solvability.F5_BIGIP_RCE":              {"type": 3, "match": {"LoadBalancer", "F5BIGIP", "NetworkDevice"}, "rate": 0.90},
    "Solvability.Citrix_Bleed":              {"type": 3, "match": {"LoadBalancer", "CitrixADC"}, "rate": 0.90},
    "Solvability.Citrix_ADC_RCE":            {"type": 3, "match": {"LoadBalancer", "CitrixADC"}, "rate": 0.90},
    "Solvability.PanOS_TOCTOU":              {"type": 3, "match": {"Firewall", "PaloAlto", "PANOS"}, "rate": 0.85},
    "Solvability.CiscoNXOS_LLDP":            {"type": 3, "match": {"Switch", "CiscoNXOS", "NetworkDevice"}, "rate": 0.65},
    "Solvability.CiscoIOS_RPKI":             {"type": 3, "match": {"Router", "CiscoIOS", "NetworkDevice"}, "rate": 0.85},
    "Solvability.Netgear_RCE":               {"type": 3, "match": {"Router", "NetworkDevice"}, "rate": 0.85},
    # ── S_Linux local ────────────────────────────────────────────────────────
    "Solvability.Docker_Socket_Escape":      {"type": 2, "match": {"Linux", "Docker"}, "rate": 0.80},
    "Solvability.Kubernetes_HostPID_Escape": {"type": 2, "match": {"Linux", "Kubernetes"}, "rate": 0.75},
    "Solvability.Container_ProcMount_Escape":{"type": 2, "match": {"Linux", "Docker"}, "rate": 0.70},
    "Solvability.Redis_Noauth_Config_Rewrite":{"type": 2, "match": {"Linux", "Redis"}, "rate": 0.80},
    "Solvability.Hadoop_FileUtil_Inject":    {"type": 2, "match": {"Linux", "Java"}, "rate": 0.65},
    "Solvability.Bundler_DNSHijack":         {"type": 2, "match": {"Linux", "AppServer"}, "rate": 0.55},
    "Solvability.WordPressDB_Creds":         {"type": 2, "match": {"Linux", "PHP", "WebServer"}, "rate": 0.75},
    "Solvability.Container_EnvVars":         {"type": 2, "match": {"Linux"}, "rate": 0.60},
    "Solvability.AWS_CredFile":              {"type": 2, "match": {"Linux"}, "rate": 0.65},
    "Solvability.VaultToken_EnvVar":         {"type": 2, "match": {"Linux", "AppServer"}, "rate": 0.65},
    "Solvability.KubeServiceAccount":        {"type": 2, "match": {"Linux", "Kubernetes"}, "rate": 0.70},
    "Solvability.MongoDB_NoAuth":            {"type": 2, "match": {"Linux", "MongoDB", "Misconfigured"}, "rate": 0.75},
    "Solvability.Redis_NoAuth":              {"type": 2, "match": {"Linux", "Redis", "Misconfigured"}, "rate": 0.80},
    "Solvability.Keycloak_AdminCreds":       {"type": 2, "match": {"Linux", "AuthServer"}, "rate": 0.65},
    "Solvability.Kafka_ConfigLeak":          {"type": 2, "match": {"Linux", "Java"}, "rate": 0.70},
    "Solvability.Grafana_DataSource":        {"type": 2, "match": {"Linux", "AppServer"}, "rate": 0.70},
    "Solvability.Vault_Unsealed":            {"type": 2, "match": {"Linux", "AppServer"}, "rate": 0.55},
    "Solvability.Airflow_Connections":       {"type": 2, "match": {"Linux", "Python"}, "rate": 0.65},
    "Solvability.SSH_PrivKey_Theft":         {"type": 2, "match": {"Linux", "SSH"}, "rate": 0.65},
    # ── S_Linux remote ───────────────────────────────────────────────────────
    "Solvability.Concourse_ContainerEscape": {"type": 3, "match": {"Linux", "AppServer"}, "rate": 0.90},
    "Solvability.ApacheSpark_PrivEsc":       {"type": 3, "match": {"Linux", "Java"}, "rate": 0.75},
    "Solvability.SnakeYAML_Deserialization": {"type": 3, "match": {"Linux", "Java"}, "rate": 0.75},
    "Solvability.ImageMagick_ShellInject":   {"type": 3, "match": {"Linux", "PHP", "WebServer"}, "rate": 0.90},
    "Solvability.MySQL2_SQLInject_1":        {"type": 3, "match": {"Linux", "MySQL"}, "rate": 0.85},
    "Solvability.MySQL2_SQLInject_2":        {"type": 3, "match": {"Linux", "MySQL"}, "rate": 0.85},
    "Solvability.JavaDeserialize_RCE_1":     {"type": 3, "match": {"Linux", "Java"}, "rate": 0.80},
    "Solvability.JavaDeserialize_RCE_2":     {"type": 3, "match": {"Linux", "Java"}, "rate": 0.80},
    "Solvability.GhostCMS_CSV_Injection":    {"type": 3, "match": {"Linux", "AppServer"}, "rate": 0.90},
    "Solvability.ApacheAvro_Deserialization":{"type": 3, "match": {"Linux", "Java"}, "rate": 0.75},
    "Solvability.LibSSH_OpenSSL_RCE":        {"type": 3, "match": {"Linux", "SSH"}, "rate": 0.80},
    "Solvability.GoGoProtobuf_Deserialization":{"type": 3, "match": {"Linux", "AppServer"}, "rate": 0.75},
    "Solvability.Zlib_IntOverflow":          {"type": 3, "match": {"Linux", "AppServer"}, "rate": 0.70},
    "Solvability.OpenEXR_OOB_Write":         {"type": 3, "match": {"Linux", "AppServer"}, "rate": 0.65},
    "Solvability.PgDump_UntrustedData":      {"type": 3, "match": {"Linux", "DatabaseServer"}, "rate": 0.75},
    "Solvability.Elasticsearch_Groovy_RCE":  {"type": 3, "match": {"Linux", "Java"}, "rate": 0.90},
    "Solvability.NodeJS_IP_SSRF":            {"type": 3, "match": {"Linux", "AppServer"}, "rate": 0.70},
    # ── S_Windows local ──────────────────────────────────────────────────────
    "Solvability.SeImpersonatePrivEsc":      {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.80},
    "Solvability.AlwaysInstallElevated":     {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.75},
    "Solvability.UnquotedServicePath":       {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.70},
    "Solvability.DLLHijacking_Windows":      {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.70},
    "Solvability.Schtasks_EOP_1":            {"type": 2, "match": {"Windows", "DomainJoined", "LocalAdmin"}, "rate": 0.72},
    "Solvability.Schtasks_EOP_2":            {"type": 2, "match": {"Windows", "DomainJoined", "LocalAdmin"}, "rate": 0.72},
    "Solvability.Schtasks_EOP_3":            {"type": 2, "match": {"Windows", "DomainJoined", "LocalAdmin"}, "rate": 0.72},
    "Solvability.Schtasks_EOP_4":            {"type": 2, "match": {"Windows", "DomainJoined", "LocalAdmin"}, "rate": 0.72},
    "Solvability.Mimikatz_NTLM":             {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.65},
    "Solvability.SAM_Dump":                  {"type": 2, "match": {"Windows", "LocalAdmin"}, "rate": 0.70},
    "Solvability.LSA_Secrets":               {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.65},
    "Solvability.HiveNightmare":             {"type": 2, "match": {"Windows", "LocalAdmin"}, "rate": 0.78},
    # ── S_Windows remote ─────────────────────────────────────────────────────
    "Solvability.SMBGhost":                  {"type": 3, "match": {"Windows", "SMBv1"}, "rate": 0.90},
    "Solvability.MS08_067":                  {"type": 3, "match": {"Windows", "SMBv1"}, "rate": 0.90},
    "Solvability.SIGRed":                    {"type": 3, "match": {"Windows", "DNSServer"}, "rate": 0.90},
    "Solvability.BlueKeep":                  {"type": 3, "match": {"Windows", "RDP", "Unpatched"}, "rate": 0.90},
    "Solvability.DejaBlue":                  {"type": 3, "match": {"Windows", "RDP", "Unpatched"}, "rate": 0.90},
    "Solvability.RDP_RCE_1226":              {"type": 3, "match": {"Windows", "RDP"}, "rate": 0.90},
    "Solvability.IIS_HTTP_Stack":            {"type": 3, "match": {"Windows", "IISServer"}, "rate": 0.90},
    "Solvability.IIS_RCE":                   {"type": 3, "match": {"Windows", "IISServer"}, "rate": 0.90},
    "Solvability.TCPIP_RCE_1":              {"type": 3, "match": {"Windows"}, "rate": 0.90},
    "Solvability.TCPIP_RCE_2":              {"type": 3, "match": {"Windows"}, "rate": 0.90},
    "Solvability.NFS_RCE_TCPIP":            {"type": 3, "match": {"Windows"}, "rate": 0.90},
    "Solvability.HTTP3_RCE":                {"type": 3, "match": {"Windows"}, "rate": 0.90},
    "Solvability.DNS_RCE_1":                {"type": 3, "match": {"Windows", "DNSServer"}, "rate": 0.90},
    "Solvability.RPC_RCE_2":                {"type": 3, "match": {"Windows", "DomainJoined"}, "rate": 0.90},
    "Solvability.WSD_RCE":                  {"type": 3, "match": {"Windows", "Workstation"}, "rate": 0.90},
    "Solvability.iSCSI_RCE":                {"type": 3, "match": {"Windows", "Workstation"}, "rate": 0.90},
    "Solvability.ProxyShell":               {"type": 3, "match": {"Windows", "MailServer"}, "rate": 0.90},
    "Solvability.ProxyLogon":               {"type": 3, "match": {"Windows", "MailServer"}, "rate": 0.90},
    "Solvability.QueueJumper":              {"type": 3, "match": {"Windows", "MSMQServer"}, "rate": 0.88},
    "Solvability.HyperV_RCE":              {"type": 3, "match": {"Windows", "HyperVHost"}, "rate": 0.90},
    "Solvability.Follina":                  {"type": 3, "match": {"Windows", "Workstation"}, "rate": 0.75},
    # ── S_Identity local ─────────────────────────────────────────────────────
    "Solvability.PassTheHash":              {"type": 2, "match": {"Windows", "NoLAPS", "DomainJoined"}, "rate": 0.65},
    "Solvability.NTLM_Relay_LDAP":         {"type": 2, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.68},
    "Solvability.ZeroLogon":               {"type": 2, "match": {"Windows", "DomainController"}, "rate": 0.70},
    "Solvability.ConstrainedDelegation_S4U":{"type": 2, "match": {"Windows", "DomainController"}, "rate": 0.70},
    "Solvability.RBCD_Attack":             {"type": 2, "match": {"Windows", "DomainController"}, "rate": 0.68},
    "Solvability.SilverTicket":            {"type": 2, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.65},
    "Solvability.TokenImpersonation":      {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.70},
    "Solvability.DCSync":                  {"type": 2, "match": {"Windows", "DomainController", "DomainAdmin"}, "rate": 0.60},
    "Solvability.NTDS_Dump":               {"type": 2, "match": {"Windows", "DomainController"}, "rate": 0.60},
    "Solvability.GoldenTicket":            {"type": 2, "match": {"Windows", "DomainController"}, "rate": 0.55},
    "Solvability.ADCS_ESC1":              {"type": 2, "match": {"Windows", "DomainController", "ADCS"}, "rate": 0.60},
    "Solvability.ADCS_ESC6":              {"type": 2, "match": {"Windows", "DomainController", "ADCS"}, "rate": 0.58},
    "Solvability.DCShadow":               {"type": 2, "match": {"Windows", "DomainController"}, "rate": 0.55},
    "Solvability.DSRM_Abuse":             {"type": 2, "match": {"Windows", "DomainController"}, "rate": 0.60},
    "Solvability.ADCS_ESC8":              {"type": 2, "match": {"Windows", "ADCS", "DomainController"}, "rate": 0.55},
    # ── S_Identity remote ────────────────────────────────────────────────────
    "Solvability.ASREPRoasting":           {"type": 3, "match": {"Windows", "DomainController"}, "rate": 0.55},
    "Solvability.Kerberoasting":           {"type": 2, "match": {"Windows", "Kerberoastable", "DomainJoined"}, "rate": 0.60},
    "Solvability.PrinterBug_Coercion":     {"type": 3, "match": {"Windows", "DomainController"}, "rate": 0.75},
    "Solvability.PetitPotam":              {"type": 3, "match": {"Windows", "DomainController"}, "rate": 0.75},
    "Solvability.UnconstrainedDelegation": {"type": 3, "match": {"Windows", "DomainController"}, "rate": 0.70},
    "Solvability.ShadowCredentials":       {"type": 2, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.70},
    "Solvability.noPac":                   {"type": 3, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.75},
    "Solvability.Certifried":              {"type": 3, "match": {"Windows", "DomainController", "ADCS"}, "rate": 0.88},
    "Solvability.AD_Services_EOP":         {"type": 3, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.88},
    "Solvability.NetNTLMv2_Downgrade":     {"type": 3, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.81},
    "Solvability.Kerberos_EOP_2":          {"type": 3, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.81},
    "Solvability.LSASS_EOP_AD":            {"type": 3, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.78},
    "Solvability.noPac_2":                 {"type": 3, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.75},
    "Solvability.Kerberos_EOP":            {"type": 3, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.75},
    "Solvability.MSAA_Priv":               {"type": 3, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.71},
    # ── S_Lateral local ──────────────────────────────────────────────────────
    "Solvability.Mimikatz_LSASS":          {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.70},
    "Solvability.LAPS_Password_Read":      {"type": 2, "match": {"Windows", "DomainJoined", "LAPS"}, "rate": 0.70},
    "Solvability.GPP_Password_Decryption": {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.75},
    "Solvability.WinRM_Credential_Cache":  {"type": 2, "match": {"Windows", "DomainJoined", "WinRM"}, "rate": 0.70},
    "Solvability.PrintNightmare_LocalPrivEsc":{"type": 2, "match": {"Windows", "PrintSpooler"}, "rate": 0.88},
    "Solvability.PrintNightmare":          {"type": 2, "match": {"Windows", "PrintSpooler"}, "rate": 0.88},
    "Solvability.SpoolSample_Coerce":      {"type": 2, "match": {"Windows", "PrintSpooler"}, "rate": 0.78},
    "Solvability.Spooler_EOP_1":           {"type": 2, "match": {"Windows", "PrintSpooler"}, "rate": 0.78},
    "Solvability.Spooler_RCE":             {"type": 2, "match": {"Windows", "PrintSpooler"}, "rate": 0.78},
    "Solvability.Exchange_NTLM_Relay":     {"type": 2, "match": {"Windows", "MailServer"}, "rate": 0.90},
    "Solvability.PrivExchange":            {"type": 2, "match": {"Windows", "MailServer"}, "rate": 0.75},
    "Solvability.ProxyNotShell_NTLM":      {"type": 2, "match": {"Windows", "MailServer"}, "rate": 0.88},
    "Solvability.Exchange_RCE_Lateral_1":  {"type": 2, "match": {"Windows", "MailServer"}, "rate": 0.88},
    "Solvability.Exchange_RCE_Lateral_2":  {"type": 2, "match": {"Windows", "MailServer"}, "rate": 0.88},
    "Solvability.MSSQL_xpCmdshell":        {"type": 2, "match": {"Windows", "MSSQLServer"}, "rate": 0.80},
    "Solvability.MSSQL_LinkedServer":      {"type": 2, "match": {"Windows", "MSSQLServer"}, "rate": 0.65},
    "Solvability.MSSQL_RCE_Lateral":       {"type": 2, "match": {"Windows", "MSSQLServer"}, "rate": 0.88},
    "Solvability.MSSQL_Privesc_Lateral":   {"type": 2, "match": {"Windows", "MSSQLServer"}, "rate": 0.78},
    "Solvability.RBCD_Write":              {"type": 2, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.68},
    "Solvability.LDAP_AuthBypass_Lateral": {"type": 2, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.88},
    "Solvability.CloudIAM_LDAP_Write":     {"type": 2, "match": {"Windows", "DomainController", "DomainJoined"}, "rate": 0.65},
    "Solvability.ADCS_CertSpoof_Lateral":  {"type": 2, "match": {"Windows", "DomainController", "ADCS"}, "rate": 0.88},
    "Solvability.ADCS_EOP_Lateral":        {"type": 2, "match": {"Windows", "DomainController", "ADCS"}, "rate": 0.78},
    "Solvability.LSA_Relay":               {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.81},
    "Solvability.Outlook_NTLM_Relay":      {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.90},
    "Solvability.PetitPotam_Relay":        {"type": 2, "match": {"Windows", "DomainController"}, "rate": 0.75},
    "Solvability.SpoolSample":             {"type": 2, "match": {"Windows", "PrintSpooler"}, "rate": 0.78},
    "Solvability.CLFS_Privesc":            {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.78},
    "Solvability.Win_EOP_Cred":            {"type": 2, "match": {"Windows", "DomainJoined", "LocalAdmin"}, "rate": 0.78},
    "Solvability.BloodHound_Recon":        {"type": 2, "match": {"Windows", "DomainJoined"}, "rate": 0.80},
    "Solvability.LDAP_Enum":               {"type": 2, "match": {"Windows", "DomainController"}, "rate": 0.80},
    # ── S_Lateral remote ─────────────────────────────────────────────────────
    "Solvability.NTLM_Relay_SMB":          {"type": 3, "match": {"Windows", "DomainJoined"}, "rate": 0.72},
    "Solvability.WinRM_Exec_Hash":         {"type": 3, "match": {"Windows", "DomainJoined", "WinRM"}, "rate": 0.75},
    "Solvability.WinRM_Exec_Ticket":       {"type": 3, "match": {"Windows", "DomainJoined", "WinRM"}, "rate": 0.70},
}

# All specialist vulns union (for quick lookup)
ALL_SPECIALIST_VULNS: Set[str] = set()
for _sp in SPECIALIST_VULNS.values():
    ALL_SPECIALIST_VULNS.update(_sp["local"])
    ALL_SPECIALIST_VULNS.update(_sp["remote"])


# ── Matching logic ────────────────────────────────────────────────────────────

def node_matches(node_props: Set[str], vuln_name: str) -> bool:
    """True if node_props satisfies this vuln's match requirements."""
    if vuln_name not in VULN_CATALOG:
        return False
    match = VULN_CATALOG[vuln_name]["match"]
    if not match:
        return True

    device_roles = match & DEVICE_ROLE_PROPS
    required     = match - DEVICE_ROLE_PROPS

    # All non-device-role props must be present
    if not required.issubset(node_props):
        return False

    # At least one device-role prop must be present (if any specified)
    if device_roles and not device_roles.intersection(node_props):
        return False

    return True


# ── Vuln YAML construction ────────────────────────────────────────────────────

def build_vuln_yaml(vuln_name: str, template_lib: Dict[str, dict]) -> dict:
    """
    Build the YAML dict for a vuln to inject into a node.
    Prefer existing template (exact structure from another node in dataset).
    Fall back to constructing from catalog data.
    """
    if vuln_name in template_lib:
        tmpl = copy.deepcopy(template_lib[vuln_name])
        # Strip credential targets — they reference other scenario's nodes
        out = tmpl.get("outcome", {})
        if isinstance(out, dict):
            otype = out.get("type", "")
            kwargs = out.get("kwargs", {}) or {}
            if otype == "leaked_credentials":
                kwargs["credentials"] = []
            elif otype == "leaked_nodes_id":
                kwargs["nodes"] = []
        return tmpl

    # Construct from catalog
    info = VULN_CATALOG[vuln_name]
    vtype = info["type"]
    rate  = info["rate"]
    otype, okwargs = _infer_outcome(vuln_name)

    short = vuln_name.replace("Solvability.", "")
    return {
        "description": f"{short} — injected for specialist vocabulary coverage",
        "type": vtype,
        "outcome": {
            "type": otype,
            "kwargs": okwargs,
        },
        "precondition": {"expression": "true"},
        "rates": {
            "probingDetectionRate": 0.0,
            "exploitDetectionRate": 0.0,
            "successRate": rate,
        },
        "URL": "",
        "cost": 2.0,
        "reward_string": f"{short} succeeded",
    }


# ── Template library builder ──────────────────────────────────────────────────

def build_template_library(dataset_root: Path, sample_limit: int = 50) -> Dict[str, dict]:
    """
    Scan a subset of node YAMLs to collect existing vuln structures as templates.
    Returns {vuln_name: yaml_dict}.
    """
    templates: Dict[str, dict] = {}
    scanned = 0
    for node_yaml in dataset_root.rglob("nodes/*.yaml"):
        if scanned >= sample_limit:
            break
        try:
            data = yaml.safe_load(node_yaml.read_text(encoding="utf-8"))
            for vname, vdict in (data.get("vulnerabilities") or {}).items():
                if vname not in templates and isinstance(vdict, dict):
                    templates[vname] = vdict
        except Exception:
            pass
        scanned += 1
    return templates


# ── Per-scenario patching ─────────────────────────────────────────────────────

def patch_scenario(
    scenario_dir: Path,
    template_lib: Dict[str, dict],
    dry_run: bool,
) -> Dict[str, int]:
    """
    Patch all node YAMLs + identifiers.yaml in a single scenario directory.
    Returns stats dict.
    """
    stats = Counter()

    ids_path = scenario_dir / "identifiers" / "identifiers.yaml"
    if not ids_path.exists():
        stats["missing_identifiers"] += 1
        return stats

    try:
        ids = yaml.safe_load(ids_path.read_text(encoding="utf-8")) or {}
    except Exception:
        stats["identifiers_parse_error"] += 1
        return stats

    local_ids:  List[str] = ids.get("local_vulnerabilities",  []) or []
    remote_ids: List[str] = ids.get("remote_vulnerabilities", []) or []
    local_id_set  = set(local_ids)
    remote_id_set = set(remote_ids)

    ids_dirty = False

    nodes_dir = scenario_dir / "nodes"
    for node_yaml in sorted(nodes_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(node_yaml.read_text(encoding="utf-8")) or {}
        except Exception:
            stats["node_parse_error"] += 1
            continue

        node_props: Set[str] = set(data.get("properties") or [])
        vulns: dict = data.get("vulnerabilities") or {}
        node_dirty = False

        for vuln_name in ALL_SPECIALIST_VULNS:
            if vuln_name in vulns:
                stats["already_present"] += 1
                continue

            if not node_matches(node_props, vuln_name):
                stats["no_match"] += 1
                continue

            # Inject vuln into node
            vuln_yaml = build_vuln_yaml(vuln_name, template_lib)
            if not dry_run:
                vulns[vuln_name] = vuln_yaml
            node_dirty = True
            stats["injected"] += 1

            # Register in identifier lists
            vtype = VULN_CATALOG[vuln_name]["type"]
            if vtype == 2 and vuln_name not in local_id_set:
                if not dry_run:
                    local_ids.append(vuln_name)
                    local_id_set.add(vuln_name)
                ids_dirty = True
                stats["identifiers_added_local"] += 1
            elif vtype == 3 and vuln_name not in remote_id_set:
                if not dry_run:
                    remote_ids.append(vuln_name)
                    remote_id_set.add(vuln_name)
                ids_dirty = True
                stats["identifiers_added_remote"] += 1

        if node_dirty and not dry_run:
            data["vulnerabilities"] = vulns
            node_yaml.write_text(
                yaml.dump(data, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            stats["nodes_written"] += 1

    if ids_dirty and not dry_run:
        ids["local_vulnerabilities"]  = local_ids
        ids["remote_vulnerabilities"] = remote_ids
        ids_path.write_text(
            yaml.dump(ids, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        stats["identifiers_written"] += 1

    return stats


# ── Coverage audit (pre/post) ─────────────────────────────────────────────────

def audit_coverage(dataset_root: Path) -> Dict[str, Dict[str, int]]:
    """
    Single-pass audit: reads each node file as raw text (no YAML parse).
    - Vuln presence: check if 'Solvability.XYZ:' appears in raw text
    - Property presence: check if each required property token appears
    - Eligible: node has all required properties but lacks the vuln

    Returns {vuln_name: {"scenarios": N, "nodes": M, "eligible": E}}.
    """
    vuln_scenarios: Dict[str, Set[str]] = defaultdict(set)
    vuln_nodes:     Dict[str, int]      = defaultdict(int)
    vuln_eligible:  Dict[str, int]      = defaultdict(int)

    # Pre-build search strings for fast raw-text matching
    # vuln presence: "Solvability.XYZ:" as a YAML key
    vuln_keys = {v: (v + ":").encode() for v in ALL_SPECIALIST_VULNS}

    # property presence: "- PropName\n" or "- PropName\r"
    # match_properties per vuln as frozensets for fast lookup
    vuln_match = {v: VULN_CATALOG[v]["match"] for v in ALL_SPECIALIST_VULNS if v in VULN_CATALOG}

    all_node_yamls = sorted(dataset_root.rglob("nodes/*.yaml"))
    total = len(all_node_yamls)
    print(f"  Single-pass raw scan of {total:,} node files...", flush=True)

    for i, node_yaml in enumerate(all_node_yamls):
        if i % 20000 == 0 and i > 0:
            print(f"  [{i:,}/{total:,}] ({i*100//total}%)...", flush=True)

        try:
            raw = node_yaml.read_bytes()
        except Exception:
            continue

        scenario_id = node_yaml.parent.parent.name

        # Which specialist vulns are present in this file?
        present: Set[str] = set()
        for vname, key in vuln_keys.items():
            if key in raw:
                present.add(vname)
                vuln_scenarios[vname].add(scenario_id)
                vuln_nodes[vname] += 1

        # For missing vulns, check if node has required properties
        # Property check: "- PropToken" anywhere in the raw bytes
        for vname in ALL_SPECIALIST_VULNS:
            if vname in present:
                continue
            match_props = vuln_match.get(vname, set())
            if not match_props:
                continue
            # Check device-role OR semantics
            device_roles = match_props & DEVICE_ROLE_PROPS
            required     = match_props - DEVICE_ROLE_PROPS
            # All required non-role props must be present
            if not all((f"- {p}").encode() in raw for p in required):
                continue
            # At least one device-role must be present (if any)
            if device_roles and not any((f"- {p}").encode() in raw for p in device_roles):
                continue
            vuln_eligible[vname] += 1

    print(f"  [{total:,}/{total:,}] done.", flush=True)
    return {
        v: {
            "scenarios": len(vuln_scenarios[v]),
            "nodes":     vuln_nodes[v],
            "eligible":  vuln_eligible[v],
        }
        for v in ALL_SPECIALIST_VULNS
    }


def print_coverage_report(coverage: Dict[str, Dict[str, int]], label: str = ""):
    total_vulns   = len(ALL_SPECIALIST_VULNS)
    covered_vulns = sum(1 for v in coverage.values() if v["scenarios"] > 0)
    dead_vulns    = total_vulns - covered_vulns

    print(f"\n{'='*60}")
    print(f"  SPECIALIST COVERAGE REPORT  {label}")
    print(f"{'='*60}")
    print(f"  Total specialist vuln slots : {total_vulns}")
    print(f"  Covered (appear in >=1 scenario): {covered_vulns}")
    print(f"  Dead (never appear)         : {dead_vulns}")
    print()

    # Per-specialist breakdown
    for sp_name, sp_vulns in SPECIALIST_VULNS.items():
        all_sp = sp_vulns["local"] + sp_vulns["remote"]
        covered = sum(1 for v in all_sp if coverage.get(v, {}).get("scenarios", 0) > 0)
        pct = covered / len(all_sp) * 100
        print(f"  {sp_name:12s}: {covered:3d}/{len(all_sp)} slots covered ({pct:.0f}%)")

    print()
    # Dead slots: split into "injectable" (eligible nodes exist) vs "no nodes" (truly absent property)
    dead_injectable = []
    dead_no_nodes   = []
    for vname in sorted(ALL_SPECIALIST_VULNS):
        info = coverage.get(vname, {})
        if info.get("scenarios", 0) == 0:
            if info.get("eligible", 0) > 0:
                dead_injectable.append((vname, info["eligible"]))
            else:
                dead_no_nodes.append(vname)

    if dead_injectable:
        print(f"  Dead but INJECTABLE (matching nodes exist, vuln just missing):")
        print(f"  {'Vuln':<45} {'eligible_nodes':>14}")
        print(f"  {'-'*45} {'-'*14}")
        for vname, elig in sorted(dead_injectable, key=lambda x: -x[1]):
            short = vname.replace("Solvability.", "")
            print(f"  {short:<45} {elig:>14,}")

    print()
    if dead_no_nodes:
        print(f"  Dead — NO MATCHING NODES in dataset (need new node types):")
        for vname in dead_no_nodes:
            short = vname.replace("Solvability.", "")
            req   = VULN_CATALOG.get(vname, {}).get("match", set())
            print(f"    ✗  {short:<42}  needs: {sorted(req)}")

    print(f"{'='*60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Patch specialist vocab coverage in CyberBattleSim scenarios")
    parser.add_argument("--dataset", required=True, help="Root of output dataset (e.g. output_specialists_final)")
    parser.add_argument("--dry-run", action="store_true", help="Report what would change, write nothing")
    parser.add_argument("--report-only", action="store_true", help="Only print coverage report, no patching")
    parser.add_argument("--template-sample", type=int, default=100,
                        help="Number of node YAMLs to scan for vuln templates (default 100)")
    args = parser.parse_args()

    dataset_root = Path(args.dataset).resolve()
    if not dataset_root.exists():
        print(f"ERROR: dataset not found: {dataset_root}", file=sys.stderr)
        sys.exit(1)

    print(f"Dataset: {dataset_root}")

    # Pre-patch coverage audit
    print("\nAuditing pre-patch coverage...")
    pre_coverage = audit_coverage(dataset_root)
    print_coverage_report(pre_coverage, label="PRE-PATCH")

    if args.report_only:
        return

    # Build template library from existing vuln instances
    print(f"\nBuilding vuln template library (sampling {args.template_sample} nodes)...")
    template_lib = build_template_library(dataset_root, sample_limit=args.template_sample)
    print(f"  Templates collected: {len(template_lib)} unique vulns")

    # Find all scenario directories
    scenario_dirs = [
        p for p in dataset_root.rglob("*/")
        if (p / "nodes").is_dir() and (p / "identifiers" / "identifiers.yaml").exists()
    ]
    print(f"\nScenarios found: {len(scenario_dirs)}")
    if args.dry_run:
        print("  (DRY RUN — no files will be written)")

    # Patch each scenario
    total_stats: Counter = Counter()
    for i, sc_dir in enumerate(scenario_dirs):
        sc_stats = patch_scenario(sc_dir, template_lib, dry_run=args.dry_run)
        total_stats.update(sc_stats)
        if (i + 1) % 100 == 0 or (i + 1) == len(scenario_dirs):
            print(f"  [{i+1}/{len(scenario_dirs)}] injected={total_stats['injected']:,}  "
                  f"nodes_written={total_stats['nodes_written']:,}  "
                  f"ids_written={total_stats['identifiers_written']:,}")

    print(f"\nPatch summary:")
    print(f"  Vulns injected       : {total_stats['injected']:,}")
    print(f"  Already present      : {total_stats['already_present']:,}")
    print(f"  No property match    : {total_stats['no_match']:,}")
    print(f"  Nodes written        : {total_stats['nodes_written']:,}")
    print(f"  Identifiers updated  : {total_stats['identifiers_written']:,}")
    print(f"  Local IDs added      : {total_stats['identifiers_added_local']:,}")
    print(f"  Remote IDs added     : {total_stats['identifiers_added_remote']:,}")

    if not args.dry_run:
        # Post-patch coverage audit
        print("\nAuditing post-patch coverage...")
        post_coverage = audit_coverage(dataset_root)
        print_coverage_report(post_coverage, label="POST-PATCH")

        print("\n" + "="*60)
        print("  NEXT STEP: Regenerate PKL files")
        print("  Training code prefers PKL over YAML — stale PKLs will")
        print("  silently use unpatched environments.")
        print()
        print("  Run:")
        print(f"    python -m cyberbattle.training.preprocess_scenarios \\")
        print(f"        --meta-root {dataset_root} \\")
        print(f"        --workers 4 --overwrite")
        print("="*60)


if __name__ == "__main__":
    main()
