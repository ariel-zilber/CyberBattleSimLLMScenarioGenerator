#!/usr/bin/env python3
"""
tools/mitre_attack_analysis.py
================================
Classify every CVE used across CyberBattleSimDomainGenerator domain configs
into MITRE ATT&CK Enterprise + ICS tactics/techniques, then produce a
per-domain statistical and quality analysis.

Outputs (written to --out-dir):
  mitre_cve_taxonomy.json   — machine-readable CVE → tactic/technique map
  mitre_domain_stats.json   — per-domain statistics
  mitre_analysis.md         — full markdown report with tables
  mitre_analysis.pdf        — LaTeX-compiled PDF (requires pdflatex)

Usage
-----
python3 tools/mitre_attack_analysis.py \\
    --out-dir /content/drive/MyDrive/thesis/code/datasets/poc/claude
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

import yaml

# =============================================================================
# MITRE ATT&CK Tactic registry
# =============================================================================
# Enterprise tactics
TACTICS: Dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
    # ICS-specific (MITRE ATT&CK for ICS)
    "ICS-IA":  "ICS – Initial Access",
    "ICS-EX":  "ICS – Execution",
    "ICS-LM":  "ICS – Lateral Movement",
    "ICS-IM":  "ICS – Impair Process Control",
    "ICS-IT":  "ICS – Inhibit Response Function",
}

TACTIC_SHORT: Dict[str, str] = {
    "TA0001": "InitAccess",
    "TA0002": "Execution",
    "TA0003": "Persist",
    "TA0004": "PrivEsc",
    "TA0005": "DefEvasion",
    "TA0006": "CredAccess",
    "TA0007": "Discovery",
    "TA0008": "LatMov",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
    "ICS-IA":  "ICS-IA",
    "ICS-EX":  "ICS-EX",
    "ICS-LM":  "ICS-LM",
    "ICS-IM":  "ICS-IM",
    "ICS-IT":  "ICS-IT",
}

# =============================================================================
# Technique registry (subset relevant to this dataset)
# =============================================================================
TECHNIQUES: Dict[str, str] = {
    "T1190":       "Exploit Public-Facing Application",
    "T1078":       "Valid Accounts",
    "T1566.001":   "Spearphishing Attachment",
    "T1210":       "Exploitation of Remote Services",
    "T1059":       "Command and Scripting Interpreter",
    "T1059.004":   "Unix Shell",
    "T1059.007":   "JavaScript",
    "T1203":       "Exploitation for Client Execution",
    "T1072":       "Software Deployment Tools",
    "T1505.003":   "Server Software Component: Web Shell",
    "T1068":       "Exploitation for Privilege Escalation",
    "T1134":       "Access Token Manipulation",
    "T1484.002":   "Domain Trust Modification",
    "T1003.001":   "OS Credential Dumping: LSASS Memory",
    "T1003.003":   "OS Credential Dumping: NTDS",
    "T1003.006":   "OS Credential Dumping: DCSync",
    "T1187":       "Forced Authentication",
    "T1558.001":   "Steal or Forge Kerberos Tickets: Golden Ticket",
    "T1558.003":   "Steal or Forge Kerberos Tickets: Kerberoasting",
    "T1558.004":   "Steal or Forge Kerberos Tickets: AS-REP Roasting",
    "T1550.002":   "Use Alternate Authentication Material: Pass the Hash",
    "T1552.001":   "Unsecured Credentials: Credentials in Files",
    "T1552.004":   "Unsecured Credentials: Private Keys",
    "T1046":       "Network Service Discovery",
    "T1069":       "Permission Groups Discovery",
    "T1087":       "Account Discovery",
    "T1482":       "Domain Trust Discovery",
    "T1021.002":   "Remote Services: SMB/Windows Admin Shares",
    "T1021.004":   "Remote Services: SSH",
    "T1005":       "Data from Local System",
    "T1074":       "Data Staged",
    "T1041":       "Exfiltration Over C2 Channel",
    "T1485":       "Data Destruction",
    "T1486":       "Data Encrypted for Impact",
    # ICS (MITRE ATT&CK for ICS framework)
    "T0822":       "ICS: External Remote Services",
    "T0855":       "ICS: Unauthorized Command Message",
    "T0856":       "ICS: Spoof Reporting Message",
    "T0873":       "ICS: Project File Infection",
    "T0880":       "ICS: Loss of Control",
    "T0889":       "ICS: Modify Program",
    "T0890":       "ICS: Exploitation of Remote Services",
}

# =============================================================================
# CVE → MITRE ATT&CK classification
#
# Each entry:
#   label       — human-readable name
#   cvss        — CVSS v3 base score (or v2 for old CVEs)
#   platform    — OS/platform family
#   category    — CWE class (RCE, AuthBypass, PrivEsc, CredLeak, …)
#   tactics     — list of TA* codes (primary first)
#   techniques  — list of T* technique IDs (primary first)
#   notes       — short clarification
# =============================================================================
CVE_DATABASE: Dict[str, dict] = {

    # ------------------------------------------------------------------ #
    # Windows / Active Directory
    # ------------------------------------------------------------------ #
    "CVE-2017-0144": {
        "label": "EternalBlue (MS17-010)",
        "cvss": 8.8, "platform": "Windows",
        "category": "RCE",
        "tactics":    ["TA0001", "TA0008"],
        "techniques": ["T1190", "T1210"],
        "notes": "SMBv1 unauthenticated RCE; primary entry vector AND lateral movement across SMB shares",
    },
    "CVE-2019-0708": {
        "label": "BlueKeep",
        "cvss": 9.8, "platform": "Windows",
        "category": "RCE",
        "tactics":    ["TA0001", "TA0008"],
        "techniques": ["T1190", "T1210"],
        "notes": "Pre-auth RDP RCE on unpatched Win7; first-foothold or lateral movement",
    },
    "CVE-2021-34527": {
        "label": "PrintNightmare",
        "cvss": 8.8, "platform": "Windows",
        "category": "RCE/PrivEsc",
        "tactics":    ["TA0004", "TA0001"],
        "techniques": ["T1068", "T1190"],
        "notes": "Windows Print Spooler local+remote privilege escalation; CISA KEV",
    },
    "CVE-2021-36942": {
        "label": "PetitPotam NTLM relay",
        "cvss": 7.5, "platform": "Windows",
        "category": "CredLeak",
        "tactics":    ["TA0006", "TA0008"],
        "techniques": ["T1187", "T1550.002"],
        "notes": "Forces NTLM authentication from DC via EfsRpc, relays to ADCS for cert issuance",
    },
    "CVE-2021-42287": {
        "label": "noPac (SAM Account Name Spoofing)",
        "cvss": 7.5, "platform": "Windows",
        "category": "PrivEsc",
        "tactics":    ["TA0004", "TA0006"],
        "techniques": ["T1068", "T1558.001"],
        "notes": "Domain user forges machine account name to obtain DC TGT; full domain takeover",
    },
    "CVE-2022-21907": {
        "label": "IIS HTTP Protocol Stack RCE",
        "cvss": 9.8, "platform": "Windows",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Unauthenticated RCE in Windows IIS via HTTP.sys; CVSS 9.8",
    },
    "CVE-2021-26855": {
        "label": "ProxyLogon (Exchange SSRF)",
        "cvss": 9.1, "platform": "Windows",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Pre-auth SSRF on Exchange OWA → authentication bypass → RCE; CISA KEV",
    },
    "CVE-2023-23397": {
        "label": "Outlook NTLM Relay (zero-click)",
        "cvss": 9.8, "platform": "Windows",
        "category": "CredLeak",
        "tactics":    ["TA0006", "TA0001"],
        "techniques": ["T1187", "T1566.001"],
        "notes": "Zero-click NTLM hash theft via crafted calendar invite; CISA KEV",
    },
    "CVE-2022-26923": {
        "label": "Certifried (ADCS PrivEsc)",
        "cvss": 8.8, "platform": "Windows",
        "category": "PrivEsc",
        "tactics":    ["TA0004", "TA0006"],
        "techniques": ["T1068", "T1484.002"],
        "notes": "Domain user requests machine certificate spoofing DC identity → full domain compromise",
    },
    "CVE-2021-25094": {
        "label": "Tatsu Builder WordPress Plugin RCE",
        "cvss": 9.8, "platform": "Linux/PHP",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Unauthenticated file upload RCE in WordPress Tatsu Builder plugin",
    },
    "CVE-2022-21663": {
        "label": "WordPress Object Injection",
        "cvss": 8.8, "platform": "Linux/PHP",
        "category": "RCE",
        "tactics":    ["TA0001", "TA0002"],
        "techniques": ["T1190", "T1059.007"],
        "notes": "PHP unserialize() gadget chain in WordPress post meta → unauthenticated RCE",
    },
    "CVE-2021-23017": {
        "label": "Nginx Resolver Off-by-One",
        "cvss": 7.7, "platform": "Linux",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Nginx DNS resolver 1-byte memory overwrite → potential worker-process code execution",
    },

    # ------------------------------------------------------------------ #
    # Network Devices
    # ------------------------------------------------------------------ #
    "CVE-2024-3400": {
        "label": "PAN-OS GlobalProtect OS Command Injection",
        "cvss": 10.0, "platform": "Palo Alto PAN-OS",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Pre-auth OS command injection on GlobalProtect gateway; CISA KEV; widely exploited",
    },
    "CVE-2023-27997": {
        "label": "FortiOS SSLVPN Heap Overflow",
        "cvss": 9.8, "platform": "Fortinet FortiOS",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Pre-auth heap-based buffer overflow on SSL VPN; CISA KEV",
    },
    "CVE-2020-12812": {
        "label": "FortiOS SSL VPN Auth Bypass",
        "cvss": 9.8, "platform": "Fortinet FortiOS",
        "category": "AuthBypass",
        "tactics":    ["TA0001", "TA0006"],
        "techniques": ["T1190", "T1078"],
        "notes": "Unauthenticated SSL VPN login via crafted username; CISA KEV",
    },
    "CVE-2018-0395": {
        "label": "Cisco NX-OS LLDP Unauthenticated RCE",
        "cvss": 8.8, "platform": "Cisco NX-OS",
        "category": "RCE",
        "tactics":    ["TA0008"],
        "techniques": ["T1210"],
        "notes": "Adjacent-network LLDP parsing unauthenticated DoS/RCE on NX-OS switches",
    },
    "CVE-2019-1595": {
        "label": "Cisco NX-OS FCoE Unauthenticated",
        "cvss": 7.4, "platform": "Cisco NX-OS",
        "category": "RCE",
        "tactics":    ["TA0008"],
        "techniques": ["T1210"],
        "notes": "Adjacent-network FCoE processing vulnerability in NX-OS data-center switches",
    },
    "CVE-2021-3054": {
        "label": "PAN-OS Web UI TOCTOU",
        "cvss": 7.2, "platform": "Palo Alto PAN-OS",
        "category": "PrivEsc",
        "tactics":    ["TA0004"],
        "techniques": ["T1068"],
        "notes": "Race condition in PAN-OS web management interface → management-plane privilege escalation",
    },
    "CVE-2026-20020": {
        "label": "Cisco ASA OSPF Unauthenticated Flooding",
        "cvss": 6.8, "platform": "Cisco ASA",
        "category": "RCE",
        "tactics":    ["TA0008"],
        "techniques": ["T1210"],
        "notes": "Unauthenticated OSPF LSA flood from adjacent network; exposes routing tables",
    },
    "CVE-2017-12334": {
        "label": "Cisco NX-OS CLI Command Injection",
        "cvss": 6.7, "platform": "Cisco NX-OS",
        "category": "PrivEsc",
        "tactics":    ["TA0004", "TA0002"],
        "techniques": ["T1068", "T1059"],
        "notes": "Post-auth CLI command injection on NX-OS; escalates to OS-level execution",
    },
    "CVE-2017-12341": {
        "label": "Cisco NX-OS CLI Command Injection (alt)",
        "cvss": 6.7, "platform": "Cisco NX-OS",
        "category": "PrivEsc",
        "tactics":    ["TA0004", "TA0002"],
        "techniques": ["T1068", "T1059"],
        "notes": "Alternate CLI injection path on NX-OS; same impact class as CVE-2017-12334",
    },
    "CVE-2023-20198": {
        "label": "Cisco IOS XE Web UI Priv-Esc",
        "cvss": 10.0, "platform": "Cisco IOS XE",
        "category": "PrivEsc",
        "tactics":    ["TA0001", "TA0004"],
        "techniques": ["T1190", "T1068"],
        "notes": "Unauthenticated level-15 account creation via web management; CISA KEV",
    },

    # ------------------------------------------------------------------ #
    # SCADA / ICS
    # ------------------------------------------------------------------ #
    "CVE-2021-27462": {
        "label": "FactoryTalk AssetCentre .NET Deserialization",
        "cvss": 10.0, "platform": "Rockwell FactoryTalk",
        "category": "RCE",
        "tactics":    ["ICS-IA", "TA0001"],
        "techniques": ["T0822", "T1190"],
        "notes": "Pre-auth .NET remoting deserialization RCE on FactoryTalk AssetCentre v10",
    },
    "CVE-2021-27476": {
        "label": "FactoryTalk RACompare Command Injection",
        "cvss": 10.0, "platform": "Rockwell FactoryTalk",
        "category": "RCE",
        "tactics":    ["ICS-EX", "TA0002"],
        "techniques": ["T0890", "T1059"],
        "notes": "Unauthenticated OS command injection in FactoryTalk RACompare; CVSSv3 10.0",
    },
    "CVE-2021-22681": {
        "label": "Rockwell Studio 5000 Cryptographic Key Reuse",
        "cvss": 10.0, "platform": "Rockwell ControlLogix",
        "category": "AuthBypass",
        "tactics":    ["ICS-LM", "ICS-IM"],
        "techniques": ["T0890", "T0855"],
        "notes": "Hardcoded private key in RSLogix firmware; forged authenticated PLC messages; CISA KEV",
    },
    "CVE-2023-32784": {
        "label": "OPC UA .NET Stack Buffer Overflow",
        "cvss": 9.8, "platform": "OPC UA / ICS",
        "category": "RCE",
        "tactics":    ["ICS-IA", "TA0001"],
        "techniques": ["T0822", "T1190"],
        "notes": "Pre-auth buffer overflow in OPC UA .NET SDK; affects Siemens/generic OPC servers",
    },
    "CVE-2018-7760": {
        "label": "Schneider Modicon M340 Auth Bypass",
        "cvss": 9.8, "platform": "Schneider Modicon",
        "category": "AuthBypass",
        "tactics":    ["ICS-IA", "ICS-IM"],
        "techniques": ["T0822", "T0855"],
        "notes": "Unauthenticated PLC program memory write via crafted HTTP request on Modicon M340",
    },
    "CVE-2018-7761": {
        "label": "Modicon M340 HTTP Request Injection",
        "cvss": 9.8, "platform": "Schneider Modicon",
        "category": "RCE",
        "tactics":    ["ICS-EX", "ICS-IM"],
        "techniques": ["T0890", "T0855"],
        "notes": "HTTP injection in Modicon M340 web server enabling RCE on PLC firmware",
    },
    "CVE-2017-16740": {
        "label": "Allen-Bradley MicroLogix 1400 Buffer Overflow",
        "cvss": 10.0, "platform": "Rockwell AllenBradley",
        "category": "RCE",
        "tactics":    ["ICS-IA", "ICS-IM"],
        "techniques": ["T0822", "T0855"],
        "notes": "Pre-auth EtherNet/IP buffer overflow on MicroLogix 1400 PLC firmware",
    },
    "CVE-2010-2772": {
        "label": "Siemens WinCC Hardcoded Backend Password",
        "cvss": 7.8, "platform": "Siemens WinCC",
        "category": "CredLeak",
        "tactics":    ["TA0006"],
        "techniques": ["T1552.001"],
        "notes": "Hardcoded MSSQL backend password in WinCC SCADA; exploited by Stuxnet",
    },
    "CVE-2023-2637": {
        "label": "FactoryTalk Hardcoded Cryptographic Key",
        "cvss": 7.3, "platform": "Rockwell FactoryTalk",
        "category": "CredLeak",
        "tactics":    ["TA0006"],
        "techniques": ["T1552.004"],
        "notes": "Hardcoded key in FactoryTalk credential storage; all stored ICS passwords decryptable",
    },
    "CVE-2022-38766": {
        "label": "FactoryTalk Services Platform Memory Corruption",
        "cvss": 9.8, "platform": "Rockwell FactoryTalk",
        "category": "RCE",
        "tactics":    ["ICS-IA", "TA0001"],
        "techniques": ["T0822", "T1190"],
        "notes": "Unauthenticated memory corruption on FactoryTalk from adjacent network segment",
    },
    "CVE-2023-27267": {
        "label": "Siemens OPC-UA SDK Buffer Overflow",
        "cvss": 7.5, "platform": "Siemens OPC-UA",
        "category": "RCE",
        "tactics":    ["ICS-LM", "TA0008"],
        "techniques": ["T0890", "T1210"],
        "notes": "Pre-auth buffer overflow in Siemens OPC-UA SDK via malformed discovery request",
    },
    "CVE-2022-3977": {
        "label": "Schneider Modicon M340 Modbus Stack Overflow",
        "cvss": 9.8, "platform": "Schneider Modicon",
        "category": "RCE",
        "tactics":    ["ICS-IA", "ICS-IM"],
        "techniques": ["T0822", "T0855"],
        "notes": "Unauthenticated RCE via Modbus FC90 on M340 PLC; firmware code execution",
    },

    # ------------------------------------------------------------------ #
    # Linux / Container / Web
    # ------------------------------------------------------------------ #
    "CVE-2025-15467": {
        "label": "Nginx libcrypto3 Critical RCE",
        "cvss": 9.8, "platform": "Linux (Nginx/OpenSSL)",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "OpenSSL 3.x use-after-free triggered by malformed TLS ClientHello on Bitnami Nginx",
    },
    "CVE-2025-69421": {
        "label": "Nginx libcrypto3 High Heap UAF",
        "cvss": 7.5, "platform": "Linux (Nginx/OpenSSL)",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "HIGH-severity heap UAF in OpenSSL 3.x; alternate RCE path on same Bitnami Nginx image",
    },
    "CVE-2026-22770": {
        "label": "WordPress ImageMagick Critical RCE",
        "cvss": 9.8, "platform": "Linux/PHP/WordPress",
        "category": "RCE",
        "tactics":    ["TA0001", "TA0003"],
        "techniques": ["T1190", "T1505.003"],
        "notes": "Malicious HEIF/TIFF media upload triggers ImageMagick memory corruption → PHP shell",
    },
    "CVE-2026-23876": {
        "label": "WordPress ImageMagick Critical RCE (variant 2)",
        "cvss": 9.8, "platform": "Linux/PHP/WordPress",
        "category": "RCE",
        "tactics":    ["TA0001", "TA0003"],
        "techniques": ["T1190", "T1505.003"],
        "notes": "Alternate ImageMagick memory corruption via PDF/PS rendering pipeline",
    },
    "CVE-2022-44268": {
        "label": "ImageMagick Arbitrary File Read/Write (v1)",
        "cvss": 6.5, "platform": "Linux/ImageMagick",
        "category": "RCE",
        "tactics":    ["TA0001", "TA0009"],
        "techniques": ["T1190", "T1005"],
        "notes": "Crafted PNG causes ImageMagick to embed/overwrite arbitrary server files",
    },
    "CVE-2023-34151": {
        "label": "ImageMagick Undefined Behaviour Heap Overflow",
        "cvss": 7.8, "platform": "Linux/ImageMagick",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Heap overflow in ImageMagick image processing; alternate RCE in WordPress media pipeline",
    },
    "CVE-2024-55637": {
        "label": "Drupal Core Critical PHP RCE",
        "cvss": 9.8, "platform": "Linux/PHP",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Unauthenticated PHP code execution via crafted Drupal core request",
    },
    "CVE-2024-41110": {
        "label": "Go stdlib / Vault Docker API Proxy RCE",
        "cvss": 9.9, "platform": "Linux/Go",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Go net/http memory corruption in Docker API proxy; affects Gitea, HashiCorp Vault Bitnami",
    },
    "CVE-2025-0377": {
        "label": "Go stdlib / Vault net/http Critical RCE",
        "cvss": 9.1, "platform": "Linux/Go",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Critical Go net/http RCE in Vault Bitnami chart; pre-auth",
    },
    "CVE-2026-33186": {
        "label": "Grafana Go stdlib RCE",
        "cvss": 8.1, "platform": "Linux/Go",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Go net/http HTTP/2 header parsing vulnerability in Grafana Bitnami chart",
    },
    "CVE-2026-35414": {
        "label": "Jenkins Script Console RCE",
        "cvss": 8.1, "platform": "Linux/Java",
        "category": "RCE",
        "tactics":    ["TA0002", "TA0001"],
        "techniques": ["T1072", "T1059"],
        "notes": "Groovy script execution via Jenkins Script Console using valid API token → OS shell",
    },
    "CVE-2026-35385": {
        "label": "Jenkins Credential Store Path Traversal",
        "cvss": 7.5, "platform": "Linux/Java",
        "category": "CredLeak",
        "tactics":    ["TA0006", "TA0009"],
        "techniques": ["T1552.001", "T1005"],
        "notes": "Jenkins credential-binding plugin path traversal exposes credentials.xml secrets",
    },
    "CVE-2024-56171": {
        "label": "libxml2 Use-After-Free in Java XML Parsing",
        "cvss": 9.8, "platform": "Linux/Java",
        "category": "RCE",
        "tactics":    ["TA0002"],
        "techniques": ["T1203"],
        "notes": "Heap UAF in libxml2 during Java XML processing; exploitable in Jenkins build containers",
    },
    "CVE-2025-6965": {
        "label": "SQLite Integer Overflow in Kafka Chart",
        "cvss": 9.8, "platform": "Linux/Java",
        "category": "RCE",
        "tactics":    ["TA0002"],
        "techniques": ["T1203"],
        "notes": "Integer overflow in SQLite library in Kafka Bitnami chart; CRITICAL",
    },
    "CVE-2024-12084": {
        "label": "Airflow Python Runtime Stack Overflow",
        "cvss": 9.8, "platform": "Linux/Python",
        "category": "RCE",
        "tactics":    ["TA0002"],
        "techniques": ["T1203"],
        "notes": "Python runtime stack overflow in Airflow; exploitable during pipeline build steps",
    },
    "CVE-2023-45853": {
        "label": "Airflow Python zlib/minizip Heap Overflow",
        "cvss": 9.8, "platform": "Linux/Python",
        "category": "RCE",
        "tactics":    ["TA0002"],
        "techniques": ["T1203"],
        "notes": "CRITICAL heap overflow in zlib/minizip Python runtime; alternate Airflow RCE path",
    },
    "CVE-2026-34457": {
        "label": "oauth2-proxy Go stdlib RCE",
        "cvss": 9.1, "platform": "Linux/Go",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Pre-auth Go net/http memory corruption on oauth2-proxy SSO gateway",
    },
    "CVE-2023-24538": {
        "label": "Go stdlib Template Injection in Redis Chart",
        "cvss": 9.8, "platform": "Linux/Go",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Critical Go text/template injection in Redis Bitnami chart",
    },
    "CVE-2023-24540": {
        "label": "Go stdlib text/template Injection in Redis Chart (alt)",
        "cvss": 9.8, "platform": "Linux/Go",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "Alternate Go template injection path in same Redis Bitnami image",
    },
    "CVE-2022-21417": {
        "label": "MySQL Server InnoDB Out-of-Bounds Read",
        "cvss": 4.9, "platform": "Linux/MySQL",
        "category": "RCE",
        "tactics":    ["TA0008"],
        "techniques": ["T1210"],
        "notes": "Low-impact MySQL InnoDB OOB read; authenticated attacker DB-tier lateral movement",
    },
    # Alias CVE used in wordpress_web_stack_v3 for Nginx LibCrypto
    "CVE-2023-0464": {
        "label": "OpenSSL Certificate Chain Verification DoS/RCE",
        "cvss": 7.5, "platform": "Linux (Nginx/OpenSSL)",
        "category": "RCE",
        "tactics":    ["TA0001"],
        "techniques": ["T1190"],
        "notes": "OpenSSL 3.x certificate chain verification code-path vulnerability; Nginx Bitnami",
    },
}

# =============================================================================
# Mapping from solvability vulnerability name → CVE ID
# (covers every named exploit in the 8 active domain configs)
# =============================================================================
VULN_TO_CVE: Dict[str, str] = {
    # Windows
    "Solvability.EternalBlue":         "CVE-2017-0144",
    "Solvability.BlueKeep":            "CVE-2019-0708",
    "Solvability.PrintNightmare":      "CVE-2021-34527",
    "Solvability.PetitPotam":          "CVE-2021-36942",
    "Solvability.noPac":               "CVE-2021-42287",
    "Solvability.IIS_RCE":             "CVE-2022-21907",
    "Solvability.ProxyLogon":          "CVE-2021-26855",
    "Solvability.ProxyShell":          "CVE-2021-34473",
    "Solvability.Outlook_NTLM":        "CVE-2023-23397",
    "Solvability.Certifried":          "CVE-2022-26923",
    "Solvability.DejaBlue":            "CVE-2019-1182",
    "Solvability.IIS_HTTP_Stack":      "CVE-2021-31166",
    "Solvability.WinRM_RCE":           "CVE-2021-31958",
    # WordPress / PHP
    "Solvability.WP_TatsuBuilder_RCE": "CVE-2021-25094",
    "Solvability.WP_ObjectInjection":  "CVE-2022-21663",
    "Solvability.Nginx_ResolverRCE":   "CVE-2021-23017",
    "Solvability.WordPress_ImageMagick":   "CVE-2026-22770",
    "Solvability.WordPress_ImageMagick_2": "CVE-2026-23876",
    "Solvability.Drupal_RCE":          "CVE-2024-55637",
    "Solvability.Drupal_RCE_2":        "CVE-2024-55638",
    # Nginx/OpenSSL
    "Solvability.Nginx_LibCrypto_Critical": "CVE-2025-15467",
    "Solvability.Nginx_LibCrypto_High":     "CVE-2025-69421",
    # Old ImageMagick (wordpress_web_stack_v3)
    # Detect by reading the description CVE reference
    # Go stdlib
    "Solvability.Vault_GoStdlib":      "CVE-2024-41110",
    "Solvability.Vault_GoStdlib_2":    "CVE-2025-0377",
    "Solvability.Grafana_GoStdlib":    "CVE-2026-33186",
    "Solvability.OAuthProxy_RCE":      "CVE-2026-34457",
    "Solvability.OAuthProxy_RCE_2":    "CVE-2026-40575",
    # Jenkins
    "Solvability.Jenkins_RCE":         "CVE-2026-35414",
    "Solvability.Jenkins_High":        "CVE-2026-35385",
    # Kafka / Airflow / Workers
    "Solvability.Kafka_LibXML":        "CVE-2024-56171",
    "Solvability.Kafka_SQLite":        "CVE-2025-6965",
    "Solvability.Airflow_RCE":         "CVE-2024-12084",
    "Solvability.Airflow_RCE_2":       "CVE-2023-45853",
    # Redis
    "Solvability.Redis_GoStdlib":      "CVE-2023-24538",
    "Solvability.Redis_GoStdlib_2":    "CVE-2023-24540",
    # MySQL (in wordpress_web_stack_v3)
    "Solvability.MySQL_RCE":           "CVE-2022-21417",
    # Network devices
    "Solvability.PanOS_CMDInject":     "CVE-2024-3400",
    "Solvability.FortiOS_SSLVPN_RCE":  "CVE-2023-27997",
    "Solvability.FortiOS_AuthBypass":  "CVE-2020-12812",
    "Solvability.CiscoNXOS_LLDP":      "CVE-2018-0395",
    "Solvability.CiscoNXOS_FCoE":      "CVE-2019-1595",
    "Solvability.PanOS_TOCTOU":        "CVE-2021-3054",
    "Solvability.CiscoASA_OSPF":       "CVE-2026-20020",
    "Solvability.CiscoIOS_XE_PrivEsc": "CVE-2023-20198",
    "Solvability.CiscoNXOS_CMDInject": "CVE-2017-12334",
    "Solvability.CiscoNXOS_CMDInject2":"CVE-2017-12341",
    "Solvability.F5_BIGIP_AuthBypass": "CVE-2022-1388",
    "Solvability.F5_BIGIP_RCE":        "CVE-2021-22986",
    "Solvability.Citrix_Bleed":        "CVE-2023-4966",
    "Solvability.Citrix_ADC_RCE":      "CVE-2022-27510",
    # SCADA / ICS
    "Solvability.FactoryTalk_Deser":   "CVE-2021-27462",
    "Solvability.FactoryTalk_CMDInject":"CVE-2021-27476",
    "Solvability.FactoryTalk_SQLInject":"CVE-2016-4522",
    "Solvability.FactoryTalk_CredLeak":"CVE-2024-21917",
    "Solvability.MicroLogix_BufferOverflow":"CVE-2017-16740",
    "Solvability.Logix5000_AuthBypass":"CVE-2016-9343",
    "Solvability.Rockwell_KeyReuse":   "CVE-2021-22681",
    "Solvability.Modicon_AuthBypass":  "CVE-2018-7760",
    "Solvability.Modicon_HTTPInject":  "CVE-2018-7761",
    "Solvability.OPC_UA_RCE":          "CVE-2023-32784",
    "Solvability.DNP3_Spoof":          "CVE-2013-2789",
    "Solvability.Modbus_AuthBypass":   "CVE-2018-10952",
    "Solvability.Siemens_S7_KeyLeak":  "CVE-2022-38465",
    "Solvability.Siemens_S7_AuthBypass":"CVE-2019-13945",
    "Solvability.WinCC_HardcodedPwd":  "CVE-2010-2772",
    "Solvability.FactoryTalk_HardcodedKey":"CVE-2023-2637",
    "Solvability.FactoryTalk_BackupExpose":"CVE-2023-2638",
    "Solvability.Wonderware_BufferOverflow":"CVE-2017-9629",
    # SCADA_AD hybrid specific
    "Solvability.FactoryTalk_RCE":     "CVE-2022-38766",
    "Solvability.OPCUA_BufferOverflow":"CVE-2023-27267",
    "Solvability.Modicon_StackOverflow":"CVE-2022-3977",
}

# CVE IDs that appear in vulnerability *descriptions* in wordpress_web_stack_v3
# (those domain entries use catalog names like WordPress_ImageMagick but point
#  to older CVEs in their description text)
DESC_CVE_OVERRIDE: Dict[str, str] = {
    # wordpress_web_stack_v3 re-maps some vulnerability names to older CVEs
    # We detect these by reading the description field
    "CVE-2022-44268": "CVE-2022-44268",   # ImageMagick v3 entry 1
    "CVE-2023-34151": "CVE-2023-34151",   # ImageMagick v3 entry 2
    "CVE-2023-0464":  "CVE-2023-0464",    # Nginx LibCrypto in v3
}


# =============================================================================
# Helpers
# =============================================================================

def _extract_cve_from_description(desc: str) -> str | None:
    """Pull the first CVE-YYYY-NNNNN string from a description field."""
    import re
    m = re.search(r"CVE-\d{4}-\d{4,7}", desc)
    return m.group(0) if m else None


def _load_domain_vulns(yaml_path: Path) -> Dict[str, List[dict]]:
    """
    Return a dict: category → list of {name, cve, cvss, description} for
    every solvability vulnerability in the YAML config.
    """
    with open(yaml_path) as f:
        cfg = yaml.safe_load(f) or {}

    results: Dict[str, List[dict]] = defaultdict(list)
    solv = cfg.get("solvability_vulnerabilities", {})
    for cat, entries in solv.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            name = entry.get("name", "")
            desc = entry.get("description", "")
            sr   = entry.get("success_rate", 0.0)
            cost = entry.get("cost", 0.0)
            prob = entry.get("probability", 0.0)

            # Resolve CVE: from name map first, then description
            cve = VULN_TO_CVE.get(name)
            if not cve:
                cve = _extract_cve_from_description(desc)

            db_entry = CVE_DATABASE.get(cve, {}) if cve else {}
            cvss = db_entry.get("cvss", 0.0)

            results[cat].append({
                "name":         name,
                "cve":          cve,
                "cvss":         cvss,
                "success_rate": sr,
                "cost":         cost,
                "probability":  prob,
                "description":  desc,
                "tactics":      db_entry.get("tactics", []),
                "techniques":   db_entry.get("techniques", []),
                "category":     db_entry.get("category", "Unknown"),
                "platform":     db_entry.get("platform", "Unknown"),
                "label":        db_entry.get("label", name),
            })
    return results


def _domain_stats(domain_name: str, vuln_map: Dict[str, List[dict]]) -> dict:
    all_entries = [e for entries in vuln_map.values() for e in entries]
    cves        = [e["cve"] for e in all_entries if e["cve"]]
    unique_cves = list(dict.fromkeys(cves))  # preserves order, deduplicates

    cvss_scores = [e["cvss"] for e in all_entries if e["cvss"] > 0]
    tactics_all: List[str] = []
    for e in all_entries:
        tactics_all.extend(e["tactics"])
    unique_tactics = list(dict.fromkeys(tactics_all))

    techniques_all: List[str] = []
    for e in all_entries:
        techniques_all.extend(e["techniques"])
    unique_techniques = list(dict.fromkeys(techniques_all))

    # CVSS severity bands
    critical = [c for c in cvss_scores if c >= 9.0]
    high     = [c for c in cvss_scores if 7.0 <= c < 9.0]
    medium   = [c for c in cvss_scores if 4.0 <= c < 7.0]
    low      = [c for c in cvss_scores if c < 4.0]

    # Entry exploits (remote_access category)
    entry_cves = [e["cve"] for e in vuln_map.get("remote_access", []) if e["cve"]]

    # Platform diversity
    platforms = list({e["platform"] for e in all_entries if e["platform"] not in ("Unknown", "")})

    return {
        "domain":             domain_name,
        "total_vulns":        len(all_entries),
        "unique_cves":        unique_cves,
        "unique_cve_count":   len(unique_cves),
        "unique_tactics":     unique_tactics,
        "unique_tactic_count":len(unique_tactics),
        "unique_techniques":  unique_techniques,
        "unique_tech_count":  len(unique_techniques),
        "cvss_critical":      len(critical),
        "cvss_high":          len(high),
        "cvss_medium":        len(medium),
        "cvss_low":           len(low),
        "cvss_mean":          round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0,
        "cvss_min":           round(min(cvss_scores), 1) if cvss_scores else 0,
        "cvss_max":           round(max(cvss_scores), 1) if cvss_scores else 0,
        "entry_cves":         list(dict.fromkeys(entry_cves)),
        "platforms":          platforms,
        "platform_count":     len(platforms),
        "has_ics_tactics":    any(t.startswith("ICS") for t in unique_tactics),
        "kill_chain_phases":  len({c for t in unique_tactics
                                    for c in [
                                        "entry" if t in ("TA0001","ICS-IA") else
                                        "exec"  if t in ("TA0002","ICS-EX") else
                                        "cred"  if t in ("TA0006",) else
                                        "priv"  if t in ("TA0004",) else
                                        "latmov"if t in ("TA0008","ICS-LM") else
                                        "impact"if t in ("TA0040","ICS-IM","ICS-IT") else
                                        "other"
                                    ]}),
    }


# =============================================================================
# Report generators
# =============================================================================

def _md_table(headers: List[str], rows: List[List[str]]) -> str:
    """Render a markdown table."""
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    h   = "| " + " | ".join(headers) + " |"
    body = "\n".join("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return h + "\n" + sep + "\n" + body + "\n"


def _severity_bar(critical: int, high: int, medium: int, low: int, total: int) -> str:
    if total == 0:
        return "—"
    parts = []
    if critical: parts.append(f"{critical}×CRIT")
    if high:     parts.append(f"{high}×HIGH")
    if medium:   parts.append(f"{medium}×MED")
    if low:      parts.append(f"{low}×LOW")
    return ", ".join(parts) if parts else "—"


def build_markdown_report(domain_stats: List[dict], vuln_maps: Dict[str, Dict]) -> str:
    lines: List[str] = []
    lines.append("# MITRE ATT&CK Analysis — CyberBattleSimDomainGenerator\n")
    lines.append(f"**Domains analysed:** {len(domain_stats)}  \n")
    total_cves = sum(s["unique_cve_count"] for s in domain_stats)
    all_cves   = set(c for s in domain_stats for c in s["unique_cves"])
    lines.append(f"**Total unique CVEs (dataset-wide):** {len(all_cves)}  \n")
    lines.append(f"**Total MITRE tactics observed:** "
                 f"{len({t for s in domain_stats for t in s['unique_tactics']})}  \n\n")

    # ---- 1. CVE Taxonomy Table ----
    lines.append("---\n")
    lines.append("## 1  CVE Taxonomy\n")
    lines.append("Full classification of every CVE used in the dataset.\n\n")
    rows = []
    for cve_id, meta in sorted(CVE_DATABASE.items()):
        # Only include CVEs actually referenced in active domains
        if cve_id not in all_cves:
            continue
        tac_str   = ", ".join(meta["tactics"])
        tech_str  = ", ".join(meta["techniques"])
        sev = ("🔴 CRIT" if meta["cvss"] >= 9.0 else
               "🟠 HIGH" if meta["cvss"] >= 7.0 else
               "🟡 MED"  if meta["cvss"] >= 4.0 else
               "🟢 LOW")
        rows.append([
            cve_id,
            meta["label"][:45],
            str(meta["cvss"]),
            sev,
            meta["platform"][:20],
            meta["category"],
            tac_str,
            tech_str,
        ])
    lines.append(_md_table(
        ["CVE ID", "Label", "CVSS", "Severity", "Platform", "Category",
         "MITRE Tactics", "Techniques"],
        rows,
    ))

    # ---- 2. Per-domain summary table ----
    lines.append("\n---\n")
    lines.append("## 2  Per-Domain Summary Statistics\n\n")
    sum_rows = []
    for s in domain_stats:
        tactics_str = ", ".join(TACTIC_SHORT.get(t, t) for t in s["unique_tactics"])
        sev_str     = _severity_bar(s["cvss_critical"], s["cvss_high"],
                                    s["cvss_medium"], s["cvss_low"],
                                    s["unique_cve_count"])
        sum_rows.append([
            s["domain"],
            str(s["unique_cve_count"]),
            f"{s['cvss_mean']} (σ {s['cvss_min']}–{s['cvss_max']})",
            sev_str,
            str(s["unique_tactic_count"]),
            str(s["unique_tech_count"]),
            str(s["kill_chain_phases"]),
            str(s["platform_count"]),
            "✓" if s["has_ics_tactics"] else "",
            tactics_str,
        ])
    lines.append(_md_table(
        ["Domain", "# CVEs", "CVSS (range)", "Severity dist.",
         "# Tactics", "# Techniques", "Kill-chain phases",
         "# Platforms", "ICS?", "Tactics covered"],
        sum_rows,
    ))

    # ---- 3. Tactic × Domain heatmap ----
    lines.append("\n---\n")
    lines.append("## 3  Tactic × Domain Coverage Heatmap\n\n")
    all_tactics = sorted({t for s in domain_stats for t in s["unique_tactics"]})
    domain_names = [s["domain"] for s in domain_stats]
    hdr = ["Tactic"] + [d[:14] for d in domain_names]
    hmap_rows = []
    for tac in all_tactics:
        row = [f"{tac} — {TACTICS.get(tac, tac)}"]
        for s in domain_stats:
            row.append("✓" if tac in s["unique_tactics"] else "")
        hmap_rows.append(row)
    lines.append(_md_table(hdr, hmap_rows))

    # ---- 4. Technique → domains ----
    lines.append("\n---\n")
    lines.append("## 4  MITRE Technique Usage Across Domains\n\n")
    all_techs = sorted({t for s in domain_stats for t in s["unique_techniques"]})
    tech_rows = []
    for tech in all_techs:
        domains_using = [s["domain"][:14] for s in domain_stats if tech in s["unique_techniques"]]
        cve_count_for_tech = sum(
            1 for cve, meta in CVE_DATABASE.items()
            if tech in meta.get("techniques", []) and cve in all_cves
        )
        tech_rows.append([
            tech,
            TECHNIQUES.get(tech, tech)[:55],
            str(cve_count_for_tech),
            str(len(domains_using)),
            ", ".join(domains_using),
        ])
    tech_rows.sort(key=lambda r: -int(r[3]))  # sort by domain count desc
    lines.append(_md_table(
        ["Technique ID", "Name", "# CVEs", "# Domains", "Domains"],
        tech_rows,
    ))

    # ---- 5. Per-domain deep-dives ----
    lines.append("\n---\n")
    lines.append("## 5  Per-Domain CVE Detail\n\n")
    for s in domain_stats:
        lines.append(f"### {s['domain']}\n\n")
        vm = vuln_maps[s["domain"]]
        all_entries = [e for entries in vm.values() for e in entries]
        cve_rows = []
        seen = set()
        for e in all_entries:
            if not e["cve"] or e["cve"] in seen:
                continue
            seen.add(e["cve"])
            meta = CVE_DATABASE.get(e["cve"], {})
            sev = ("CRIT" if e["cvss"] >= 9.0 else
                   "HIGH" if e["cvss"] >= 7.0 else
                   "MED"  if e["cvss"] >= 4.0 else
                   "LOW")
            cve_rows.append([
                e["cve"],
                meta.get("label", e["name"])[:45],
                str(e["cvss"]),
                sev,
                meta.get("category", "—"),
                ", ".join(e["tactics"]) or "—",
                ", ".join(e["techniques"]) or "—",
            ])
        cve_rows.sort(key=lambda r: -float(r[2]))
        lines.append(_md_table(
            ["CVE", "Label", "CVSS", "Sev", "Category", "Tactics", "Techniques"],
            cve_rows,
        ))
        lines.append(
            f"**Kill-chain phases:** {s['kill_chain_phases']}  "
            f"| **Avg CVSS:** {s['cvss_mean']}  "
            f"| **ICS tactics:** {'Yes' if s['has_ics_tactics'] else 'No'}  \n\n"
        )

    # ---- 6. Cross-domain Jaccard similarity ----
    lines.append("\n---\n")
    lines.append("## 6  Cross-Domain CVE Jaccard Similarity\n\n")
    lines.append("Pairwise Jaccard similarity based on shared CVE sets (0 = no overlap, 1 = identical).\n\n")
    cve_sets = {s["domain"]: set(s["unique_cves"]) for s in domain_stats}
    names = list(cve_sets.keys())
    jac_hdr = ["Domain"] + [n[:14] for n in names]
    jac_rows = []
    for na in names:
        row = [na[:20]]
        for nb in names:
            if na == nb:
                row.append("—")
            else:
                inter = len(cve_sets[na] & cve_sets[nb])
                union = len(cve_sets[na] | cve_sets[nb])
                j = round(inter / union, 2) if union else 0
                row.append(str(j))
        jac_rows.append(row)
    lines.append(_md_table(jac_hdr, jac_rows))

    # ---- 7. Quality assessment ----
    lines.append("\n---\n")
    lines.append("## 7  Dataset Quality Assessment\n\n")
    lines.append("Quality dimensions computed across the 8 active domain configurations.\n\n")

    q_rows = []
    for s in domain_stats:
        # CVE diversity score: unique CVEs / total vuln slots (higher = less reuse)
        total = s["total_vulns"]
        div_score = round(s["unique_cve_count"] / total, 2) if total else 0
        # Tactic coverage score: # tactics / 11 enterprise + 5 ICS = 16 possible
        tac_cov = round(s["unique_tactic_count"] / 11, 2)  # vs enterprise tactics only
        # Severity quality: fraction of CRIT+HIGH
        sev_frac = round((s["cvss_critical"] + s["cvss_high"]) / s["unique_cve_count"], 2) \
                   if s["unique_cve_count"] else 0
        q_rows.append([
            s["domain"],
            str(div_score),
            str(tac_cov),
            str(s["kill_chain_phases"]) + "/6",
            str(sev_frac),
            "✓" if s["has_ics_tactics"] else "",
        ])
    lines.append(_md_table(
        ["Domain", "CVE diversity", "Tactic coverage (vs 11 ent.)",
         "Kill-chain depth", "CRIT+HIGH fraction", "ICS tactics"],
        q_rows,
    ))

    return "\n".join(lines)


# =============================================================================
# LaTeX report
# =============================================================================
_PREAMBLE = r"""
\documentclass[11pt,a4paper]{article}
\usepackage{geometry,booktabs,longtable,colortbl,xcolor,hyperref,amssymb}
\geometry{margin=2.0cm}
\definecolor{crit}{HTML}{D32F2F}
\definecolor{high}{HTML}{F57C00}
\definecolor{med}{HTML}{FBC02D}
\definecolor{low}{HTML}{388E3C}
\definecolor{covyes}{HTML}{C8E6C9}
\definecolor{covno}{HTML}{FFCDD2}
\hypersetup{colorlinks=true,linkcolor=blue,urlcolor=blue}
\title{\textbf{MITRE ATT\&CK Analysis}\\
       \large CyberBattleSimDomainGenerator Dataset}
\author{Generated by \texttt{mitre\_attack\_analysis.py}}
\date{\today}
\begin{document}
\maketitle\tableofcontents\clearpage
"""
_POSTAMBLE = r"\end{document}"


def _latex_escape(s: str) -> str:
    """Minimal LaTeX escaping for table cells. Backslash MUST go first."""
    s = str(s).replace("\\", r"\textbackslash{}")
    s = s.replace("&", r"\&")
    s = s.replace("%", r"\%")
    s = s.replace("$", r"\$")
    s = s.replace("#", r"\#")
    s = s.replace("_", r"\_")
    s = s.replace("{", r"\{")
    s = s.replace("}", r"\}")
    s = s.replace("~", r"\textasciitilde{}")
    s = s.replace("^", r"\^{}")
    return s


def _sev_cell(cvss: float) -> str:
    if cvss >= 9.0: return r"\cellcolor{crit}\textcolor{white}{CRIT}"
    if cvss >= 7.0: return r"\cellcolor{high}HIGH"
    if cvss >= 4.0: return r"\cellcolor{med}MED"
    return r"\cellcolor{low}\textcolor{white}{LOW}"


def build_latex_report(domain_stats: List[dict], vuln_maps: Dict[str, Dict]) -> str:
    all_cves = set(c for s in domain_stats for c in s["unique_cves"])
    body: List[str] = []

    # ---- Section 1: CVE taxonomy ----
    body.append(r"\section{CVE Taxonomy}")
    body.append(r"All \textbf{" + str(len(all_cves)) + r"} unique CVEs referenced across the "
                r"eight active domain configurations, classified by MITRE ATT\&CK tactic and technique.")
    body.append(r"""
\begin{longtable}{@{}p{2.8cm}p{4.5cm}p{0.8cm}p{1.0cm}p{2.2cm}p{2.5cm}@{}}
\toprule
\textbf{CVE} & \textbf{Label} & \textbf{CVSS} & \textbf{Sev} & \textbf{Primary Tactic} & \textbf{Technique(s)} \\
\midrule
\endhead
""")
    for cve_id in sorted(all_cves):
        if cve_id not in CVE_DATABASE:
            continue
        m = CVE_DATABASE[cve_id]
        tac  = m["tactics"][0] if m["tactics"] else "—"
        tech = m["techniques"][0] if m["techniques"] else "—"
        body.append(
            f"\\texttt{{{_latex_escape(cve_id)}}} & "
            f"{_latex_escape(m['label'][:48])} & "
            f"{m['cvss']} & "
            f"{_sev_cell(m['cvss'])} & "
            f"\\texttt{{{_latex_escape(tac)}}} & "
            f"\\texttt{{{_latex_escape(tech)}}} \\\\"
        )
    body.append(r"\bottomrule\end{longtable}")

    # ---- Section 2: Per-domain summary ----
    body.append(r"\section{Per-Domain Summary Statistics}")
    body.append(r"""
\begin{longtable}{@{}p{3.5cm}rrrrrrc@{}}
\toprule
\textbf{Domain} & \textbf{\#CVE} & \textbf{Avg CVSS} &
\textbf{CRIT} & \textbf{HIGH} & \textbf{Tactics} & \textbf{Techniques} &
\textbf{ICS?} \\
\midrule
\endhead
""")
    for s in domain_stats:
        ics = r"\checkmark" if s["has_ics_tactics"] else ""
        body.append(
            f"{_latex_escape(s['domain'])} & "
            f"{s['unique_cve_count']} & "
            f"{s['cvss_mean']} & "
            f"{s['cvss_critical']} & "
            f"{s['cvss_high']} & "
            f"{s['unique_tactic_count']} & "
            f"{s['unique_tech_count']} & "
            f"{ics} \\\\"
        )
    body.append(r"\bottomrule\end{longtable}")

    # ---- Section 3: Tactic heatmap ----
    body.append(r"\section{Tactic $\times$ Domain Coverage Heatmap}")
    all_tactics = sorted({t for s in domain_stats for t in s["unique_tactics"]})
    n = len(domain_stats)
    col_spec = "p{4.0cm}" + "c" * n
    body.append(r"\begin{table}[ht]\centering\small")
    body.append(r"\begin{tabular}{" + col_spec + r"}\toprule")
    short_names = [s["domain"].replace("_", "\\_")[:12] for s in domain_stats]
    body.append(r"\textbf{Tactic} & " + " & ".join(
        r"\rotatebox{70}{\scriptsize " + n + "}" for n in short_names
    ) + r" \\")
    body.append(r"\midrule")
    for tac in all_tactics:
        name = TACTICS.get(tac, tac)
        cells = []
        for s in domain_stats:
            if tac in s["unique_tactics"]:
                cells.append(r"\cellcolor{covyes}$\checkmark$")
            else:
                cells.append(r"\cellcolor{covno}$\times$")
        body.append(
            f"\\texttt{{{_latex_escape(tac)}}} {_latex_escape(name)} & " +
            " & ".join(cells) + r" \\"
        )
    body.append(r"\bottomrule\end{tabular}")
    body.append(r"\caption{Tactic coverage heatmap. \colorbox{covyes}{Green}=covered, "
                r"\colorbox{covno}{Red}=not covered.}")
    body.append(r"\end{table}")

    # ---- Section 4: Jaccard similarity ----
    body.append(r"\section{Cross-Domain CVE Jaccard Similarity}")
    cve_sets   = {s["domain"]: set(s["unique_cves"]) for s in domain_stats}
    names      = list(cve_sets.keys())
    n          = len(names)
    col_spec2  = "l" + "c" * n
    body.append(r"\begin{table}[ht]\centering\small")
    body.append(r"\begin{tabular}{" + col_spec2 + r"}\toprule")
    body.append(r" & " + " & ".join(
        r"\rotatebox{70}{\scriptsize " + _latex_escape(nm[:14]) + "}" for nm in names
    ) + r" \\")
    body.append(r"\midrule")
    for na in names:
        row_cells = [_latex_escape(na[:18])]
        for nb in names:
            if na == nb:
                row_cells.append("—")
            else:
                inter = len(cve_sets[na] & cve_sets[nb])
                union = len(cve_sets[na] | cve_sets[nb])
                j = round(inter / union, 2) if union else 0.0
                # colour-scale
                if   j >= 0.5: col = r"\cellcolor{high}"
                elif j >= 0.2: col = r"\cellcolor{med}"
                else:           col = ""
                row_cells.append(f"{col}{j:.2f}")
        body.append(" & ".join(row_cells) + r" \\")
    body.append(r"\bottomrule\end{tabular}")
    body.append(r"\caption{Pairwise Jaccard similarity (CVE sets). "
                r"\colorbox{high}{Orange} $\geq 0.5$, "
                r"\colorbox{med}{Yellow} $\geq 0.2$.}")
    body.append(r"\end{table}")

    # ---- Section 5: Quality assessment ----
    body.append(r"\section{Dataset Quality Assessment}")
    body.append(r"""
\begin{table}[ht]\centering
\begin{tabular}{@{}lcccccc@{}}
\toprule
\textbf{Domain} & \textbf{CVE diversity} & \textbf{Tactic cov.} &
\textbf{Kill-chain} & \textbf{CRIT+HIGH \%} & \textbf{ICS} \\
\midrule
""")
    for s in domain_stats:
        total = s["total_vulns"]
        div   = round(s["unique_cve_count"] / total, 2) if total else 0
        tac   = round(s["unique_tactic_count"] / 11, 2)
        sev_f = round((s["cvss_critical"] + s["cvss_high"]) / s["unique_cve_count"] * 100)  \
                if s["unique_cve_count"] else 0
        ics   = r"\checkmark" if s["has_ics_tactics"] else ""
        body.append(
            f"{_latex_escape(s['domain'])} & {div} & {tac} & "
            f"{s['kill_chain_phases']}/6 & {sev_f}\\% & {ics} \\\\"
        )
    body.append(r"""\bottomrule
\end{tabular}
\caption{Quality dimensions: CVE diversity = unique CVEs / total vulnerability slots;
tactic coverage vs.\ 11 enterprise tactics; kill-chain phases = distinct attack-stage categories covered.}
\end{table}""")

    return _PREAMBLE + "\n".join(body) + "\n" + _POSTAMBLE


# =============================================================================
# Main
# =============================================================================
_ACTIVE_DOMAINS = [
    "enterprise_ad_v6",
    "jenkins_cicd_v2",
    "network_device_infra_v3",
    "scada_ad_hybrid_v1",
    "scada_ics_v2",
    "wordpress_ad_hybrid_v3",
    "wordpress_jenkins_hybrid_v1",
    "wordpress_web_stack_v3",
]


def main():
    parser = argparse.ArgumentParser(description="MITRE ATT&CK CVE analysis for CyberBattleSim domains")
    parser.add_argument("--data-dir",  default="data",
                        help="Directory containing domain YAML configs (default: data)")
    parser.add_argument("--out-dir",
                        default="/content/drive/MyDrive/thesis/code/datasets/poc/claude",
                        help="Output directory for reports")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    out_dir  = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  MITRE ATT&CK ANALYSIS")
    print("=" * 60)

    # Load domain configs
    vuln_maps:    Dict[str, Dict] = {}
    domain_stats: List[dict]      = []

    for domain in _ACTIVE_DOMAINS:
        yaml_path = data_dir / f"{domain}.yaml"
        if not yaml_path.is_file():
            print(f"  WARN  {domain}.yaml not found — skipping")
            continue
        print(f"  Loading {domain} ...")
        vm    = _load_domain_vulns(yaml_path)
        stats = _domain_stats(domain, vm)
        vuln_maps[domain]  = vm
        domain_stats.append(stats)
        print(f"    CVEs: {stats['unique_cve_count']}  Tactics: {stats['unique_tactic_count']}  "
              f"CVSS avg: {stats['cvss_mean']}")

    print()
    all_cves_global = set(c for s in domain_stats for c in s["unique_cves"])
    print(f"  Dataset-wide unique CVEs: {len(all_cves_global)}")
    print(f"  Dataset-wide unique tactics: {len({t for s in domain_stats for t in s['unique_tactics']})}")

    # ---- Write JSON ----
    taxonomy_path = out_dir / "mitre_cve_taxonomy.json"
    with open(taxonomy_path, "w") as f:
        export = {
            cve: {**CVE_DATABASE[cve], "tactic_labels": [TACTICS.get(t, t) for t in CVE_DATABASE[cve]["tactics"]]}
            for cve in sorted(all_cves_global) if cve in CVE_DATABASE
        }
        json.dump(export, f, indent=2)
    print(f"  Taxonomy JSON: {taxonomy_path}")

    stats_path = out_dir / "mitre_domain_stats.json"
    with open(stats_path, "w") as f:
        json.dump(domain_stats, f, indent=2)
    print(f"  Stats JSON:    {stats_path}")

    # ---- Write Markdown ----
    md_path = out_dir / "mitre_analysis.md"
    md_text = build_markdown_report(domain_stats, vuln_maps)
    with open(md_path, "w") as f:
        f.write(md_text)
    print(f"  Markdown:      {md_path}")

    # ---- Write LaTeX + compile PDF ----
    tex_path = out_dir / "mitre_analysis.tex"
    tex_text = build_latex_report(domain_stats, vuln_maps)
    with open(tex_path, "w") as f:
        f.write(tex_text)
    print(f"  LaTeX source:  {tex_path}")

    pdf_path = out_dir / "mitre_analysis.pdf"
    try:
        for _ in range(2):  # two passes for TOC
            r = subprocess.run(
                ["pdflatex", "-interaction=nonstopmode", "-output-directory",
                 str(out_dir), str(tex_path)],
                capture_output=True, text=True, timeout=120,
            )
        if (out_dir / "mitre_analysis.pdf").is_file():
            print(f"  PDF:           {pdf_path}")
        else:
            print("  WARN: pdflatex ran but no PDF produced — check .log")
    except FileNotFoundError:
        print("  WARN: pdflatex not found — PDF not generated")
    except Exception as e:
        print(f"  WARN: pdflatex error — {e}")

    print("=" * 60)
    print("  Done.")
    print("=" * 60)


if __name__ == "__main__":
    main()
