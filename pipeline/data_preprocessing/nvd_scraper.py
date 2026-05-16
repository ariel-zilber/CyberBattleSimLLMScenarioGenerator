"""
tools/nvd_scraper.py
====================
Query the NVD API v2 to collect Windows-specific CVE data for grounding
CyberBattleSim scenario parameters.

Two query modes:
  1. Direct lookup  — fetch a curated list of well-known Windows exploit CVEs by ID
  2. Keyword search — fetch recent HIGH/CRITICAL CVEs for each Windows product category

Output: data/vulnerability_db/windows_cves.json  (same schema as bitnami_cves.json)

Usage (standalone):
    python tools/nvd_scraper.py --out data/vulnerability_db/windows_cves.json
    python tools/nvd_scraper.py --api-key <key> --out /tmp/win_cves.json

NVD API v2 docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limits: 5 req/30 s (no key) | 50 req/30 s (with key)
"""
from __future__ import annotations

import json
import time
import re
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# ── Constants ─────────────────────────────────────────────────────────────────

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Delay between requests (seconds) to stay within rate limits
REQUEST_DELAY_NO_KEY  = 6.5   # 5 req/30 s → ~1 per 6 s (with margin)
REQUEST_DELAY_WITH_KEY = 0.65  # 50 req/30 s

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0,
}

# ── Well-known Windows CVEs (direct lookup) ───────────────────────────────────
#
# Curated list of high-value Windows CVEs that map to existing CBS vulnerability
# catalog entries. These are fetched by CVE ID to get ground-truth CVSS data.

KNOWN_WINDOWS_CVES: list[dict] = [
    # SMB / EternalBlue family
    {"id": "CVE-2017-0144", "category": "smb",              "label": "EternalBlue"},
    {"id": "CVE-2020-0796", "category": "smb",              "label": "SMBGhost"},
    {"id": "CVE-2017-0147", "category": "smb",              "label": "EternalRomance"},
    {"id": "CVE-2008-4250", "category": "smb",              "label": "MS08_067"},
    {"id": "CVE-2020-17096", "category": "smb",             "label": "NTFS_RCE"},
    {"id": "CVE-2022-32230", "category": "smb",             "label": "SMB_InfDisc"},
    # RDP
    {"id": "CVE-2019-0708", "category": "rdp",              "label": "BlueKeep"},
    {"id": "CVE-2019-1182", "category": "rdp",              "label": "DejaBlue"},
    {"id": "CVE-2018-0886", "category": "rdp",              "label": "CredSSP"},
    {"id": "CVE-2019-1226", "category": "rdp",              "label": "RDP_RCE_1226"},
    {"id": "CVE-2019-1225", "category": "rdp",              "label": "RDP_InfoDisc"},
    {"id": "CVE-2019-0787", "category": "rdp",              "label": "RDP_RCE_0787"},
    {"id": "CVE-2019-0788", "category": "rdp",              "label": "RDP_RCE_0788"},
    {"id": "CVE-2020-0655", "category": "rdp",              "label": "RDG_RCE"},
    {"id": "CVE-2023-35352", "category": "rdp",             "label": "RD_Cert_Bypass"},
    # Active Directory / Kerberos
    {"id": "CVE-2020-1472", "category": "active_directory", "label": "ZeroLogon"},
    {"id": "CVE-2021-42287", "category": "active_directory","label": "noPac_1"},
    {"id": "CVE-2021-42278", "category": "active_directory","label": "noPac_2"},
    {"id": "CVE-2021-36942", "category": "active_directory","label": "PetitPotam"},
    {"id": "CVE-2022-26931", "category": "active_directory","label": "Kerberos_EOP"},
    {"id": "CVE-2022-37958", "category": "active_directory","label": "NetNTLMv2_Downgrade"},
    {"id": "CVE-2021-36949", "category": "active_directory","label": "MSAA_Priv"},
    {"id": "CVE-2023-28244", "category": "active_directory","label": "Kerberos_EOP_2"},
    {"id": "CVE-2022-21896", "category": "active_directory","label": "Kerberos_EOP_3"},
    {"id": "CVE-2022-21857", "category": "active_directory","label": "AD_Services_EOP"},
    {"id": "CVE-2023-21524", "category": "active_directory","label": "LSASS_EOP"},
    # ADCS (Certificate Services)
    {"id": "CVE-2022-26923", "category": "adcs",            "label": "Certifried"},
    {"id": "CVE-2022-34691", "category": "adcs",            "label": "ADCS_CertSpoof"},
    {"id": "CVE-2024-26212", "category": "adcs",            "label": "ADCS_EOP_1"},
    {"id": "CVE-2024-26233", "category": "adcs",            "label": "ADCS_EOP_2"},
    {"id": "CVE-2024-30082", "category": "adcs",            "label": "ADCS_EOP_3"},
    {"id": "CVE-2022-26929", "category": "adcs",            "label": "ADCS_EOP_4"},
    {"id": "CVE-2023-36368", "category": "adcs",            "label": "ADCS_InfDisc"},
    # Print Spooler
    {"id": "CVE-2021-34527", "category": "print_spooler",   "label": "PrintNightmare"},
    {"id": "CVE-2022-38028", "category": "print_spooler",   "label": "SpoolSample"},
    {"id": "CVE-2022-30206", "category": "print_spooler",   "label": "Spooler_EOP_1"},
    {"id": "CVE-2022-22022", "category": "print_spooler",   "label": "Spooler_EOP_2"},
    {"id": "CVE-2021-36958", "category": "print_spooler",   "label": "Spooler_RCE"},
    {"id": "CVE-2021-34483", "category": "print_spooler",   "label": "Spooler_EOP_3"},
    {"id": "CVE-2022-30226", "category": "print_spooler",   "label": "Spooler_EOP_4"},
    # IIS
    {"id": "CVE-2021-31166", "category": "iis",             "label": "HTTP_Protocol_Stack"},
    {"id": "CVE-2022-21907", "category": "iis",             "label": "IIS_RCE"},
    {"id": "CVE-2021-27085", "category": "iis",             "label": "IIS_RCE_2"},
    {"id": "CVE-2022-30209", "category": "iis",             "label": "IIS_EOP"},
    {"id": "CVE-2022-21983", "category": "iis",             "label": "IIS_Spoofing"},
    {"id": "CVE-2023-36393", "category": "iis",             "label": "IIS_EOP_2"},
    {"id": "CVE-2021-40444", "category": "iis",             "label": "MSHTML_RCE"},
    # Exchange Server
    {"id": "CVE-2021-34473", "category": "exchange",        "label": "ProxyShell_RCE"},
    {"id": "CVE-2021-34523", "category": "exchange",        "label": "ProxyShell_Privesc"},
    {"id": "CVE-2021-26855", "category": "exchange",        "label": "ProxyLogon"},
    {"id": "CVE-2022-41040", "category": "exchange",        "label": "ProxyNotShell_SSRF"},
    {"id": "CVE-2022-41082", "category": "exchange",        "label": "ProxyNotShell_RCE"},
    {"id": "CVE-2023-21529", "category": "exchange",        "label": "Exchange_RCE_1"},
    {"id": "CVE-2023-21706", "category": "exchange",        "label": "Exchange_RCE_2"},
    {"id": "CVE-2023-21707", "category": "exchange",        "label": "Exchange_RCE_3"},
    {"id": "CVE-2024-21410", "category": "exchange",        "label": "Exchange_NTLM_Relay"},
    {"id": "CVE-2023-35368", "category": "exchange",        "label": "Exchange_RCE_4"},
    {"id": "CVE-2024-26198", "category": "exchange",        "label": "Exchange_RCE_5"},
    # MSSQL
    {"id": "CVE-2023-21688", "category": "mssql",           "label": "MSSQL_Privesc"},
    {"id": "CVE-2024-28995", "category": "mssql",           "label": "MSSQL_InfoDisc"},
    {"id": "CVE-2024-37338", "category": "mssql",           "label": "MSSQL_RCE_1"},
    {"id": "CVE-2024-37340", "category": "mssql",           "label": "MSSQL_RCE_2"},
    {"id": "CVE-2024-37342", "category": "mssql",           "label": "MSSQL_RCE_3"},
    # NTLM relay / Outlook
    {"id": "CVE-2023-23397", "category": "ntlm_relay",      "label": "Outlook_NTLM"},
    {"id": "CVE-2022-26925", "category": "ntlm_relay",      "label": "LSA_Spoofing"},
    {"id": "CVE-2021-33757", "category": "ntlm_relay",      "label": "Netlogon_Auth"},
    {"id": "CVE-2023-21746", "category": "ntlm_relay",      "label": "NTLM_EOP"},
    {"id": "CVE-2022-24497", "category": "ntlm_relay",      "label": "NFS_RCE"},
    # WinRM / PowerShell
    {"id": "CVE-2021-31958", "category": "winrm",           "label": "WinRM_RCE"},
    {"id": "CVE-2022-22035", "category": "winrm",           "label": "PPTP_RCE"},
    {"id": "CVE-2023-36401", "category": "winrm",           "label": "Remote_Registry"},
    {"id": "CVE-2023-21722", "category": "winrm",           "label": "WinRM_EOP"},
    # Credential theft
    {"id": "CVE-2021-36934", "category": "credential",      "label": "HiveNightmare"},
    {"id": "CVE-2022-37969", "category": "credential",      "label": "CLFS_Privesc"},
    {"id": "CVE-2022-24474", "category": "credential",      "label": "Win_EOP_Cred"},
    {"id": "CVE-2023-21727", "category": "credential",      "label": "LSASS_EOP"},
    {"id": "CVE-2023-28229", "category": "credential",      "label": "CNG_EOP"},
    # ── NEW CATEGORIES ────────────────────────────────────────────────────────────
    # Windows Kernel / Win32k
    {"id": "CVE-2021-34486", "category": "kernel",          "label": "Win32k_EOP_1"},
    {"id": "CVE-2021-31979", "category": "kernel",          "label": "Kernel_EOP_1"},
    {"id": "CVE-2021-33771", "category": "kernel",          "label": "Kernel_EOP_2"},
    {"id": "CVE-2023-23376", "category": "kernel",          "label": "CLFS_EOP_1"},
    {"id": "CVE-2023-28252", "category": "kernel",          "label": "CLFS_EOP_2"},
    {"id": "CVE-2024-21338", "category": "kernel",          "label": "Kernel_EOP_3"},
    {"id": "CVE-2022-24521", "category": "kernel",          "label": "CLFS_EOP_3"},
    {"id": "CVE-2023-35359", "category": "kernel",          "label": "Win32k_EOP_2"},
    {"id": "CVE-2021-26868", "category": "kernel",          "label": "Win32k_EOP_3"},
    {"id": "CVE-2021-36955", "category": "kernel",          "label": "Kernel_EOP_4"},
    {"id": "CVE-2022-37989", "category": "kernel",          "label": "Kernel_EOP_5"},
    {"id": "CVE-2020-1027",  "category": "kernel",          "label": "Kernel_EOP_6"},
    {"id": "CVE-2022-21999", "category": "kernel",          "label": "Win32k_EOP_4"},
    {"id": "CVE-2022-41125", "category": "kernel",          "label": "CNG_EOP_2"},
    {"id": "CVE-2023-21674", "category": "kernel",          "label": "ALPC_EOP"},
    # TCP/IP Stack
    {"id": "CVE-2021-24074", "category": "tcpip",           "label": "TCPIP_RCE_1"},
    {"id": "CVE-2021-24094", "category": "tcpip",           "label": "TCPIP_RCE_2"},
    {"id": "CVE-2021-24086", "category": "tcpip",           "label": "TCPIP_DoS"},
    {"id": "CVE-2022-34715", "category": "tcpip",           "label": "NFS_RCE"},
    {"id": "CVE-2023-23392", "category": "tcpip",           "label": "HTTP3_RCE"},
    {"id": "CVE-2023-28243", "category": "tcpip",           "label": "PPTP_RCE"},
    {"id": "CVE-2022-35804", "category": "tcpip",           "label": "SMB_Client_RCE"},
    # DNS Server
    {"id": "CVE-2020-1350",  "category": "dns",             "label": "SIGRed"},
    {"id": "CVE-2021-26897", "category": "dns",             "label": "DNS_RCE_1"},
    {"id": "CVE-2021-26898", "category": "dns",             "label": "DNS_EOP"},
    {"id": "CVE-2023-28254", "category": "dns",             "label": "DNS_RCE_2"},
    {"id": "CVE-2023-23400", "category": "dns",             "label": "DNS_RCE_3"},
    {"id": "CVE-2021-28470", "category": "dns",             "label": "DNS_Client_RCE"},
    {"id": "CVE-2023-28305", "category": "dns",             "label": "DNS_RCE_4"},
    {"id": "CVE-2022-34693", "category": "dns",             "label": "DNS_Spoof"},
    # LDAP
    {"id": "CVE-2022-26919", "category": "ldap",            "label": "LDAP_RCE_1"},
    {"id": "CVE-2023-28283", "category": "ldap",            "label": "LDAP_RCE_2"},
    {"id": "CVE-2022-30216", "category": "ldap",            "label": "LDAP_Spoof"},
    {"id": "CVE-2022-22031", "category": "ldap",            "label": "LDAP_EOP"},
    {"id": "CVE-2023-21757", "category": "ldap",            "label": "LDAP_DoS"},
    {"id": "CVE-2023-21676", "category": "ldap",            "label": "LDAP_InfoDisc"},
    {"id": "CVE-2024-20674", "category": "ldap",            "label": "LDAP_AuthBypass"},
    # RPC / DCOM
    {"id": "CVE-2022-30149", "category": "rpc_dcom",        "label": "DCOM_RCE_1"},
    {"id": "CVE-2022-30221", "category": "rpc_dcom",        "label": "RPC_RCE_1"},
    {"id": "CVE-2023-21678", "category": "rpc_dcom",        "label": "RPC_EOP"},
    {"id": "CVE-2021-26414", "category": "rpc_dcom",        "label": "DCOM_AuthBypass"},
    {"id": "CVE-2022-26809", "category": "rpc_dcom",        "label": "RPC_RCE_2"},
    {"id": "CVE-2023-23405", "category": "rpc_dcom",        "label": "RPC_RCE_3"},
    # Hyper-V
    {"id": "CVE-2021-28476", "category": "hyper_v",         "label": "HyperV_RCE"},
    {"id": "CVE-2022-37977", "category": "hyper_v",         "label": "HyperV_DoS"},
    {"id": "CVE-2023-21766", "category": "hyper_v",         "label": "HyperV_InfoDisc"},
    {"id": "CVE-2023-35628", "category": "hyper_v",         "label": "HyperV_RCE_2"},
    {"id": "CVE-2022-35795", "category": "hyper_v",         "label": "HyperV_EOP"},
    # Windows Workstation / General OS services
    {"id": "CVE-2023-21822", "category": "workstation",     "label": "Win32k_EOP"},
    {"id": "CVE-2023-28250", "category": "workstation",     "label": "WSD_RCE"},
    {"id": "CVE-2023-21803", "category": "workstation",     "label": "iSCSI_RCE"},
    {"id": "CVE-2022-22021", "category": "workstation",     "label": "Edge_EOP"},
    {"id": "CVE-2023-21537", "category": "workstation",     "label": "MSMQ_EOP"},
    {"id": "CVE-2023-28260", "category": "workstation",     "label": "DotNet_EOP"},
    # Network Drivers / Bluetooth
    {"id": "CVE-2023-21739", "category": "bluetooth",       "label": "BT_EOP"},
    {"id": "CVE-2022-34703", "category": "bluetooth",       "label": "BT_EOP_2"},
    {"id": "CVE-2023-24931", "category": "bluetooth",       "label": "SChannel_EOP"},
    {"id": "CVE-2023-28224", "category": "bluetooth",       "label": "PPTP_DoS"},
    {"id": "CVE-2022-26828", "category": "bluetooth",       "label": "BT_EOP_3"},
    # ── S_Windows SUBSTITUTION CATEGORIES ────────────────────────────────────────
    # Replacing lateral movement categories (ntlm_relay, winrm, credential,
    # print_spooler, exchange, mssql, ldap, adcs) which moved to S_Lateral.
    # Note: wmi substituted with msmq — MSMQ has richer standalone RCE CVE pool.
    # Microsoft Office / Document Exploitation
    {"id": "CVE-2022-30190", "category": "office",          "label": "Follina"},
    {"id": "CVE-2023-36884", "category": "office",          "label": "OfficeHTML_RCE"},
    {"id": "CVE-2024-21413", "category": "office",          "label": "Outlook_Moniker"},
    {"id": "CVE-2022-21840", "category": "office",          "label": "Office_RCE_1"},
    {"id": "CVE-2022-41031", "category": "office",          "label": "Word_RCE"},
    {"id": "CVE-2023-36745", "category": "office",          "label": "Exchange_Preview_RCE"},
    {"id": "CVE-2021-42292", "category": "office",          "label": "Excel_SFB"},
    {"id": "CVE-2023-21715", "category": "office",          "label": "Publisher_SFB"},
    # Windows Task Scheduler Privilege Escalation
    {"id": "CVE-2019-1069",  "category": "task_scheduler",  "label": "Schtasks_EOP_1"},
    {"id": "CVE-2019-1170",  "category": "task_scheduler",  "label": "Schtasks_EOP_2"},
    {"id": "CVE-2022-21960", "category": "task_scheduler",  "label": "Schtasks_EOP_3"},
    {"id": "CVE-2023-21541", "category": "task_scheduler",  "label": "Schtasks_EOP_4"},
    {"id": "CVE-2022-44695", "category": "task_scheduler",  "label": "Schtasks_EOP_5"},
    {"id": "CVE-2023-28228", "category": "task_scheduler",  "label": "Schtasks_EOP_6"},
    {"id": "CVE-2024-26237", "category": "task_scheduler",  "label": "Schtasks_EOP_7"},
    {"id": "CVE-2022-30205", "category": "task_scheduler",  "label": "Schtasks_EOP_8"},
    # Microsoft Message Queuing (MSMQ) RCE
    {"id": "CVE-2023-21554", "category": "msmq",            "label": "QueueJumper"},
    {"id": "CVE-2023-28302", "category": "msmq",            "label": "MSMQ_DoS"},
    {"id": "CVE-2023-21769", "category": "msmq",            "label": "MSMQ_EOP"},
    {"id": "CVE-2023-35309", "category": "msmq",            "label": "MSMQ_RCE_2"},
    {"id": "CVE-2024-26208", "category": "msmq",            "label": "MSMQ_RCE_3"},
    {"id": "CVE-2024-30080", "category": "msmq",            "label": "MSMQ_RCE_4"},
    # Windows Netlogon / OS Authentication Bypass
    {"id": "CVE-2022-38023", "category": "netlogon",        "label": "Netlogon_EOP_1"},
    {"id": "CVE-2023-21728", "category": "netlogon",        "label": "Netlogon_Vuln"},
    {"id": "CVE-2022-21909", "category": "netlogon",        "label": "Netlogon_EOP_2"},
    {"id": "CVE-2023-21526", "category": "netlogon",        "label": "Netlogon_InfDisc"},
    {"id": "CVE-2023-36422", "category": "netlogon",        "label": "Netlogon_EOP_3"},
]

# ── Keyword queries for each product category ─────────────────────────────────
#
# Each entry runs one NVD keyword search to catch recent CVEs not in the
# curated list above.

KEYWORD_QUERIES: list[dict] = [
    # SMB
    {"keywords": "windows smb remote code execution",           "category": "smb",              "pages": 2},
    {"keywords": "windows server message block",                "category": "smb",              "pages": 1},
    # RDP
    {"keywords": "windows rdp remote code execution",           "category": "rdp",              "pages": 2},
    {"keywords": "windows remote desktop services",             "category": "rdp",              "pages": 1},
    # Active Directory
    {"keywords": "active directory kerberos privilege",         "category": "active_directory", "pages": 2},
    {"keywords": "windows netlogon domain controller",          "category": "active_directory", "pages": 2},
    {"keywords": "active directory elevation of privilege",     "category": "active_directory", "pages": 1},
    # ADCS
    {"keywords": "windows certificate services adcs",           "category": "adcs",             "pages": 2},
    {"keywords": "active directory certificate services",       "category": "adcs",             "pages": 1},
    # Print Spooler
    {"keywords": "windows print spooler",                       "category": "print_spooler",    "pages": 2},
    # IIS
    {"keywords": "internet information services iis",           "category": "iis",              "pages": 2},
    {"keywords": "windows http.sys",                            "category": "iis",              "pages": 1},
    # Exchange
    {"keywords": "microsoft exchange server remote",            "category": "exchange",         "pages": 3},
    {"keywords": "exchange server elevation privilege",         "category": "exchange",         "pages": 2},
    # MSSQL
    {"keywords": "microsoft sql server remote code",            "category": "mssql",            "pages": 2},
    {"keywords": "sql server database engine elevation",        "category": "mssql",            "pages": 1},
    # NTLM relay
    {"keywords": "windows ntlm authentication relay",           "category": "ntlm_relay",       "pages": 2},
    {"keywords": "windows new technology lan manager",          "category": "ntlm_relay",       "pages": 1},
    # Credential
    {"keywords": "windows lsass credential",                    "category": "credential",       "pages": 2},
    {"keywords": "windows sam database local security",         "category": "credential",       "pages": 1},
    # WinRM
    {"keywords": "windows remote management winrm powershell",  "category": "winrm",            "pages": 1},
    # Kernel
    {"keywords": "windows kernel elevation of privilege",       "category": "kernel",           "pages": 3},
    {"keywords": "windows win32k elevation",                    "category": "kernel",           "pages": 2},
    {"keywords": "windows common log file system clfs",         "category": "kernel",           "pages": 1},
    # TCP/IP
    {"keywords": "windows tcp ip remote code execution",        "category": "tcpip",            "pages": 2},
    {"keywords": "windows ipv6 network stack",                  "category": "tcpip",            "pages": 1},
    # DNS
    {"keywords": "windows dns server remote code",              "category": "dns",              "pages": 2},
    {"keywords": "windows dns client resolution",               "category": "dns",              "pages": 1},
    # LDAP
    {"keywords": "windows ldap remote code execution",          "category": "ldap",             "pages": 2},
    {"keywords": "windows lightweight directory access protocol","category": "ldap",             "pages": 1},
    # RPC/DCOM
    {"keywords": "windows remote procedure call rpc",           "category": "rpc_dcom",         "pages": 2},
    {"keywords": "windows dcom component object model",         "category": "rpc_dcom",         "pages": 1},
    # Hyper-V
    {"keywords": "windows hyper-v remote code execution",       "category": "hyper_v",          "pages": 2},
    # Workstation / general
    {"keywords": "windows workstation elevation privilege",      "category": "workstation",      "pages": 2},
    # Bluetooth / Network drivers
    {"keywords": "windows bluetooth remote code execution",     "category": "bluetooth",        "pages": 1},
    {"keywords": "windows network driver elevation",            "category": "bluetooth",        "pages": 1},
    # ── S_Windows substitution categories ────────────────────────────────────
    # Office / Document Exploitation
    {"keywords": "microsoft office remote code execution",      "category": "office",           "pages": 2},
    {"keywords": "microsoft word excel outlook rce",            "category": "office",           "pages": 1},
    {"keywords": "windows mshtml follina moniker",              "category": "office",           "pages": 1},
    # Task Scheduler Privilege Escalation
    {"keywords": "windows task scheduler elevation privilege",  "category": "task_scheduler",   "pages": 2},
    {"keywords": "windows schtasks dll hijack elevation",       "category": "task_scheduler",   "pages": 1},
    # MSMQ RCE (replaces old workstation MSMQ entry)
    {"keywords": "microsoft message queuing msmq remote code",  "category": "msmq",             "pages": 2},
    {"keywords": "windows message queuing elevation privilege", "category": "msmq",             "pages": 1},
    # Netlogon OS Authentication Bypass
    {"keywords": "windows netlogon elevation of privilege",     "category": "netlogon",         "pages": 2},
    {"keywords": "netlogon zerologon authentication bypass",    "category": "netlogon",         "pages": 1},
]

# ── Product-category → CBS properties ────────────────────────────────────────

CATEGORY_TO_PROPS: dict[str, list[str]] = {
    "smb":            ["Windows", "SMBv1", "FileServer", "SMB"],
    "rdp":            ["Windows", "RDP", "Unpatched"],
    "active_directory": ["Windows", "DomainController", "DomainJoined", "LDAP"],
    "adcs":           ["Windows", "DomainController", "ADCS", "CertAuthority"],
    "print_spooler":  ["Windows", "PrintSpooler", "Unpatched"],
    "iis":            ["Windows", "IISServer", "WebServer"],
    "exchange":       ["Windows", "MailServer"],
    "mssql":          ["Windows", "MSSQLServer", "DatabaseServer"],
    "ntlm_relay":     ["Windows", "DomainJoined"],
    "winrm":          ["Windows", "DomainJoined"],
    "credential":     ["Windows", "DomainJoined", "LocalAdmin"],
    "workstation":    ["Windows", "Workstation"],
    # New categories
    "kernel":         ["Windows", "DomainJoined"],
    "tcpip":          ["Windows", "NetworkDevice"],
    "dns":            ["Windows", "DNSServer"],
    "ldap":           ["Windows", "DomainController", "DomainJoined"],
    "rpc_dcom":       ["Windows", "DomainJoined"],
    "hyper_v":        ["Windows", "HyperVHost"],
    "bluetooth":      ["Windows", "Workstation"],
    # ── S_Windows substitution categories ────────────────────────────────────
    "office":         ["Windows", "Workstation", "Unpatched"],
    "task_scheduler": ["Windows", "DomainJoined", "LocalAdmin"],
    "msmq":           ["Windows", "MSMQServer"],
    "netlogon":       ["Windows", "DomainController", "DomainJoined"],
}

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class WindowsCVE:
    cve_id:              str
    label:               str
    category:            str
    description:         str
    severity:            str
    cvss_score:          float
    attack_vector:       str
    attack_complexity:   str
    privileges_required: str
    user_interaction:    str
    published:           str
    cbs_properties:      List[str] = field(default_factory=list)
    references:          List[str] = field(default_factory=list)

    @property
    def normalised_success_rate(self) -> float:
        base = max(0.0, min(1.0, self.cvss_score / 10.0))
        if self.attack_complexity == "HIGH":
            base *= 0.7
        if self.user_interaction == "REQUIRED":
            base *= 0.85
        return round(max(0.30, min(0.90, base)), 2)

    @property
    def exploit_cost(self) -> float:
        if self.cvss_score >= 9.0: return 1.0
        if self.cvss_score >= 7.0: return 1.5
        if self.cvss_score >= 5.0: return 2.0
        return 3.0

    @property
    def cbs_type(self) -> str:
        """REMOTE for AV=NETWORK/ADJACENT, LOCAL otherwise."""
        return "REMOTE" if self.attack_vector in ("NETWORK", "ADJACENT") else "LOCAL"

    @property
    def probability(self) -> float:
        """Recommended CBS probability (how many qualifying nodes are vulnerable)."""
        if self.severity == "CRITICAL": return 0.85
        if self.severity == "HIGH":     return 0.65
        return 0.45


# ── NVD API client ────────────────────────────────────────────────────────────

class NVDClient:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key    = api_key
        self.delay      = REQUEST_DELAY_WITH_KEY if api_key else REQUEST_DELAY_NO_KEY
        self._last_call = 0.0

    def _get(self, params: dict) -> dict:
        self._rate_limit()
        url = NVD_BASE + "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        req = urllib.request.Request(url, headers=headers)
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    print(f"  [rate limit] sleeping 30 s (attempt {attempt+1}/3)")
                    time.sleep(30)
                else:
                    raise
        return {}

    def _rate_limit(self):
        elapsed = time.time() - self._last_call
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_call = time.time()

    def fetch_by_id(self, cve_id: str) -> Optional[dict]:
        data = self._get({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        return vulns[0]["cve"] if vulns else None

    def fetch_by_keyword(
        self,
        keywords: str,
        severity: str = "HIGH",
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> list[dict]:
        data = self._get({
            "keywordSearch":    keywords,
            "cvssV3Severity":   severity,
            "resultsPerPage":   results_per_page,
            "startIndex":       start_index,
        })
        return [v["cve"] for v in data.get("vulnerabilities", [])]


# ── Parser ────────────────────────────────────────────────────────────────────

def _parse_cvss(cve: dict) -> tuple[float, str, str, str, str]:
    """Return (score, attack_vector, attack_complexity, privileges_required, user_interaction)."""
    metrics = cve.get("metrics", {})
    # Prefer CVSSv3.1, fall back to v3.0, then v2
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            m = entries[0].get("cvssData", {})
            return (
                float(m.get("baseScore", 5.0)),
                m.get("attackVector", "UNKNOWN"),
                m.get("attackComplexity", "LOW"),
                m.get("privilegesRequired", "NONE"),
                m.get("userInteraction", "NONE"),
            )
    # CVSSv2 fallback
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        m = entries[0].get("cvssData", {})
        av_raw = m.get("accessVector", "UNKNOWN")
        av_map = {"NETWORK": "NETWORK", "ADJACENT_NETWORK": "ADJACENT", "LOCAL": "LOCAL"}
        return (
            float(m.get("baseScore", 5.0)),
            av_map.get(av_raw, "UNKNOWN"),
            "LOW" if m.get("accessComplexity", "LOW") == "LOW" else "HIGH",
            "NONE",
            "NONE",
        )
    return 5.0, "UNKNOWN", "LOW", "NONE", "NONE"


def _severity_from_score(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


def _description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")[:400]
    return ""


def _references(cve: dict) -> list[str]:
    return [r["url"] for r in cve.get("references", [])[:4]]


def _published(cve: dict) -> str:
    return cve.get("published", "")[:10]


def parse_cve(
    cve: dict,
    category: str,
    label: str = "",
) -> Optional[WindowsCVE]:
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    score, av, ac, pr, ui = _parse_cvss(cve)
    severity = _severity_from_score(score)

    return WindowsCVE(
        cve_id              = cve_id,
        label               = label or cve_id,
        category            = category,
        description         = _description(cve),
        severity            = severity,
        cvss_score          = score,
        attack_vector       = av,
        attack_complexity   = ac,
        privileges_required = pr,
        user_interaction    = ui,
        published           = _published(cve),
        cbs_properties      = list(CATEGORY_TO_PROPS.get(category, ["Windows"])),
        references          = _references(cve),
    )


# ── Main scraper ──────────────────────────────────────────────────────────────

class NVDScraper:
    def __init__(self, api_key: Optional[str] = None, min_severity: str = "HIGH"):
        self.client       = NVDClient(api_key)
        self.min_rank     = SEVERITY_RANK.get(min_severity.upper(), 3)

    def scrape(self) -> list[WindowsCVE]:
        cves: dict[str, WindowsCVE] = {}

        # Phase 1: curated well-known CVEs
        print(f"Phase 1: fetching {len(KNOWN_WINDOWS_CVES)} well-known CVEs …")
        for entry in KNOWN_WINDOWS_CVES:
            cve_id = entry["id"]
            print(f"  {cve_id} ({entry['label']}) …", end=" ", flush=True)
            raw = self.client.fetch_by_id(cve_id)
            if raw:
                c = parse_cve(raw, entry["category"], entry["label"])
                if c and SEVERITY_RANK.get(c.severity, 0) >= self.min_rank:
                    cves[c.cve_id] = c
                    print(f"CVSS={c.cvss_score} AV={c.attack_vector} ✓")
                else:
                    print("below threshold — skipped")
            else:
                print("not found")

        # Phase 2: keyword searches
        print(f"\nPhase 2: keyword queries ({len(KEYWORD_QUERIES)} categories) …")
        for q in KEYWORD_QUERIES:
            kw = q["keywords"]
            cat = q["category"]
            print(f"  [{cat}] '{kw}' …")
            for sev in ("CRITICAL", "HIGH"):
                if SEVERITY_RANK.get(sev, 0) < self.min_rank:
                    continue
                raw_list = self.client.fetch_by_keyword(kw, severity=sev, results_per_page=15)
                for raw in raw_list:
                    c = parse_cve(raw, cat)
                    if c and c.cve_id not in cves:
                        # Only include Windows-related CVEs
                        desc_lower = c.description.lower()
                        if any(kw_part in desc_lower for kw_part in
                               ["windows", "microsoft", "active directory", "iis", "exchange",
                                "kerberos", "ntlm", "smb", "rdp", "mssql", "sql server"]):
                            cves[c.cve_id] = c

        result = sorted(cves.values(), key=lambda c: c.cvss_score, reverse=True)
        print(f"\nTotal unique CVEs collected: {len(result)}")
        return result


# ── Serialisation ─────────────────────────────────────────────────────────────

def to_dict(c: WindowsCVE) -> dict:
    return {
        "cve_id":              c.cve_id,
        "label":               c.label,
        "category":            c.category,
        "description":         c.description,
        "severity":            c.severity,
        "cvss_score":          c.cvss_score,
        "attack_vector":       c.attack_vector,
        "attack_complexity":   c.attack_complexity,
        "privileges_required": c.privileges_required,
        "user_interaction":    c.user_interaction,
        "published":           c.published,
        "cbs_properties":      c.cbs_properties,
        "success_rate":        c.normalised_success_rate,
        "exploit_cost":        c.exploit_cost,
        "cbs_type":            c.cbs_type,
        "probability":         c.probability,
        "references":          c.references,
    }


def save_dataset(cves: list[WindowsCVE], out_path: Path) -> dict:
    data = {
        "source":         "NVD API v2 (nvd.nist.gov)",
        "os_family":      "Windows",
        "unique_cve_count": len(cves),
        "categories":     sorted({c.category for c in cves}),
        "cves":           [to_dict(c) for c in cves],
        "category_vuln_map": _build_category_map(cves),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2))
    print(f"\nSaved {len(cves)} CVEs → {out_path}")
    return data


def _build_category_map(cves: list[WindowsCVE]) -> dict:
    result: dict[str, dict] = {}
    for c in cves:
        cat = c.category
        if cat not in result:
            result[cat] = {
                "properties": list(CATEGORY_TO_PROPS.get(cat, ["Windows"])),
                "cve_count":  0,
                "top_cves":   [],
            }
        result[cat]["cve_count"] += 1
        if len(result[cat]["top_cves"]) < 5:
            result[cat]["top_cves"].append(c.cve_id)
    return result


def load_windows_dataset(path: Optional[Path] = None) -> dict:
    p = path or (Path(__file__).resolve().parent.parent
                 / "data" / "vulnerability_db" / "windows_cves.json")
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def filter_windows_cves(
    data: dict,
    categories: Optional[list[str]] = None,
    min_cvss: float = 6.5,
    network_only: bool = True,
) -> list[dict]:
    cves = data.get("cves", [])
    out = []
    for c in cves:
        if c["cvss_score"] < min_cvss:
            continue
        if network_only and c["attack_vector"] not in ("NETWORK", "ADJACENT"):
            continue
        if categories and c["category"] not in categories:
            continue
        out.append(c)
    return sorted(out, key=lambda x: x["cvss_score"], reverse=True)


def build_windows_config_prompt(
    data: dict,
    scenario_description: str,
    categories: Optional[list[str]] = None,
    min_cvss: float = 6.5,
) -> str:
    """Build an LLM prompt section for Windows CVE-grounded scenario generation."""
    filtered = filter_windows_cves(data, categories=categories, min_cvss=min_cvss)
    if not filtered:
        return "# No Windows CVE data available for the selected categories.\n"

    lines = [
        "## Windows CVE Ground Truth (NVD-Sourced)",
        f"Scenario: {scenario_description}",
        f"CVEs available: {len(filtered)} (CVSS ≥ {min_cvss}, network-exploitable)",
        "",
        "Use these CVE-derived parameters for Windows vulnerability definitions.",
        "The success_rate and exploit_cost columns are CBS-ready values.",
        "",
        "| CVE ID | Category | CVSS | AV | AC | PR | success_rate | cost | CBS Properties |",
        "|--------|----------|------|----|----|-----|-------------|------|----------------|",
    ]
    for c in filtered[:25]:
        props_str = ", ".join(c["cbs_properties"][:4])
        lines.append(
            f"| {c['cve_id']} | {c['category']} | {c['cvss_score']} "
            f"| {c['attack_vector'][:3]} | {c['attack_complexity'][:1]} "
            f"| {c['privileges_required'][:1]} | {c['success_rate']} "
            f"| {c['exploit_cost']} | {props_str} |"
        )

    lines += [
        "",
        "### Category → CBS Node Mapping",
    ]
    cat_map = data.get("category_vuln_map", {})
    for cat, info in cat_map.items():
        if not categories or cat in categories:
            lines.append(
                f"- **{cat}**: {info['cve_count']} CVEs  "
                f"→ match_properties: {info['properties']}"
            )

    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scrape Windows CVEs from NVD API v2")
    parser.add_argument("--api-key", default="",
                        help="NVD API key (optional — higher rate limit)")
    parser.add_argument("--out", default="data/vulnerability_db/windows_cves.json",
                        help="Output JSON path")
    parser.add_argument("--severity", default="HIGH",
                        help="Minimum severity (default: HIGH)")
    args = parser.parse_args()

    scraper = NVDScraper(
        api_key      = args.api_key or None,
        min_severity = args.severity,
    )
    cves = scraper.scrape()
    save_dataset(cves, Path(args.out))
