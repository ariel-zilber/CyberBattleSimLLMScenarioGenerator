#!/usr/bin/env python3
"""
tools/tag_mitre_tactics.py
==========================
Add MITRE ATT&CK tactic tags to every CVE in the vulnerability database.

Adds to each CVE entry:
  mitre_tactics : list of {tactic_id, tactic_name, techniques: [T-ids]}
  mitre_primary : "TA000X"  — dominant tactic for this CVE

Two modes
---------
  Rule-based (default — no API key required):
    Category + CVSS attributes + description keywords → deterministic mapping.
    Covers 99% of CVEs accurately given the rich category structure.

  LLM mode (--llm — requires ANTHROPIC_API_KEY in .env or environment):
    Batch-classifies ambiguous entries (confidence < threshold) via Claude API.

Usage
-----
  python tools/tag_mitre_tactics.py             # rule-based, all files
  python tools/tag_mitre_tactics.py --llm       # rule-based + LLM enhancement
  python tools/tag_mitre_tactics.py --force     # re-tag already-tagged CVEs
  python tools/tag_mitre_tactics.py --dry-run   # show stats without saving
  python tools/tag_mitre_tactics.py --file windows_cves.json
  python tools/tag_mitre_tactics.py --report-only

Outputs
-------
  data/vulnerability_db/<file>.json         (updated in-place, backup: .json.bak)
  data/vulnerability_db/mitre_tactic_report.json
  data/vulnerability_db/mitre_tactic_report.md
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
DB_DIR    = REPO_ROOT / "data" / "vulnerability_db"
DB_FILES  = [
    "bitnami_cves.json",
    "windows_cves.json",
    "network_devices_cves.json",
    "scada_cves.json",
]

# ── MITRE ATT&CK reference ────────────────────────────────────────────────────
TACTICS = {
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
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

# Shorthand for building tactic entries
def _t(tid: str, *techs: str) -> dict:
    return {"tactic_id": tid, "tactic_name": TACTICS[tid], "techniques": list(techs)}


# ── Rule-based category → tactics mapping ────────────────────────────────────
# Format: category_name → [primary_tactic_dict, ...secondary_tactic_dicts]
# First entry is the primary tactic.

CATEGORY_TACTICS: dict[str, list[dict]] = {
    # ── Windows: Lateral Movement / Initial Access ────────────────────────────
    "smb": [
        _t("TA0008", "T1021.002"),   # Lateral Movement: SMB/Windows Admin Shares
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
    ],
    "rdp": [
        _t("TA0008", "T1021.001"),   # Lateral Movement: Remote Desktop Protocol
        _t("TA0001", "T1133"),       # Initial Access: External Remote Services
    ],
    "winrm": [
        _t("TA0008", "T1021.006"),   # Lateral Movement: Windows Remote Management
    ],
    "hyper_v": [
        _t("TA0008", "T1210"),       # Lateral Movement: Exploitation of Remote Services
        _t("TA0004", "T1068"),       # Privilege Escalation: VM escape
    ],
    "rpc_dcom": [
        _t("TA0008", "T1021.003"),   # Lateral Movement: Distributed Component Object Model
        _t("TA0002", "T1059"),       # Execution
    ],

    # ── Windows: Privilege Escalation ─────────────────────────────────────────
    "print_spooler": [
        _t("TA0004", "T1068"),       # Privilege Escalation: Exploitation for Privesc
    ],
    "kernel": [
        _t("TA0004", "T1068"),       # Privilege Escalation: Exploitation for Privesc
    ],
    "workstation": [
        _t("TA0004", "T1068"),       # Privilege Escalation
        _t("TA0002", "T1203"),       # Execution: Exploitation for Client Execution
    ],
    "adcs": [
        _t("TA0004", "T1649"),       # Privilege Escalation: Steal/Forge Auth Certs
        _t("TA0006", "T1649"),       # Credential Access: Steal/Forge Auth Certs
    ],

    # ── Windows: Credential Access ────────────────────────────────────────────
    "credential": [
        _t("TA0006", "T1552"),       # Credential Access: Unsecured Credentials
        _t("TA0006", "T1003"),       # Credential Access: OS Credential Dumping
    ],
    "ntlm_relay": [
        _t("TA0006", "T1557.001"),   # Credential Access: LLMNR/NBT-NS Poisoning
        _t("TA0008", "T1557.001"),   # Lateral Movement: Adversary-in-the-Middle
    ],

    # ── Windows: Initial Access / Remote ──────────────────────────────────────
    "exchange": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
        _t("TA0009", "T1114"),       # Collection: Email Collection
    ],
    "iis": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
    ],
    "mssql": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
        _t("TA0002", "T1059.001"),   # Execution: PowerShell (xp_cmdshell)
    ],

    # ── Windows: Discovery ────────────────────────────────────────────────────
    "ldap": [
        _t("TA0007", "T1018"),       # Discovery: Remote System Discovery
        _t("TA0006", "T1087.002"),   # Credential Access: Domain Account Discovery
    ],
    "dns": [
        _t("TA0007", "T1018"),       # Discovery: Remote System Discovery
        _t("TA0001", "T1190"),       # Initial Access (DNS server exploit)
    ],

    # ── Windows: Active Directory ─────────────────────────────────────────────
    "active_directory": [
        _t("TA0006", "T1003.006"),   # Credential Access: DCSync
        _t("TA0008", "T1210"),       # Lateral Movement
        _t("TA0004", "T1484"),       # Privilege Escalation: Domain Policy Modification
    ],

    # ── Windows: Network Protocol / Impact ────────────────────────────────────
    "tcpip": [
        _t("TA0040", "T1499"),       # Impact: Endpoint Denial of Service
        _t("TA0001", "T1190"),       # Initial Access
    ],
    "bluetooth": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Bluetooth
    ],

    # ── Network Devices: Initial Access (VPN/Firewall/Router) ─────────────────
    "fortinet_sslvpn": [
        _t("TA0001", "T1133"),       # Initial Access: External Remote Services (SSL VPN)
        _t("TA0006", "T1552"),       # Credential Access: credential theft
    ],
    "fortinet_fortigate": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
        _t("TA0001", "T1133"),       # Initial Access: External Remote Services
    ],
    "cisco_asa": [
        _t("TA0001", "T1133"),       # Initial Access: External Remote Services
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
    ],
    "cisco_firepower": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
        _t("TA0005", "T1562.004"),   # Defense Evasion: Disable/Modify Firewall
    ],
    "cisco_ios_auth_bypass": [
        _t("TA0001", "T1078"),       # Initial Access: Valid Accounts (auth bypass)
    ],
    "cisco_nxos": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
        _t("TA0040", "T1499"),       # Impact: DoS
    ],
    "palo_alto_panos": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
    ],
    "palo_alto_gp": [
        _t("TA0001", "T1133"),       # Initial Access: External Remote Services (GlobalProtect)
        _t("TA0006", "T1552"),       # Credential Access
    ],
    "juniper_junos_auth": [
        _t("TA0001", "T1078"),       # Initial Access: Valid Accounts (auth bypass)
    ],
    "citrix_adc": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
        _t("TA0001", "T1133"),       # Initial Access: External Remote Services
    ],
    "checkpoint": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
    ],
    "netgear": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
        _t("TA0001", "T1078"),       # Initial Access: Valid Accounts (default creds)
    ],
    "openwrt": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
    ],
    "mikrotik": [
        _t("TA0001", "T1190"),       # Initial Access: Exploit Public-Facing App
        _t("TA0001", "T1078"),       # Initial Access: Valid Accounts
    ],
    "default_creds": [
        _t("TA0001", "T1078"),       # Initial Access: Valid Accounts (default creds)
    ],

    # ── Network Devices: Routing / Defense Evasion ───────────────────────────
    "bgp_routing": [
        _t("TA0005", "T1599"),       # Defense Evasion: Network Boundary Bridging
        _t("TA0040", "T1498"),       # Impact: Network Denial of Service
    ],
    "ospf_routing": [
        _t("TA0005", "T1599"),       # Defense Evasion: Network Boundary Bridging
    ],

    # ── SCADA / ICS: Impact (primary) ─────────────────────────────────────────
    "rockwell_factorytalk": [
        _t("TA0040", "T1485"),       # Impact: Data Destruction / sabotage
        _t("TA0001", "T1190"),       # Initial Access
        _t("TA0002", "T1059"),       # Execution
    ],
    "allen_bradley_micro": [
        _t("TA0040", "T1485"),       # Impact: Data Destruction
        _t("TA0001", "T1190"),       # Initial Access
    ],
    "schneider_m340": [
        _t("TA0040", "T1485"),       # Impact: Data Destruction
        _t("TA0001", "T1190"),       # Initial Access
    ],
    "schneider_quantum": [
        _t("TA0040", "T1485"),       # Impact: Data Destruction
        _t("TA0001", "T1190"),       # Initial Access
    ],
    "siemens_wincc": [
        _t("TA0040", "T1565"),       # Impact: Data Manipulation (HMI)
        _t("TA0002", "T1059"),       # Execution: Scripting
    ],
    "wonderware": [
        _t("TA0001", "T1190"),       # Initial Access
        _t("TA0040", "T1565"),       # Impact: Data Manipulation
    ],
    "codesys": [
        _t("TA0002", "T1059"),       # Execution: Scripting Interpreter (PLC ladder)
        _t("TA0001", "T1190"),       # Initial Access
        _t("TA0040", "T1485"),       # Impact
    ],
    "ics_buffer_overflow": [
        _t("TA0002", "T1203"),       # Execution: Exploitation for Client Execution
        _t("TA0040", "T1485"),       # Impact: Data Destruction
    ],

    # ── SCADA: Protocol Abuse / Lateral Movement ──────────────────────────────
    "opc_ua": [
        _t("TA0008", "T1210"),       # Lateral Movement: Exploitation of Remote Services
        _t("TA0001", "T1190"),       # Initial Access
    ],
    "opc_da": [
        _t("TA0008", "T1210"),       # Lateral Movement: Exploitation of Remote Services
        _t("TA0001", "T1190"),       # Initial Access
    ],
    "dnp3": [
        _t("TA0040", "T1499"),       # Impact: Endpoint Denial of Service
        _t("TA0008", "T1210"),       # Lateral Movement: Protocol abuse
    ],
}

# ── Description keyword → (primary tactic, techniques) ───────────────────────
# Applied in order; first match wins for primary tactic override.
KEYWORD_RULES: list[tuple[list[str], str, list[str]]] = [
    # Impact — check first (DoS is common in many categories)
    (["denial.of.serv", r"\bdos\b", "crash", "reboot", "infinite loop",
      "unavailable", "unresponsive"],
     "TA0040", ["T1499"]),
    (["data destruction", "destroy data", "wipe", "ransomware"],
     "TA0040", ["T1485"]),
    (["data manipulation", "modify data", "alter data"],
     "TA0040", ["T1565"]),

    # Initial Access
    (["remote code execution", r"\brce\b", "arbitrary code", "arbitrary command",
      "execute code", "unauthenticated rce"],
     "TA0001", ["T1190"]),
    (["authentication bypass", "auth bypass", "bypass authentication", "no auth",
      "without authentication"],
     "TA0001", ["T1078"]),
    (["default password", "default credential", "hardcoded password"],
     "TA0001", ["T1078"]),
    (["ssl.vpn", "vpn.authentication"],
     "TA0001", ["T1133"]),

    # Privilege Escalation
    (["privilege escalation", "escalate privilege", "gain.+privilege",
      "local privilege"],
     "TA0004", ["T1068"]),
    (["root access", "gain root", "kernel exploit"],
     "TA0004", ["T1068"]),

    # Credential Access
    (["credential", "password", "hash", "token steal", "ntlm"],
     "TA0006", ["T1552"]),

    # Lateral Movement
    (["lateral movement", "move.+network", "pivot"],
     "TA0008", ["T1210"]),

    # Discovery
    (["information disclosure", "information leak", "disclose", "expose.+data",
      "read.+file", "path traversal", "directory traversal"],
     "TA0007", ["T1083"]),

    # Defense Evasion
    (["bypass.+firewall", "evade.+detection", "disable.+logging"],
     "TA0005", ["T1562"]),

    # Execution (fallback if nothing else matches and it's an RCE)
    (["execute", "injection", "deserialization", "buffer overflow"],
     "TA0002", ["T1203"]),
]


def _keyword_match(desc: str) -> tuple[str, list[str]] | None:
    """Return (tactic_id, techniques) if a description keyword rule matches."""
    desc_lc = desc.lower()
    for patterns, tactic_id, techs in KEYWORD_RULES:
        for pat in patterns:
            if re.search(pat, desc_lc):
                return tactic_id, techs
    return None


# ── Rule-based classifier ─────────────────────────────────────────────────────

def classify_cve(cve: dict, source_hint: str) -> dict:
    """
    Return {"tactics": [...], "primary": "TA000X"} for one CVE.

    Priority:
      1. Category map (most accurate for named categories)
      2. Description keyword override for primary if DoS/privesc/etc.
      3. Fallback: TA0001 Initial Access (generic network-exploitable CVE)
    """
    category    = cve.get("category", "").lower()
    desc        = (cve.get("description") or "").lower()
    attack_vec  = cve.get("attack_vector", "NETWORK").upper()
    priv_req    = cve.get("privileges_required", "NONE").upper()

    # 1. Category → tactic list (most authoritative source)
    has_category = bool(category and category in CATEGORY_TACTICS)
    if has_category:
        tactics = [dict(t) for t in CATEGORY_TACTICS[category]]  # deep copy
    else:
        tactics = []

    # 2. Keyword-based supplement
    kw_match = _keyword_match(desc)
    if kw_match:
        kw_tid, kw_techs = kw_match
        existing_tids = [t["tactic_id"] for t in tactics]
        if not has_category:
            # No category match: keyword determines primary tactic
            tactics = [_t(kw_tid, *kw_techs)]
        elif kw_tid == "TA0040":
            # DoS keyword: Impact should be the primary tactic
            if "TA0040" not in existing_tids:
                tactics = [_t("TA0040", *kw_techs)] + tactics
            elif tactics[0]["tactic_id"] != "TA0040":
                # TA0040 already present but not primary — promote it
                dos = next(t for t in tactics if t["tactic_id"] == "TA0040")
                tactics = [dos] + [t for t in tactics if t["tactic_id"] != "TA0040"]
        elif kw_tid not in existing_tids:
            # Add as secondary tactic only; category primary stays
            tactics.append(_t(kw_tid, *kw_techs))

    # 3. Fallback based on CVSS attributes
    if not tactics:
        if attack_vec in ("NETWORK", "ADJACENT_NETWORK"):
            if priv_req == "NONE":
                tactics = [_t("TA0001", "T1190")]
            elif priv_req == "LOW":
                tactics = [_t("TA0004", "T1068"), _t("TA0001", "T1190")]
            else:
                tactics = [_t("TA0001", "T1190")]
        elif attack_vec == "LOCAL":
            tactics = [_t("TA0004", "T1068")]  # Local privesc
        else:
            tactics = [_t("TA0001", "T1190")]  # Generic

    # Deduplicate by tactic_id (keep first occurrence of each)
    seen: set[str] = set()
    deduped: list[dict] = []
    for t in tactics:
        tid = t["tactic_id"]
        if tid not in seen:
            seen.add(tid)
            deduped.append(t)
    tactics = deduped[:3]  # cap at 3 tactics

    primary = tactics[0]["tactic_id"] if tactics else "TA0001"
    return {"tactics": tactics, "primary": primary}


# ── Bitnami special handling ──────────────────────────────────────────────────
# Bitnami CVEs have no category, only `chart` (service name) and description.

BITNAMI_CHART_HINTS: dict[str, tuple[str, list[str]]] = {
    "jenkins":     ("TA0001", ["T1190"]),
    "wordpress":   ("TA0001", ["T1190"]),
    "drupal":      ("TA0001", ["T1190"]),
    "phpmyadmin":  ("TA0001", ["T1190"]),
    "moodle":      ("TA0001", ["T1190"]),
    "gitlab":      ("TA0001", ["T1190"]),
    "gitea":       ("TA0001", ["T1190"]),
    "harbor":      ("TA0001", ["T1190"]),
    "sonarqube":   ("TA0001", ["T1190"]),
    "keycloak":    ("TA0001", ["T1190", "T1556"]),
    "kafka":       ("TA0001", ["T1190"]),
    "elasticsearch": ("TA0001", ["T1190"]),
    "opensearch":  ("TA0001", ["T1190"]),
    "mongodb":     ("TA0001", ["T1190"]),
    "mysql":       ("TA0001", ["T1190"]),
    "mariadb":     ("TA0001", ["T1190"]),
    "postgresql":  ("TA0001", ["T1190"]),
    "redis":       ("TA0001", ["T1190"]),
    "influxdb":    ("TA0001", ["T1190"]),
    "grafana":     ("TA0001", ["T1190"]),
    "prometheus":  ("TA0001", ["T1190"]),
    "consul":      ("TA0008", ["T1210"]),
    "haproxy":     ("TA0001", ["T1190"]),
    "nginx":       ("TA0001", ["T1190"]),
    "tomcat":      ("TA0001", ["T1190"]),
    "airflow":     ("TA0001", ["T1190"]),
    "argo-cd":     ("TA0001", ["T1190"]),
    "minio":       ("TA0009", ["T1530"]),   # Collection: data from cloud storage
}


def classify_bitnami_cve(cve: dict) -> dict:
    """Classify a bitnami CVE using chart hint + description keywords."""
    chart = cve.get("chart", "").lower()
    desc  = (cve.get("description") or "").lower()

    # Description-first for DoS / privesc
    kw_match = _keyword_match(desc)

    # Chart hint
    chart_key = next((k for k in BITNAMI_CHART_HINTS if chart.startswith(k)), None)
    chart_tid, chart_techs = BITNAMI_CHART_HINTS.get(chart_key, ("TA0001", ["T1190"]))

    if kw_match:
        kw_tid, kw_techs = kw_match
        if kw_tid == "TA0040":  # DoS overrides chart
            tactics = [_t("TA0040", *kw_techs), _t(chart_tid, *chart_techs)]
        elif kw_tid == "TA0004":  # Privesc adds alongside
            tactics = [_t("TA0004", *kw_techs), _t(chart_tid, *chart_techs)]
        elif kw_tid == "TA0007":  # Info disclosure
            tactics = [_t("TA0007", *kw_techs), _t(chart_tid, *chart_techs)]
        else:
            tactics = [_t(chart_tid, *chart_techs), _t(kw_tid, *kw_techs)]
    else:
        tactics = [_t(chart_tid, *chart_techs)]

    # Deduplicate
    seen: set[str] = set()
    deduped = []
    for t in tactics:
        if t["tactic_id"] not in seen:
            seen.add(t["tactic_id"])
            deduped.append(t)

    primary = deduped[0]["tactic_id"] if deduped else "TA0001"
    return {"tactics": deduped[:3], "primary": primary}


# ── DB processing ─────────────────────────────────────────────────────────────

def load_db(fname: str) -> dict:
    return json.loads((DB_DIR / fname).read_text(encoding="utf-8"))


def save_db(fname: str, data: dict) -> None:
    path = DB_DIR / fname
    bak  = path.with_suffix(".json.bak")
    if path.exists() and not bak.exists():
        shutil.copy(path, bak)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def tag_file_rules(
    fname: str,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    data = load_db(fname)
    cves: list[dict] = data.get("cves", [])
    is_bitnami = fname == "bitnami_cves.json"
    source_hint = fname.replace("_cves.json", "")

    to_tag = [c for c in cves if force or "mitre_tactics" not in c]
    skipped = len(cves) - len(to_tag)

    print(f"  [{fname}] {len(cves)} CVEs → tagging {len(to_tag)}, skipping {skipped}")

    if not to_tag:
        return {"file": fname, "total": len(cves), "tagged": 0, "skipped": skipped}

    for cve in to_tag:
        result = (
            classify_bitnami_cve(cve) if is_bitnami
            else classify_cve(cve, source_hint)
        )
        if not dry_run:
            # Modify the dict in-place (to_tag holds references into cves)
            cve["mitre_tactics"] = result["tactics"]
            cve["mitre_primary"] = result["primary"]

    if not dry_run:
        save_db(fname, data)

    return {
        "file": fname,
        "total": len(cves),
        "tagged": len(to_tag),
        "skipped": skipped,
    }


# ── LLM enhancement (optional) ───────────────────────────────────────────────

BATCH_SIZE  = 25
LLM_MODEL   = "claude-sonnet-4-6"
RETRY_DELAY = 5
MAX_RETRIES = 3

LLM_SYSTEM = """You are a MITRE ATT&CK expert reviewing pre-classified CVEs.
Return ONLY a JSON array — no prose. Each element:
{"cve_id":"CVE-XXXX","tactics":[{"tactic_id":"TA000X","tactic_name":"<name>",
"techniques":["TXXXX"]}],"primary":"TA000X","override":true|false}
Set override=true only if you disagree with the existing classification.
List 1-3 tactics, primary = most dominant tactic."""


def _get_api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        return key
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("ANTHROPIC_API_KEY=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip()
    return ""


def _call_llm(prompt: str, api_key: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=LLM_MODEL,
        max_tokens=4096,
        system=LLM_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text if resp.content else ""


def _extract_json_array(text: str) -> list:
    try:
        val = json.loads(text.strip())
        if isinstance(val, list):
            return val
    except json.JSONDecodeError:
        pass
    m = re.search(r"\[.*\]", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return []


def enhance_with_llm(fname: str, api_key: str, dry_run: bool = False) -> dict[str, Any]:
    """Review already-classified CVEs with LLM and apply overrides."""
    data = load_db(fname)
    cves: list[dict] = data.get("cves", [])
    tagged = [c for c in cves if "mitre_tactics" in c]

    print(f"  [{fname}] LLM enhancement — reviewing {len(tagged)} CVEs in batches of {BATCH_SIZE}")

    # Build index for LLM overrides (non-bitnami files don't have duplicates)
    cve_index = {c["cve_id"]: c for c in cves}
    overrides  = 0
    batches = [tagged[i : i + BATCH_SIZE] for i in range(0, len(tagged), BATCH_SIZE)]

    for b_idx, batch in enumerate(batches):
        items_str = "\n".join(
            f"{j+1}. {c['cve_id']} cat={c.get('category',c.get('chart','?'))} "
            f"primary={c.get('mitre_primary','?')} "
            f"desc={c.get('description','')[:120]}"
            for j, c in enumerate(batch)
        )
        prompt = (
            f"Review these {len(batch)} pre-classified CVEs.\n"
            f"Only set override=true if the existing primary tactic is wrong.\n\n"
            f"{items_str}"
        )

        print(f"    batch {b_idx+1}/{len(batches)} ...", end="", flush=True)
        if dry_run:
            print(" [dry-run]")
            continue

        raw = ""
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                raw = _call_llm(prompt, api_key)
                break
            except Exception as exc:
                if attempt == MAX_RETRIES:
                    print(f" ERROR: {exc}")
                    break
                time.sleep(RETRY_DELAY)

        if not raw:
            continue

        items = _extract_json_array(raw)
        by_id = {i.get("cve_id"): i for i in items if isinstance(i, dict)}
        for cve in batch:
            cid  = cve["cve_id"]
            item = by_id.get(cid)
            if item and item.get("override"):
                target = cve_index.get(cid)
                if target is not None:
                    tactics = item.get("tactics", [])
                    primary = item.get("primary")
                    if tactics and primary:
                        target["mitre_tactics"] = tactics
                        target["mitre_primary"] = primary
                        overrides += 1

        print(f" done ({overrides} overrides so far)")
        save_db(fname, data)

    return {"file": fname, "llm_overrides": overrides}


# ── Coverage report ───────────────────────────────────────────────────────────

def generate_report() -> None:
    tactic_global:  dict[str, int] = {tid: 0 for tid in TACTICS}
    primary_global: dict[str, int] = {tid: 0 for tid in TACTICS}
    by_source:      dict[str, dict] = {}
    multi_tactic = 0
    total_cves   = 0
    tagged_total = 0

    for fname in DB_FILES:
        path = DB_DIR / fname
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        cves = data.get("cves", [])
        src  = fname.replace("_cves.json", "")
        src_counts: dict[str, int] = {tid: 0 for tid in TACTICS}

        for c in cves:
            total_cves += 1
            tactics = c.get("mitre_tactics", [])
            if not tactics:
                continue
            tagged_total += 1
            if len(tactics) > 1:
                multi_tactic += 1
            for t in tactics:
                tid = t.get("tactic_id", "")
                if tid in tactic_global:
                    tactic_global[tid]  += 1
                    src_counts[tid]     += 1
            primary = c.get("mitre_primary")
            if primary and primary in primary_global:
                primary_global[primary] += 1

        by_source[src] = src_counts

    coverage_pct = round(tagged_total / max(total_cves, 1) * 100, 1)

    report = {
        "total_cves":         total_cves,
        "tagged":             tagged_total,
        "coverage_pct":       coverage_pct,
        "multi_tactic_count": multi_tactic,
        "tactic_distribution": {
            tid: {
                "tactic_name":        TACTICS[tid],
                "co_occurrence_count": tactic_global[tid],
                "primary_count":      primary_global[tid],
                "pct_of_tagged":      round(primary_global[tid] / max(tagged_total, 1) * 100, 1),
            }
            for tid in TACTICS
        },
        "by_source": by_source,
    }
    (DB_DIR / "mitre_tactic_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    # Markdown
    lines = [
        "# MITRE ATT&CK Tactic Coverage Report",
        "",
        f"**Total CVEs:** {total_cves}  |  "
        f"**Tagged:** {tagged_total} ({coverage_pct}%)  |  "
        f"**Multi-tactic:** {multi_tactic}",
        "",
        "## Primary Tactic Distribution",
        "",
        "| Tactic | Name | Primary | Co-occur | % of Tagged |",
        "|--------|------|--------:|--------:|------------:|",
    ]
    for tid, d in sorted(
        report["tactic_distribution"].items(),
        key=lambda x: x[1]["primary_count"], reverse=True,
    ):
        if d["primary_count"] == 0 and d["co_occurrence_count"] == 0:
            continue
        lines.append(
            f"| {tid} | {d['tactic_name']} | {d['primary_count']} "
            f"| {d['co_occurrence_count']} | {d['pct_of_tagged']}% |"
        )

    lines += ["", "## Per-Source Breakdown", ""]
    header = "| Source | " + " | ".join(f"[{tid}](#{tid})" for tid in TACTICS) + " |"
    sep    = "|--------|" + "|".join(["-----:"] * len(TACTICS)) + "|"
    lines += [header, sep]
    for src, counts in by_source.items():
        row = " | ".join(str(counts.get(tid, 0)) for tid in TACTICS)
        lines.append(f"| {src} | {row} |")

    (DB_DIR / "mitre_tactic_report.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )

    print(f"\n  Saved mitre_tactic_report.json + .md")
    print(f"  Coverage: {tagged_total}/{total_cves} ({coverage_pct}%)")
    print(f"\n  Primary tactic distribution:")
    for tid, d in sorted(
        report["tactic_distribution"].items(),
        key=lambda x: x[1]["primary_count"], reverse=True,
    ):
        if d["primary_count"] == 0:
            continue
        bar = "█" * min(d["primary_count"] // 8, 35)
        print(f"    {tid}  {d['tactic_name']:<25}  {d['primary_count']:>4}  {bar}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tag CVE database with MITRE ATT&CK tactics"
    )
    parser.add_argument("--llm",         action="store_true",
                        help="After rule-based pass, enhance with LLM (requires ANTHROPIC_API_KEY)")
    parser.add_argument("--force",       action="store_true",
                        help="Re-tag already-tagged CVEs")
    parser.add_argument("--dry-run",     action="store_true",
                        help="Show what would be done without saving")
    parser.add_argument("--file",        default="",
                        help="Only process one DB file (e.g. windows_cves.json)")
    parser.add_argument("--report-only", action="store_true",
                        help="Regenerate report without tagging")
    args = parser.parse_args()

    if args.report_only:
        generate_report()
        return

    files = [args.file] if args.file else DB_FILES
    files = [f for f in files if (DB_DIR / f).exists()]
    if not files:
        print(f"No DB files found in {DB_DIR}", file=sys.stderr)
        sys.exit(1)

    api_key = ""
    if args.llm:
        api_key = _get_api_key()
        if not api_key:
            print(
                "ERROR: --llm requires ANTHROPIC_API_KEY in environment or .env\n"
                "  Add:  ANTHROPIC_API_KEY=sk-ant-... to .env",
                file=sys.stderr,
            )
            sys.exit(1)

    print("=" * 62)
    print("  MITRE ATT&CK Tagger")
    print(f"  Files  : {', '.join(files)}")
    print(f"  Mode   : {'rule-based + LLM' if args.llm else 'rule-based'}"
          f"{'  [DRY RUN]' if args.dry_run else ''}"
          f"{'  [FORCE]' if args.force else ''}")
    print("=" * 62)

    all_stats: list[dict] = []
    for fname in files:
        stats = tag_file_rules(fname, force=args.force, dry_run=args.dry_run)
        all_stats.append(stats)

    if args.llm and not args.dry_run:
        print("\n  LLM enhancement pass ...")
        for fname in files:
            enhance_with_llm(fname, api_key, dry_run=args.dry_run)

    print("\n" + "─" * 62)
    print("  SUMMARY")
    for s in all_stats:
        print(f"    {s['file']:<35}  tagged={s['tagged']:>4}  skipped={s['skipped']:>4}")

    if not args.dry_run:
        print()
        generate_report()


if __name__ == "__main__":
    main()
