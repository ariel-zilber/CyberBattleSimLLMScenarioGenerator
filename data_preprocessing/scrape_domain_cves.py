#!/usr/bin/env python3
"""
tools/scrape_domain_cves.py
============================
Scrape NVD API + EPSS + CISA KEV for two new domains:
  - network_devices  (Cisco, Juniper, Fortinet, Palo Alto, F5, Citrix, ...)
  - scada            (Siemens, Schneider, Rockwell, CODESYS, Modbus, DNP3, ...)

Outputs:
  data/vulnerability_db/network_devices_cves.json
  data/vulnerability_db/scada_cves.json

Usage
-----
  python3 tools/scrape_domain_cves.py --domain all
  python3 tools/scrape_domain_cves.py --domain network_devices
  python3 tools/scrape_domain_cves.py --domain scada
  python3 tools/scrape_domain_cves.py --domain all --min-cvss 6.0 --limit-per-query 50
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR   = REPO_ROOT / "data" / "vulnerability_db"

NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# NVD rate limit: 5 requests / 30s without API key. We sleep conservatively.
NVD_SLEEP = 7.0   # seconds between NVD requests

# ─────────────────────────────────────────────────────────────────────────────
# Domain definitions: keyword queries + CPE fragments + category mappings
# ─────────────────────────────────────────────────────────────────────────────

NETWORK_QUERIES: List[Tuple[str, str]] = [
    # (keyword_query, category)
    ("cisco ios remote code execution",                   "cisco_ios_rce"),
    ("cisco ios-xe privilege escalation",                 "cisco_ios_privesc"),
    ("cisco ios authentication bypass",                   "cisco_ios_auth_bypass"),
    ("cisco nx-os vulnerability",                         "cisco_nxos"),
    ("cisco asa firewall vulnerability",                  "cisco_asa"),
    ("cisco firepower ftd vulnerability",                 "cisco_firepower"),
    ("juniper junos remote code execution",               "juniper_junos_rce"),
    ("juniper junos authentication bypass",               "juniper_junos_auth"),
    ("fortinet fortigate fortiOS vulnerability",          "fortinet_fortigate"),
    ("fortinet fortiOS ssl vpn vulnerability",            "fortinet_sslvpn"),
    ("palo alto pan-os vulnerability",                    "palo_alto_panos"),
    ("palo alto globalprotect vulnerability",             "palo_alto_gp"),
    ("f5 big-ip remote code execution",                   "f5_bigip_rce"),
    ("f5 big-ip authentication bypass",                   "f5_bigip_auth"),
    ("citrix netscaler adc gateway vulnerability",        "citrix_adc"),
    ("sonicwall firewall remote code execution",          "sonicwall"),
    ("check point firewall vulnerability",                "checkpoint"),
    ("mikrotik routeros vulnerability",                   "mikrotik"),
    ("openwrt vulnerability",                             "openwrt"),
    ("netgear router remote code execution",              "netgear"),
    ("d-link router vulnerability command injection",     "dlink"),
    ("zyxel router firewall vulnerability",               "zyxel"),
    ("solarwinds network management vulnerability",       "solarwinds_nm"),
    ("network snmp remote code execution",                "snmp_rce"),
    ("bgp routing protocol vulnerability",                "bgp_routing"),
    ("ospf routing protocol vulnerability",               "ospf_routing"),
    ("spanning tree protocol stp vulnerability",          "stp"),
    ("vlan trunking dot1q vulnerability",                 "vlan"),
    ("ssh remote code execution network device",          "ssh_network"),
    ("telnet network device authentication bypass",       "telnet_network"),
    ("web interface router command injection",            "web_mgmt_cmd_inject"),
    ("network device default credentials",                "default_creds"),
    ("radius authentication bypass network",              "radius_auth"),
]

SCADA_QUERIES: List[Tuple[str, str]] = [
    # Siemens
    ("siemens simatic s7-300 s7-400 plc vulnerability",  "siemens_s7_classic"),
    ("siemens simatic s7-1200 s7-1500 vulnerability",    "siemens_s7_modern"),
    ("siemens simatic wincc vulnerability",               "siemens_wincc"),
    ("siemens simatic step 7 tia portal vulnerability",  "siemens_tia"),
    ("siemens simatic hmi vulnerability",                 "siemens_hmi"),
    ("siemens s7comm remote code execution",              "siemens_s7comm"),
    ("siemens profinet vulnerability",                    "siemens_profinet"),
    # Schneider Electric
    ("schneider electric modicon m340 vulnerability",    "schneider_m340"),
    ("schneider electric modicon quantum vulnerability", "schneider_quantum"),
    ("schneider electric unity pro vulnerability",       "schneider_unity"),
    ("schneider electric ecostruxure vulnerability",     "schneider_ecostruxure"),
    ("schneider electric wonderware vulnerability",      "wonderware"),
    # Rockwell / Allen-Bradley
    ("rockwell automation allen-bradley plc vulnerability", "rockwell_plc"),
    ("rockwell logix5000 controllogix vulnerability",    "rockwell_controllogix"),
    ("rockwell factorytalk vulnerability",               "rockwell_factorytalk"),
    ("allen-bradley micrologix vulnerability",           "allen_bradley_micro"),
    # GE / AVEVA / Emerson
    ("ge cimplicity proficy vulnerability",              "ge_proficy"),
    ("aveva intouch scada vulnerability",                "aveva_intouch"),
    ("emerson deltav dcs vulnerability",                 "emerson_deltav"),
    # CODESYS / OPC / industrial protocols
    ("codesys runtime plc vulnerability",                "codesys"),
    ("opc ua server vulnerability",                      "opc_ua"),
    ("opc da dcom vulnerability",                        "opc_da"),
    ("modbus tcp remote code execution",                 "modbus_rce"),
    ("dnp3 scada vulnerability",                         "dnp3"),
    ("iec 61850 scada vulnerability",                    "iec61850"),
    ("profibus profinet industrial vulnerability",       "profibus"),
    ("ethernet ip allen-bradley vulnerability",          "ethernetip"),
    # HMI / historian / engineering workstations
    ("industrial hmi remote code execution",             "hmi_rce"),
    ("scada historian vulnerability",                    "historian"),
    ("engineering workstation ics vulnerability",        "ew_ics"),
    ("industrial remote access vpn ics vulnerability",   "ics_remote_access"),
    # Cross-cutting ICS
    ("ics scada authentication bypass",                  "ics_auth_bypass"),
    ("industrial control system remote code execution",  "ics_rce"),
    ("plc firmware vulnerability remote code execution", "plc_firmware"),
    ("ics default credentials vulnerability",            "ics_default_creds"),
    ("scada web interface cross site scripting",         "scada_xss"),
    ("industrial protocol buffer overflow",              "ics_buffer_overflow"),
]

# ─────────────────────────────────────────────────────────────────────────────
# CBS property mappings: category → list of CBS node properties
# ─────────────────────────────────────────────────────────────────────────────

NETWORK_CATEGORY_PROPS: Dict[str, List[str]] = {
    "cisco_ios_rce":       ["Router", "CiscoIOS", "NetworkDevice", "Unpatched"],
    "cisco_ios_privesc":   ["Router", "CiscoIOS", "NetworkDevice"],
    "cisco_ios_auth_bypass":["Router", "CiscoIOS", "NetworkDevice", "Unpatched"],
    "cisco_nxos":          ["Switch", "CiscoNXOS", "NetworkDevice"],
    "cisco_asa":           ["Firewall", "CiscoASA", "NetworkDevice"],
    "cisco_firepower":     ["Firewall", "CiscoFirepower", "NGFW", "NetworkDevice"],
    "juniper_junos_rce":   ["Router", "JuniperJunos", "NetworkDevice", "Unpatched"],
    "juniper_junos_auth":  ["Router", "JuniperJunos", "NetworkDevice"],
    "fortinet_fortigate":  ["Firewall", "FortiGate", "FortiOS", "NGFW", "NetworkDevice"],
    "fortinet_sslvpn":     ["Firewall", "FortiGate", "SSLVPN", "NetworkDevice"],
    "palo_alto_panos":     ["Firewall", "PaloAlto", "PANOS", "NGFW", "NetworkDevice"],
    "palo_alto_gp":        ["Firewall", "PaloAlto", "GlobalProtect", "NetworkDevice"],
    "f5_bigip_rce":        ["LoadBalancer", "F5BIGIP", "NetworkDevice", "Unpatched"],
    "f5_bigip_auth":       ["LoadBalancer", "F5BIGIP", "NetworkDevice"],
    "citrix_adc":          ["LoadBalancer", "CitrixADC", "Netscaler", "NetworkDevice"],
    "sonicwall":           ["Firewall", "SonicWall", "NetworkDevice", "Unpatched"],
    "checkpoint":          ["Firewall", "CheckPoint", "NGFW", "NetworkDevice"],
    "mikrotik":            ["Router", "Mikrotik", "NetworkDevice", "Unpatched"],
    "openwrt":             ["Router", "OpenWrt", "NetworkDevice"],
    "netgear":             ["Router", "Netgear", "NetworkDevice", "Unpatched"],
    "dlink":               ["Router", "DLink", "NetworkDevice", "Unpatched"],
    "zyxel":               ["Firewall", "Zyxel", "NetworkDevice", "Unpatched"],
    "solarwinds_nm":       ["NetworkManagement", "SolarWinds", "NetworkDevice"],
    "snmp_rce":            ["Router", "Switch", "NetworkDevice", "SNMP"],
    "bgp_routing":         ["Router", "BGP", "NetworkDevice"],
    "ospf_routing":        ["Router", "OSPF", "NetworkDevice"],
    "stp":                 ["Switch", "STP", "NetworkDevice"],
    "vlan":                ["Switch", "VLAN", "NetworkDevice"],
    "ssh_network":         ["Router", "Switch", "SSH", "NetworkDevice"],
    "telnet_network":      ["Router", "Switch", "Telnet", "NetworkDevice", "LegacyDevice"],
    "web_mgmt_cmd_inject": ["Router", "Firewall", "HTTP", "NetworkDevice"],
    "default_creds":       ["Router", "Switch", "Firewall", "NetworkDevice", "DefaultCredentials"],
    "radius_auth":         ["Router", "Switch", "RADIUS", "AAA", "NetworkDevice"],
}

SCADA_CATEGORY_PROPS: Dict[str, List[str]] = {
    "siemens_s7_classic":  ["PLC", "Siemens", "S7Classic", "S7Comm", "ICS"],
    "siemens_s7_modern":   ["PLC", "Siemens", "S7Modern", "S7CommPlus", "ICS"],
    "siemens_wincc":       ["SCADA", "Siemens", "WinCC", "HMI", "ICS"],
    "siemens_tia":         ["EngineeringWorkstation", "Siemens", "TIAPortal", "ICS"],
    "siemens_hmi":         ["HMI", "Siemens", "ICS"],
    "siemens_s7comm":      ["PLC", "Siemens", "S7Comm", "ICS", "Unpatched"],
    "siemens_profinet":    ["PLC", "Siemens", "PROFINET", "ICS"],
    "schneider_m340":      ["PLC", "Schneider", "ModiconM340", "Modbus", "ICS"],
    "schneider_quantum":   ["PLC", "Schneider", "ModiconQuantum", "Modbus", "ICS"],
    "schneider_unity":     ["EngineeringWorkstation", "Schneider", "UnityPro", "ICS"],
    "schneider_ecostruxure":["SCADA", "Schneider", "EcoStruxure", "ICS"],
    "wonderware":          ["SCADA", "Wonderware", "InTouch", "HMI", "ICS"],
    "rockwell_plc":        ["PLC", "Rockwell", "AllenBradley", "EtherNetIP", "ICS"],
    "rockwell_controllogix":["PLC", "Rockwell", "ControlLogix", "EtherNetIP", "ICS"],
    "rockwell_factorytalk": ["SCADA", "Rockwell", "FactoryTalk", "HMI", "ICS"],
    "allen_bradley_micro": ["PLC", "Rockwell", "AllenBradley", "ICS", "LegacyDevice"],
    "ge_proficy":          ["SCADA", "GE", "Proficy", "Cimplicity", "ICS"],
    "aveva_intouch":       ["SCADA", "AVEVA", "InTouch", "HMI", "ICS"],
    "emerson_deltav":      ["DCS", "Emerson", "DeltaV", "ICS"],
    "codesys":             ["PLC", "CODESYS", "ICS", "Unpatched"],
    "opc_ua":              ["OPCServer", "OPCUA", "ICS"],
    "opc_da":              ["OPCServer", "OPCDA", "DCOM", "ICS", "LegacyDevice"],
    "modbus_rce":          ["PLC", "Modbus", "ModbusTCP", "ICS", "Unpatched"],
    "dnp3":                ["RTU", "DNP3", "ICS", "Unpatched"],
    "iec61850":            ["IED", "IEC61850", "ICS"],
    "profibus":            ["PLC", "PROFIBUS", "ICS", "LegacyDevice"],
    "ethernetip":          ["PLC", "EtherNetIP", "AllenBradley", "ICS"],
    "hmi_rce":             ["HMI", "ICS", "Unpatched"],
    "historian":           ["Historian", "SCADA", "ICS"],
    "ew_ics":              ["EngineeringWorkstation", "ICS"],
    "ics_remote_access":   ["JumpServer", "RemoteAccess", "ICS", "VPN"],
    "ics_auth_bypass":     ["PLC", "SCADA", "HMI", "ICS", "Unpatched"],
    "ics_rce":             ["PLC", "SCADA", "ICS", "Unpatched"],
    "plc_firmware":        ["PLC", "ICS", "Unpatched", "LegacyDevice"],
    "ics_default_creds":   ["PLC", "HMI", "SCADA", "ICS", "DefaultCredentials"],
    "scada_xss":           ["SCADA", "HMI", "HTTP", "ICS"],
    "ics_buffer_overflow": ["PLC", "RTU", "ICS", "Unpatched"],
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def fetch_nvd_page(query: str, start: int, page_size: int,
                   min_cvss: float, api_key: Optional[str]) -> Tuple[List[dict], int]:
    """Fetch one page of NVD results. Returns (cves, total_results)."""
    params = {
        "keywordSearch":  query,
        "resultsPerPage": page_size,
        "startIndex":     start,
    }
    if min_cvss >= 9.0:
        params["cvssV3Severity"] = "CRITICAL"
    elif min_cvss >= 7.0:
        params["cvssV3Severity"] = "HIGH"
    elif min_cvss >= 4.0:
        params["cvssV3Severity"] = "MEDIUM"

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(3):
        try:
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=30)
            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            total = data.get("totalResults", len(vulns))
            return [v["cve"] for v in vulns], total
        except requests.RequestException as e:
            _log(f"  NVD attempt {attempt+1}/3 failed: {e}")
            if attempt < 2:
                time.sleep(15)
    return [], 0


def fetch_all_for_query(query: str, limit_per_query: int, min_cvss: float,
                        api_key: Optional[str]) -> List[dict]:
    """Paginate NVD to collect up to limit_per_query CVEs for a keyword query."""
    PAGE = 100
    all_cves: List[dict] = []
    start = 0

    while len(all_cves) < limit_per_query:
        remaining = limit_per_query - len(all_cves)
        page_size = min(PAGE, remaining)
        cves, total = fetch_nvd_page(query, start, page_size, min_cvss, api_key)
        all_cves.extend(cves)
        _log(f"    [{query[:45]:<45}] {len(all_cves)}/{min(total, limit_per_query)} CVEs")

        if len(cves) < page_size or start + page_size >= total:
            break
        start += page_size
        time.sleep(NVD_SLEEP)

    return all_cves


def fetch_epss(cve_ids: List[str]) -> Dict[str, float]:
    """Batch-fetch EPSS scores (100 IDs per request)."""
    scores: Dict[str, float] = {}
    BATCH = 100
    for i in range(0, len(cve_ids), BATCH):
        batch = cve_ids[i:i + BATCH]
        try:
            r = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=20)
            r.raise_for_status()
            for item in r.json().get("data", []):
                scores[item["cve"]] = float(item["epss"])
        except requests.RequestException as e:
            _log(f"  EPSS batch {i//BATCH + 1} failed: {e}")
        time.sleep(1)
    return scores


def fetch_kev() -> Set[str]:
    """Return CVE IDs in CISA Known Exploited Vulnerabilities catalog."""
    try:
        r = requests.get(KEV_URL, timeout=20)
        r.raise_for_status()
        ids = {v["cveID"] for v in r.json().get("vulnerabilities", [])}
        _log(f"  KEV: loaded {len(ids)} known-exploited CVEs")
        return ids
    except requests.RequestException as e:
        _log(f"  KEV fetch failed: {e}")
        return set()


def extract_cvss(cve: dict) -> Optional[dict]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        m = cve.get("metrics", {}).get(key, [])
        if m:
            return m[0]["cvssData"]
    return None


def cvss_av_to_cbs_type(av: str) -> str:
    return "REMOTE" if av in ("NETWORK", "ADJACENT_NETWORK", "ADJACENT") else "LOCAL"


def cvss_to_success_rate(ac: str, av: str, kev: bool) -> float:
    base = {
        ("LOW",  "NETWORK"):  0.85, ("LOW",  "ADJACENT"): 0.80,
        ("LOW",  "LOCAL"):    0.75, ("HIGH", "NETWORK"):  0.60,
        ("HIGH", "ADJACENT"): 0.55, ("HIGH", "LOCAL"):    0.50,
    }.get((ac, av), 0.65)
    return min(base + 0.05, 0.95) if kev else base


def cvss_to_cost(score: float, ac: str) -> float:
    if ac == "LOW":
        return 0.5 if score >= 9.0 else (1.0 if score >= 7.0 else 1.5)
    return 1.5 if score >= 9.0 else (2.0 if score >= 7.0 else 2.5)


def build_label(description: str, cve_id: str) -> str:
    PATTERNS = [
        (r"remote code execution",          "RCE"),
        (r"privilege escal",                "PrivEsc"),
        (r"authentication\s*bypass",        "AuthBypass"),
        (r"command\s*inject",               "CMDInject"),
        (r"buffer\s*overflow",              "BufferOverflow"),
        (r"path\s*traversal",               "PathTraversal"),
        (r"hardcoded\s*creden|default\s*creden", "DefaultCreds"),
        (r"information\s*disclos",          "InfoDisclosure"),
        (r"denial.of.service",              "DoS"),
        (r"sql\s*injection",                "SQLInjection"),
        (r"cross.site\s*script",            "XSS"),
        (r"deserialization",                "Deserialization"),
        (r"s7comm",                         "S7CommExploit"),
        (r"modbus",                         "ModbusExploit"),
        (r"dnp3",                           "DNP3Exploit"),
        (r"opc",                            "OPCExploit"),
        (r"firmware",                       "FirmwareExploit"),
    ]
    dl = description.lower()
    for pattern, label in PATTERNS:
        if re.search(pattern, dl):
            return label
    m = re.search(r"CVE-(\d{4})-(\d+)", cve_id)
    if m:
        return f"CVE{m.group(1)}_{m.group(2)[-4:]}"
    return "UnknownExploit"


def cve_to_entry(cve: dict, category: str, props: List[str],
                 epss_score: float, kev_ids: Set[str]) -> Optional[dict]:
    """Convert a raw NVD CVE dict to the vulnerability_db entry format."""
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions", [])
    description  = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

    cvss = extract_cvss(cve)
    if not cvss:
        return None

    base_score = cvss.get("baseScore", 5.0)
    av  = cvss.get("attackVector",       "LOCAL")
    ac  = cvss.get("attackComplexity",   "HIGH")
    pr  = cvss.get("privilegesRequired", "NONE")
    ui  = cvss.get("userInteraction",    "NONE")

    severity = cvss.get("baseSeverity", "")
    if not severity:
        if base_score >= 9.0:   severity = "CRITICAL"
        elif base_score >= 7.0: severity = "HIGH"
        elif base_score >= 4.0: severity = "MEDIUM"
        else:                   severity = "LOW"

    in_kev = cve_id in kev_ids
    cbs_type = cvss_av_to_cbs_type(av)

    published_list = cve.get("published", "")
    published = published_list[:10] if published_list else ""

    refs = [r.get("url", "") for r in cve.get("references", [])[:5] if r.get("url")]

    return {
        "cve_id":             cve_id,
        "label":              build_label(description, cve_id),
        "category":           category,
        "description":        description[:200].rstrip(),
        "severity":           severity,
        "cvss_score":         base_score,
        "attack_vector":      av,
        "attack_complexity":  ac,
        "privileges_required": pr,
        "user_interaction":   ui,
        "published":          published,
        "in_kev":             in_kev,
        "epss_score":         round(epss_score, 4),
        "cbs_properties":     props,
        "success_rate":       cvss_to_success_rate(ac, av, in_kev),
        "exploit_cost":       cvss_to_cost(base_score, ac),
        "cbs_type":           cbs_type,
        "probability":        round(min(epss_score * 3.0, 0.95) if epss_score > 0 else 0.4, 3),
        "references":         refs,
    }


def build_category_vuln_map(cves: List[dict],
                             category_props: Dict[str, List[str]]) -> Dict[str, dict]:
    """Build the category_vuln_map summary section."""
    groups: Dict[str, List[dict]] = defaultdict(list)
    for c in cves:
        groups[c["category"]].append(c)

    result = {}
    for cat, entries in groups.items():
        top = sorted(entries, key=lambda x: x["cvss_score"], reverse=True)[:5]
        result[cat] = {
            "properties": category_props.get(cat, []),
            "cve_count":  len(entries),
            "top_cves":   [e["cve_id"] for e in top],
            "kev_count":  sum(1 for e in entries if e.get("in_kev")),
        }
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Main scraping function
# ─────────────────────────────────────────────────────────────────────────────

def scrape_domain(
    domain_name: str,
    queries: List[Tuple[str, str]],
    category_props: Dict[str, List[str]],
    min_cvss: float,
    limit_per_query: int,
    api_key: Optional[str],
) -> dict:
    """
    Scrape NVD for all queries in a domain, enrich with EPSS + KEV,
    deduplicate, and return a vulnerability_db JSON object.
    """
    _log(f"=== Scraping domain: {domain_name} ===")
    _log(f"  {len(queries)} queries, limit={limit_per_query}/query, min_cvss={min_cvss}")

    # Step 1: fetch KEV (once)
    _log("Fetching CISA KEV…")
    kev_ids = fetch_kev()
    time.sleep(2)

    # Step 2: collect raw CVEs per category
    raw_by_category: Dict[str, List[dict]] = {}
    seen_ids: Set[str] = set()

    for idx, (query, category) in enumerate(queries, 1):
        _log(f"  [{idx:02d}/{len(queries)}] {category}: \"{query}\"")
        raw_cves = fetch_all_for_query(query, limit_per_query, min_cvss, api_key)
        raw_by_category[category] = raw_cves
        new_ids = {c.get("id") for c in raw_cves} - seen_ids
        seen_ids.update(new_ids)
        _log(f"    → {len(raw_cves)} fetched, {len(new_ids)} new unique")
        time.sleep(NVD_SLEEP)

    # Collect all unique CVE IDs for EPSS batch
    all_unique_cve_ids = list(seen_ids)
    _log(f"\nTotal unique CVEs across all queries: {len(all_unique_cve_ids)}")

    # Step 3: EPSS scores
    _log("Fetching EPSS scores…")
    epss_map = fetch_epss(all_unique_cve_ids)
    _log(f"  EPSS: got scores for {len(epss_map)} CVEs")

    # Step 4: convert to entries, deduplicate by cve_id (keep highest CVSS)
    processed: Dict[str, dict] = {}
    for category, raw_cves in raw_by_category.items():
        props = category_props.get(category, [])
        for raw in raw_cves:
            cve_id = raw.get("id", "")
            epss   = epss_map.get(cve_id, 0.0)
            entry  = cve_to_entry(raw, category, props, epss, kev_ids)
            if entry is None:
                continue
            existing = processed.get(cve_id)
            if existing is None or entry["cvss_score"] > existing["cvss_score"]:
                processed[cve_id] = entry

    cves = sorted(processed.values(), key=lambda x: x["cvss_score"], reverse=True)
    kev_count = sum(1 for c in cves if c.get("in_kev"))

    _log(f"\n  Final: {len(cves)} unique CVEs  ({kev_count} in CISA KEV)")

    # Step 5: build output document
    categories = sorted(set(c["category"] for c in cves))
    category_vuln_map = build_category_vuln_map(cves, category_props)

    return {
        "source":            "NVD API v2 (nvd.nist.gov) + EPSS (first.org) + CISA KEV",
        "domain":            domain_name,
        "scraped_at":        datetime.now().isoformat(),
        "unique_cve_count":  len(cves),
        "kev_count":         kev_count,
        "categories":        categories,
        "category_vuln_map": category_vuln_map,
        "cves":              cves,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scrape NVD + EPSS + KEV for network_devices and/or scada domains"
    )
    parser.add_argument("--domain", choices=["network_devices", "scada", "all"],
                        default="all", help="Which domain to scrape (default: all)")
    parser.add_argument("--min-cvss", type=float, default=6.0,
                        help="Minimum CVSS score to include (default: 6.0)")
    parser.add_argument("--limit-per-query", type=int, default=100,
                        help="Max CVEs per keyword query (default: 100)")
    parser.add_argument("--api-key", type=str, default=None,
                        help="NVD API key (increases rate limit to 50 req/30s)")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    domains_to_run = []
    if args.domain in ("network_devices", "all"):
        domains_to_run.append(("network_devices", NETWORK_QUERIES, NETWORK_CATEGORY_PROPS))
    if args.domain in ("scada", "all"):
        domains_to_run.append(("scada", SCADA_QUERIES, SCADA_CATEGORY_PROPS))

    for domain_name, queries, category_props in domains_to_run:
        out_path = OUT_DIR / f"{domain_name}_cves.json"

        result = scrape_domain(
            domain_name    = domain_name,
            queries        = queries,
            category_props = category_props,
            min_cvss       = args.min_cvss,
            limit_per_query= args.limit_per_query,
            api_key        = args.api_key,
        )

        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)

        _log(f"\n✓ Saved {out_path}  ({result['unique_cve_count']} CVEs)")

        if len(domains_to_run) > 1:
            _log("Sleeping 30s before next domain…")
            time.sleep(30)

    _log("\nDone.")


if __name__ == "__main__":
    main()
