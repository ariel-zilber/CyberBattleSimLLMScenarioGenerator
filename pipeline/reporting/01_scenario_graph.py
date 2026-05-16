#!/usr/bin/env python3
"""
tools/generate_scenario_graph.py
==================================
Generate a network architecture diagram for a CyberBattleSim scenario.

Layout
------
- Each IP subnet is drawn as a labelled zone (rectangle with dashed border)
- Nodes sit inside their subnet, arranged in rows by service type
- Arrows between subnets show where cross-subnet traffic is permitted
  (derived from credential links that cross subnet boundaries)
- The attacker entry node appears in its own "External" zone at the top

Output: <scenario>/graphs/network_graph.svg
        <scenario>/graphs/attack_paths.svg
        <scenario>/graphs/subnet_topology.svg

Usage:
    python3 tools/generate_scenario_graph.py <scenario_dir>
    python3 tools/generate_scenario_graph.py <scenario_dir> -r --pdf
"""
from __future__ import annotations

import argparse
import math
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
from collections import deque

# ── light-theme palette ───────────────────────────────────────────────────────
BG            = "#f5f7fa"        # canvas background
TEXT          = "#1a202c"        # primary text
SUBTEXT       = "#4a5568"        # secondary text
ZONE_BORDER   = "#718096"

EXT_FILL      = ("#e2e8f0", "#4a5568")   # external/attacker zone

# ── GLOBALTECH ref.md zone palette (matches docs/reference/ref.md colors) ────
# Each entry: (fill, stroke, zone_id, full_name)
_GT_ZONES: Dict[str, Tuple[str, str, str, str]] = {
    "Z1_HQVLANs":     ("#e8eaf6", "#5c6bc0", "Z1", "Corporate HQ — VLANs"),
    "Z1_ServerFarm":  ("#f3e5f5", "#7e57c2", "Z1", "Corporate HQ — Server Farm"),
    "Z2":             ("#ffebee", "#e53935", "Z2", "HQ Edge"),
    "HQ_Edge":        ("#ffebee", "#e53935", "Z2", "HQ Edge"),
    "Z4":             ("#fff8e1", "#f9a825", "Z4", "Internet Edge"),
    "InternetEdge":   ("#fff8e1", "#f9a825", "Z4", "Internet Edge"),
    "Z5":             ("#f9fbe7", "#827717", "Z5", "Branch Office"),
    "Z6_WebTier":     ("#e3f2fd", "#1565c0", "Z6", "AWS Cloud — Web Tier"),
    "Z6_AppTier":     ("#e8f5e9", "#2e7d32", "Z6", "AWS Cloud — App Tier"),
    "Z6_WorkerTier":  ("#e0f2f1", "#00695c", "Z6", "AWS Cloud — Worker Tier"),
    "Z6_DataTier":    ("#fce4ec", "#ad1457", "Z6", "AWS Cloud — Data Tier"),
    "Z7":             ("#fce4ec", "#c62828", "Z7", "Remote Users"),
    "Z8":             ("#e0f2f1", "#006064", "Z8", "Key Management"),
}

# Fallback by subnet prefix (first two or three octets)
_GT_SUBNET_PREFIX: Dict[str, str] = {
    "10.0.1":  "InternetEdge",
    "10.0.2":  "HQ_Edge",
    "10.1.0":  "Z1_HQVLANs",
    "10.1.1":  "Z1_HQVLANs",
    "10.1.2":  "Z1_HQVLANs",
    "10.1.3":  "Z1_HQVLANs",
    "10.1.10": "Z1_ServerFarm",
    "10.3.1":  "Z6_WebTier",
    "10.3.2":  "Z6_AppTier",
    "10.3.3":  "Z6_WorkerTier",
    "10.3.4":  "Z6_DataTier",
    "10.3.0":  "Z6_WebTier",
}

# Fallback by service-type prefix (for flat single-domain configs like srec)
_GT_SERVICE_PREFIX: Dict[str, str] = {
    "ISPRouter":         "InternetEdge",
    "WAFAppliance":      "InternetEdge",
    "IPSAppliance":      "InternetEdge",
    "CiscoASA":          "InternetEdge",
    "F5LoadBalancer":    "InternetEdge",
    "CitrixADC":         "InternetEdge",
    "JuniperRouter":     "InternetEdge",
    "CiscoEdgeRouter":   "HQ_Edge",
    "PaloAltoFirewall":  "HQ_Edge",
    "FortiGateAppliance":"HQ_Edge",
    "CiscoNXOS":         "HQ_Edge",
    "CiscoFirepower":    "HQ_Edge",
    "AWSWebServer":      "Z6_WebTier",
    "AWSGitLab":         "Z6_WebTier",
    "AWSAppServer":      "Z6_AppTier",
    "AWSJenkins":        "Z6_AppTier",
    "AWSAuthServer":     "Z6_AppTier",
    "AWSWorkerNode":     "Z6_WorkerTier",
    "AWSRabbitMQ":       "Z6_WorkerTier",
    "AWSRedis":          "Z6_DataTier",
    "AWSPostgreSQL":     "Z6_DataTier",
    "AWSMySQL":          "Z6_DataTier",
    "AWSElasticsearch":  "Z6_DataTier",
    "SalesWorkstation":  "Z1_HQVLANs",
    "FinanceWorkstation":"Z1_HQVLANs",
    "RnDWorkstation":    "Z1_HQVLANs",
    "AdminWorkstation":  "Z1_HQVLANs",
    "DomainController":  "Z1_ServerFarm",
    "FileServer":        "Z1_ServerFarm",
    "MSSQLServer":       "Z1_ServerFarm",
    "ExchangeServer":    "Z1_ServerFarm",
    "IISServer":         "Z1_ServerFarm",
    "PrintServer":       "Z1_ServerFarm",
    "ADCS_Server":       "Z1_ServerFarm",
    "HyperVHost":        "Z1_ServerFarm",
    "SharePointServer":  "Z1_ServerFarm",
    "RDGateway":         "Z1_ServerFarm",
}

# Preferred display order for zones in kill-chain left→right
_GT_ZONE_ORDER = [
    "InternetEdge", "HQ_Edge",
    "Z6_WebTier", "Z6_AppTier", "Z6_WorkerTier", "Z6_DataTier",
    "Z1_HQVLANs", "Z1_ServerFarm",
    "Z5", "Z7", "Z8",
]

# Canonical subnet CIDRs for each GLOBALTECH zone key (used by schema mode to
# place service-type-routed nodes into the right zone when a domain uses a
# broad/flat subnet like 10.0.0.0/8).
_ZONE_CANONICAL_CIDRS: Dict[str, str] = {
    "InternetEdge":   "10.0.1.0/24",
    "HQ_Edge":        "10.0.2.0/24",
    "Z1_HQVLANs":     "10.1.0.0/24",
    "Z1_ServerFarm":  "10.1.10.0/24",
    "Z6_WebTier":     "10.3.1.0/24",
    "Z6_AppTier":     "10.3.2.0/24",
    "Z6_WorkerTier":  "10.3.3.0/24",
    "Z6_DataTier":    "10.3.4.0/24",
    "Z5":             "10.5.0.0/24",
    "Z7":             "10.7.0.0/24",
    "Z8":             "10.8.0.0/24",
}

def _resolve_zone(domain_label: str, subnet_cidr: str) -> Tuple[str, str, str, str]:
    """Return (fill, stroke, zone_id, full_name) for a domain label or subnet CIDR.

    Lookup order: exact domain label → subnet prefix (3 octets) →
    subnet prefix (2 octets) → generic fallback.
    """
    # 1. exact domain label
    if domain_label in _GT_ZONES:
        return _GT_ZONES[domain_label]
    # strip leading Z-prefix fragment (e.g. "Z1_HQVLANs" stored without leading qualifier)
    for key in _GT_ZONES:
        if domain_label.startswith(key) or key in domain_label:
            return _GT_ZONES[key]
    # 2. subnet 3-octet prefix (e.g. "10.1.10")
    parts = subnet_cidr.split("/")[0].rsplit(".", 1)[0]   # "10.1.10"
    if parts in _GT_SUBNET_PREFIX:
        key = _GT_SUBNET_PREFIX[parts]
        return _GT_ZONES[key]
    # 3. subnet 2-octet prefix (e.g. "10.1")
    parts2 = parts.rsplit(".", 1)[0]                       # "10.1"
    for prefix, key in _GT_SUBNET_PREFIX.items():
        if prefix.startswith(parts2):
            return _GT_ZONES[key]
    # 4. generic grey
    return ("#f0f4f8", "#718096", "??", domain_label)

def _resolve_zone_for_service(service_type: str) -> Tuple[str, str, str, str]:
    """Resolve GLOBALTECH zone from node service type (for flat-domain configs)."""
    for prefix, key in _GT_SERVICE_PREFIX.items():
        if service_type.startswith(prefix):
            return _GT_ZONES[key]
    return ("#f0f4f8", "#718096", "??", service_type)

def _virtual_zone_key(node_id: str, nodes: dict) -> str:
    """For flat-domain (10.0.0.0/8) configs, derive a virtual zone key from service type."""
    t = nodes[node_id]["type"]
    for prefix, key in _GT_SERVICE_PREFIX.items():
        if t.startswith(prefix):
            return key
    return "unknown"

# Keep ZONE_FILLS for fallback cycling in legacy code paths
ZONE_FILLS = [
    ("#c6f6d5", "#276749"),
    ("#bee3f8", "#2b6cb0"),
    ("#fed7d7", "#9b2c2c"),
    ("#fefcbf", "#744210"),
    ("#e9d8fd", "#553c9a"),
    ("#b2f5ea", "#234e52"),
    ("#fbd38d", "#744210"),
]

# Port chip colours (reused in info-paths)
PORT_COLORS: Dict[str, str] = {
    "HTTP":    "#2b6cb0", "HTTPS":  "#1a365d",
    "SSH":     "#c05621", "RDP":    "#9b2c2c",
    "SMB":     "#6b46c1", "LDAP":   "#553c9a",
    "WINRM":   "#97266d", "WinRM":  "#97266d",
    "MySQL":   "#276749", "Redis":  "#9b2c2c",
    "Modbus":  "#5f370e", "OPCUA":  "#065666",
    "Kerberos":"#44337a", "DNS":    "#2a4365",
    "SNMP":    "#22543d", "FTP":    "#1a365d",
    "SMTP":    "#276749", "IMAP":   "#276749",
    "MSSQL":   "#2c7a7b",
}

# ── layout constants ──────────────────────────────────────────────────────────
ICO_W, ICO_H  = 34, 40    # node icon canvas size
CELL_W        = 52         # icon cell width (icon + side padding)
CELL_H        = 58         # icon cell height (icon + label)
ICONS_PER_ROW = 6          # max icons per row inside a zone
ZONE_PAD      = 16         # inner padding
ZONE_HDR      = 38         # zone title bar
FW_ROW_H      = 36         # firewall-ports strip at zone bottom
COL_GAP       = 110        # horizontal gap between depth columns (room for FW icon)
ROW_GAP       = 40         # vertical gap between zones in the same column
CLOUD_W       = 90         # external network cloud width
CLOUD_H       = 60
# ── light-theme aliases used by layout & render ──────────────────────────────
NODE_W, NODE_H       = CELL_W, CELL_H
NODE_GAP_X           = 6
NODE_GAP_Y           = 8
NODES_PER_ROW        = ICONS_PER_ROW
TYPE_H               = 22
ZONE_HEADER          = ZONE_HDR
ZONE_STROKE          = ZONE_BORDER

START_ZONE    = "#dbeafe"
START_STROKE  = "#2b6cb0"
GOAL_STROKE   = "#c53030"
START_STROKE2 = "#2b6cb0"
DEFAULT_FILL  = "#ffffff"
GOAL_FILL     = "#fff5f5"
START_FILL    = "#ebf8ff"

TYPE_COLORS: Dict[str, str] = {
    "DomainController":      "#6b46c1",
    "CertificateAuthority":  "#c05621",
    "BackupServer":          "#553c9a",
    "ExchangeServer":        "#2b6cb0",
    "FileServer":            "#276749",
    "ManagementServer":      "#744210",
    "PrintServer":           "#4a5568",
    "SQLServer":             "#276749",
    "WebServer":             "#2b6cb0",
    "Workstation":           "#4a5568",
    "Workstations":          "#4a5568",
    "PLCController":         "#065666",
    "ModbusPLC":             "#234e52",
    "AllenBradleyPLC":       "#1a365d",
    "SiemensPLC":            "#1e4488",
    "SCADA":                 "#97266d",
    "SCADAServer":           "#97266d",
    "HMI":                   "#9b2c2c",
    "HMIWorkstation":        "#9b2c2c",
    "HistorianServer":       "#744210",
    "EngineeringStation":    "#2d3748",
    "OPCServer":             "#234e52",
    "APIGateway":            "#1a365d",
    "LoadBalancer":          "#1a365d",
    "AppServer":             "#1a3a6b",
    "WebDatabase":           "#276749",
    "CacheServer":           "#c05621",
    "AdminPanel":            "#553c9a",
    "JumpHost":              "#744210",
}
DEFAULT_TYPE_COLOR = "#4a5568"

# ─────────────────────────────────────────────────────────────────────────────

def _make_loader():
    class L(yaml.SafeLoader): pass
    def _ign(loader, tag, node):
        if isinstance(node, yaml.ScalarNode):   return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode): return loader.construct_sequence(node, deep=True)
        return loader.construct_mapping(node, deep=True)
    L.add_multi_constructor("", _ign)
    return L

_LOADER = _make_loader()

# ─────────────────────────────────────────────────────────────────────────────
# Parse

def _service_type(node_id: str) -> str:
    if node_id == "start": return "start"
    parts = [p for p in node_id.split("_") if not p.isdigit()]
    t = parts[1] if len(parts) >= 2 else parts[-1]
    if t.endswith("s") and len(t) > 4:
        singular = t[:-1]
        if not singular.endswith("C") and not singular.endswith("l"):
            t = singular
    return t

def _node_num(node_id: str) -> str:
    parts = node_id.split("_")
    nums = [p for p in parts if p.isdigit()]
    return nums[-1] if nums else ""

def _short(node_id: str) -> str:
    if node_id == "start": return "ATTACKER"
    t = _service_type(node_id)
    n = _node_num(node_id)
    abbr = {
        # Windows / AD
        "DomainController": "DC", "CertificateAuthority": "CA",
        "ExchangeServer": "Exchange", "ManagementServer": "Mgmt",
        "BackupServer": "Backup", "FileServer": "File",
        "WebServer": "Web", "SQLServer": "SQL",
        "PrintServer": "Print", "Workstation": "WS",
        "Workstations": "WS", "MSSQLServer": "MSSQL",
        "IISServer": "IIS", "HyperVHost": "Hyper-V",
        "RDGateway": "RD-GW", "SharePointServer": "SharePt",
        "ADCS_Server": "ADCS", "ADCSServer": "ADCS",
        "SalesWorkstation": "Sales-WS", "AdminWorkstation": "Admin-WS",
        "FinanceWorkstation": "Fin-WS", "RnDWorkstation": "RnD-WS",
        # SCADA / OT
        "AllenBradleyPLC": "AB-PLC", "SiemensPLC": "S7-PLC",
        "ModbusPLC": "MB-PLC", "SCADAServer": "SCADA",
        "HMIWorkstation": "HMI", "HistorianServer": "Historian",
        "EngineeringStation": "Engr", "OPCServer": "OPC",
        # AWS cloud (also add singularized forms since _service_type() strips trailing s)
        "AWSWebServer": "Web", "AWSAppServer": "App",
        "AWSGitLab": "GitLab", "AWSJenkins": "Jenkins", "AWSJenkin": "Jenkins",
        "AWSAuthServer": "Auth", "AWSWorkerNode": "Worker",
        "AWSRabbitMQ": "RabbitMQ", "AWSRedis": "Redis", "AWSRedi": "Redis",
        "AWSPostgreSQL": "PostgreSQL", "AWSMySQL": "MySQL",
        "AWSElasticsearch": "Elastic",
        # Network appliances
        "ISPRouter": "ISP-Rtr", "WAFAppliance": "WAF",
        "IPSAppliance": "IPS", "CiscoASA": "Cisco-ASA",
        "CiscoNXOS": "NXOS", "CiscoFirepower": "Firepower",
        "CiscoEdgeRouter": "Edge-Rtr", "CiscoIOS": "Cisco-IOS",
        "PaloAltoFirewall": "PAN-FW", "FortiGateAppliance": "FortiGate",
        "F5LoadBalancer": "F5-LB", "CitrixADC": "Citrix-ADC",
        "JuniperRouter": "Juniper",
        # Generic
        "APIGateway": "API-GW", "LoadBalancer": "LB",
        "AppServer": "App", "WebDatabase": "WebDB",
        "CacheServer": "Cache", "AdminPanel": "Admin",
        "JumpHost": "Jump",
    }.get(t, t[:8])
    return f"{abbr}_{n}" if n else abbr

def parse_scenario(nodes_dir: Path):
    global _SCHEMA_MODE
    _SCHEMA_MODE = False
    nodes   = {}
    subnets: Dict[str, dict] = {}

    for f in sorted(nodes_dir.glob("*.yaml")):
        nid = f.stem
        try:
            with open(f) as fh:
                raw = yaml.load(fh, Loader=_LOADER) or {}
        except Exception as e:
            print(f"  [warn] {f.name}: {e}", file=sys.stderr)
            continue

        net_info = raw.get("network_info") or []
        ip     = ""
        subnet = "0.0.0.0/0"
        if net_info and isinstance(net_info[0], dict):
            ip     = net_info[0].get("ip_address", "")
            subnet = net_info[0].get("subnet", {}).get("network", "0.0.0.0/0")

        services = [s["name"] for s in (raw.get("services") or [])
                    if isinstance(s, dict) and s.get("name")]

        fw_out_subnets = set()
        for rule in (raw.get("firewall") or {}).get("outgoing") or []:
            if isinstance(rule, dict):
                r_net = rule.get("subnet", {}).get("network", "")
                if r_net and r_net != subnet and not r_net.endswith("/32"):
                    fw_out_subnets.add(r_net)

        nodes[nid] = {
            "type":    _service_type(nid),
            "ip":      ip,
            "subnet":  subnet,
            "is_goal": raw.get("is_goal", False),
            "is_start":nid == "start",
            "services": services,
            "fw_out":  fw_out_subnets,
        }

        parts = nid.split("_")
        words = [p for p in parts if not p.isdigit()]
        domain_label = words[0] if words else subnet

        if subnet not in subnets:
            subnets[subnet] = {"label": domain_label, "node_ids": []}
        subnets[subnet]["node_ids"].append(nid)

    cross_links: set = set()
    node_edges: List[Tuple[str, str]] = []
    edge_ports_raw: Dict[Tuple[str,str], set] = {}

    for f in sorted(nodes_dir.glob("*.yaml")):
        nid = f.stem
        if nid not in nodes:
            continue
        try:
            with open(f) as fh:
                raw = yaml.load(fh, Loader=_LOADER) or {}
        except Exception:
            continue
        src_subnet = nodes[nid]["subnet"]
        for vuln in (raw.get("vulnerabilities") or {}).values():
            if not isinstance(vuln, dict): continue
            outcome = vuln.get("outcome") or {}
            if outcome.get("type") != "leaked_credentials": continue
            for cred in (outcome.get("kwargs") or {}).get("credentials") or []:
                if not isinstance(cred, dict): continue
                target = (cred.get("kwargs") or {}).get("node")
                port   = (cred.get("kwargs") or {}).get("port", "")
                if target and target in nodes:
                    node_edges.append((nid, target))
                    edge_ports_raw.setdefault((nid, target), set()).add(port)
                    dst_subnet = nodes[target]["subnet"]
                    if dst_subnet != src_subnet:
                        cross_links.add((src_subnet, dst_subnet))

    for nid, n in nodes.items():
        if n["is_start"]:
            for cidr in subnets:
                if cidr != n["subnet"]:
                    cross_links.add((n["subnet"], cidr))

    seen_edges: set = set()
    unique_edges: List[Tuple[str, str]] = []
    for e in node_edges:
        if e not in seen_edges:
            seen_edges.add(e)
            unique_edges.append(e)
    node_edges = unique_edges
    edge_ports = {k: sorted(v - {""}) for k, v in edge_ports_raw.items()}

    return nodes, subnets, cross_links, node_edges, edge_ports

def parse_firewall_rules(nodes_dir: Path, nodes: dict):
    subnet_ports: Dict[str, set] = {}
    cross_rules: Dict[tuple, list] = {}

    for f in sorted(nodes_dir.glob("*.yaml")):
        nid = f.stem
        if nid not in nodes:
            continue
        try:
            with open(f) as fh:
                raw = yaml.load(fh, Loader=_LOADER) or {}
        except Exception:
            continue

        my_subnet = nodes[nid]["subnet"]
        fw = raw.get("firewall") or {}

        for direction, rules in [("OUT", fw.get("outgoing") or []),
                                  ("IN",  fw.get("incoming")  or [])]:
            for r in rules:
                if not isinstance(r, dict):
                    continue
                peer   = (r.get("subnet") or {}).get("network", "")
                port   = r.get("port", "")
                reason = r.get("reason", "")
                
                skip_port = (not port or port in ("*", "ALL", "all"))

                if peer == my_subnet or peer.endswith("/32"):
                    if not skip_port:
                        subnet_ports.setdefault(my_subnet, set()).add(port)
                elif peer and peer != "0.0.0.0/0" and peer in {
                        n["subnet"] for n in nodes.values()}:
                    key = (my_subnet, peer)
                    entry = (direction, port if not skip_port else "*", reason)
                    if entry not in cross_rules.get(key, []):
                        cross_rules.setdefault(key, []).append(entry)

    result_ports = {
        cidr: sorted(ports)[:10]
        for cidr, ports in subnet_ports.items()
    }
    return result_ports, cross_rules

# ─────────────────────────────────────────────────────────────────────────────
# Layout

def _nodes_per_row(n_total: int) -> int:
    if n_total <= 4:  return n_total
    if n_total <= 12: return min(n_total, 4)
    if n_total <= 30: return 5
    return 6

def _type_block_size(n: int) -> Tuple[int, int]:
    per_row = _nodes_per_row(n)
    return per_row, math.ceil(n / per_row)

def _zone_size(subnet_info: dict, nodes: dict, has_fw_row: bool = True) -> Tuple[int, int]:
    nids = subnet_info["node_ids"]
    if not nids:
        return (260, 130)

    types: Dict[str, List[str]] = {}
    for nid in nids:
        t = nodes[nid]["type"]
        types.setdefault(t, []).append(nid)

    sorted_types = sorted(types.items(), key=lambda x: -len(x[1]))

    blocks = []
    for tname, members in sorted_types:
        cols, rows = _type_block_size(len(members))
        bw = cols * (NODE_W + NODE_GAP_X)
        if _SCHEMA_MODE:
            # No type-label row; step-C skipped for complete rows in compute_layout
            bh = rows * (NODE_H + NODE_GAP_Y)
        else:
            bh = rows * (NODE_H + NODE_GAP_Y) + TYPE_H
        blocks.append((tname, bw, bh))

    col0_h, col1_h = 0, 0
    col0_w, col1_w = 0, 0
    for _, bw, bh in blocks:
        if col0_h <= col1_h:
            col0_h += bh + NODE_GAP_Y
            col0_w = max(col0_w, bw)
        else:
            col1_h += bh + NODE_GAP_Y
            col1_w = max(col1_w, bw)

    total_w = col0_w + col1_w + NODE_GAP_X * 3 + 2 * ZONE_PAD
    fw_extra = FW_ROW_H if has_fw_row else 0
    total_h  = ZONE_HEADER + max(col0_h, col1_h) + 2 * ZONE_PAD + fw_extra
    return (max(total_w, 260), max(total_h, 140))

def compute_layout(subnets: dict, nodes: dict, cross_links: set):
    start_subnet = None
    for nid, n in nodes.items():
        if n["is_start"]:
            start_subnet = n["subnet"]
            break

    internal_cidrs = [c for c in subnets if c != start_subnet]
    sizes = {cidr: _zone_size(subnets[cidr], nodes) for cidr in subnets}

    MARGIN = 40
    GAP    = 50

    total_int_w = sum(sizes[c][0] for c in internal_cidrs) + GAP * (max(len(internal_cidrs) - 1, 0))
    max_int_h   = max((sizes[c][1] for c in internal_cidrs), default=200)

    attacker_w, attacker_h = sizes.get(start_subnet, (220, 120))
    canvas_w = max(total_int_w, attacker_w) + 2 * MARGIN
    canvas_h = attacker_h + GAP * 2 + max_int_h + 2 * MARGIN

    zone_rects: Dict[str, Tuple[int, int, int, int]] = {}

    if start_subnet:
        ax = (canvas_w - attacker_w) // 2
        ay = MARGIN
        zone_rects[start_subnet] = (ax, ay, attacker_w, attacker_h)

    int_start_x = (canvas_w - total_int_w) // 2
    int_y = MARGIN + attacker_h + GAP * 2
    cur_x = int_start_x
    for cidr in internal_cidrs:
        w, h = sizes[cidr]
        zone_rects[cidr] = (cur_x, int_y, w, h)
        cur_x += w + GAP

    node_pos: Dict[str, Tuple[int, int]] = {}

    for cidr, info in subnets.items():
        if cidr not in zone_rects:
            continue
        zx, zy, zw, zh = zone_rects[cidr]
        nids = info["node_ids"]

        types: Dict[str, List[str]] = {}
        for nid in nids:
            t = nodes[nid]["type"]
            types.setdefault(t, []).append(nid)

        sorted_types = sorted(types.items(), key=lambda x: -len(x[1]))

        blocks_info = []
        for tname, members in sorted_types:
            per_row = _nodes_per_row(len(members))
            n_rows  = math.ceil(len(members) / per_row)
            if _SCHEMA_MODE:
                bh = n_rows * (NODE_H + NODE_GAP_Y)
            else:
                bh = n_rows * (NODE_H + NODE_GAP_Y) + TYPE_H
            bw = per_row * (NODE_W + NODE_GAP_X)
            blocks_info.append((tname, members, per_row, bw, bh))

        col0_items, col1_items = [], []
        col0_h, col1_h = 0, 0
        col0_w, col1_w = 0, 0
        for item in blocks_info:
            _, _, _, bw, bh = item
            if col0_h <= col1_h:
                col0_items.append(item)
                col0_h += bh + NODE_GAP_Y
                col0_w = max(col0_w, bw)
            else:
                col1_items.append(item)
                col1_h += bh + NODE_GAP_Y
                col1_w = max(col1_w, bw)

        base_y = zy + ZONE_HEADER + ZONE_PAD
        lx     = zx + ZONE_PAD
        rx     = lx + col0_w + NODE_GAP_X * 2

        for items, start_x in [(col0_items, lx), (col1_items, rx)]:
            cur_y = base_y
            for tname, members, per_row, bw, bh in items:
                if not _SCHEMA_MODE:
                    cur_y += TYPE_H
                col_i = 0
                for nid in members:
                    cx = start_x + col_i * (NODE_W + NODE_GAP_X) + NODE_W // 2
                    cy = cur_y + NODE_H // 2
                    node_pos[nid] = (cx, cy)
                    col_i += 1
                    if col_i >= per_row:
                        col_i = 0
                        cur_y += NODE_H + NODE_GAP_Y
                # step-C: skip for schema mode when last row was complete (col_i==0)
                if not (_SCHEMA_MODE and col_i == 0):
                    cur_y += NODE_H + NODE_GAP_Y

    return zone_rects, node_pos, canvas_w, canvas_h

# ─────────────────────────────────────────────────────────────────────────────
# SVG helpers

def _esc(s) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def _type_fill(t: str) -> str:
    return TYPE_COLORS.get(t, DEFAULT_TYPE_COLOR)

def _port_chip(x: float, y: float, port: str) -> str:
    color = PORT_COLORS.get(port, "#607D8B")
    chip_w = max(32, len(port) * 7 + 10)
    chip_h = 17
    return (
        f'<rect x="{x:.0f}" y="{y:.0f}" width="{chip_w}" height="{chip_h}" rx="4" '
        f'fill="{color}" opacity="0.85"/>'
        f'<text x="{x + chip_w/2:.0f}" y="{y + 12:.0f}" text-anchor="middle" '
        f'font-family="monospace" font-size="10" font-weight="bold" fill="white">'
        f'{_esc(port)}</text>'
    )

def _node_category(node_type: str) -> str:
    t = node_type.lower()
    if "domaincontrol" in t or "certific" in t: return "dc"
    if "web" in t or "api" in t or "loadbal" in t: return "web"
    if "workstation" in t or "hmi" in t:            return "workstation"
    if "plc" in t or "scada" in t or "opc" in t or "modbus" in t or "historian" in t:
        return "plc"
    if t == "start":                                return "attacker"
    return "server"

def _icon_svg(cat: str, cx: float, cy: float, fill: str, accent: str) -> str:
    s = []
    if cat == "server":
        s += [
            f'<rect x="{cx-11:.0f}" y="{cy-12:.0f}" width="22" height="24" rx="2" '
            f'fill="{fill}" stroke="{accent}" stroke-width="1.5"/>',
        ]
        for yo in (-5, 0, 5):
            s += [
                f'<line x1="{cx-8:.0f}" y1="{cy+yo:.0f}" x2="{cx+4:.0f}" y2="{cy+yo:.0f}" '
                f'stroke="{accent}" stroke-width="1" opacity="0.5"/>',
                f'<circle cx="{cx+7:.0f}" cy="{cy+yo:.0f}" r="1.8" fill="{accent}" opacity="0.7"/>',
            ]
    elif cat == "dc":
        for yo, op in ((-6, "1.0"), (5, "0.65")):
            s += [
                f'<rect x="{cx-10:.0f}" y="{cy+yo:.0f}" width="20" height="8" rx="1" '
                f'fill="{fill}" stroke="{accent}" stroke-width="1.2" opacity="{op}"/>',
                f'<circle cx="{cx+7:.0f}" cy="{cy+yo+4:.0f}" r="1.5" fill="{accent}" opacity="{op}"/>',
            ]
    elif cat == "web":
        s += [
            f'<circle cx="{cx:.0f}" cy="{cy:.0f}" r="11" fill="{fill}" '
            f'stroke="{accent}" stroke-width="1.5"/>',
            f'<ellipse cx="{cx:.0f}" cy="{cy:.0f}" rx="5" ry="11" fill="none" '
            f'stroke="{accent}" stroke-width="1" opacity="0.6"/>',
            f'<line x1="{cx-11:.0f}" y1="{cy:.0f}" x2="{cx+11:.0f}" y2="{cy:.0f}" '
            f'stroke="{accent}" stroke-width="1" opacity="0.6"/>',
        ]
    elif cat == "workstation":
        s += [
            f'<rect x="{cx-11:.0f}" y="{cy-11:.0f}" width="22" height="15" rx="2" '
            f'fill="{fill}" stroke="{accent}" stroke-width="1.5"/>',
            f'<rect x="{cx-3:.0f}" y="{cy+4:.0f}" width="6" height="4" rx="1" '
            f'fill="{accent}" opacity="0.7"/>',
            f'<rect x="{cx-8:.0f}" y="{cy+8:.0f}" width="16" height="3" rx="1" '
            f'fill="{accent}" opacity="0.5"/>',
        ]
    elif cat == "plc":
        s += [
            f'<rect x="{cx-11:.0f}" y="{cy-8:.0f}" width="22" height="16" rx="2" '
            f'fill="{fill}" stroke="{accent}" stroke-width="1.5"/>',
            f'<circle cx="{cx-5:.0f}" cy="{cy:.0f}" r="2.5" fill="{accent}" opacity="0.8"/>',
            f'<circle cx="{cx+5:.0f}" cy="{cy:.0f}" r="2.5" fill="{accent}" opacity="0.8"/>',
            f'<line x1="{cx-9:.0f}" y1="{cy-4:.0f}" x2="{cx+9:.0f}" y2="{cy-4:.0f}" '
            f'stroke="{accent}" stroke-width="1" opacity="0.4"/>',
        ]
    elif cat == "attacker":
        s += [
            f'<rect x="{cx-12:.0f}" y="{cy-8:.0f}" width="24" height="14" rx="2" '
            f'fill="{fill}" stroke="{accent}" stroke-width="1.5"/>',
            f'<line x1="{cx-14:.0f}" y1="{cy+7:.0f}" x2="{cx+14:.0f}" y2="{cy+7:.0f}" '
            f'stroke="{accent}" stroke-width="2.5"/>',
        ]
    else:
        s.append(
            f'<rect x="{cx-11:.0f}" y="{cy-11:.0f}" width="22" height="22" rx="3" '
            f'fill="{fill}" stroke="{accent}" stroke-width="1.5"/>'
        )
    return "".join(s)

def _firewall_brick(mx: float, my: float) -> str:
    ow, oh = 22, 18
    bw, bh = 7, 4
    ox, oy = mx - ow / 2, my - oh / 2
    parts = [
        f'<rect x="{ox:.0f}" y="{oy:.0f}" width="{ow}" height="{oh}" rx="2" '
        f'fill="white" stroke="#a0aec0" stroke-width="1.2"/>',
    ]
    for row in range(3):
        ry = oy + 1 + row * (bh + 1)
        off = (bw // 2 + 1) if row % 2 else 0
        bx = ox + 1 - off
        while bx < ox + ow:
            rx0 = max(bx, ox + 1)
            rx1 = min(bx + bw, ox + ow - 1)
            if rx1 > rx0:
                parts.append(
                    f'<rect x="{rx0:.0f}" y="{ry:.0f}" '
                    f'width="{rx1 - rx0:.0f}" height="{bh}" rx="0.5" '
                    f'fill="#a0aec0" stroke="white" stroke-width="0.3"/>'
                )
            bx += bw + 1
    return "".join(parts)

def render(nodes, subnets, cross_links, node_edges, zone_rects, node_pos, cw, ch,
           subnet_ports=None, cross_rules=None) -> str:
    L = []
    w = L.append

    w(f'<svg xmlns="http://www.w3.org/2000/svg" width="{cw}" height="{ch}" '
      f'viewBox="0 0 {cw} {ch}">')

    w('<defs>')
    w('<marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" '
      'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
      '<path d="M0,0 L10,5 L0,10 z" fill="#718096"/></marker>')
    w('<marker id="arrSmall" viewBox="0 0 8 8" refX="7" refY="4" '
      'markerWidth="4" markerHeight="4" orient="auto-start-reverse">'
      '<path d="M0,0 L8,4 L0,8 z" fill="context-stroke"/></marker>')
    w('</defs>')

    w(f'<rect width="{cw}" height="{ch}" fill="{BG}"/>')

    # GLOBALTECH header bar
    w(f'<rect x="0" y="0" width="{cw}" height="46" fill="#1a202c"/>')
    w(f'<text x="14" y="17" font-family="sans-serif" font-size="11" '
      f'font-weight="bold" fill="#90cdf4" letter-spacing="2">GLOBALTECH ENTERPRISE NETWORK</text>')
    w(f'<text x="14" y="35" font-family="monospace" font-size="13" '
      f'font-weight="bold" fill="white">Network Architecture</text>')

    n_goals = sum(1 for n in nodes.values() if n["is_goal"])
    n_subs  = len([c for c in subnets if c != next(
        (nodes[nid]["subnet"] for nid in nodes if nodes[nid]["is_start"]), None)])
    w(f'<text x="{cw - 14}" y="35" text-anchor="end" font-family="monospace" font-size="10" '
      f'fill="#718096">{len(nodes)} nodes  ·  {n_goals} goal(s)  ·  {n_subs} subnet(s)</text>')

    for (src_c, dst_c) in cross_links:
        if src_c not in zone_rects or dst_c not in zone_rects:
            continue
        sx, sy, sw, sh = zone_rects[src_c]
        dx, dy, dw, dh = zone_rects[dst_c]
        x1, y1 = sx + sw // 2, sy + sh
        x2, y2 = dx + dw // 2, dy
        mid_y = (y1 + y2) // 2
        w(f'<path d="M{x1},{y1} C{x1},{mid_y} {x2},{mid_y} {x2},{y2}" '
          f'stroke="#718096" stroke-width="2" stroke-opacity="0.55" '
          f'fill="none" marker-end="url(#arr)"/>')

        fw_mx = (x1 + x2) / 2
        fw_my = (y1 + y2) / 2
        w(_firewall_brick(fw_mx, fw_my))

        lx = int((x1 + x2) / 2)
        ly = int(fw_my) + 16
        rules = (cross_rules or {}).get((src_c, dst_c), [])
        rule_ports = sorted({r[1] for r in rules if r[1] not in ("*", "ALL", "all")})
        if rule_ports:
            full_label = " · ".join(rule_ports[:4])
            lw_text = len(full_label) * 6 + 12
            w(f'<rect x="{lx - lw_text//2}" y="{ly - 9}" width="{lw_text}" '
              f'height="14" rx="3" fill="white" stroke="#718096" stroke-width="0.8"/>')
            w(f'<text x="{lx}" y="{ly + 2}" text-anchor="middle" '
              f'font-family="monospace" font-size="9" fill="{SUBTEXT}">'
              f'{_esc(full_label)}</text>')

    start_subnet = next(
        (nodes[nid]["subnet"] for nid in nodes if nodes[nid]["is_start"]), None)

    zone_meta: Dict[str, dict] = {}
    for i, (cidr, info) in enumerate(subnets.items()):
        if cidr not in zone_rects:
            continue
        zx, zy, zw, zh = zone_rects[cidr]
        is_ext = (cidr == start_subnet)
        if is_ext:
            zfill, zstroke = EXT_FILL
            zlabel = info["label"]
        else:
            zfill, zstroke, zone_id, zone_full = _resolve_zone(info["label"], cidr)
            zlabel = f"{zone_id} — {zone_full}" if zone_id != "??" else info["label"]
        zone_meta[cidr] = {"fill": zfill, "stroke": zstroke,
                           "is_ext": is_ext, "label": zlabel}
        w(f'<rect x="{zx}" y="{zy}" width="{zw}" height="{zh}" rx="12" fill="{zfill}"/>')

    within_edges = [(s, t) for s, t in node_edges
                    if nodes[s]["subnet"] == nodes[t]["subnet"]]
    cross_edges  = [(s, t) for s, t in node_edges
                    if nodes[s]["subnet"] != nodes[t]["subnet"]]

    def _is_special(s, t):
        return nodes[s]["is_start"] or nodes[t]["is_goal"]

    for src, dst in within_edges:
        if src not in node_pos or dst not in node_pos:
            continue
        x1, y1 = node_pos[src]
        x2, y2 = node_pos[dst]
        special = _is_special(src, dst)
        if special:
            stroke_c, sw, opacity = "#2b6cb0", "1.4", "0.55"
        else:
            stroke_c, sw, opacity = "#718096", "0.8", "0.20"
        w(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
          f'stroke="{stroke_c}" stroke-width="{sw}" opacity="{opacity}"/>')

    for i, (cidr, info) in enumerate(subnets.items()):
        if cidr not in zone_rects:
            continue
        zx, zy, zw, zh = zone_rects[cidr]
        m = zone_meta[cidr]
        is_ext  = m["is_ext"]
        zstroke = m["stroke"]
        label   = m["label"]

        w(f'<rect x="{zx}" y="{zy}" width="{zw}" height="{zh}" rx="12" '
          f'fill="none" stroke="{zstroke}" stroke-width="2.5"/>')

        w(f'<rect x="{zx+2}" y="{zy+2}" width="{zw-4}" height="{ZONE_HEADER-2}" rx="10" '
          f'fill="{zstroke}" opacity="0.15"/>')
        w(f'<text x="{zx+14}" y="{zy+16}" font-family="sans-serif" font-size="13" '
          f'font-weight="bold" fill="{zstroke}">'
          f'{"[EXT] EXTERNAL" if is_ext else _esc(label)}</text>')
        w(f'<text x="{zx+14}" y="{zy+29}" font-family="monospace" font-size="10" '
          f'fill="{SUBTEXT}">{_esc(cidr)}</text>')

        n_within = sum(1 for s, t in within_edges
                       if nodes[s]["subnet"] == cidr or nodes[t]["subnet"] == cidr)
        n_cross  = sum(1 for s, t in cross_edges
                       if nodes[s]["subnet"] == cidr or nodes[t]["subnet"] == cidr)
        badge = f"{n_within}w {n_cross}x"
        w(f'<text x="{zx+zw-10}" y="{zy+29}" text-anchor="end" '
          f'font-family="monospace" font-size="9" fill="{zstroke}" opacity="0.6">'
          f'{_esc(badge)}</text>')

        nids = info["node_ids"]
        types: Dict[str, List[str]] = {}
        for nid in nids:
            t = nodes[nid]["type"]
            types.setdefault(t, []).append(nid)

        sorted_types_r = sorted(types.items(), key=lambda x: -len(x[1]))
        blocks_r = []
        for tname, members in sorted_types_r:
            per_row = _nodes_per_row(len(members))
            n_rows  = math.ceil(len(members) / per_row)
            bh = n_rows * (NODE_H + NODE_GAP_Y) + TYPE_H
            bw = per_row * (NODE_W + NODE_GAP_X)
            blocks_r.append((tname, members, per_row, bw, bh))

        col0_r, col1_r = [], []
        col0_h_r, col1_h_r = 0, 0
        col0_w_r = 0
        for item in blocks_r:
            _, _, _, bw, bh = item
            if col0_h_r <= col1_h_r:
                col0_r.append(item); col0_h_r += bh + NODE_GAP_Y
                col0_w_r = max(col0_w_r, bw)
            else:
                col1_r.append(item); col1_h_r += bh + NODE_GAP_Y

        base_yr = zy + ZONE_HEADER + ZONE_PAD
        lxr = zx + ZONE_PAD
        rxr = lxr + col0_w_r + NODE_GAP_X * 2

        for items_r, start_xr in [(col0_r, lxr), (col1_r, rxr)]:
            cur_yr = base_yr
            for tname, members, per_row, bw, bh in items_r:
                if not _SCHEMA_MODE:
                    label_y = cur_yr + 13
                    w(f'<text x="{start_xr+4}" y="{label_y}" '
                      f'font-family="sans-serif" font-size="11" font-weight="600" '
                      f'fill="{zone_meta[cidr]["stroke"]}" opacity="0.7">{_esc(tname)}</text>')
                cur_yr += TYPE_H
                n_rows = math.ceil(len(members) / per_row)
                cur_yr += n_rows * (NODE_H + NODE_GAP_Y) + NODE_GAP_Y

    for src, dst in cross_edges:
        if src not in node_pos or dst not in node_pos:
            continue
        x1, y1 = node_pos[src]
        x2, y2 = node_pos[dst]
        special = _is_special(src, dst)
        stroke_c = "#2ea043" if nodes[src]["is_start"] else (
                   "#c53030" if nodes[dst]["is_goal"] else "#744210")
        sw      = "1.8" if special else "1.0"
        opacity = "0.65" if special else "0.30"
        mx = (x1 + x2) / 2
        my = (y1 + y2) / 2 - abs(x2 - x1) * 0.2
        w(f'<path d="M{x1:.0f},{y1:.0f} Q{mx:.0f},{my:.0f} {x2:.0f},{y2:.0f}" '
          f'stroke="{stroke_c}" stroke-width="{sw}" opacity="{opacity}" '
          f'fill="none" marker-end="url(#arrSmall)"/>')

    for i, (cidr, info) in enumerate(subnets.items()):
        if cidr not in zone_rects:
            continue
        zx, zy, zw, zh = zone_rects[cidr]
        ports = (subnet_ports or {}).get(cidr, [])
        if not ports:
            continue

        sep_y = zy + zh - FW_ROW_H
        w(f'<line x1="{zx+10}" y1="{sep_y}" x2="{zx+zw-10}" y2="{sep_y}" '
          f'stroke="{zone_meta[cidr]["stroke"]}" stroke-width="0.8" opacity="0.35"/>')
        w(f'<text x="{zx+14}" y="{sep_y+13}" font-family="sans-serif" '
          f'font-size="10" fill="{SUBTEXT}">allowed ports:</text>')

        chip_x = zx + 14 + 92
        chip_y = sep_y + 19
        for port in ports:
            chip_w = max(32, len(port) * 7 + 10)
            if chip_x + chip_w > zx + zw - 112:
                break
            w(_port_chip(chip_x, chip_y, port))
            chip_x += chip_w + 5

        block_x = zx + zw - 105
        w(f'<rect x="{block_x}" y="{chip_y-1}" width="98" height="17" rx="4" '
          f'fill="#fff5f5" stroke="#c53030" stroke-width="1"/>')
        w(f'<text x="{block_x+49}" y="{chip_y+12}" text-anchor="middle" '
          f'font-family="monospace" font-size="10" font-weight="bold" fill="#c53030">'
          f'default: BLOCK</text>')

    for nid, n in nodes.items():
        if nid not in node_pos:
            continue
        cx, cy = node_pos[nid]
        bx = cx - NODE_W // 2
        by = cy - NODE_H // 2

        is_start = n["is_start"]
        is_goal  = n["is_goal"]
        type_c   = TYPE_COLORS.get(n["type"], DEFAULT_TYPE_COLOR)
        if is_start:
            box_fill, box_stroke = START_FILL, START_STROKE2
        elif is_goal:
            box_fill, box_stroke = GOAL_FILL, GOAL_STROKE
        else:
            box_fill, box_stroke = DEFAULT_FILL, type_c
        sw_node = "2.5" if (is_start or is_goal) else "1.5"

        svcs    = n["services"]
        svc_str = ", ".join(svcs) if svcs else "none"
        tip_lines = [nid, f"IP: {n.get('ip','?')}", f"Services: {svc_str}",
                     f"Subnet: {n['subnet']}"]
        if is_goal:  tip_lines.append("GOAL NODE")
        if is_start: tip_lines.append("ATTACKER ENTRY")

        w(f'<rect x="{bx}" y="{by}" width="{NODE_W}" height="{NODE_H}" rx="6" '
          f'fill="{box_fill}" stroke="{box_stroke}" stroke-width="{sw_node}">'
          f'<title>{_esc(chr(10).join(tip_lines))}</title></rect>')

        if not is_start and not is_goal:
            w(f'<rect x="{bx}" y="{by+5}" width="4" height="{NODE_H-10}" rx="2" '
              f'fill="{type_c}" opacity="0.7"/>')

        icon_cy = by + ICO_H // 2 + 2
        cat = _node_category(n["type"])
        ico_fill = "#f0f4ff" if not is_start else "#e8f4fd"
        w(_icon_svg(cat, cx, icon_cy, ico_fill, box_stroke))

        if is_goal:
            w(f'<rect x="{bx+NODE_W-16}" y="{by-1}" width="17" height="14" rx="3" '
              f'fill="{GOAL_STROKE}"/>')
            w(f'<text x="{bx+NODE_W-7}" y="{by+10}" text-anchor="middle" '
              f'font-size="11" fill="white">*</text>')

        label = _short(nid)
        w(f'<text x="{cx}" y="{by+NODE_H-14}" text-anchor="middle" '
          f'font-family="sans-serif" font-size="10" font-weight="600" fill="{box_stroke}">'
          f'{_esc(label)}</text>')

        ip = n.get("ip", "")
        if ip:
            w(f'<text x="{cx}" y="{by+NODE_H-4}" text-anchor="middle" '
              f'font-family="monospace" font-size="8" fill="{SUBTEXT}">'
              f'{_esc(ip)}</text>')

    w('</svg>')
    return "\n".join(L)

# ─────────────────────────────────────────────────────────────────────────────
# Information-paths diagram

def _short_type(nid: str) -> str:
    if nid == "start":
        return "START"
    parts = [p for p in nid.split("_") if not p.isdigit()]
    words = parts[1:] if len(parts) > 1 else parts
    return "".join(w[:4] for w in words)[:10]

def render_info_paths(nodes: dict, node_edges: List[Tuple[str,str]],
                      edge_ports: Dict[Tuple[str,str], List[str]]) -> str:
    """Zone-aggregated kill-chain attack path diagram.

    Replaces the old per-node depth-column layout which produced
    23 000 px-wide canvases unreadable at any print size.

    Layout: fixed 1400 × 580 px canvas.
    Each GLOBALTECH zone that lies on the BFS attack path is drawn
    as a vertical column.  Individual service types (with counts) are
    listed inside each column.  Thick arrows between columns show the
    lateral movement direction and the dominant port.
    """
    from collections import deque

    start = next((nid for nid, n in nodes.items() if n["is_start"]), None)
    goals = [nid for nid, n in nodes.items() if n["is_goal"]]
    if not start or not goals:
        return "<svg xmlns='http://www.w3.org/2000/svg' width='400' height='100'>" \
               "<text x='20' y='60' font-family='monospace' font-size='14' fill='#ccc'>" \
               "No start/goal nodes found.</text></svg>"

    # ── BFS: build adjacency and find all nodes reachable toward any goal ────
    adj:  Dict[str, List[str]] = {}
    for src, dst in node_edges:
        adj.setdefault(src, []).append(dst)

    # BFS forward from start
    fwd: Dict[str, int] = {start: 0}
    q: deque = deque([start])
    while q:
        n = q.popleft()
        for t in adj.get(n, []):
            if t not in fwd:
                fwd[t] = fwd[n] + 1
                q.append(t)

    # BFS backward from goals to find which nodes lead to a goal
    radj: Dict[str, List[str]] = {}
    for src, dst in node_edges:
        radj.setdefault(dst, []).append(src)
    bwd: set = set(goals)
    q = deque(goals)
    while q:
        n = q.popleft()
        for s in radj.get(n, []):
            if s not in bwd:
                bwd.add(s)
                q.append(s)

    on_path = {n for n in fwd if n in bwd}
    if not on_path:
        on_path = {start} | set(goals)

    # ── Assign each on-path node to a GLOBALTECH zone key ────────────────────
    is_flat = len({nodes[n]["subnet"] for n in nodes if not nodes[n]["is_start"]}) <= 1

    def _zone_key_for(nid: str) -> str:
        if nodes[nid]["is_start"]:
            return "__external__"
        if is_flat:
            return _virtual_zone_key(nid, nodes)
        subnet = nodes[nid]["subnet"]
        domain_label = next(
            (info["label"] for cidr, info in {}.items() if cidr == subnet),
            subnet.split("/")[0].rsplit(".", 1)[0],
        )
        for key in _GT_SUBNET_PREFIX:
            if subnet.startswith(key.rsplit(".", 1)[0]):
                return _GT_SUBNET_PREFIX.get(key, "unknown")
        return "unknown"

    # Build per-zone membership from on_path nodes
    zone_nodes: Dict[str, List[str]] = {}
    for nid in on_path:
        zk = _zone_key_for(nid)
        zone_nodes.setdefault(zk, []).append(nid)

    # Order zones: external first, then canonical GLOBALTECH order, unknowns last
    ordered_zones: List[str] = []
    if "__external__" in zone_nodes:
        ordered_zones.append("__external__")
    for zk in _GT_ZONE_ORDER:
        if zk in zone_nodes:
            ordered_zones.append(zk)
    for zk in zone_nodes:
        if zk not in ordered_zones:
            ordered_zones.append(zk)

    # ── Canvas layout: fixed max 1400px, zones as horizontal columns ─────────
    CANVAS_W   = 1400
    CANVAS_H   = 560
    PAD_X      = 30
    PAD_Y      = 80
    HDR_H      = 50          # header bar height
    ARROW_W    = 54          # gap between zone columns reserved for arrows
    n_zones    = len(ordered_zones)
    usable_w   = CANVAS_W - 2 * PAD_X - max(n_zones - 1, 0) * ARROW_W
    col_w      = max(140, usable_w // max(n_zones, 1))
    col_h      = CANVAS_H - PAD_Y - HDR_H - 20

    col_x_map: Dict[str, int] = {}
    cx = PAD_X
    for zk in ordered_zones:
        col_x_map[zk] = cx
        cx += col_w + ARROW_W

    # ── Service-type summary for each zone column ─────────────────────────────
    def _svc_summary(nids: List[str]) -> List[Tuple[str, int]]:
        counts: Dict[str, int] = {}
        for nid in nids:
            t = nodes[nid]["type"]
            counts[t] = counts.get(t, 0) + 1
        return sorted(counts.items(), key=lambda x: -x[1])

    # ── Dominant port on each inter-zone edge ─────────────────────────────────
    zone_arrow_ports: Dict[Tuple[str,str], set] = {}
    for src, dst in node_edges:
        if src not in on_path or dst not in on_path:
            continue
        zs, zd = _zone_key_for(src), _zone_key_for(dst)
        if zs != zd:
            key = (zs, zd)
            ports = edge_ports.get((src, dst), [])
            zone_arrow_ports.setdefault(key, set()).update(ports)

    # ── Render ────────────────────────────────────────────────────────────────
    L: List[str] = []
    w = L.append

    w(f'<svg xmlns="http://www.w3.org/2000/svg" width="{CANVAS_W}" height="{CANVAS_H}" '
      f'viewBox="0 0 {CANVAS_W} {CANVAS_H}">')
    w('<defs>')
    for mid, color in [("kcArr","#e53935"), ("kcArrB","#1565c0"), ("kcArrG","#2e7d32")]:
        w(f'<marker id="{mid}" viewBox="0 0 10 10" refX="9" refY="5" '
          f'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
          f'<path d="M0,0 L10,5 L0,10 z" fill="{color}"/></marker>')
    w('</defs>')
    w(f'<rect width="{CANVAS_W}" height="{CANVAS_H}" fill="{BG}"/>')

    # Header bar
    w(f'<rect x="0" y="0" width="{CANVAS_W}" height="{HDR_H}" fill="#1a202c"/>')
    w(f'<text x="20" y="22" font-family="sans-serif" font-size="14" font-weight="bold" '
      f'fill="white">GLOBALTECH — Attack Chain</text>')
    w(f'<text x="20" y="40" font-family="monospace" font-size="10" fill="#a0aec0">'
      f'{len(on_path)} nodes on path  ·  {len(goals)} goal(s)  ·  '
      f'zones derived from ref.md Z1–Z8 topology</text>')

    # Draw zone columns
    for zk in ordered_zones:
        nids = zone_nodes[zk]
        col_left = col_x_map[zk]

        if zk == "__external__":
            fill, stroke, zone_id, full_name = EXT_FILL[0], EXT_FILL[1], "Z3", "Internet / Attacker"
        else:
            meta = _GT_ZONES.get(zk)
            if meta:
                fill, stroke, zone_id, full_name = meta
            else:
                fill, stroke, zone_id, full_name = "#f0f4f8", "#718096", "??", zk

        # Zone box
        w(f'<rect x="{col_left}" y="{PAD_Y}" width="{col_w}" height="{col_h}" rx="10" '
          f'fill="{fill}" stroke="{stroke}" stroke-width="2.5"/>')

        # Zone ID badge
        badge_w = max(36, len(zone_id) * 9 + 10)
        w(f'<rect x="{col_left + 8}" y="{PAD_Y + 8}" width="{badge_w}" height="22" '
          f'rx="5" fill="{stroke}"/>')
        w(f'<text x="{col_left + 8 + badge_w//2}" y="{PAD_Y + 23}" '
          f'text-anchor="middle" font-family="sans-serif" font-size="11" '
          f'font-weight="bold" fill="white">{_esc(zone_id)}</text>')

        # Zone full name
        name_x = col_left + 8 + badge_w + 6
        avail = col_w - badge_w - 22
        fname_short = full_name if len(full_name) * 7 < avail else full_name[:avail//7]
        w(f'<text x="{name_x}" y="{PAD_Y + 23}" font-family="sans-serif" '
          f'font-size="10" font-weight="bold" fill="{stroke}">{_esc(fname_short)}</text>')

        # Node count
        n_goals_here = sum(1 for nid in nids if nodes[nid]["is_goal"])
        w(f'<text x="{col_left + col_w - 10}" y="{PAD_Y + 23}" text-anchor="end" '
          f'font-family="monospace" font-size="13" font-weight="bold" '
          f'fill="{stroke}" opacity="0.5">{len(nids)}</text>')

        # Divider under header
        w(f'<line x1="{col_left + 6}" y1="{PAD_Y + 38}" '
          f'x2="{col_left + col_w - 6}" y2="{PAD_Y + 38}" '
          f'stroke="{stroke}" stroke-width="1" opacity="0.4"/>')

        # Service type rows
        summary = _svc_summary(nids)
        ty = PAD_Y + 50
        row_h = min(22, max(16, (col_h - 55) // max(len(summary), 1)))
        for svc_type, cnt in summary[:8]:
            color = TYPE_COLORS.get(svc_type, DEFAULT_TYPE_COLOR)
            w(f'<rect x="{col_left + 10}" y="{ty - 11}" width="9" height="9" '
              f'rx="2" fill="{color}"/>')
            label = svc_type if len(svc_type) <= 18 else svc_type[:16] + "…"
            w(f'<text x="{col_left + 23}" y="{ty - 2}" font-family="sans-serif" '
              f'font-size="11" fill="{TEXT}">{_esc(label)}</text>')
            w(f'<text x="{col_left + col_w - 10}" y="{ty - 2}" text-anchor="end" '
              f'font-family="monospace" font-size="11" font-weight="bold" '
              f'fill="{stroke}" opacity="0.7">{cnt}</text>')
            ty += row_h
        if len(summary) > 8:
            w(f'<text x="{col_left + col_w//2}" y="{ty + 4}" text-anchor="middle" '
              f'font-family="monospace" font-size="10" fill="{SUBTEXT}">'
              f'+{len(summary)-8} more types</text>')

        # Goal highlight bar
        if n_goals_here:
            gy = PAD_Y + col_h - 26
            w(f'<rect x="{col_left + 6}" y="{gy}" width="{col_w - 12}" height="18" '
              f'rx="5" fill="{GOAL_STROKE}" opacity="0.15"/>')
            goal_nids = [nid for nid in nids if nodes[nid]["is_goal"]]
            goal_labels = ", ".join(nodes[g]["type"] for g in goal_nids[:2])
            w(f'<text x="{col_left + col_w//2}" y="{gy + 13}" text-anchor="middle" '
              f'font-family="monospace" font-size="10" font-weight="bold" '
              f'fill="{GOAL_STROKE}">★ GOAL: {_esc(goal_labels)}</text>')

    # Draw inter-zone arrows
    for i, zk in enumerate(ordered_zones[:-1]):
        zk_next = ordered_zones[i + 1]
        src_x = col_x_map[zk] + col_w
        dst_x = col_x_map[zk_next]
        mid_y = PAD_Y + col_h // 2

        key = (zk, zk_next)
        ports = sorted(zone_arrow_ports.get(key, set()) - {"", "*"})
        port_lbl = " · ".join(ports[:3]) if ports else "→"

        arrow_cx = (src_x + dst_x) // 2
        w(f'<line x1="{src_x + 4}" y1="{mid_y}" x2="{dst_x - 4}" y2="{mid_y}" '
          f'stroke="#e53935" stroke-width="3.5" marker-end="url(#kcArr)"/>')

        if port_lbl != "→":
            lw = len(port_lbl) * 6.5 + 12
            lx_ = arrow_cx - lw // 2
            w(f'<rect x="{lx_:.0f}" y="{mid_y - 21}" width="{lw:.0f}" height="15" '
              f'rx="4" fill="white" stroke="#e53935" stroke-width="1"/>')
            w(f'<text x="{arrow_cx}" y="{mid_y - 10}" text-anchor="middle" '
              f'font-family="monospace" font-size="9" fill="#e53935">'
              f'{_esc(port_lbl)}</text>')

    # Legend
    ly = CANVAS_H - 26
    legend = [("#e53935","Lateral movement (zone-to-zone)"),
              ("#6b46c1","★  Terminal goal node"),
              ("#1a202c","Number = nodes on attack path")]
    lx = 20
    for lc, lbl in legend:
        w(f'<rect x="{lx}" y="{ly - 8}" width="12" height="12" rx="2" fill="{lc}"/>')
        w(f'<text x="{lx + 16}" y="{ly + 2}" font-family="monospace" '
          f'font-size="10" fill="{SUBTEXT}">{_esc(lbl)}</text>')
        lx += len(lbl) * 6 + 36

    w('</svg>')
    return "\n".join(L)

# ─────────────────────────────────────────────────────────────────────────────
# Subnet topology diagram

def _topo_layout(subnets: dict, nodes: dict):
    ZW, ZH   = 220, 155
    H_GAP    = 55
    V_GAP    = 52
    MARGIN   = 44
    PER_ROW  = 4
    # Minimum width to fit the header subtitle text (~75 chars × 7px + margin)
    MIN_CANVAS_W = 600

    start_cidr = next(
        (nodes[nid]["subnet"] for nid in nodes if nodes[nid]["is_start"]), None)

    internals = [c for c in subnets if c != start_cidr]

    n_cols  = min(len(internals), PER_ROW)
    n_rows  = math.ceil(len(internals) / PER_ROW) if internals else 1
    int_w   = n_cols * ZW + max(n_cols - 1, 0) * H_GAP
    canvas_w = max(max(int_w, ZW) + 2 * MARGIN, MIN_CANVAS_W)

    att_x = (canvas_w - ZW) // 2
    att_y = MARGIN
    rects = {}
    if start_cidr:
        rects[start_cidr] = (att_x, att_y, ZW, ZH)

    int_start_x = (canvas_w - int_w) // 2
    int_start_y = att_y + ZH + V_GAP + 20
    for idx, cidr in enumerate(internals):
        row = idx // PER_ROW
        col = idx  % PER_ROW
        x   = int_start_x + col * (ZW + H_GAP)
        y   = int_start_y + row * (ZH + V_GAP)
        rects[cidr] = (x, y, ZW, ZH)

    canvas_h = int_start_y + n_rows * ZH + (n_rows - 1) * V_GAP + MARGIN
    return rects, canvas_w, canvas_h
def render_subnet_topology(nodes: dict, subnets: dict, cross_links: set,
                            subnet_ports=None, cross_rules=None) -> str:
    topo_rects, cw, ch = _topo_layout(subnets, nodes)

    L: List[str] = []
    w = L.append

    w(f'<svg xmlns="http://www.w3.org/2000/svg" width="{cw}" height="{ch}" '
      f'viewBox="0 0 {cw} {ch}">')

    w('<defs>')
    w('<marker id="tArr" viewBox="0 0 10 10" refX="9" refY="5" '
      'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
      '<path d="M0,0 L10,5 L0,10 z" fill="#718096"/></marker>')
    w('</defs>')

    w(f'<rect width="{cw}" height="{ch}" fill="{BG}"/>')

    # GLOBALTECH header bar (matches attack path diagram)
    w(f'<rect x="0" y="0" width="{cw}" height="42" fill="#1a202c"/>')
    w(f'<text x="14" y="17" font-family="sans-serif" font-size="11" '
      f'font-weight="bold" fill="#90cdf4" letter-spacing="2">GLOBALTECH ENTERPRISE NETWORK</text>')
    w(f'<text x="14" y="33" font-family="monospace" font-size="11" '
      f'font-weight="bold" fill="white">Subnet Topology</text>')

    n_goals = sum(1 for n in nodes.values() if n["is_goal"])
    w(f'<text x="{cw - 14}" y="33" text-anchor="end" font-family="monospace" font-size="10" '
      f'fill="#718096">'
      f'{len(nodes)} nodes  ·  {len(subnets)} zones  ·  {n_goals} goal(s)</text>')

    # ── FIXED START CIDR EXTRACTION ──
    start_cidr = next((n["subnet"] for n in nodes.values() if n.get("is_start")), None)

    zone_meta: Dict[str, dict] = {}
    for i, (cidr, info) in enumerate(subnets.items()):
        if cidr not in topo_rects:
            continue
        is_ext = (cidr == start_cidr)
        if is_ext:
            zfill, zstroke = EXT_FILL
            zlabel = info["label"]
        else:
            zfill, zstroke, zone_id, zone_full = _resolve_zone(info["label"], cidr)
            zlabel = f"{zone_id} — {zone_full}" if zone_id != "??" else info["label"]
        zone_meta[cidr] = {"fill": zfill, "stroke": zstroke,
                           "is_ext": is_ext, "label": zlabel}

    for cidr, info in subnets.items():
        if cidr not in topo_rects:
            continue
        zx, zy, zw, zh = topo_rects[cidr]
        m = zone_meta[cidr]
        w(f'<rect x="{zx}" y="{zy}" width="{zw}" height="{zh}" rx="14" '
          f'fill="{m["fill"]}" stroke="{m["stroke"]}" stroke-width="2.5"/>')

    drawn_arrows: set = set()
    for (src_c, dst_c) in cross_links:
        if src_c not in topo_rects or dst_c not in topo_rects:
            continue
        canon = tuple(sorted([src_c, dst_c]))
        if canon in drawn_arrows:
            continue
        drawn_arrows.add(canon)

        sx, sy, sw_z, sh_z = topo_rects[src_c]
        dx, dy, dw_z, dh_z = topo_rects[dst_c]

        scx, scy = sx + sw_z // 2, sy + sh_z // 2
        dcx, dcy = dx + dw_z // 2, dy + dh_z // 2

        if abs(dcx - scx) >= abs(dcy - scy):
            if dcx >= scx:
                x1, y1 = sx + sw_z, scy
                x2, y2 = dx,         dcy
            else:
                x1, y1 = sx,         scy
                x2, y2 = dx + dw_z,  dcy
        else:
            if dcy >= scy:
                x1, y1 = scx, sy + sh_z
                x2, y2 = dcx, dy
            else:
                x1, y1 = scx, sy
                x2, y2 = dcx, dy + dh_z

        mid_x = (x1 + x2) / 2
        mid_y = (y1 + y2) / 2

        w(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
          f'stroke="#718096" stroke-width="2.2" stroke-opacity="0.60" '
          f'marker-end="url(#tArr)"/>')

        w(_firewall_brick(mid_x, mid_y))

        rules = (cross_rules or {}).get((src_c, dst_c), []) + \
                (cross_rules or {}).get((dst_c, src_c), [])
        rule_ports = sorted({r[1] for r in rules if r[1] not in ("*", "ALL", "all")})
        if rule_ports:
            lbl = " · ".join(rule_ports[:4])
            lw  = len(lbl) * 6 + 12
            lx_ = int(mid_x)
            ly_ = int(mid_y) + 16
            w(f'<rect x="{lx_ - lw//2}" y="{ly_ - 9}" width="{lw}" '
              f'height="14" rx="3" fill="white" stroke="#718096" stroke-width="0.8"/>')
            w(f'<text x="{lx_}" y="{ly_ + 2}" text-anchor="middle" '
              f'font-family="monospace" font-size="9" fill="{SUBTEXT}">'
              f'{_esc(lbl)}</text>')

    for cidr, info in subnets.items():
        if cidr not in topo_rects:
            continue
        zx, zy, zw, zh = topo_rects[cidr]
        m = zone_meta[cidr]
        is_ext  = m["is_ext"]
        zstroke = m["stroke"]

        HDR = 38
        w(f'<rect x="{zx+2}" y="{zy+2}" width="{zw-4}" height="{HDR-2}" rx="12" '
          f'fill="{zstroke}" opacity="0.15"/>')

        # Truncate label to fit zone box width (~26 chars at font-size 12)
        raw_label = "[EXTERNAL] ATTACKER" if is_ext else m["label"]
        if len(raw_label) > 26:
            raw_label = raw_label[:24] + "…"
        label = _esc(raw_label)
        w(f'<text x="{zx+12}" y="{zy+17}" font-family="sans-serif" font-size="12" '
          f'font-weight="bold" fill="{zstroke}">{label}</text>')

        w(f'<text x="{zx+12}" y="{zy+32}" font-family="monospace" font-size="9" '
          f'fill="{SUBTEXT}">{_esc(cidr)}</text>')

        nids = info["node_ids"]
        n_count = len(nids)
        # Node count in bottom-right of header, smaller font to avoid overlapping label
        w(f'<text x="{zx+zw-10}" y="{zy+32}" text-anchor="end" '
          f'font-family="monospace" font-size="13" font-weight="bold" fill="{zstroke}" '
          f'opacity="0.40">{n_count}</text>')

        type_counts: Dict[str, int] = {}
        for nid in nids:
            t = nodes[nid]["type"]
            type_counts[t] = type_counts.get(t, 0) + 1
        top_types = sorted(type_counts.items(), key=lambda x: -x[1])[:4]

        ty = zy + HDR + 14
        for tname, cnt in top_types:
            tcolor = TYPE_COLORS.get(tname, DEFAULT_TYPE_COLOR)
            abbr_map = {
                "DomainController": "DC", "CertificateAuthority": "CA",
                "Workstation": "WS", "Workstations": "WS",
                "ExchangeServer": "Exchange", "ManagementServer": "Mgmt",
                "BackupServer": "Backup", "FileServer": "File",
                "WebServer": "Web", "SQLServer": "SQL",
                "PrintServer": "Print", "PLCController": "PLC",
                "ModbusPLC": "MB-PLC", "AllenBradleyPLC": "AB-PLC",
                "SiemensPLC": "S7-PLC", "SCADAServer": "SCADA",
                "HMIWorkstation": "HMI", "HistorianServer": "Historian",
                "EngineeringStation": "Engr", "OPCServer": "OPC",
                "APIGateway": "API-GW", "LoadBalancer": "LB",
                "AppServer": "App", "WebDatabase": "WebDB",
                "CacheServer": "Cache", "AdminPanel": "Admin",
                "JumpHost": "Jump",
            }
            short_t = abbr_map.get(tname, tname[:14])
            w(f'<rect x="{zx+12}" y="{ty-10}" width="8" height="8" rx="2" '
              f'fill="{tcolor}"/>')
            w(f'<text x="{zx+24}" y="{ty-3}" font-family="sans-serif" font-size="11" '
              f'fill="{TEXT}">{_esc(short_t)}</text>')
            w(f'<text x="{zx+zw-12}" y="{ty-3}" text-anchor="end" '
              f'font-family="monospace" font-size="11" font-weight="bold" '
              f'fill="{zstroke}" opacity="0.7">{cnt}</text>')
            ty += 16

        n_goals_local = sum(1 for nid in nids if nodes[nid]["is_goal"])
        if n_goals_local:
            w(f'<rect x="{zx+12}" y="{zh + zy - 24}" width="{zw - 24}" '
              f'height="16" rx="4" fill="{GOAL_STROKE}" opacity="0.12"/>')
            w(f'<text x="{zx + zw//2}" y="{zh + zy - 12}" text-anchor="middle" '
              f'font-family="monospace" font-size="10" font-weight="bold" fill="{GOAL_STROKE}">'
              f'★ {n_goals_local} GOAL NODE{"S" if n_goals_local>1 else ""}</text>')

        ports = (subnet_ports or {}).get(cidr, [])
        if ports:
            chip_x = zx + 12
            chip_y = zy + zh - (26 if n_goals_local else 10)
            for port in ports[:6]:
                cw_c = max(28, len(port) * 6 + 8)
                if chip_x + cw_c > zx + zw - 10:
                    break
                color = PORT_COLORS.get(port, "#607D8B")
                w(f'<rect x="{chip_x}" y="{chip_y - 12}" width="{cw_c}" '
                  f'height="13" rx="3" fill="{color}" opacity="0.75"/>')
                w(f'<text x="{chip_x + cw_c//2}" y="{chip_y - 2}" '
                  f'text-anchor="middle" font-family="monospace" font-size="8" '
                  f'font-weight="bold" fill="white">{_esc(port)}</text>')
                chip_x += cw_c + 4

    w('</svg>')
    return "\n".join(L)
# ─────────────────────────────────────────────────────────────────────────────
# PDF Integration & Separator

def create_title_svg(scenario_name: str, out_path: Path) -> Path:
    """Creates a simple SVG title page for the PDF."""
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="768" viewBox="0 0 1024 768">\n'
        f'  <rect width="1024" height="768" fill="{BG}"/>\n'
        f'  <text x="512" y="370" text-anchor="middle" font-family="sans-serif" font-size="20" font-weight="bold" fill="{TEXT}">{_esc(scenario_name)}</text>\n'
        f'  <text x="512" y="410" text-anchor="middle" font-family="monospace" font-size="8" fill="{SUBTEXT}">Network Architecture &amp; Attack Paths</text>\n'
        f'</svg>'
    )
    out_path.write_text(svg, encoding="utf-8")
    return out_path

def create_combined_pdf(svg_paths: List[Path], out_pdf: Path):
    """Converts a list of SVGs to PDFs and merges them into a single document."""
    try:
        import cairosvg
        from pypdf import PdfWriter
    except ImportError:
        print("\n[!] Error: To generate PDFs, you need 'cairosvg' and 'pypdf'.")
        print("    Run: pip install cairosvg pypdf")
        return

    print(f"[•] Combining {len(svg_paths)} pages into {out_pdf.name} ...")
    
    try:
        merger = PdfWriter()
        temp_pdfs = []
        
        for i, svg_file in enumerate(svg_paths):
            if 'compact_subne' not in svg_file.name and 'title_se' not in svg_file.name:
                print(f"  [•] Processing {svg_file.name} ...")
                continue
            temp_pdf = svg_file.with_suffix(f'.temp{i}.pdf')
            temp_pdfs.append(temp_pdf)
            cairosvg.svg2pdf(url=str(svg_file), write_to=str(temp_pdf))
            merger.append(str(temp_pdf))
            
        merger.write(str(out_pdf))
        merger.close()
        
        for temp_pdf in temp_pdfs:
            if temp_pdf.exists():
                temp_pdf.unlink()
                
        print(f"[✓] Master PDF created -> {out_pdf} ({out_pdf.stat().st_size // 1024} KB)")
    except Exception as e:
        print(f"  [!] Failed to create PDF: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# Schema-level diagram  (one representative node per service group)

_SCHEMA_COUNTS: Dict[str, Tuple[int, int]] = {}
_SCHEMA_MODE: bool = False


def parse_config_schema(config_path: Path):
    """Parse a CBS config YAML and return schema-level graph structures.

    Creates one fake node per service group (instead of per-instance files).
    The ip field is set to the count range "×min–max" so it renders in the
    existing node IP slot.  Returns the same tuple as parse_scenario() so it
    is compatible with compute_layout() and render().
    """
    global _SCHEMA_COUNTS, _SCHEMA_MODE
    _SCHEMA_COUNTS = {}
    _SCHEMA_MODE = True

    with open(config_path, encoding="utf-8") as f:
        cfg = yaml.load(f, Loader=_LOADER) or {}

    nodes: Dict[str, dict] = {}
    subnets: Dict[str, dict] = {}

    # Attacker entry node
    start_subnet = "0.0.0.0/0"
    nodes["start"] = {
        "type": "start", "ip": "", "subnet": start_subnet,
        "is_goal": False, "is_start": True, "services": [], "fw_out": set(),
    }
    subnets[start_subnet] = {"label": "External", "node_ids": ["start"]}

    domain_subnet: Dict[str, str] = {}   # domain name → CIDR
    svc_to_subnet: Dict[str, str] = {}   # service type → CIDR

    for i, d in enumerate(cfg.get("domains") or []):
        if not isinstance(d, dict):
            continue
        name = str(d.get("name", f"domain{i}"))
        subnet_val = d.get("subnet") or {}
        if isinstance(subnet_val, dict):
            cidr = str(subnet_val.get("network", f"10.99.{i}.0/24"))
        else:
            cidr = str(subnet_val) if subnet_val else f"10.99.{i}.0/24"

        domain_subnet[name] = cidr
        # Don't pre-create the subnet entry here — each service group will
        # create its own canonical zone subnet (or share the domain cidr if
        # no prefix mapping exists), avoiding empty ghost subnets.

        # Remove underscores from domain name so _service_type() extracts correctly
        dom_clean = name.replace("_", "")

        for g in (d.get("groups") or []):
            if not isinstance(g, dict):
                continue
            svc    = str(g.get("service", "?"))
            min_c  = int(g.get("min_count", 1))
            max_c  = int(g.get("max_count", 1))
            is_goal = bool(g.get("is_goal", False))

            # Route each service to its proper GLOBALTECH zone using service-type
            # prefix lookup. This handles flat single-domain configs (e.g. 10.0.0.0/8)
            # where all services share one domain but belong to different zones.
            zone_key = _GT_SERVICE_PREFIX.get(svc)
            if zone_key and zone_key in _ZONE_CANONICAL_CIDRS:
                svc_cidr  = _ZONE_CANONICAL_CIDRS[zone_key]
                svc_label = zone_key
            else:
                svc_cidr  = cidr
                svc_label = name

            if svc_cidr not in subnets:
                subnets[svc_cidr] = {"label": svc_label, "node_ids": []}

            nid  = f"{dom_clean}_{svc}"
            base = nid
            dup  = 0
            while nid in nodes:
                dup += 1
                nid = f"{base}_{dup}"

            _SCHEMA_COUNTS[nid] = (min_c, max_c)
            svc_to_subnet[svc] = svc_cidr

            nodes[nid] = {
                "type":     svc,
                "ip":       f"×{min_c}–{max_c}",   # ×min–max in IP slot
                "subnet":   svc_cidr,
                "is_goal":  is_goal,
                "is_start": False,
                "services": [],
                "fw_out":   set(),
            }
            subnets[svc_cidr]["node_ids"].append(nid)

    # Inter-zone cross_links from inter_domain_constraints
    cross_links: set = set()
    for idc in (cfg.get("inter_domain_constraints") or []):
        if not isinstance(idc, dict):
            continue
        s_sub = domain_subnet.get(str(idc.get("source_domain", "")))
        t_sub = domain_subnet.get(str(idc.get("target_domain", "")))
        if s_sub and t_sub and s_sub != t_sub:
            cross_links.add((s_sub, t_sub))

    # Also derive from attack_flow (service-type level)
    for entry in (cfg.get("attack_flow") or []):
        if not isinstance(entry, dict):
            continue
        src_sub = svc_to_subnet.get(str(entry.get("source_pattern", "")))
        if not src_sub:
            continue
        for tgt_svc in (entry.get("targets") or []):
            tgt_sub = svc_to_subnet.get(str(tgt_svc))
            if tgt_sub and tgt_sub != src_sub:
                cross_links.add((src_sub, tgt_sub))

    # Attacker → every internal subnet
    for cidr in list(subnets):
        if cidr != start_subnet:
            cross_links.add((start_subnet, cidr))

    return nodes, subnets, cross_links, [], {}


def generate_schema_png(config_path: Path, output_png: Path,
                         title: str = "") -> bool:
    """Generate a schema-level architecture PNG from a CBS config YAML.

    Uses the same render() pipeline as per-instance diagrams so the visual
    style matches exactly.  Returns True on success.
    """
    nodes, subnets, cross_links, node_edges, edge_ports = parse_config_schema(config_path)
    if not nodes:
        return False

    zone_rects, node_pos, cw, ch = compute_layout(subnets, nodes, cross_links)
    svg = render(nodes, subnets, cross_links, node_edges, zone_rects, node_pos, cw, ch)

    output_png.parent.mkdir(parents=True, exist_ok=True)

    try:
        import cairosvg
        cairosvg.svg2png(
            bytestring=svg.encode("utf-8"),
            write_to=str(output_png),
            scale=2.0,
        )
        return True
    except ImportError:
        pass

    svg_tmp = output_png.with_suffix(".schema_tmp.svg")
    svg_tmp.write_text(svg, encoding="utf-8")
    r = subprocess.run(
        ["inkscape", "--export-type=png", "--export-dpi=192",
         f"--export-filename={output_png}", str(svg_tmp)],
        capture_output=True,
    )
    svg_tmp.unlink(missing_ok=True)
    return r.returncode == 0


# ─────────────────────────────────────────────────────────────────────────────
# CLI
import graphviz

def generate_compact_subnet_topology(nodes, subnets, cross_links, cross_rules, output_path):
    # LR (Left-to-Right) usually looks best for subnet topologies
    dot = graphviz.Digraph(comment='Subnet Topology', format='svg')
    dot.attr(rankdir='LR', nodesep='0.8', ranksep='1.2')
    dot.attr('node', fontname='Verdana', shape='box', style='rounded,filled', margin='0.3,0.2')
    dot.attr('edge', fontname='Verdana', fontsize='10', color='#718096')

    # Find the start/attacker subnet
    start_cidr = next((n["subnet"] for n in nodes.values() if n.get("is_start")), None)

    # 1. Create Subnet Nodes
    for cidr, info in subnets.items():
        label_text = info['label']
        is_ext = (cidr == start_cidr)
        
        # Calculate local stats
        local_nodes = info['node_ids']
        n_count = len(local_nodes)
        n_goals = sum(1 for nid in local_nodes if nodes[nid].get('is_goal'))
        
        # Build the text lPDFabel
        lines = []
        if is_ext:
            lines.append("[EXTERNAL ATTACKER]")
        else:
            lines.append(f"ZONE: {label_text}")
            
        lines.append(f"CIDR: {cidr}")
        lines.append(f"Nodes: {n_count}")
        
        if n_goals > 0:
            lines.append(f"★ {n_goals} GOAL(S) ★")
            
        node_label = "\n".join(lines)
        
        # Apply GLOBALTECH zone colors
        if is_ext:
            fill = "#e2e8f0"; stroke = "#4a5568"; width = "2"
        elif n_goals > 0:
            gt_fill, gt_stroke, _, _ = _resolve_zone(label_text, cidr)
            fill = gt_fill; stroke = "#c53030"; width = "2.5"
        else:
            gt_fill, gt_stroke, _, _ = _resolve_zone(label_text, cidr)
            fill = gt_fill; stroke = gt_stroke; width = "1.5"

        # Replace plain label_text with "ZID — full_name" for internal subnets
        if not is_ext:
            _, _, zone_id, zone_full = _resolve_zone(label_text, cidr)
            if zone_id != "??":
                lines[0] = f"{zone_id}: {zone_full}"

        node_label = "\n".join(lines)
        dot.node(cidr, label=node_label, fillcolor=fill, color=stroke, penwidth=width)

    # 2. Create Cross-Subnet Edges (Firewall Rules)
    drawn_edges = set()
    for src, dst in cross_links:
        # Prevent drawing the exact same edge twice if bidirectional 
        # (Graphviz handles it, but cleaner to manage ports)
        edge_key = (src, dst)
        if edge_key in drawn_edges:
            continue
            
        drawn_edges.add(edge_key)
        
        # Extract allowed ports for the label
        rules = cross_rules.get(edge_key, [])
        rule_ports = sorted({r[1] for r in rules if r[1] not in ("*", "ALL", "all")})
        
        # Format the port label (e.g., "SSH, HTTP")
        edge_label = "\n".join(rule_ports[:4]) 
        if len(rule_ports) > 4:
            edge_label += "\n..."
            
        # Draw the connection
        dot.edge(src, dst, label=edge_label, fontcolor="#4a5568")

    # Render the SVG
    dot.render(output_path, cleanup=True)

def process_scenario(scenario: Path, out_path: Optional[Path] = None) -> List[Path]:
    """Processes a single scenario directory and generates the graphs."""
    nodes_dir = scenario / "nodes"
    if not nodes_dir.is_dir():
        print(f"[error] No nodes/ directory in {scenario}", file=sys.stderr)
        return []

    out = out_path if out_path else scenario / "graphs" / "network_graph.svg"
    out.parent.mkdir(exist_ok=True)

    print(f"[•] Parsing {nodes_dir} …")
    nodes, subnets, cross_links, node_edges, edge_ports = parse_scenario(nodes_dir)
    subnet_ports, cross_rules = parse_firewall_rules(nodes_dir, nodes)

    goals = sum(1 for n in nodes.values() if n["is_goal"])
    print(f"[•] {len(nodes)} nodes  |  {len(subnets)} subnets  |  "
          f"{goals} goal(s)  |  {len(node_edges)} direct connections")
    for cidr, info in subnets.items():
        ports = subnet_ports.get(cidr, [])
        print(f"    {cidr:20s}  {len(info['node_ids']):3d} nodes  "
              f"ports=[{', '.join(ports)}]")

    # ── NEW: Compact Graphviz Subnet Topology ────────────────────────────────
    compact_base = out.parent / "compact_subnet_topology"
    compact_out_file = out.parent / "compact_subnet_topology.svg"
    print("[•] Rendering compact Graphviz Subnet Topology …")
    try:
        generate_compact_subnet_topology(nodes, subnets, cross_links, cross_rules, str(compact_base))
        if compact_out_file.exists():
            print(f"[✓] compact_subnet_topology.svg → {compact_out_file} ({compact_out_file.stat().st_size // 1024} KB)")
    except Exception as e:
        print(f"[!] Graphviz failed (is it installed?): {e}")

    # ── File 1: network architecture diagram ─────────────────────────────────
    print("[•] Computing layout …")
    zone_rects, node_pos, cw, ch = compute_layout(subnets, nodes, cross_links)

    print(f"[•] Rendering network diagram ({cw}×{ch}) …")
    svg1 = render(nodes, subnets, cross_links, node_edges, zone_rects, node_pos, cw, ch,
                  subnet_ports=subnet_ports, cross_rules=cross_rules)
    out.write_text(svg1, encoding="utf-8")
    print(f"[✓] network_graph.svg  → {out}  ({out.stat().st_size // 1024} KB)")

    # ── File 2: information / attack-paths diagram ────────────────────────────
    out2 = out.parent / "attack_paths.svg"
    print("[•] Rendering information-paths diagram …")
    svg2 = render_info_paths(nodes, node_edges, edge_ports)
    out2.write_text(svg2, encoding="utf-8")
    print(f"[✓] attack_paths.svg   → {out2}  ({out2.stat().st_size // 1024} KB)")

    # ── File 3: simplified subnet topology diagram ────────────────────────────
    out3 = out.parent / "subnet_topology.svg"
    print("[•] Rendering subnet topology diagram …")
    svg3 = render_subnet_topology(nodes, subnets, cross_links,
                                   subnet_ports=subnet_ports, cross_rules=cross_rules)
    out3.write_text(svg3, encoding="utf-8")
    print(f"[✓] subnet_topology.svg → {out3}  ({out3.stat().st_size // 1024} KB)\n")

    # ── Collect Generated Files for PDF Master ───────────────────────────────
    generated_files = [out, out2, out3]
    
    # Add the new compact graph to the PDF list if it was created successfully
    if compact_out_file.exists():
        # Insert at the beginning so it shows up as the first graph in the PDF
        generated_files.insert(0, compact_out_file)

    return generated_files
def main():
    ap = argparse.ArgumentParser(
        description="Generate network architecture SVGs for CyberBattleSim scenario(s)."
    )
    ap.add_argument("target_dir",
                    help="Scenario directory, or a base directory if using --recursive")
    ap.add_argument("-r", "--recursive", action="store_true",
                    help="Recursively find and process all directories containing a 'nodes/' folder")
    ap.add_argument("--out", metavar="FILE",
                    help="Output SVG path (ignored in recursive mode)")
    ap.add_argument("--pdf", action="store_true",
                    help="Compile all generated SVGs into a single master PDF")
    args = ap.parse_args()

    target = Path(args.target_dir).resolve()

    if args.recursive:
        print(f"[*] Scanning recursively for scenarios in {target} ...")
        scenario_dirs = [p.parent for p in target.rglob("nodes") if p.is_dir()]
        scenario_dirs = sorted(list(set(scenario_dirs)))

        if not scenario_dirs:
            sys.exit(f"[!] No scenario directories (containing a 'nodes/' folder) found in {target}")

        print(f"[*] Found {len(scenario_dirs)} scenario(s).")
        
        master_svg_list: List[Path] = []
        
        for s_dir in scenario_dirs:
            print(f"\n{'='*70}\n[>] Processing Scenario: {s_dir.name}\n    Location: {s_dir}\n{'='*70}")
            
            # --- Insert the Separator Page Before the Graphs ---
            if args.pdf:
                title_svg_path = s_dir / "graphs" / "00_title_separator.svg"
                title_svg_path.parent.mkdir(exist_ok=True)
                
                # GET RELATIVE PATH FOR TITLE (e.g. "multi-domain/hybrid.../v0-2")
                try:
                    rel_path = s_dir.relative_to(target)
                    display_name = str(rel_path) if str(rel_path) != '.' else s_dir.name
                except ValueError:
                    display_name = s_dir.name
                    
                # Format it with spaces so it looks nice in the PDF
                display_name = display_name.replace("/", " / ").replace("\\", " / ")
                
                create_title_svg(display_name, title_svg_path)
                master_svg_list.append(title_svg_path)
                
            generated_svgs = process_scenario(s_dir)
            master_svg_list.extend(generated_svgs)
            
        print("\n[✓] All recursive processing complete.")
        
        if args.pdf and master_svg_list:
            master_pdf_path = target / "all_scenarios_combined.pdf"
            print(f"\n{'='*70}\n[>] Compiling Master PDF\n{'='*70}")
            create_combined_pdf(master_svg_list, master_pdf_path)

    else:
        if not (target / "nodes").is_dir():
            sys.exit(f"[error] No nodes/ directory found in {target}")
        
        out_path = Path(args.out).resolve() if args.out else None
        
        # --- Insert the Separator Page Before the Graphs ---
        master_svg_list = []
        if args.pdf:
            title_svg_path = target / "graphs" / "00_title_separator.svg"
            title_svg_path.parent.mkdir(exist_ok=True)
            create_title_svg(target.name, title_svg_path)
            master_svg_list.append(title_svg_path)
            
        generated_svgs = process_scenario(target, out_path)
        master_svg_list.extend(generated_svgs)
        
        out_def = out_path if out_path else target / "graphs" / "network_graph.svg"
        print("Open in browser:")
        print(f"  file://{out_def}")
        print(f"  file://{out_def.parent / 'attack_paths.svg'}")
        print(f"  file://{out_def.parent / 'subnet_topology.svg'}")
        
        if args.pdf and master_svg_list:
            pdf_path = out_def.parent / "combined_graphs.pdf"
            create_combined_pdf(master_svg_list, pdf_path)
            print(f"  file://{pdf_path}")

if __name__ == "__main__":
    main()