#!/usr/bin/env python3
"""
tools/config_checker.py
=========================
Validate a domain config YAML before generating scenarios from it.
Catches common mistakes that produce degenerate or unpublishable datasets.

Checks performed
----------------
1. Identifiers completeness
   - Every property used in services.default_properties is declared in
     identifiers.base_properties
   - Every port used in services.port or constraints.protocol is declared in
     identifiers.standard_ports

2. Service / group consistency
   - Every group.service references a defined service
   - Every constraint source/target references a defined group (or service)
   - mandatory_services reference defined services

3. Attack flow depth (§4.5)
   - Builds a directed graph from attack_flow
   - Reports shortest path from the inferred entry service type(s) to each
     goal service type
   - Flags any goal with depth < 2 (too easy) or unreachable (broken)

4. Vulnerability coverage
   - At least one solvability_vulnerability covers each goal node's
     match_properties set
   - remote_access, credential_leak, discovery, goal_access categories present

5. Constraint soundness
   - LEAK_KNOWN_CREDENTIALS and KNOWS constraints have a matching MUST_CONNECT
     along the same path (otherwise the credential is useless)
   - No goal node has MUST_HAVE: Unauthenticated

Usage
-----
python3 tools/config_checker.py data/active_directory.yaml
python3 tools/config_checker.py data/ot_scada.yaml --strict
python3 tools/config_checker.py data/hybrid_2domain_web_to_ad.yaml --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import re
import yaml

# Import AGENT_CATEGORY_ALLOWLIST from pipeline/constants.py (one level up from phase1/)
_PIPELINE_DIR = Path(__file__).resolve().parent.parent
_REPO_ROOT = _PIPELINE_DIR.parent
CATALOG_PATH = _REPO_ROOT / "prompts" / "reference" / "vulnerability_catalog.md"

sys.path.insert(0, str(_PIPELINE_DIR))
try:
    from constants import AGENT_CATEGORY_ALLOWLIST  # noqa: E402
except ImportError:
    AGENT_CATEGORY_ALLOWLIST: dict = {}  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------

class C:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    END    = "\033[0m"

def ok(msg):   print(f"  {C.GREEN}✓{C.END} {msg}")
def warn(msg): print(f"  {C.YELLOW}⚠{C.END} {msg}")
def err(msg):  print(f"  {C.RED}✗{C.END} {msg}")
def info(msg): print(f"  {C.BLUE}→{C.END} {msg}")


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _load(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_vulnerability_catalog() -> Dict[str, Set[str]]:
    """Parse vulnerability_catalog.md to map categories to technique names."""
    if not CATALOG_PATH.is_file():
        return {}

    catalog: Dict[str, Set[str]] = defaultdict(set)
    current_category = ""

    with open(CATALOG_PATH) as f:
        for line in f:
            # Match ## Category: `name`
            cat_match = re.search(r"## Category: `([^`]+)`", line)
            if cat_match:
                current_category = cat_match.group(1)
                continue

            if not current_category:
                continue

            # Match | `Solvability.Name` |
            tech_match = re.search(r"\|\s*`?(Solvability\.[^`\s|]+)`?\s*\|", line)
            if tech_match:
                catalog[current_category].add(tech_match.group(1))

    return dict(catalog)


# ---------------------------------------------------------------------------
# Check 1 — Identifiers completeness
# ---------------------------------------------------------------------------

def check_identifiers(cfg: dict) -> List[str]:
    issues = []
    base_props     = set(cfg.get("identifiers", {}).get("base_properties", []))
    standard_ports = set(cfg.get("identifiers", {}).get("standard_ports", []))
    # Port labels are valid as properties (they appear in default_properties frequently)
    valid_props = base_props | standard_ports

    services = cfg.get("services", {})
    for svc_name, svc in services.items():
        for prop in svc.get("default_properties", []):
            if prop not in valid_props:
                issues.append(
                    f"service '{svc_name}': property '{prop}' "
                    f"not in identifiers.base_properties"
                )
        port_label = str(svc.get("port", ""))
        # Port is numeric in the YAML; check protocol labels in constraints instead

    # Check constraint protocols
    for domain in cfg.get("domains", []):
        for c in domain.get("constraints", []):
            proto = c.get("protocol", "")
            if proto and proto not in standard_ports:
                issues.append(
                    f"constraint '{c.get('source')}→{c.get('target')}': "
                    f"protocol '{proto}' not in identifiers.standard_ports"
                )

    # Check match_properties in solvability_vulnerabilities
    solv = cfg.get("solvability_vulnerabilities", {})
    for category, vulns in solv.items():
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            for mp in v.get("match_properties", []):
                if mp not in valid_props:
                    issues.append(
                        f"solvability_vuln '{v.get('name','')}': "
                        f"match_property '{mp}' not in identifiers.base_properties"
                    )

    # Check os_management_ports
    for os_label, port_label in cfg.get("os_management_ports", {}).items():
        if port_label not in standard_ports:
            issues.append(
                f"os_management_ports '{os_label}': port '{port_label}' "
                f"not in identifiers.standard_ports"
            )

    # Check for orphaned identifiers (Q1)
    used_props: Set[str] = set()
    for svc in services.values():
        used_props.update(svc.get("default_properties", []))
    for domain in cfg.get("domains", []):
        for g in domain.get("groups", []):
            used_props.update(g.get("properties", []))
    for category, vulns in solv.items():
        if isinstance(vulns, list):
            for v in vulns:
                used_props.update(v.get("match_properties", []))
    
    for prop in base_props:
        if prop not in used_props and prop != "breach_node":
            issues.append(
                f"orphaned property: '{prop}' is declared in "
                f"identifiers.base_properties but never used in any service, group, "
                f"or vulnerability match_properties"
            )

    return issues


# ---------------------------------------------------------------------------
# Check 2 — Service / group consistency
# ---------------------------------------------------------------------------

def check_groups(cfg: dict) -> List[str]:
    issues = []
    services_defined = set(cfg.get("services", {}).keys())

    for domain in cfg.get("domains", []):
        domain_name = domain.get("name", "?")
        groups_defined: Set[str] = set()

        for g in domain.get("groups", []):
            gname = g.get("name", "")
            gsvc  = g.get("service", "")
            groups_defined.add(gname)
            if gsvc not in services_defined:
                issues.append(
                    f"domain '{domain_name}' group '{gname}': "
                    f"service '{gsvc}' is not defined under services:"
                )

        for svc in domain.get("mandatory_services", []):
            if svc not in services_defined:
                issues.append(
                    f"domain '{domain_name}' mandatory_services: "
                    f"'{svc}' is not defined under services:"
                )

        for c in domain.get("constraints", []):
            src = c.get("source", "")
            tgt = c.get("target", "")
            rel = c.get("relation", "")
            if rel == "MUST_HAVE":
                continue
            if src and src not in groups_defined and src not in services_defined:
                issues.append(
                    f"domain '{domain_name}' constraint: "
                    f"source '{src}' not a defined group or service"
                )
            if tgt and tgt not in groups_defined and tgt not in services_defined:
                issues.append(
                    f"domain '{domain_name}' constraint: "
                    f"target '{tgt}' not a defined group or service"
                )

        for svc in domain.get("filler", []):
            if svc not in services_defined:
                issues.append(
                    f"domain '{domain_name}' filler: "
                    f"'{svc}' is not defined under services:"
                )

    return issues


# ---------------------------------------------------------------------------
# Check 3 — Attack flow depth
# ---------------------------------------------------------------------------

def _build_flow_graph(attack_flow: List[dict]) -> Dict[str, Set[str]]:
    adj: Dict[str, Set[str]] = defaultdict(set)
    for rule in attack_flow:
        src = rule.get("source_pattern", "")
        for tgt in rule.get("targets", []):
            adj[src].add(tgt)
    return dict(adj)


def _bfs(adj: Dict[str, Set[str]], start: str) -> Dict[str, int]:
    """BFS from start. Returns {node: min_depth}."""
    dist = {start: 0}
    queue: deque = deque([start])
    while queue:
        node = queue.popleft()
        for nbr in adj.get(node, set()):
            if nbr not in dist:
                dist[nbr] = dist[node] + 1
                queue.append(nbr)
    return dist


def check_attack_flow_depth(cfg: dict) -> Tuple[List[str], dict]:
    """
    Returns (issues, depth_report).
    depth_report = {goal_service: min_depth_from_entry}
    """
    issues = []
    attack_flow = cfg.get("attack_flow", [])
    services    = cfg.get("services", {})
    goal_services = [k for k, v in services.items() if v.get("is_goal", False)]

    if not attack_flow:
        issues.append("attack_flow is empty — no lateral movement paths defined")
        return issues, {}

    adj = _build_flow_graph(attack_flow)

    # Infer entry service types: appear as source but not as any target
    all_targets  = {t for rule in attack_flow for t in rule.get("targets", [])}
    all_sources  = {rule["source_pattern"] for rule in attack_flow}
    # Entry services: appear as source but never as target, AND are not goal nodes
    # (goal nodes that also appear as sources are intermediate+goal, not entry)
    entry_svcs = (all_sources - all_targets) - set(goal_services)

    if not entry_svcs:
        # Fallback: non-goal sources not appearing as targets
        entry_svcs = all_sources - all_targets
    if not entry_svcs:
        # Fallback: use the first source in the list
        entry_svcs = {attack_flow[0]["source_pattern"]}
        issues.append(
            f"Could not infer entry service — all sources are also targets. "
            f"Using '{list(entry_svcs)[0]}' as start."
        )

    # BFS depths from each entry service
    depth_per_entry: Dict[str, Dict[str, int]] = {}
    for entry in entry_svcs:
        depth_per_entry[entry] = _bfs(adj, entry)

    # For each goal: take the minimum across all entry services
    depth_report: Dict[str, int] = {}
    for goal in goal_services:
        min_d = min(
            (d.get(goal, 9999) for d in depth_per_entry.values()),
            default=9999
        )
        depth_report[goal] = min_d

        if min_d == 9999:
            issues.append(
                f"Goal service '{goal}' is UNREACHABLE from any entry service "
                f"({', '.join(entry_svcs)}) via attack_flow — scenario will be unsolvable"
            )
        elif min_d < 2:
            issues.append(
                f"Goal service '{goal}' is reachable in {min_d} hop(s) from entry — "
                f"minimum required is 2 (too easy, will bias meta-agent selection)"
            )

    return issues, depth_report


# ---------------------------------------------------------------------------
# Check 4 — Vulnerability coverage of goal nodes
# ---------------------------------------------------------------------------

def check_vulnerability_coverage(cfg: dict) -> List[str]:
    issues = []
    services = cfg.get("services", {})
    solv     = cfg.get("solvability_vulnerabilities", {})

    goal_services = {k: v for k, v in services.items() if v.get("is_goal", False)}
    if not goal_services:
        issues.append("No services have is_goal: true — nothing to capture")
        return issues

    # Collect all match_properties sets from solvability vulns
    all_match_sets: List[Set[str]] = []
    for category, vulns in solv.items():
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            mp = set(v.get("match_properties", []))
            all_match_sets.append(mp)

    for goal_name, goal_svc in goal_services.items():
        goal_props = set(goal_svc.get("default_properties", []))
        covered = any(
            mp.issubset(goal_props)
            for mp in all_match_sets
        )
        if not covered:
            issues.append(
                f"Goal service '{goal_name}' has no matching solvability_vulnerability "
                f"(properties: {sorted(goal_props)[:5]}{'...' if len(goal_props) > 5 else ''}) "
                f"— agent cannot exploit it"
            )

    # Determine required categories based on metadata.agent (D-A5)
    agent = cfg.get("metadata", {}).get("agent", "")
    if agent and AGENT_CATEGORY_ALLOWLIST and agent in AGENT_CATEGORY_ALLOWLIST:
        required_categories = set(AGENT_CATEGORY_ALLOWLIST[agent])
    else:
        required_categories = {"remote_access", "credential_leak", "discovery", "goal_access"}
    present_categories = set(k for k, v in solv.items() if isinstance(v, list) and v)
    for cat in required_categories:
        if cat not in present_categories:
            issues.append(
                f"solvability_vulnerabilities is missing category '{cat}' "
                f"(required for agent '{agent or 'unknown'}') "
                f"— scenarios will have incomplete attack chains"
            )

    return issues


# ---------------------------------------------------------------------------
# Check 4b — Agent-category allowlist (D-A5)
# ---------------------------------------------------------------------------

def check_agent_category_allowlist(cfg: dict, catalog: Optional[Dict[str, Set[str]]] = None) -> List[str]:
    """Validate that every solvability category and technique belongs to the agent's allowlist
    and the canonical catalog sections.
    """
    issues = []
    agent = cfg.get("metadata", {}).get("agent", "")
    if not agent:
        return []

    permitted = AGENT_CATEGORY_ALLOWLIST.get(agent) if AGENT_CATEGORY_ALLOWLIST else None
    if permitted is None and AGENT_CATEGORY_ALLOWLIST:
        issues.append(
            f"metadata.agent '{agent}' is not in the AGENT_CATEGORY_ALLOWLIST "
            f"(known agents: {', '.join(AGENT_CATEGORY_ALLOWLIST)})"
        )
        return issues

    permitted_set = set(permitted) if permitted else set()
    solv = cfg.get("solvability_vulnerabilities", {})
    for category, vulns in solv.items():
        if not isinstance(vulns, list) or not vulns:
            continue

        # 1. Check if category is allowed for this agent
        if AGENT_CATEGORY_ALLOWLIST and category not in permitted_set:
            issues.append(
                f"Agent '{agent}' is not permitted to use solvability category "
                f"'{category}' (allowed: {sorted(permitted_set)})"
            )

        # 2. Check if techniques in this category are canonically valid (Q6)
        if catalog and category in catalog:
            valid_techniques = catalog[category]
            for v in vulns:
                vname = v.get("name", "")
                if vname and vname not in valid_techniques:
                    # Check if it exists in ANOTHER category (hallucinated category pairing)
                    other_cats = [cat for cat, techs in catalog.items() if vname in techs]
                    if other_cats:
                        issues.append(
                            f"Technique '{vname}' is in category '{category}' but canonically "
                            f"belongs to {other_cats} — incorrect category pairing"
                        )
                    else:
                        issues.append(
                            f"Technique '{vname}' in category '{category}' is not in the "
                            f"canonical vulnerability_catalog.md"
                        )
    return issues


# ---------------------------------------------------------------------------
# Check 5 — Constraint soundness
# ---------------------------------------------------------------------------

def check_constraints(cfg: dict) -> List[str]:
    issues = []
    services = cfg.get("services", {})
    goal_services = {k for k, v in services.items() if v.get("is_goal", False)}

    # Group-to-service map
    group_to_service: Dict[str, str] = {}
    for domain in cfg.get("domains", []):
        for g in domain.get("groups", []):
            group_to_service[g["name"]] = g["service"]

    for domain in cfg.get("domains", []):
        domain_name = domain.get("name", "?")
        # Collect MUST_CONNECT edges for this domain
        connected: Set[Tuple[str, str]] = set()
        for c in domain.get("constraints", []):
            if c.get("relation") == "MUST_CONNECT":
                src_svc = group_to_service.get(c.get("source", ""), c.get("source", ""))
                tgt_svc = group_to_service.get(c.get("target", ""), c.get("target", ""))
                connected.add((src_svc, tgt_svc))

        for c in domain.get("constraints", []):
            src_group = c.get("source", "")
            tgt_group = c.get("target", "")
            rel       = c.get("relation", "")
            prop      = c.get("property", "")

            src_svc = group_to_service.get(src_group, src_group)
            tgt_svc = group_to_service.get(tgt_group, tgt_group)

            # Warn if LEAK_KNOWN_CREDENTIALS exists without MUST_CONNECT
            if rel == "LEAK_KNOWN_CREDENTIALS":
                if (src_svc, tgt_svc) not in connected:
                    issues.append(
                        f"domain '{domain_name}': "
                        f"LEAK_KNOWN_CREDENTIALS {src_svc}→{tgt_svc} "
                        f"but no MUST_CONNECT along the same edge — "
                        f"credential leak may have no usable path"
                    )

            # Warn if MUST_HAVE: Unauthenticated on a goal service
            if rel == "MUST_HAVE" and prop == "Unauthenticated":
                if src_svc in goal_services:
                    issues.append(
                        f"domain '{domain_name}': "
                        f"MUST_HAVE Unauthenticated on goal service '{src_svc}' — "
                        f"trivially exploitable, will dominate meta-agent selection"
                    )

    return issues


# ---------------------------------------------------------------------------
# Check 6 — Config-level settings
# ---------------------------------------------------------------------------

def check_config_settings(cfg: dict) -> List[str]:
    issues = []
    top = cfg.get("config", {})

    min_n = top.get("min_total_nodes", 0)
    max_n = top.get("max_total_nodes", 0)
    if min_n <= 0:
        issues.append(f"config.min_total_nodes={min_n} — must be > 0")
    if max_n <= min_n:
        issues.append(
            f"config.max_total_nodes={max_n} ≤ min_total_nodes={min_n} "
            f"— no variance in scenario size"
        )
    if max_n > 500:
        issues.append(
            f"config.max_total_nodes={max_n} is very large — "
            f"generation may be slow; consider ≤ 250"
        )

    goal_cfg = top.get("goal_config", {})
    num_goals = goal_cfg.get("num_goals", 0)
    if num_goals <= 0:
        issues.append("config.goal_config.num_goals must be ≥ 1")

    services = cfg.get("services", {})
    goal_eligible = [k for k, v in services.items() if v.get("is_goal", False)]
    if num_goals > len(goal_eligible):
        issues.append(
            f"config.goal_config.num_goals={num_goals} but only "
            f"{len(goal_eligible)} service(s) have is_goal: true "
            f"({', '.join(goal_eligible)})"
        )

    start_node = cfg.get("start_node", {})
    if not start_node:
        issues.append("start_node section is missing")
    else:
        if "breach_node" not in start_node.get("properties", []):
            issues.append(
                "start_node.properties does not contain 'breach_node' — "
                "the generator requires this marker"
            )
        if start_node.get("leaked_node_coverage", 0) > 0.5:
            issues.append(
                f"start_node.leaked_node_coverage="
                f"{start_node['leaked_node_coverage']} > 0.5 — "
                f"agent starts with too much visibility, difficulty is reduced"
            )

    return issues


# ---------------------------------------------------------------------------
# Pretty report
# ---------------------------------------------------------------------------

def _section(title: str):
    print(f"\n{C.BOLD}{C.BLUE}{'─'*60}{C.END}")
    print(f"{C.BOLD}{C.BLUE}  {title}{C.END}")
    print(f"{C.BOLD}{C.BLUE}{'─'*60}{C.END}")


def _print_depth_table(depth_report: dict, services: dict):
    print()
    print(f"  {'Service':<30} {'Min depth':>9} {'is_goal':>7}")
    print(f"  {'─'*30} {'─'*9} {'─'*7}")
    for svc_name, depth in sorted(depth_report.items(), key=lambda x: x[1]):
        is_goal = services.get(svc_name, {}).get("is_goal", False)
        goal_marker = "★" if is_goal else " "
        depth_str = str(depth) if depth < 9999 else "∞ (unreachable)"
        color = C.RED if depth < 2 or depth >= 9999 else (C.YELLOW if depth == 2 else C.GREEN)
        print(
            f"  {goal_marker} {svc_name:<28} "
            f"{color}{depth_str:>9}{C.END} "
            f"{'yes' if is_goal else '':>7}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Validate a CyberBattleSim domain config YAML (§4.5 + completeness checks)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("config", metavar="YAML",
                        help="Path to the domain config YAML to check")
    parser.add_argument("--strict", action="store_true",
                        help="Treat warnings as errors (non-zero exit if any warning)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON instead of human-readable text")
    args = parser.parse_args()

    path = Path(args.config)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    cfg = _load(str(path))
    services = cfg.get("services", {})
    catalog = load_vulnerability_catalog()

    all_errors:   List[str] = []
    all_warnings: List[str] = []

    # ---- Run all checks ----
    checks = [
        ("Config settings",            check_config_settings(cfg)),
        ("Identifiers completeness",   check_identifiers(cfg)),
        ("Service / group consistency", check_groups(cfg)),
        ("Vulnerability coverage",     check_vulnerability_coverage(cfg)),
        ("Agent-category allowlist",   check_agent_category_allowlist(cfg, catalog)),
        ("Constraint soundness",       check_constraints(cfg)),
    ]
    depth_issues, depth_report = check_attack_flow_depth(cfg)

    # Categorise: unreachable / depth<2 = error; everything else = warning (some are errors)
    ERROR_KEYWORDS = ["UNREACHABLE", "unsolvable", "not defined", "not in identifiers",
                      "is missing", "must be", "breach_node", "incorrect category pairing",
                      "vulnerability_catalog.md", "orphaned property"]
    for check_name, issues in checks:
        for issue in issues:
            if any(k.lower() in issue.lower() for k in ERROR_KEYWORDS):
                all_errors.append(f"[{check_name}] {issue}")
            else:
                all_warnings.append(f"[{check_name}] {issue}")

    for issue in depth_issues:
        if "UNREACHABLE" in issue or "unsolvable" in issue.lower():
            all_errors.append(f"[Attack flow depth] {issue}")
        else:
            all_warnings.append(f"[Attack flow depth] {issue}")

    # ---- JSON output ----
    if args.json:
        payload = {
            "config":   str(path),
            "errors":   all_errors,
            "warnings": all_warnings,
            "depth_report": {k: (v if v < 9999 else None) for k, v in depth_report.items()},
            "passed":   len(all_errors) == 0 and (not args.strict or len(all_warnings) == 0),
        }
        print(json.dumps(payload, indent=2))
        sys.exit(0 if payload["passed"] else 1)

    # ---- Human-readable output ----
    print(f"\n{C.BOLD}Config checker — {path}{C.END}")

    _section("Attack Flow Depth Report")
    if depth_report:
        _print_depth_table(depth_report, services)
    else:
        warn("No attack flow defined — cannot compute depth")

    _section("Errors")
    if all_errors:
        for e in all_errors:
            err(e)
    else:
        ok("No errors found")

    _section("Warnings")
    if all_warnings:
        for w in all_warnings:
            warn(w)
    else:
        ok("No warnings found")

    # ---- Summary ----
    _section("Summary")
    goal_services = [k for k, v in services.items() if v.get("is_goal", False)]
    info(f"Services defined     : {len(services)}")
    info(f"Goal services        : {len(goal_services)} ({', '.join(goal_services)})")
    info(f"Attack flow rules    : {len(cfg.get('attack_flow', []))}")
    info(f"Domains              : {len(cfg.get('domains', []))}")

    solv_vulns = sum(
        len(v) for v in cfg.get("solvability_vulnerabilities", {}).values()
        if isinstance(v, list)
    )
    info(f"Solvability vulns    : {solv_vulns}")

    total_constraints = sum(
        len(d.get("constraints", []))
        for d in cfg.get("domains", [])
    )
    info(f"Constraints total    : {total_constraints}")

    passed = len(all_errors) == 0
    if args.strict:
        passed = passed and len(all_warnings) == 0

    print()
    if passed:
        print(f"{C.GREEN}{C.BOLD}  ✓ Config is valid{' and warning-free' if args.strict else ''}{C.END}")
    else:
        issues_word = "errors" if all_errors else "warnings"
        count = len(all_errors) if all_errors else len(all_warnings)
        print(f"{C.RED}{C.BOLD}  ✗ Config has {count} {issues_word} — fix before generating data{C.END}")
    print()

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
