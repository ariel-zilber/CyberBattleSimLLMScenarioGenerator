#!/usr/bin/env python3
"""
Static validation for specialist scenario YAML configs.

Catches all bug classes found during scenario development:
  1. YAML parse errors
  2. Unknown service keys / ports / properties vs global_vocabulary.yaml
  3. Vulnerability type mismatch (LOCAL/REMOTE vs global vocab)
  4. Property used in service but not declared in identifiers.base_properties
  5. Technique in wrong solvability category vs vulnerability_catalog.md

Usage:
  python tools/static_validation.py data/scenarios/specialists/*.yaml
  python tools/static_validation.py data/scenarios/specialists/*.yaml --vocab path/to/global_vocabulary.yaml
  python tools/static_validation.py data/scenarios/specialists/*.yaml --catalog prompts/reference/vulnerability_catalog.md
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_VOCAB = _ROOT / "data" / "global_vocabulary.yaml"
_CBS_VOCAB = Path("/Users/ariel.zilbershteyin/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml")
_DEFAULT_CATALOG = _ROOT / "prompts" / "reference" / "vulnerability_catalog.md"

# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_global_vocab(path: Path) -> dict[str, set[str]]:
    raw = yaml.safe_load(path.read_text()) or {}
    ports = set(raw.get("ports", []))
    return {
        "local":      set(raw.get("local_vulnerabilities", [])),
        "remote":     set(raw.get("remote_vulnerabilities", [])),
        "ports":      ports,
        "services":   set(raw.get("service_ids", [])),
        "properties": set(raw.get("properties", [])) | ports | {"breach_node"},
    }


def load_vuln_catalog(path: Path) -> dict[str, set[str]]:
    """Parse vulnerability_catalog.md → {category: {Solvability.* names}}."""
    catalog: dict[str, set[str]] = defaultdict(set)
    current: str | None = None
    for line in path.read_text().splitlines():
        m = re.match(r'^##\s+Category:\s+`(\w+)`', line)
        if m:
            current = m.group(1)
        if current:
            for name in re.findall(r'`(Solvability\.\w+)`', line):
                catalog[current].add(name)
    return dict(catalog)


def load_catalog_rates(path: Path) -> dict[str, float]:
    """Parse vulnerability_catalog.md → {Solvability.Name: canonical_success_rate}.

    Two table formats exist in the catalog:
      REMOTE: | `Solvability.X` | CVE | desc | CVSS | **0.90** | cost | R | props |
      LOCAL:  | `Solvability.X` | desc | props | 0.65 | notes |

    REMOTE entries use bold markdown (**rate**); LOCAL entries use a plain float
    in column 4 (0-indexed after splitting on '|').
    """
    rates: dict[str, float] = {}
    for line in path.read_text().splitlines():
        if '`Solvability.' not in line or '|' not in line:
            continue
        m_name = re.search(r'`(Solvability\.\w+)`', line)
        if not m_name:
            continue
        name = m_name.group(1)
        # REMOTE format: bold rate
        m_bold = re.search(r'\*\*([\d.]+)\*\*', line)
        if m_bold:
            try:
                rates[name] = float(m_bold.group(1))
            except ValueError:
                pass
            continue
        # LOCAL format: plain float in 4th pipe column (cols[4] after split on '|')
        cols = [c.strip() for c in line.split('|')]
        if len(cols) >= 5:
            try:
                rates[name] = float(cols[4])
            except ValueError:
                pass
    return rates

# ---------------------------------------------------------------------------
# Per-file checks
# ---------------------------------------------------------------------------

LEGACY_PREFIXES = ("Remote.Probe.", "External.", "Local.")
FORBIDDEN_TOKENS = {
    "S_Recon", "BranchRouter", "BranchSDWAN", "AWSHTTP",
    "Solvability.ARP_Table_Dump", "Solvability.Nmap_Internal",
    "Solvability.CDP_Neighbors", "Solvability.CiscoASA_OSPF",
}

# Maps service name → which specialist "owns" that service type.
# Used to verify that the goal pool (is_goal services + intermediate_goals)
# spans at least 3 different specialist domains.
_SPECIALIST_SERVICE_MAP: dict[str, str] = {
    # S_Network — perimeter / routing / firewall devices
    "ISPRouter": "s_network", "MikroTikRouter": "s_network",
    "CiscoASA": "s_network", "CiscoNXOS": "s_network",
    "CiscoFirepower": "s_network", "CiscoEdgeRouter": "s_network",
    "JuniperRouter": "s_network", "FortiGateAppliance": "s_network",
    "PaloAltoFirewall": "s_network", "WAFAppliance": "s_network",
    "F5LoadBalancer": "s_network",
    # S_Windows — Windows workstations / print / exchange
    "SalesWorkstation": "s_windows", "PrintServer": "s_windows",
    "ExchangeServer": "s_windows", "LegacyWorkstation": "s_windows",
    "FinanceWorkstation": "s_windows", "DeveloperWorkstation": "s_windows",
    # S_Identity — AD / PKI / PAM
    "DomainController": "s_identity", "ADCS_Server": "s_identity",
    "FileServer": "s_identity", "CyberArkPAM": "s_identity",
    # S_Linux — cloud / POSIX services
    "postfix": "s_linux", "AppServer": "s_linux", "AWSAppServer": "s_linux",
    "RnDWorkstation": "s_linux", "DockerHost": "s_linux",
    "JenkinsServer": "s_linux", "GitLabServer": "s_linux",
    "ftpd": "s_linux", "NginxServer": "s_linux",
    # S_Lateral — cross-zone pivot hosts
    "AdminWorkstation": "s_lateral",
}


def check_vocab(fp: Path, data: dict, vocab: dict[str, set[str]]) -> list[str]:
    """Check service keys, ports, properties, vuln names against global vocab."""
    issues: list[str] = []

    def err(path: str, kind: str, val: Any) -> None:
        issues.append(f"{fp.name}:{path}: {kind}: {val}")

    def walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            if path == "services":
                for svc in obj:
                    if svc not in vocab["services"]:
                        err(f"services.{svc}", "unknown service key", svc)

            for key, val in obj.items():
                kpath = f"{path}.{key}" if path else key

                if key in {"port", "protocol", "default_entry_port"} and isinstance(val, str):
                    if val not in vocab["ports"]:
                        err(kpath, "unknown port", val)

                if key in {"standard_ports", "standard_ports_extra", "preferred_entry_ports"} and isinstance(val, list):
                    for i, item in enumerate(val):
                        if isinstance(item, str) and item not in vocab["ports"]:
                            err(f"{kpath}[{i}]", "unknown port", item)

                if key == "service" and isinstance(val, str) and val not in vocab["services"]:
                    err(kpath, "unknown service ref", val)

                if key in {"default_properties", "properties", "match_properties", "base_properties"} and isinstance(val, list):
                    for i, item in enumerate(val):
                        if isinstance(item, str) and item not in vocab["properties"]:
                            err(f"{kpath}[{i}]", "unknown property", item)

                if key == "name" and isinstance(val, str):
                    if any(val.startswith(p) for p in LEGACY_PREFIXES):
                        err(kpath, "legacy vulnerability name", val)
                    elif val.startswith("Solvability."):
                        vtype = obj.get("type")
                        if vtype == "LOCAL" and val not in vocab["local"]:
                            err(kpath, "not a global local vulnerability", val)
                        elif vtype == "REMOTE" and val not in vocab["remote"]:
                            err(kpath, "not a global remote vulnerability", val)
                        elif vtype not in {"LOCAL", "REMOTE"} and val not in (vocab["local"] | vocab["remote"]):
                            err(kpath, "not a global vulnerability", val)

                if isinstance(val, str):
                    for tok in FORBIDDEN_TOKENS:
                        if tok in val:
                            err(kpath, "forbidden legacy token", tok)

                walk(val, kpath)

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")

    walk(data)
    return issues


def check_identifiers(fp: Path, data: dict) -> list[str]:
    """Every property used in any service must be declared in identifiers.base_properties."""
    issues: list[str] = []
    declared = set(data.get("identifiers", {}).get("base_properties", []))
    ports_ok = set(data.get("identifiers", {}).get("standard_ports", []))
    allowed = declared | ports_ok | {"breach_node"}

    for svc_name, cfg in data.get("services", {}).items():
        if not isinstance(cfg, dict):
            continue
        for pkey in ("default_properties", "properties", "base_properties", "match_properties"):
            for prop in cfg.get(pkey, []) or []:
                if isinstance(prop, str) and prop not in allowed:
                    issues.append(
                        f"{fp.name}:services.{svc_name}.{pkey}: "
                        f"property '{prop}' not in identifiers.base_properties"
                    )
    return issues


def check_categories(fp: Path, data: dict, catalog: dict[str, set[str]]) -> list[str]:
    """Each Solvability.* technique must be in its canonical catalog category."""
    issues: list[str] = []
    all_catalog = set().union(*catalog.values()) if catalog else set()
    sv = data.get("solvability_vulnerabilities", {})

    for category, entries in sv.items():
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            if not name.startswith("Solvability."):
                continue
            if name not in all_catalog:
                continue  # off-catalog names caught by check_vocab
            canonical = [cat for cat, techs in catalog.items() if name in techs]
            if canonical and category not in canonical:
                issues.append(
                    f"{fp.name}:solvability_vulnerabilities.{category}: "
                    f"'{name}' belongs in {canonical}, not '{category}'"
                )
    return issues

# ---------------------------------------------------------------------------
# Duplicate property check
# ---------------------------------------------------------------------------

def check_duplicates(fp: Path, data: dict) -> list[str]:
    """Flag duplicate entries in any list field that should be a set."""
    issues: list[str] = []

    def _check_list(lst: list, path: str) -> None:
        seen: set = set()
        for item in lst:
            if not isinstance(item, str):
                continue
            if item in seen:
                issues.append(f"{fp.name}:{path}: duplicate value '{item}'")
            seen.add(item)

    # Services: default_properties, properties, match_properties
    for svc_name, cfg in data.get("services", {}).items():
        if not isinstance(cfg, dict):
            continue
        for field in ("default_properties", "properties", "base_properties"):
            lst = cfg.get(field)
            if isinstance(lst, list):
                _check_list(lst, f"services.{svc_name}.{field}")

    # identifiers.base_properties
    idents = data.get("identifiers", {})
    for field in ("base_properties", "standard_ports"):
        lst = idents.get(field)
        if isinstance(lst, list):
            _check_list(lst, f"identifiers.{field}")

    # solvability_vulnerabilities: duplicate technique names per category
    for cat, entries in data.get("solvability_vulnerabilities", {}).items():
        names_seen: set = set()
        for entry in (entries or []):
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            if name in names_seen:
                issues.append(
                    f"{fp.name}:solvability_vulnerabilities.{cat}: "
                    f"duplicate technique '{name}'"
                )
            names_seen.add(name)
            # match_properties within each vuln
            mp = entry.get("match_properties")
            if isinstance(mp, list):
                _check_list(mp, f"solvability_vulnerabilities.{cat}.{name}.match_properties")

    return issues


# ---------------------------------------------------------------------------
# Goal value check
# ---------------------------------------------------------------------------

def check_goal_values(fp: Path, data: dict) -> list[str]:
    """Goal services must have value > 0 and must be strictly higher than all
    non-goal services so GoalNormalizer selects them first.

    A zero-value goal node produces no reward signal — the DRL agent has no
    incentive to capture it.  A goal whose value is ≤ any non-goal node will
    be displaced by GoalNormalizer, making the stated terminal_goal unreachable
    by reward alone.
    """
    issues: list[str] = []
    services = data.get("services", {})

    goal_vals: list[tuple[str, float]] = []
    non_goal_vals: list[float] = []

    for name, cfg in services.items():
        if not isinstance(cfg, dict):
            continue
        val = cfg.get("value", None)
        if not isinstance(val, (int, float)):
            continue
        if cfg.get("is_goal"):
            goal_vals.append((name, float(val)))
        else:
            non_goal_vals.append(float(val))

    max_non_goal = max(non_goal_vals, default=0.0)

    for name, val in goal_vals:
        if val <= 0:
            issues.append(
                f"{fp.name}:services.{name}: is_goal service has value={val} "
                f"— zero/negative value gives no reward signal to DRL agent"
            )
        elif val <= max_non_goal:
            issues.append(
                f"{fp.name}:services.{name}: is_goal value={val} ≤ "
                f"non-goal max={max_non_goal} — GoalNormalizer will not "
                f"select this as the primary goal (it will pick a higher-value non-goal instead)"
            )

    return issues


# ---------------------------------------------------------------------------
# Goal specialist coverage check
# ---------------------------------------------------------------------------

def check_goal_specialist_coverage(fp: Path, data: dict) -> list[str]:
    """Every active specialist must have at least one goal service.

    Goal pool = services with ``is_goal: true``  +  ``metadata.intermediate_goals``.
    Each entry is mapped to a specialist via *_SPECIALIST_SERVICE_MAP*.
    Requires ≥ 3 distinct specialists covered (matching ``num_goals``).
    Also flags if the goal pool itself has < 3 entries (GoalNormalizer can't
    meet ``num_goals=3`` from a single explicit is_goal service without
    promoting random value-based nodes that may all belong to the same specialist).
    """
    issues: list[str] = []
    meta     = data.get("metadata", {})
    services = data.get("services", {})

    # Collect explicit goal services
    is_goal_svcs: set[str] = {
        k for k, v in services.items()
        if isinstance(v, dict) and v.get("is_goal")
    }
    # Collect intermediate_goals milestone services
    intermediate: set[str] = {
        g.get("name", "") for g in (meta.get("intermediate_goals") or [])
        if isinstance(g, dict) and g.get("name")
    }
    goal_pool = is_goal_svcs | intermediate

    if len(goal_pool) < 3:
        issues.append(
            f"{fp.name}:metadata: goal pool has only {len(goal_pool)} entries "
            f"(is_goal={sorted(is_goal_svcs)}, intermediate_goals={sorted(intermediate)}). "
            f"Need ≥ 3 so GoalNormalizer can select one per specialist."
        )

    # Map each goal service to its specialist
    covered: dict[str, list[str]] = {}
    unmapped: list[str] = []
    for svc in sorted(goal_pool):
        spec = _SPECIALIST_SERVICE_MAP.get(svc)
        if spec:
            covered.setdefault(spec, []).append(svc)
        else:
            unmapped.append(svc)

    if unmapped:
        issues.append(
            f"{fp.name}:metadata: goal service(s) {unmapped} not in specialist map — "
            f"add to _SPECIALIST_SERVICE_MAP in static_validation.py"
        )

    if len(covered) < 3:
        issues.append(
            f"{fp.name}:metadata: goal pool spans only {len(covered)} specialist(s) "
            f"({sorted(covered.keys())}). Need ≥ 3 for one-goal-per-specialist guarantee. "
            f"Add intermediate_goals covering missing specialists."
        )

    return issues


# ---------------------------------------------------------------------------
# Breach-node check
# ---------------------------------------------------------------------------

def check_breach_node(fp: Path, data: dict) -> list[str]:
    """At least one service OR start_node must carry the breach_node property.

    Without a breach node CyberBattleSim has no attacker entry point and the
    environment is unrunnable.
    """
    for cfg in data.get("services", {}).values():
        if isinstance(cfg, dict):
            for field in ("default_properties", "properties", "base_properties"):
                if "breach_node" in (cfg.get(field) or []):
                    return []
    start = data.get("start_node", {})
    if isinstance(start, dict) and "breach_node" in (start.get("properties") or []):
        return []
    return [f"{fp.name}: no breach_node property found — attacker has no entry point"]


# ---------------------------------------------------------------------------
# Remote-entry check
# ---------------------------------------------------------------------------

def check_remote_entry(fp: Path, data: dict) -> list[str]:
    """At least one REMOTE vulnerability must exist in solvability_vulnerabilities.

    A config with only LOCAL vulns is unwinnable: the attacker cannot enter
    the network from outside.  start_node vulnerabilities count toward this
    check because they fire before the main attack graph.
    """
    for entries in data.get("solvability_vulnerabilities", {}).values():
        for e in (entries or []):
            if isinstance(e, dict) and e.get("type") == "REMOTE":
                return []
    start = data.get("start_node", {})
    if isinstance(start, dict):
        for e in start.get("vulnerabilities", {}).values():
            if isinstance(e, dict) and e.get("type") == "REMOTE":
                return []
    return [f"{fp.name}: no REMOTE vulnerability found — game is unwinnable by design"]


# ---------------------------------------------------------------------------
# Success-rate bounds check
# ---------------------------------------------------------------------------

def check_success_rates(fp: Path, data: dict) -> list[str]:
    """Every success_rate must be in [0.05, 0.95].

    Values outside this range produce either trivially solved or practically
    unsolvable scenarios, both of which collapse the DRL training signal.
    """
    issues: list[str] = []
    LO, HI = 0.05, 0.95

    def _walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            if "success_rate" in obj:
                val = obj["success_rate"]
                if isinstance(val, (int, float)) and not (LO <= float(val) <= HI):
                    issues.append(
                        f"{fp.name}:{path}.success_rate={val} outside [{LO},{HI}] "
                        f"— trivial or impossible exploit"
                    )
            for k, v in obj.items():
                _walk(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{path}[{i}]")

    # probe_vulnerabilities intentionally use 1.0 (always-succeed discovery scans)
    for section in ("solvability_vulnerabilities", "constraint_vulnerabilities", "start_node"):
        _walk(data.get(section, {}), section)
    return issues


# ---------------------------------------------------------------------------
# Category spread check
# ---------------------------------------------------------------------------

def check_category_spread(fp: Path, data: dict) -> list[str]:
    """solvability_vulnerabilities must have ≥2 distinct non-empty categories.

    A single-category scenario means the entire attack chain uses one tactic
    class (e.g. only lateral_movement), which is unrealistic and limits the
    DRL agent's tactic diversity.
    """
    sv = data.get("solvability_vulnerabilities", {})
    active = [cat for cat, entries in sv.items() if entries]
    if len(active) < 2:
        return [
            f"{fp.name}:solvability_vulnerabilities: only {len(active)} non-empty "
            f"category ({active}) — need ≥2 for realistic multi-tactic attack chains"
        ]
    return []


# ---------------------------------------------------------------------------
# Value monotonicity check
# ---------------------------------------------------------------------------

def check_value_monotonicity(fp: Path, data: dict) -> list[str]:
    """Warn if all non-goal services share the same value (no reward gradient).

    Uniform service values give the DRL agent no incentive to prioritise
    high-value targets; the reward landscape is flat and training converges
    poorly.
    """
    services = data.get("services", {})
    non_goal_vals = [
        float(cfg.get("value", 0))
        for cfg in services.values()
        if isinstance(cfg, dict)
        and not cfg.get("is_goal")
        and isinstance(cfg.get("value"), (int, float))
    ]
    if len(non_goal_vals) >= 3 and len(set(non_goal_vals)) == 1:
        return [
            f"{fp.name}:services: all {len(non_goal_vals)} non-goal services have "
            f"value={non_goal_vals[0]} — uniform rewards collapse DRL training signal"
        ]
    return []


# ---------------------------------------------------------------------------
# Orphan service check
# ---------------------------------------------------------------------------

def check_orphan_services(fp: Path, data: dict) -> list[str]:
    """Services with completely empty config contribute nothing to the attack graph."""
    issues: list[str] = []
    for name, cfg in data.get("services", {}).items():
        if not isinstance(cfg, dict) or len(cfg) == 0:
            issues.append(
                f"{fp.name}:services.{name}: empty service definition — "
                f"no port, properties, or vulnerability references"
            )
    return issues


# ---------------------------------------------------------------------------
# Firewall checks
# ---------------------------------------------------------------------------

# Maps service name → required properties subset (all must be present)
_FW_REQUIRED_PROPS: dict[str, list[str]] = {
    "CiscoASA":         ["Firewall", "CiscoASA"],
    "CiscoFirepower":   ["Firewall", "CiscoFirepower"],
    "FortiGateAppliance": ["Firewall", "FortiGate"],
    "PaloAltoFirewall": ["Firewall", "PaloAlto", "PANOS"],
    "WAFAppliance":     ["Firewall", "WAF"],
    "F5LoadBalancer":   ["LoadBalancer"],
    "JuniperRouter":    ["Firewall"],
    "CiscoNXOS":        ["Switch", "CiscoNXOS"],
    "CiscoEdgeRouter":  ["Router"],
}

# Internal crown-jewel services that must be gated behind ≥1 firewall hop
_INTERNAL_SVCS = {"DomainController", "AdminWorkstation", "FileServer",
                  "ADCS_Server", "CyberArkPAM", "DomainController"}

_FW_SVC_NAMES = set(_FW_REQUIRED_PROPS.keys())


def _af_matches(pattern: str, svc_name: str) -> bool:
    """Return True if attack_flow pattern matches a service name (substring or equal)."""
    return pattern == svc_name or pattern in svc_name or svc_name in pattern


def check_firewall_consistency(fp: Path, data: dict) -> list[str]:
    """Each firewall-type service must carry its vendor-specific properties.

    A PaloAltoFirewall without PANOS or a FortiGateAppliance without FortiGate
    means match_properties in solvability_vulnerabilities will never fire for
    that service, silently making it unexploitable.
    """
    issues: list[str] = []
    services = data.get("services", {})
    for svc_name, required in _FW_REQUIRED_PROPS.items():
        cfg = services.get(svc_name)
        if not isinstance(cfg, dict):
            continue
        props: set[str] = set()
        for field in ("default_properties", "properties", "base_properties"):
            props |= set(cfg.get(field) or [])
        missing = [p for p in required if p not in props]
        if missing:
            issues.append(
                f"{fp.name}:services.{svc_name}: missing required vendor "
                f"properties {missing} — match_properties checks will silently fail"
            )
    return issues


def check_firewall_not_goal(fp: Path, data: dict) -> list[str]:
    """Firewall/network devices must not be marked is_goal.

    Network infrastructure is a traversal node; making it a goal means the
    DRL agent earns reward for pivoting to a router instead of a crown jewel.
    """
    issues: list[str] = []
    services = data.get("services", {})
    for svc_name in _FW_SVC_NAMES:
        cfg = services.get(svc_name)
        if isinstance(cfg, dict) and cfg.get("is_goal"):
            issues.append(
                f"{fp.name}:services.{svc_name}: firewall/network device has "
                f"is_goal=true — network infrastructure should not be a crown jewel"
            )
    return issues


def check_attack_flow_dag(fp: Path, data: dict) -> list[str]:
    """attack_flow must be a DAG (directed acyclic graph) — no cycles.

    A cycle in the attack flow (A→B→A) is a topology error: it means two nodes
    mutually depend on each other for exploitation, which CyberBattleSim cannot
    model.
    """
    af = data.get("attack_flow", [])
    if not isinstance(af, list):
        return []

    # Build adjacency list
    graph: dict[str, list[str]] = {}
    for entry in af:
        if not isinstance(entry, dict):
            continue
        src = entry.get("source_pattern", "")
        targets = entry.get("targets", []) or []
        graph.setdefault(src, [])
        for t in targets:
            graph[src].append(t)
            graph.setdefault(t, [])

    # DFS cycle detection
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {n: WHITE for n in graph}
    cycle_edges: list[str] = []

    def dfs(u: str) -> None:
        color[u] = GRAY
        for v in graph.get(u, []):
            if color.get(v, WHITE) == GRAY:
                cycle_edges.append(f"{u} → {v}")
            elif color.get(v, WHITE) == WHITE:
                dfs(v)
        color[u] = BLACK

    for node in list(graph):
        if color.get(node, WHITE) == WHITE:
            dfs(node)

    if cycle_edges:
        return [
            f"{fp.name}:attack_flow: cycle detected — {cycle_edges} — "
            f"CyberBattleSim requires a DAG topology"
        ]
    return []


def check_firewall_in_attack_flow(fp: Path, data: dict) -> list[str]:
    """Every firewall-type service that exists must appear in attack_flow.

    A firewall service not referenced in any attack_flow source_pattern or
    target is a ghost node: Phase 2 will generate it but the attacker can
    never reach or traverse it, wasting action slots.
    """
    issues: list[str] = []
    services = data.get("services", {})
    af = data.get("attack_flow", [])
    if not isinstance(af, list):
        return []

    af_patterns: set[str] = set()
    for entry in af:
        if not isinstance(entry, dict):
            continue
        af_patterns.add(entry.get("source_pattern", ""))
        af_patterns |= set(entry.get("targets", []) or [])

    for svc_name in _FW_SVC_NAMES:
        if svc_name not in services:
            continue
        if not any(_af_matches(pat, svc_name) for pat in af_patterns):
            issues.append(
                f"{fp.name}:services.{svc_name}: firewall/network service not "
                f"referenced in attack_flow — unreachable ghost node"
            )
    return issues


def check_internal_nodes_gated(fp: Path, data: dict) -> list[str]:
    """Internal crown-jewel nodes must not be directly reachable from attack_flow roots.

    attack_flow roots = source_pattern nodes that are never a target.
    If DomainController is reachable in 1 hop from the root, there is no
    firewall traversal required, making the scenario trivially easy.
    """
    issues: list[str] = []
    af = data.get("attack_flow", [])
    if not isinstance(af, list) or not af:
        return []

    graph: dict[str, list[str]] = {}
    all_targets: set[str] = set()
    for entry in af:
        if not isinstance(entry, dict):
            continue
        src = entry.get("source_pattern", "")
        targets = entry.get("targets", []) or []
        graph.setdefault(src, []).extend(targets)
        all_targets |= set(targets)

    roots = set(graph) - all_targets
    if not roots:
        return []

    # BFS: find 1-hop neighbours of roots
    one_hop: set[str] = set()
    for root in roots:
        one_hop |= set(graph.get(root, []))

    services = data.get("services", {})
    for internal in _INTERNAL_SVCS:
        if internal not in services:
            continue
        direct = any(_af_matches(pat, internal) for pat in one_hop)
        if direct:
            issues.append(
                f"{fp.name}:attack_flow: {internal} reachable in 1 hop from "
                f"root ({sorted(roots)}) — no firewall traversal required, "
                f"scenario is trivially penetrable"
            )
    return issues


def check_perimeter_fw_remote_vuln(fp: Path, data: dict) -> list[str]:
    """The internet-facing (perimeter) firewall must have a matching REMOTE vulnerability.

    Perimeter firewall = first-hop firewall node reachable from the attack_flow
    root.  If no REMOTE solvability vulnerability has match_properties overlapping
    with the perimeter firewall's properties, the attacker cannot enter from outside.
    """
    issues: list[str] = []
    af = data.get("attack_flow", [])
    services = data.get("services", {})
    sv = data.get("solvability_vulnerabilities", {})
    if not isinstance(af, list) or not services:
        return []

    # Collect all REMOTE technique match_properties
    remote_match_props: list[set[str]] = []
    for entries in sv.values():
        for e in (entries or []):
            if isinstance(e, dict) and e.get("type") == "REMOTE":
                mp = set(e.get("match_properties") or [])
                if mp:
                    remote_match_props.append(mp)

    # Build attack_flow graph + find roots
    graph: dict[str, list[str]] = {}
    all_targets: set[str] = set()
    for entry in af:
        if not isinstance(entry, dict):
            continue
        src = entry.get("source_pattern", "")
        targets = entry.get("targets", []) or []
        graph.setdefault(src, []).extend(targets)
        all_targets |= set(targets)

    roots = set(graph) - all_targets
    one_hop: set[str] = set()
    for root in roots:
        one_hop |= set(graph.get(root, []))

    # For each firewall in one-hop positions, verify REMOTE vuln coverage
    for svc_name in _FW_SVC_NAMES:
        if svc_name not in services:
            continue
        if not any(_af_matches(pat, svc_name) for pat in one_hop):
            continue  # not a perimeter firewall
        svc_props: set[str] = set()
        cfg = services[svc_name]
        if isinstance(cfg, dict):
            for field in ("default_properties", "properties", "base_properties"):
                svc_props |= set(cfg.get(field) or [])
        covered = any(mp & svc_props for mp in remote_match_props)
        if not covered:
            issues.append(
                f"{fp.name}:services.{svc_name}: perimeter firewall has no REMOTE "
                f"vulnerability whose match_properties overlaps its properties {sorted(svc_props)} "
                f"— attacker cannot exploit this gateway from outside"
            )
    return issues


# ---------------------------------------------------------------------------
# Dead-technique check  (most critical hallucination catch)
# ---------------------------------------------------------------------------

def check_dead_techniques(fp: Path, data: dict) -> list[str]:
    """Every solvability technique must be satisfiable by ≥1 service.

    A technique is satisfiable when at least one service's properties is a
    superset of the technique's match_properties.  Dead techniques — whose
    match_properties no service can satisfy — silently never fire: the DRL
    agent discovers them in its action space but they always return failure,
    wasting action budget and distorting the training signal.

    Root causes in practice:
      - LLM writes match_properties that require a property combination no
        service carries (e.g. Router AND Switch on the same node)
      - Service is missing a required vendor tag (no Unpatched, no SSLVPN)
      - Technique copied from a different scenario where the matching service
        existed but was not brought along
    """
    issues: list[str] = []

    # Collect all service property sets
    svc_props: dict[str, frozenset[str]] = {}
    for svc_name, cfg in data.get("services", {}).items():
        if isinstance(cfg, dict):
            p: set[str] = set()
            for field in ("default_properties", "properties", "base_properties"):
                p |= set(cfg.get(field) or [])
            svc_props[svc_name] = frozenset(p)

    if not svc_props:
        return []

    for cat, entries in data.get("solvability_vulnerabilities", {}).items():
        for e in (entries or []):
            if not isinstance(e, dict):
                continue
            mp = frozenset(e.get("match_properties") or [])
            if not mp:
                continue
            name = e.get("name", "?")
            satisfiable = any(mp <= props for props in svc_props.values())
            if not satisfiable:
                issues.append(
                    f"{fp.name}:solvability_vulnerabilities.{cat}.{name}: "
                    f"match_properties={sorted(mp)} — no service satisfies all "
                    f"required properties; technique is permanently dead"
                )
    return issues


# ---------------------------------------------------------------------------
# Attack-flow dangling reference check
# ---------------------------------------------------------------------------

def check_af_nodes_exist(fp: Path, data: dict) -> list[str]:
    """Every node pattern in attack_flow must match ≥1 service name.

    Dangling patterns — referencing nodes that don't exist in services — mean
    Phase 2 generates edges into the void: the attacker traverses a path that
    leads to a node type that was never instantiated.
    """
    issues: list[str] = []
    af = data.get("attack_flow", [])
    if not isinstance(af, list):
        return []

    svc_names = set(data.get("services", {}).keys())
    if not svc_names:
        return []

    seen: set[str] = set()
    for entry in af:
        if not isinstance(entry, dict):
            continue
        patterns = [entry.get("source_pattern", "")] + list(entry.get("targets", []) or [])
        for pat in patterns:
            if not pat or pat in seen:
                continue
            seen.add(pat)
            if not any(_af_matches(pat, svc) for svc in svc_names):
                issues.append(
                    f"{fp.name}:attack_flow: pattern '{pat}' matches no service "
                    f"in services dict — dangling reference to non-existent node"
                )
    return issues


# ---------------------------------------------------------------------------
# Dead-end firewall check
# ---------------------------------------------------------------------------

def check_firewall_not_deadend(fp: Path, data: dict) -> list[str]:
    """A firewall that is a target but never a source in attack_flow is a dead end.

    Compromising a dead-end firewall advances nothing: the attacker reaches it
    but has nowhere to go.  Real firewalls gate access to internal segments and
    must appear as both a traversal target and an onward source.
    """
    issues: list[str] = []
    af = data.get("attack_flow", [])
    if not isinstance(af, list):
        return []

    sources: set[str] = {e.get("source_pattern", "") for e in af if isinstance(e, dict)}
    targets_all: set[str] = {
        t for e in af if isinstance(e, dict) for t in (e.get("targets", []) or [])
    }
    services = data.get("services", {})

    for svc_name in _FW_SVC_NAMES:
        if svc_name not in services:
            continue
        in_target = any(_af_matches(t, svc_name) for t in targets_all)
        in_source = any(_af_matches(s, svc_name) for s in sources)
        if in_target and not in_source:
            issues.append(
                f"{fp.name}:attack_flow: {svc_name} is reachable (target) but "
                f"has no outgoing edges (never a source) — dead-end firewall, "
                f"compromising it leads nowhere"
            )
    return issues


# ---------------------------------------------------------------------------
# Attack-flow reachability check
# ---------------------------------------------------------------------------

def check_goal_reachable(fp: Path, data: dict) -> list[str]:
    """terminal_goal must be reachable from attack_flow root(s) via BFS.

    The DAG check (fw_dag) catches cycles.  This check catches disconnected
    graphs: scenarios where the topology never leads to the terminal objective
    regardless of which vulnerabilities the agent exploits.  Such scenarios are
    unwinnable by design and will produce zero terminal reward during training.
    """
    af = data.get("attack_flow", [])
    if not isinstance(af, list) or not af:
        return []

    terminal_goal = (data.get("metadata") or {}).get("terminal_goal", "")
    if not terminal_goal:
        return []

    # Build adjacency list from attack_flow entries
    graph: dict[str, list[str]] = {}
    all_targets: set[str] = set()
    for entry in af:
        if not isinstance(entry, dict):
            continue
        src = entry.get("source_pattern", "")
        targets = entry.get("targets", []) or []
        graph.setdefault(src, []).extend(targets)
        all_targets |= set(targets)
        for t in targets:
            graph.setdefault(t, [])

    # Roots = source nodes that are never a target
    roots = set(graph) - all_targets
    if not roots:
        return []  # pure cycle — already caught by fw_dag

    # BFS from all roots
    visited: set[str] = set(roots)
    queue = list(roots)
    while queue:
        node = queue.pop(0)
        for nb in graph.get(node, []):
            if nb not in visited:
                visited.add(nb)
                queue.append(nb)

    # terminal_goal matches if any visited pattern is a substring match
    if any(_af_matches(terminal_goal, node) or _af_matches(node, terminal_goal)
           for node in visited):
        return []

    return [
        f"{fp.name}:attack_flow: terminal_goal '{terminal_goal}' unreachable "
        f"from root(s) {sorted(roots)} via attack_flow — "
        f"scenario is unwinnable, graph is disconnected from objective"
    ]


# ---------------------------------------------------------------------------
# Minimum attack-path depth check
# ---------------------------------------------------------------------------

def check_attack_path_depth(fp: Path, data: dict) -> list[str]:
    """Shortest path from attack_flow root(s) to terminal_goal must be ≥ 2 hops.

    A 1-hop scenario requires no lateral movement: the attacker compromises the
    terminal objective in a single step, collapsing the DRL training signal to a
    bandit problem with no sequential decision-making value.

    Depth < 2 → ERROR (trivially easy, structurally unsound)
    Depth == 2 → WARN (minimal traversal, consider adding an intermediate node)
    """
    af = data.get("attack_flow", [])
    if not isinstance(af, list) or not af:
        return []

    terminal_goal = (data.get("metadata") or {}).get("terminal_goal", "")
    if not terminal_goal:
        return []

    graph: dict[str, list[str]] = {}
    all_targets: set[str] = set()
    for entry in af:
        if not isinstance(entry, dict):
            continue
        src = entry.get("source_pattern", "")
        targets = entry.get("targets", []) or []
        graph.setdefault(src, []).extend(targets)
        all_targets |= set(targets)
        for t in targets:
            graph.setdefault(t, [])

    roots = set(graph) - all_targets
    if not roots:
        return []  # pure cycle — caught by fw_dag

    # BFS with per-node distance tracking
    from collections import deque
    dist: dict[str, int] = {r: 0 for r in roots}
    queue: deque[str] = deque(roots)
    while queue:
        node = queue.popleft()
        for nb in graph.get(node, []):
            if nb not in dist:
                dist[nb] = dist[node] + 1
                queue.append(nb)

    goal_depths = [
        d for node, d in dist.items()
        if _af_matches(terminal_goal, node) or _af_matches(node, terminal_goal)
    ]
    if not goal_depths:
        return []  # unreachability already caught by check_goal_reachable

    min_depth = min(goal_depths)

    if min_depth < 2:
        return [
            f"{fp.name}:attack_flow: shortest path to terminal_goal '{terminal_goal}' "
            f"is {min_depth} hop(s) — no lateral movement required, "
            f"scenario is trivially easy and collapses DRL training to bandit"
        ]
    if min_depth == 2:
        return [
            f"{fp.name}:attack_flow: WARN shortest path to terminal_goal '{terminal_goal}' "
            f"is {min_depth} hops — minimal traversal depth, "
            f"consider inserting an intermediate node to deepen the kill chain"
        ]
    return []


# ---------------------------------------------------------------------------
# Dead-service check
# ---------------------------------------------------------------------------

def check_dead_services(fp: Path, data: dict) -> list[str]:
    """Every non-breach service must be targetable by ≥1 live solvability technique.

    A service that no technique can compromise instantiates in the simulation but
    the agent can never capture it via exploit.  It wastes graph capacity and
    confuses policy learning.

    Exemption: services reachable via LEAK_KNOWN_CREDENTIALS (connect-only nodes)
    are excluded — they are compromised by a connect action, not an exploit.
    """
    issues: list[str] = []
    services = data.get("services", {})
    if not services:
        return []

    # Build per-service property sets; identify breach services
    svc_props: dict[str, frozenset[str]] = {}
    breach_svcs: set[str] = set()
    for svc_name, cfg in services.items():
        if not isinstance(cfg, dict):
            continue
        p: set[str] = set()
        for field in ("default_properties", "properties", "base_properties"):
            p |= set(cfg.get(field) or [])
        svc_props[svc_name] = frozenset(p)
        if "breach_node" in p:
            breach_svcs.add(svc_name)

    # Identify credential-target services (reachable via connect, not exploit)
    cred_targets: set[str] = set()
    for cfg in services.values():
        if not isinstance(cfg, dict):
            continue
        for cred in (cfg.get("credentials") or []):
            if isinstance(cred, dict):
                svc = cred.get("service") or cred.get("target_service", "")
                if svc:
                    cred_targets.add(svc)
    # start_node leaked credentials
    for cred in ((data.get("start_node") or {}).get("leak_known_credentials") or []):
        if isinstance(cred, dict):
            svc = cred.get("service") or cred.get("target_service", "")
            if svc:
                cred_targets.add(svc)

    # Collect match_properties of all live techniques
    # An empty mp matches every service (no restriction), so short-circuit globally.
    any_universal = False
    live_mps: list[frozenset[str]] = []
    for entries in data.get("solvability_vulnerabilities", {}).values():
        for e in (entries or []):
            if not isinstance(e, dict):
                continue
            mp = frozenset(e.get("match_properties") or [])
            if not mp:
                any_universal = True
            live_mps.append(mp)

    if any_universal:
        return []  # at least one technique can target any service

    for svc_name, props in svc_props.items():
        if svc_name in breach_svcs or svc_name in cred_targets:
            continue
        if not any(mp <= props for mp in live_mps):
            issues.append(
                f"{fp.name}:services.{svc_name}: WARN no solvability technique "
                f"targets this service — instantiates in simulation but never exploitable"
            )
    return issues


# ---------------------------------------------------------------------------
# Dead-property check
# ---------------------------------------------------------------------------

def check_dead_properties(fp: Path, data: dict) -> list[str]:
    """Every property in identifiers.base_properties must appear on ≥1 service.

    A property declared but never placed on any service can never satisfy any
    technique's match_properties: it exists as dead vocabulary that inflates the
    observation space without contributing to any exploit condition.

    Note: properties that only appear in match_properties (but not on any service)
    are already caught as dead techniques by check_dead_techniques.  This check
    catches the root cause — the unused property declaration itself.
    """
    declared = set((data.get("identifiers") or {}).get("base_properties") or [])
    declared -= {"breach_node"}  # breach_node is placed on start_node, not a service
    if not declared:
        return []

    # Collect properties actually placed on services
    on_services: set[str] = set()
    for cfg in data.get("services", {}).values():
        if not isinstance(cfg, dict):
            continue
        for field in ("default_properties", "properties", "base_properties"):
            on_services |= set(cfg.get(field) or [])
    # start_node properties count too
    sn = data.get("start_node") or {}
    if isinstance(sn, dict):
        on_services |= set(sn.get("properties") or [])

    dead = sorted(declared - on_services)
    return [
        f"{fp.name}:identifiers.base_properties: '{p}' declared but never placed "
        f"on any service — dead vocabulary entry"
        for p in dead
    ]


# ---------------------------------------------------------------------------
# Dead constraint-vulnerability check
# ---------------------------------------------------------------------------

def check_dead_constraint_vulns(fp: Path, data: dict) -> list[str]:
    """constraint_vulnerabilities entries must be satisfiable by ≥1 service.

    constraint_vulnerabilities (leak_known_credentials, leak_neighbors) are
    subject to the same dead-technique risk as solvability_vulnerabilities:
    if match_properties is not a subset of any service's properties the
    constraint never fires — no credentials or topology hints are ever leaked
    to the agent.  check_dead_techniques only scans solvability_vulnerabilities;
    this check closes the gap.
    """
    issues: list[str] = []
    cv = data.get("constraint_vulnerabilities")
    if not isinstance(cv, dict):
        return []

    svc_props: dict[str, frozenset[str]] = {}
    for svc_name, cfg in data.get("services", {}).items():
        if isinstance(cfg, dict):
            p: set[str] = set()
            for field in ("default_properties", "properties", "base_properties"):
                p |= set(cfg.get(field) or [])
            svc_props[svc_name] = frozenset(p)

    if not svc_props:
        return []

    for constraint_name, entry in cv.items():
        if not isinstance(entry, dict):
            continue
        mp = frozenset(entry.get("match_properties") or [])
        if not mp:
            continue  # no restriction — fires on any node
        name = entry.get("name", constraint_name)
        satisfiable = any(mp <= props for props in svc_props.values())
        if not satisfiable:
            issues.append(
                f"{fp.name}:constraint_vulnerabilities.{constraint_name} "
                f"('{name}'): match_properties={sorted(mp)} — no service satisfies "
                f"all required properties; constraint never fires"
            )
    return issues


# ---------------------------------------------------------------------------
# Success-rate catalog consistency check
# ---------------------------------------------------------------------------

def check_success_rate_consistency(fp: Path, data: dict,
                                   catalog_rates: dict[str, float]) -> list[str]:
    """Every technique's success_rate must match its catalog canonical value ±0.05.

    The catalog defines a canonical success_rate per technique derived from CVSS
    score and exploitability evidence.  Scenarios that override it by more than
    0.05 are making up values — either an LLM hallucination or a deliberate tweak
    that should be explicitly justified.  Either way it needs to be flagged:
    a hallucinated rate of 0.99 on a CVE catalogued at 0.60 grossly distorts
    the difficulty of that kill-chain segment.
    """
    issues: list[str] = []
    TOLERANCE = 0.05

    for cat, entries in data.get("solvability_vulnerabilities", {}).items():
        for e in (entries or []):
            if not isinstance(e, dict):
                continue
            name = e.get("name", "")
            if not name.startswith("Solvability.") or name not in catalog_rates:
                continue
            scenario_sr = e.get("success_rate")
            if not isinstance(scenario_sr, (int, float)):
                continue
            canonical = catalog_rates[name]
            diff = abs(float(scenario_sr) - canonical)
            if diff > TOLERANCE:
                issues.append(
                    f"{fp.name}:solvability_vulnerabilities.{cat}.{name}: "
                    f"success_rate={scenario_sr} deviates from catalog canonical "
                    f"{canonical} by {diff:.2f} (tolerance ±{TOLERANCE}) — "
                    f"unauthorized override of canonical exploit difficulty"
                )
    return issues


# ---------------------------------------------------------------------------
# Node-range sanity check
# ---------------------------------------------------------------------------

def check_node_range(fp: Path, data: dict) -> list[str]:
    """config node range and metadata node_range must be valid and consistent.

    min_total_nodes ≥ max_total_nodes collapses the generator: Phase 2 cannot
    produce a graph within the specified bounds.  Zero or negative bounds are
    nonsensical.  Mismatch between config and metadata signals a copy-paste error.
    """
    issues: list[str] = []
    cfg = data.get("config", {})
    min_n = cfg.get("min_total_nodes")
    max_n = cfg.get("max_total_nodes")

    if min_n is not None and max_n is not None:
        if not isinstance(min_n, (int, float)) or not isinstance(max_n, (int, float)):
            issues.append(f"{fp.name}:config: min_total_nodes/max_total_nodes must be numeric")
        else:
            if min_n <= 0 or max_n <= 0:
                issues.append(
                    f"{fp.name}:config: node range [{min_n}, {max_n}] contains "
                    f"non-positive value — generator cannot instantiate 0 or negative nodes"
                )
            if min_n >= max_n:
                issues.append(
                    f"{fp.name}:config: min_total_nodes={min_n} ≥ max_total_nodes={max_n} "
                    f"— empty range, Phase 2 generator has no valid target size"
                )

    # metadata.node_range must agree with config bounds
    nr = (data.get("metadata") or {}).get("node_range")
    if isinstance(nr, list) and len(nr) == 2:
        lo, hi = nr[0], nr[1]
        if isinstance(lo, (int, float)) and isinstance(hi, (int, float)):
            if lo <= 0 or hi <= 0:
                issues.append(
                    f"{fp.name}:metadata.node_range: [{lo}, {hi}] contains "
                    f"non-positive value"
                )
            elif lo >= hi:
                issues.append(
                    f"{fp.name}:metadata.node_range: [{lo}, {hi}] — min ≥ max, empty range"
                )
            elif min_n is not None and max_n is not None:
                if lo != min_n or hi != max_n:
                    issues.append(
                        f"{fp.name}: metadata.node_range [{lo},{hi}] ≠ "
                        f"config bounds [{min_n},{max_n}] — copy-paste mismatch"
                    )
    return issues


# ---------------------------------------------------------------------------
# Domain service duplicate check
# ---------------------------------------------------------------------------

def check_domain_service_duplicates(fp: Path, data: dict) -> list[str]:
    """Within a domain, the same service type must not appear in two groups.

    If two groups in the same domain both reference service 'X', Phase 2 will
    instantiate service X twice in that zone — creating duplicate node types that
    confuse the attack graph generator and may produce overlapping credential
    namespaces.
    """
    issues: list[str] = []
    for domain in (data.get("domains") or []):
        if not isinstance(domain, dict):
            continue
        domain_name = domain.get("name", "?")
        seen: dict[str, str] = {}
        for group in (domain.get("groups") or []):
            if not isinstance(group, dict):
                continue
            svc = group.get("service", "")
            gname = group.get("name", "?")
            if not svc:
                continue
            if svc in seen:
                issues.append(
                    f"{fp.name}:domains.{domain_name}: service '{svc}' referenced by "
                    f"groups '{seen[svc]}' and '{gname}' — duplicate in same domain "
                    f"causes instantiation collision"
                )
            else:
                seen[svc] = gname
    return issues


# ---------------------------------------------------------------------------
# Effective exploit probability check
# ---------------------------------------------------------------------------

def check_exploit_effective_probability(fp: Path, data: dict) -> list[str]:
    """success_rate × probability must be ≥ 0.005 for each solvability technique.

    success_rate is the per-attempt exploit success rate.
    probability is the node instantiation likelihood (fraction of episodes where
    the node type even exists).  Their product is the expected contribution of
    this technique to the agent's training signal per episode step.

    Below 0.005 the technique is effectively invisible to the DRL agent: it almost
    never fires, never succeeds when it does, and contributes near-zero gradient
    signal — wasting an action slot in the policy network.
    """
    issues: list[str] = []
    THRESHOLD = 0.005

    for cat, entries in data.get("solvability_vulnerabilities", {}).items():
        for e in (entries or []):
            if not isinstance(e, dict):
                continue
            sr = e.get("success_rate")
            prob = e.get("probability")
            if not isinstance(sr, (int, float)) or not isinstance(prob, (int, float)):
                continue
            effective = float(sr) * float(prob)
            if effective < THRESHOLD:
                issues.append(
                    f"{fp.name}:solvability_vulnerabilities.{cat}.{e.get('name','?')}: "
                    f"success_rate={sr} × probability={prob} = {effective:.4f} < {THRESHOLD} "
                    f"— near-zero training contribution, effectively invisible to DRL agent"
                )
    return issues


# ---------------------------------------------------------------------------
# Goal-service exploitability check
# ---------------------------------------------------------------------------

def check_goal_service_exploitability(fp: Path, data: dict) -> list[str]:
    """Every is_goal service must be reachable by ≥1 live solvability technique.

    A goal service with no live technique targeting it and no credential granting
    access to it can never be captured by the agent — the terminal goal is
    permanently unachievable and the episode never terminates with reward.

    This check specifically targets is_goal services; dead_svc covers all
    services but emits a WARN.  A dead goal service is an ERROR.
    """
    issues: list[str] = []
    services = data.get("services", {})

    svc_props: dict[str, frozenset[str]] = {}
    for svc_name, cfg in services.items():
        if isinstance(cfg, dict):
            p: set[str] = set()
            for field in ("default_properties", "properties", "base_properties"):
                p |= set(cfg.get(field) or [])
            svc_props[svc_name] = frozenset(p)

    any_universal = False
    live_mps: list[frozenset[str]] = []
    for entries in data.get("solvability_vulnerabilities", {}).values():
        for e in (entries or []):
            if not isinstance(e, dict):
                continue
            mp = frozenset(e.get("match_properties") or [])
            if not mp:
                any_universal = True
            if not mp or any(mp <= props for props in svc_props.values()):
                live_mps.append(mp)  # only live techniques

    if any_universal:
        return []  # universal technique can target any service including goals

    # Credential targets (connect-only access — counts as reachable)
    cred_targets: set[str] = set()
    for cfg in services.values():
        if isinstance(cfg, dict):
            for cred in (cfg.get("credentials") or []):
                if isinstance(cred, dict):
                    t = cred.get("service") or cred.get("target_service", "")
                    if t:
                        cred_targets.add(t)

    for svc_name, cfg in services.items():
        if not isinstance(cfg, dict) or not cfg.get("is_goal"):
            continue
        if svc_name in cred_targets:
            continue
        props = svc_props.get(svc_name, frozenset())
        if not any(mp <= props for mp in live_mps):
            issues.append(
                f"{fp.name}:services.{svc_name}: is_goal service has no live "
                f"solvability technique targeting it and is not a credential target "
                f"— terminal goal is permanently unachievable, episode never rewards"
            )
    return issues


# ---------------------------------------------------------------------------
# Domain service reference integrity check
# ---------------------------------------------------------------------------

def check_domain_service_refs(fp: Path, data: dict) -> list[str]:
    """Every service name in domain mandatory_services, filler, and groups must
    exist as a key in the top-level services dict.

    Phase 2 resolves these names at runtime with a direct dict lookup.  A name
    that is missing from services causes an immediate KeyError crash with no
    useful diagnostic — the entire pipeline run fails and must be restarted.

    Checked fields per domain: mandatory_services, filler, groups[].service.
    """
    issues: list[str] = []
    known = set(data.get("services", {}).keys())

    for domain in (data.get("domains") or []):
        if not isinstance(domain, dict):
            continue
        dname = domain.get("name", "?")

        for svc in (domain.get("mandatory_services") or []):
            if isinstance(svc, str) and svc not in known:
                issues.append(
                    f"{fp.name}:domains.{dname}.mandatory_services: "
                    f"'{svc}' not in services — Phase 2 KeyError crash at runtime"
                )

        for svc in (domain.get("filler") or []):
            if isinstance(svc, str) and svc not in known:
                issues.append(
                    f"{fp.name}:domains.{dname}.filler: "
                    f"'{svc}' not in services — Phase 2 KeyError crash at runtime"
                )

        for group in (domain.get("groups") or []):
            if not isinstance(group, dict):
                continue
            svc = group.get("service", "")
            if svc and svc not in known:
                issues.append(
                    f"{fp.name}:domains.{dname}.groups.{group.get('name','?')}: "
                    f"service '{svc}' not in services — Phase 2 KeyError crash at runtime"
                )

    return issues


# ---------------------------------------------------------------------------
# Leaked-node feasibility check
# ---------------------------------------------------------------------------

def check_leaked_node_feasibility(fp: Path, data: dict) -> list[str]:
    """start_node.min_leaked_nodes must be achievable within the node range.

    Two invariants:
      1. min_leaked_nodes ≤ min_total_nodes — cannot leak more nodes than exist.
      2. leaked_node_coverage × min_total_nodes ≥ min_leaked_nodes — the coverage
         fraction must produce at least min_leaked_nodes nodes at minimum graph size.
         If not, Phase 2 cannot satisfy the minimum even in the best case.
      3. leaked_node_coverage ∈ [0.0, 1.0] — a fraction must be a fraction.

    Violations cause silent constraint failures in Phase 2: the generator loops
    indefinitely trying to satisfy an impossible leaked-node budget, or crashes
    with an assertion error.
    """
    issues: list[str] = []
    sn = data.get("start_node") or {}
    cfg = data.get("config") or {}

    min_leaked = sn.get("min_leaked_nodes")
    coverage   = sn.get("leaked_node_coverage")
    min_nodes  = cfg.get("min_total_nodes")

    if isinstance(coverage, (int, float)):
        if not (0.0 <= float(coverage) <= 1.0):
            issues.append(
                f"{fp.name}:start_node.leaked_node_coverage={coverage} "
                f"outside [0, 1] — must be a fraction"
            )

    if isinstance(min_leaked, (int, float)) and isinstance(min_nodes, (int, float)):
        if min_leaked > min_nodes:
            issues.append(
                f"{fp.name}:start_node.min_leaked_nodes={min_leaked} > "
                f"config.min_total_nodes={min_nodes} — "
                f"impossible to leak more nodes than exist in the graph"
            )
        if isinstance(coverage, (int, float)) and 0.0 <= float(coverage) <= 1.0:
            max_leakable = float(coverage) * float(min_nodes)
            if max_leakable < float(min_leaked):
                issues.append(
                    f"{fp.name}: leaked_node_coverage={coverage} × "
                    f"min_total_nodes={min_nodes} = {max_leakable:.1f} "
                    f"< min_leaked_nodes={min_leaked} — "
                    f"coverage fraction cannot satisfy minimum leaked-node budget"
                )

    return issues


# ---------------------------------------------------------------------------
# Domain group count bounds check
# ---------------------------------------------------------------------------

def check_domain_group_bounds(fp: Path, data: dict) -> list[str]:
    """Every domain group must have min_count ≤ max_count, both ≥ 0, max ≥ 1.

    Inverted bounds (min > max) put the Phase 2 generator into an infinite
    satisfaction loop — it tries to instantiate between N and M nodes where
    N > M, which is impossible.  max_count=0 means the group is never
    instantiated (silent dead group).
    """
    issues: list[str] = []
    for domain in (data.get("domains") or []):
        if not isinstance(domain, dict):
            continue
        dname = domain.get("name", "?")
        for group in (domain.get("groups") or []):
            if not isinstance(group, dict):
                continue
            gname = group.get("name", "?")
            mn = group.get("min_count")
            mx = group.get("max_count")
            if not isinstance(mn, (int, float)) or not isinstance(mx, (int, float)):
                continue
            if mn < 0 or mx < 0:
                issues.append(
                    f"{fp.name}:domains.{dname}.groups.{gname}: "
                    f"min_count={mn}, max_count={mx} — negative counts are nonsensical"
                )
            elif mx == 0:
                issues.append(
                    f"{fp.name}:domains.{dname}.groups.{gname}: "
                    f"max_count=0 — group never instantiated (silent dead group)"
                )
            elif mn > mx:
                issues.append(
                    f"{fp.name}:domains.{dname}.groups.{gname}: "
                    f"min_count={mn} > max_count={mx} — "
                    f"impossible range, Phase 2 generator enters infinite loop"
                )
    return issues


# ---------------------------------------------------------------------------
# Technique field bounds check
# ---------------------------------------------------------------------------

def check_technique_field_bounds(fp: Path, data: dict) -> list[str]:
    """Validate numeric fields on every solvability and constraint technique.

    Fields and invariants:
      probability     ∈ (0, 1]  — fraction of nodes this type is placed on;
                                  0 = never instantiated; >1 is not a fraction
      cost            > 0       — zero-cost exploits are always free to attempt,
                                  flooding the replay buffer and collapsing the
                                  DRL training signal; negative cost is nonsensical
      target_coverage ∈ [0, 1] — fraction of reachable services targeted;
                                  >1 means more targets than nodes exist → Phase 2 crash
      node_probability ∈ [0,1] — same semantics as probability on constraint vulns
    """
    issues: list[str] = []

    def _check(name: str, entry: dict, path: str) -> None:
        prob = entry.get("probability")
        if isinstance(prob, (int, float)):
            if prob <= 0 or prob > 1:
                issues.append(
                    f"{fp.name}:{path}.{name}: probability={prob} outside (0, 1] "
                    f"— node never instantiated (≤0) or invalid fraction (>1)"
                )

        cost = entry.get("cost")
        if isinstance(cost, (int, float)):
            if cost <= 0:
                issues.append(
                    f"{fp.name}:{path}.{name}: cost={cost} ≤ 0 "
                    f"— free/negative-cost exploit distorts DRL training signal"
                )

        tc = entry.get("target_coverage")
        if isinstance(tc, (int, float)) and not (0.0 <= float(tc) <= 1.0):
            issues.append(
                f"{fp.name}:{path}.{name}: target_coverage={tc} outside [0, 1] "
                f"— Phase 2 tries to target more nodes than exist"
            )

        np_ = entry.get("node_probability")
        if isinstance(np_, (int, float)) and not (0.0 <= float(np_) <= 1.0):
            issues.append(
                f"{fp.name}:{path}.{name}: node_probability={np_} outside [0, 1]"
            )

    for cat, entries in data.get("solvability_vulnerabilities", {}).items():
        for e in (entries or []):
            if isinstance(e, dict):
                _check(e.get("name", "?"), e, f"solvability_vulnerabilities.{cat}")

    for cname, entry in (data.get("constraint_vulnerabilities") or {}).items():
        if isinstance(entry, dict):
            _check(entry.get("name", cname), entry,
                   f"constraint_vulnerabilities.{cname}")

    return issues


# ---------------------------------------------------------------------------
# Node budget
# ---------------------------------------------------------------------------

def check_node_budget(fp: Path, data: dict) -> list[str]:
    """Domain group counts must be consistent with the scenario node budget.

    Two invariants:
      sum(min_count) ≤ max_total_nodes  — mandatory nodes fit in the budget;
                                          violated → Phase 2 env constructor crash
      sum(max_count) ≥ min_total_nodes  — groups can supply enough nodes to meet
                                          the minimum; violated → Phase 2 under-fills
    """
    issues: list[str] = []

    cfg = data.get("config") or {}
    min_nodes = cfg.get("min_total_nodes")
    max_nodes = cfg.get("max_total_nodes")
    if not isinstance(min_nodes, (int, float)) or not isinstance(max_nodes, (int, float)):
        return issues

    total_min = 0
    total_max = 0
    has_filler = False
    for domain in (data.get("domains") or []):
        if not isinstance(domain, dict):
            continue
        if domain.get("filler"):
            has_filler = True
        for grp in (domain.get("groups") or []):
            if not isinstance(grp, dict):
                continue
            mc = grp.get("min_count", 0)
            xc = grp.get("max_count", 0)
            if isinstance(mc, (int, float)):
                total_min += mc
            if isinstance(xc, (int, float)):
                total_max += xc

    if total_min == 0 and total_max == 0:
        return issues  # no domain groups — not applicable

    # Mandatory nodes must always fit within the total budget regardless of filler.
    if total_min > max_nodes:
        issues.append(
            f"{fp.name}: sum of domain group min_count={total_min} > "
            f"config.max_total_nodes={max_nodes} "
            f"— mandatory group nodes exceed budget; Phase 2 env constructor crashes"
        )

    # Without filler, groups are the only node source — must cover the minimum.
    if not has_filler and total_max < min_nodes:
        issues.append(
            f"{fp.name}: sum of domain group max_count={total_max} < "
            f"config.min_total_nodes={min_nodes} and no filler defined "
            f"— cannot reach minimum node count; environment is under-populated"
        )

    return issues


# ---------------------------------------------------------------------------
# Zero-target technique coverage
# ---------------------------------------------------------------------------

def check_zero_target_coverage(fp: Path, data: dict) -> list[str]:
    """Techniques whose target_coverage × max_total_nodes rounds to 0 are silent no-ops.

    CBS selects `floor(target_coverage × N)` targets. If that product < 1, the
    technique fires but picks nothing — identical to a dead technique but invisible
    to the dead_tech check because match_properties are perfectly valid.
    """
    issues: list[str] = []

    max_nodes = (data.get("config") or {}).get("max_total_nodes")
    if not isinstance(max_nodes, (int, float)) or max_nodes <= 0:
        return issues

    for cat, entries in data.get("solvability_vulnerabilities", {}).items():
        for e in (entries or []):
            if not isinstance(e, dict):
                continue
            tc = e.get("target_coverage")
            if not isinstance(tc, (int, float)):
                continue
            if tc * max_nodes < 1.0:
                issues.append(
                    f"{fp.name}:solvability_vulnerabilities.{cat}.{e.get('name','?')}: "
                    f"target_coverage={tc} × max_total_nodes={max_nodes} = "
                    f"{tc * max_nodes:.3f} < 1 "
                    f"— technique selects 0 targets; fires but does nothing"
                )

    return issues


# ---------------------------------------------------------------------------
# Goal service value
# ---------------------------------------------------------------------------

def check_goal_value_positive(fp: Path, data: dict) -> list[str]:
    """The terminal goal service must have value > 0.

    value=0 means the DRL agent receives zero reward for solving the scenario.
    The agent trains to convergence and learns nothing useful.
    """
    issues: list[str] = []
    for svc_name, cfg in data.get("services", {}).items():
        if not isinstance(cfg, dict) or not cfg.get("is_goal"):
            continue
        val = cfg.get("value")
        if isinstance(val, (int, float)) and val <= 0:
            issues.append(
                f"{fp.name}: is_goal service '{svc_name}' has value={val} ≤ 0 "
                f"— DRL agent receives zero terminal reward; scenario is untrainable"
            )

    return issues


# ---------------------------------------------------------------------------
# Credential chain integrity
# ---------------------------------------------------------------------------

def check_credential_chain_integrity(fp: Path, data: dict) -> list[str]:
    """LEAK_KNOWN_CREDENTIALS constraints must form a viable credential chain.

    Three invariants:
      (a) source and target are valid group names that map to known services
      (b) the source service has ≥1 live solvability technique — otherwise the
          attacker can never exploit it to trigger the credential leak
      (c) the target service has ≥1 live technique OR is is_goal — otherwise the
          leaked credentials are never redeemed (dead credential)

    A dead-credential situation means the attacker acquires creds that unlock
    nothing, so a required BFS hop is silently missing and the scenario is
    unsolvable despite looking correct on paper.
    """
    issues: list[str] = []

    # ── build group_name → service_name map ───────────────────────────────────
    group_to_svc: dict[str, str] = {}
    for domain in (data.get("domains") or []):
        if not isinstance(domain, dict):
            continue
        for grp in (domain.get("groups") or []):
            if isinstance(grp, dict) and grp.get("name") and grp.get("service"):
                group_to_svc[grp["name"]] = grp["service"]

    if not group_to_svc:
        return issues  # no domains — check not applicable

    services: dict[str, dict] = data.get("services", {})

    # ── build live-technique set: services that have ≥1 live solvability tech ─
    svc_props: dict[str, frozenset[str]] = {}
    for svc_name, cfg in services.items():
        if isinstance(cfg, dict):
            p: set[str] = set()
            for field in ("default_properties", "properties", "base_properties"):
                p |= set(cfg.get(field) or [])
            svc_props[svc_name] = frozenset(p)

    live_svc: set[str] = set()
    for entries in data.get("solvability_vulnerabilities", {}).values():
        for e in (entries or []):
            if not isinstance(e, dict):
                continue
            mp = frozenset(e.get("match_properties") or [])
            is_live = not mp or any(mp <= props for props in svc_props.values())
            if not is_live:
                continue
            # which services does this technique target?
            for svc_name, props in svc_props.items():
                if not mp or mp <= props:
                    live_svc.add(svc_name)

    goal_svcs = {k for k, v in services.items() if isinstance(v, dict) and v.get("is_goal")}

    # ── scan LEAK_KNOWN_CREDENTIALS constraints ────────────────────────────────
    for block in (data.get("inter_domain_constraints") or []):
        if not isinstance(block, dict):
            continue
        src_dom = block.get("source_domain", "?")
        tgt_dom = block.get("target_domain", "?")
        for c in (block.get("constraints") or []):
            if not isinstance(c, dict) or c.get("relation") != "LEAK_KNOWN_CREDENTIALS":
                continue
            src_grp = c.get("source", "")
            tgt_grp = c.get("target", "")
            edge    = f"{src_grp} → {tgt_grp} ({src_dom} → {tgt_dom})"

            # (a) group name resolution
            src_svc = group_to_svc.get(src_grp)
            tgt_svc = group_to_svc.get(tgt_grp)

            if src_svc is None:
                issues.append(
                    f"{fp.name}: LEAK_KNOWN_CREDENTIALS {edge}: "
                    f"source group '{src_grp}' not found in any domain's groups"
                )
                continue
            if src_svc not in services:
                issues.append(
                    f"{fp.name}: LEAK_KNOWN_CREDENTIALS {edge}: "
                    f"source group '{src_grp}' resolves to service '{src_svc}' "
                    f"which is not defined in services"
                )
                continue

            if tgt_svc is None:
                issues.append(
                    f"{fp.name}: LEAK_KNOWN_CREDENTIALS {edge}: "
                    f"target group '{tgt_grp}' not found in any domain's groups"
                )
                continue
            if tgt_svc not in services:
                issues.append(
                    f"{fp.name}: LEAK_KNOWN_CREDENTIALS {edge}: "
                    f"target group '{tgt_grp}' resolves to service '{tgt_svc}' "
                    f"which is not defined in services"
                )
                continue

            # (b) source must be exploitable
            if src_svc not in live_svc:
                issues.append(
                    f"{fp.name}: LEAK_KNOWN_CREDENTIALS {edge}: "
                    f"source service '{src_svc}' has no live solvability technique "
                    f"— credential leak can never fire; BFS chain broken"
                )

            # (c) target must be useful
            if tgt_svc not in live_svc and tgt_svc not in goal_svcs:
                issues.append(
                    f"{fp.name}: LEAK_KNOWN_CREDENTIALS {edge}: "
                    f"target service '{tgt_svc}' has no live technique and is not is_goal "
                    f"— leaked credentials are never redeemed (dead credential)"
                )

    return issues


# ---------------------------------------------------------------------------
# Intermediate-goals attack-flow membership check
# ---------------------------------------------------------------------------

def check_intermediate_goals_on_path(fp: Path, data: dict) -> list[str]:
    """Every intermediate_goal service must be reachable via attack_flow.

    GoalNormalizer may select any intermediate_goal as an episode goal.
    If that service is not in the attack_flow graph the Phase 2 constraint
    engine never creates edges to it — the agent cannot reach it and the
    episode either never terminates or terminates without that goal's reward.

    Exemption: services that are LEAK_KNOWN_CREDENTIALS targets are reachable
    via credential connect-action without an explicit attack_flow edge.

    Two sub-checks:
      (a) service appears as a source_pattern or target in attack_flow
      (b) service is BFS-reachable from attack_flow roots
    """
    issues: list[str] = []
    meta = data.get("metadata") or {}
    af   = data.get("attack_flow") or []
    if not isinstance(af, list) or not af:
        return []

    intermediate = [
        g.get("name", "")
        for g in (meta.get("intermediate_goals") or [])
        if isinstance(g, dict) and g.get("name")
    ]
    if not intermediate:
        return []

    # Build attack_flow graph + collect all referenced node patterns
    graph: dict[str, list[str]] = {}
    all_targets: set[str] = set()
    af_nodes: set[str] = set()
    for entry in af:
        if not isinstance(entry, dict):
            continue
        src = entry.get("source_pattern", "")
        targets = entry.get("targets", []) or []
        graph.setdefault(src, []).extend(targets)
        all_targets |= set(targets)
        af_nodes.add(src)
        af_nodes.update(targets)
        for t in targets:
            graph.setdefault(t, [])

    roots = set(graph) - all_targets
    if not roots:
        return []

    # BFS from roots to find all reachable nodes
    reachable: set[str] = set(roots)
    queue = list(roots)
    while queue:
        node = queue.pop(0)
        for nb in graph.get(node, []):
            if nb not in reachable:
                reachable.add(nb)
                queue.append(nb)

    # Build group_name → service_name map for LEAK_KNOWN_CREDENTIALS exemption
    grp_to_svc: dict[str, str] = {}
    for dom in (data.get("domains") or []):
        if not isinstance(dom, dict):
            continue
        for grp in (dom.get("groups") or []):
            if isinstance(grp, dict) and grp.get("name") and grp.get("service"):
                grp_to_svc[grp["name"]] = grp["service"]

    cred_target_svcs: set[str] = set()
    for block in (data.get("inter_domain_constraints") or []):
        if not isinstance(block, dict):
            continue
        for c in (block.get("constraints") or []):
            if isinstance(c, dict) and c.get("relation") == "LEAK_KNOWN_CREDENTIALS":
                tgt_grp = c.get("target", "")
                tgt_svc = grp_to_svc.get(tgt_grp, tgt_grp)
                cred_target_svcs.add(tgt_svc)

    for svc in intermediate:
        # Exempt credential-chain targets
        if svc in cred_target_svcs:
            continue
        # (a) membership check
        in_af = any(_af_matches(svc, n) or _af_matches(n, svc) for n in af_nodes)
        if not in_af:
            issues.append(
                f"{fp.name}: intermediate_goal '{svc}' not referenced in attack_flow "
                f"— Phase 2 never creates edges to it; agent cannot reach this milestone"
            )
            continue  # skip BFS check — already flagged
        # (b) BFS reachability
        in_reach = any(
            _af_matches(svc, n) or _af_matches(n, svc) for n in reachable
        )
        if not in_reach:
            issues.append(
                f"{fp.name}: intermediate_goal '{svc}' is in attack_flow but not "
                f"BFS-reachable from roots {sorted(roots)} — disconnected from attack path"
            )

    return issues


# ---------------------------------------------------------------------------
# Intermediate-goal value and num_goals feasibility checks
# ---------------------------------------------------------------------------

def check_intermediate_goal_values(fp: Path, data: dict) -> list[str]:
    """Every intermediate_goal must have value > 0.

    A zero or negative value gives the DRL agent no reward for reaching that
    milestone. GoalNormalizer may still select it as an episode goal (it picks
    from all valued services by default), but the agent learns nothing from
    capturing it — the milestone is decorative.
    """
    issues: list[str] = []
    for ig in ((data.get("metadata") or {}).get("intermediate_goals") or []):
        if not isinstance(ig, dict):
            continue
        val  = ig.get("value")
        name = ig.get("name", "?")
        if isinstance(val, (int, float)) and val <= 0:
            issues.append(
                f"{fp.name}:metadata.intermediate_goals.{name}: "
                f"value={val} ≤ 0 — agent gets no reward for reaching this "
                f"milestone; GoalNormalizer selection is wasted"
            )
    return issues


def check_num_goals_feasibility(fp: Path, data: dict) -> list[str]:
    """num_goals must not exceed the count of services with value > 0.

    GoalNormalizer selects exactly num_goals goal nodes per episode from all
    services that have a positive value.  If fewer services qualify than
    num_goals, GoalNormalizer cannot form a valid goal set and either crashes
    or silently produces a degenerate episode with repeated goals.
    """
    num_goals = (data.get("config") or {}).get("goal_config", {}).get("num_goals")
    if not isinstance(num_goals, (int, float)):
        return []

    valued = sum(
        1 for cfg in data.get("services", {}).values()
        if isinstance(cfg, dict) and isinstance(cfg.get("value"), (int, float))
        and cfg.get("value", 0) > 0
    )
    if valued < int(num_goals):
        return [
            f"{fp.name}:config.goal_config.num_goals={num_goals} > "
            f"{valued} services with value > 0 — GoalNormalizer cannot "
            f"form a valid {num_goals}-goal episode; crash or degenerate output"
        ]
    return []


# ---------------------------------------------------------------------------
# Domain constraint group-name resolution check
# ---------------------------------------------------------------------------

def check_domain_constraint_groups(fp: Path, data: dict) -> list[str]:
    """Every group name referenced in domain constraints must exist in that domain.

    Intra-domain constraints (domain.constraints):
      - source must be a group name in that domain's groups list
      - MUST_CONNECT target must also be a group name in the same domain
      - MUST_HAVE target is a property name — not checked here

    Inter-domain constraints (inter_domain_constraints):
      - source must be a group name in source_domain
      - target must be a group name in target_domain

    Typos (AdminWorkstation vs AdminWorkstations) are silently ignored by Phase 2:
    the constraint never fires, so no connection or credential leak is created.
    """
    issues: list[str] = []

    # Build domain → frozenset of group names
    domain_groups: dict[str, frozenset[str]] = {}
    for dom in (data.get("domains") or []):
        if not isinstance(dom, dict):
            continue
        dname = dom.get("name", "")
        if not dname:
            continue
        domain_groups[dname] = frozenset(
            g["name"] for g in (dom.get("groups") or [])
            if isinstance(g, dict) and g.get("name")
        )

    # ── Intra-domain constraints ───────────────────────────────────────────────
    for dom in (data.get("domains") or []):
        if not isinstance(dom, dict):
            continue
        dname = dom.get("name", "?")
        groups = domain_groups.get(dname, frozenset())
        if not groups:
            continue

        for c in (dom.get("constraints") or []):
            if not isinstance(c, dict):
                continue
            relation = c.get("relation", "")
            src = c.get("source", "")
            tgt = c.get("target", "")

            if src and src not in groups:
                issues.append(
                    f"{fp.name}:domains.{dname}.constraints: "
                    f"source '{src}' not a group in this domain "
                    f"(groups: {sorted(groups)}) — constraint silently ignored"
                )
            # Only check target as group for MUST_CONNECT; MUST_HAVE target is a property
            if relation == "MUST_CONNECT" and tgt and tgt not in groups:
                issues.append(
                    f"{fp.name}:domains.{dname}.constraints: "
                    f"MUST_CONNECT target '{tgt}' not a group in this domain "
                    f"(groups: {sorted(groups)}) — connection never created"
                )

    # ── Inter-domain constraints ───────────────────────────────────────────────
    for block in (data.get("inter_domain_constraints") or []):
        if not isinstance(block, dict):
            continue
        src_dom = block.get("source_domain", "?")
        tgt_dom = block.get("target_domain", "?")
        src_groups = domain_groups.get(src_dom, frozenset())
        tgt_groups = domain_groups.get(tgt_dom, frozenset())

        for c in (block.get("constraints") or []):
            if not isinstance(c, dict):
                continue
            src = c.get("source", "")
            tgt = c.get("target", "")

            if src and src_groups and src not in src_groups:
                issues.append(
                    f"{fp.name}:inter_domain_constraints "
                    f"({src_dom}→{tgt_dom}): source '{src}' not a group "
                    f"in '{src_dom}' (groups: {sorted(src_groups)}) "
                    f"— constraint silently ignored"
                )
            if tgt and tgt_groups and tgt not in tgt_groups:
                issues.append(
                    f"{fp.name}:inter_domain_constraints "
                    f"({src_dom}→{tgt_dom}): target '{tgt}' not a group "
                    f"in '{tgt_dom}' (groups: {sorted(tgt_groups)}) "
                    f"— constraint silently ignored"
                )

    return issues


# ---------------------------------------------------------------------------
# Mutually exclusive / contradictory property combinations
# ---------------------------------------------------------------------------

# Groups where a service may have at most ONE member.
_MUTEX_GROUPS: list[tuple[str, frozenset[str]]] = [
    ("OS family", frozenset({"Windows", "Linux", "MacOS", "Unix"})),
    ("Windows version", frozenset({
        "WinXP", "Win7", "Win8", "Win10", "Win11",
        "Win2003", "Win2008", "Win2012", "Win2016", "Win2019", "Win2022",
    })),
    ("Linux distro", frozenset({"Ubuntu", "CentOS", "Debian", "Alpine", "Kali", "RedHat"})),
    # Device brand/product-line identifiers — a node can only BE one product.
    # Note: PANOS / FortiOS / GlobalProtect are firmware tags that *complement*
    # their vendor tag (PaloAlto+PANOS is correct), so they are excluded here.
    ("network device vendor", frozenset({
        "CiscoIOS", "CiscoNXOS", "CiscoASA", "CiscoFirepower", "CiscoSD_WAN",
        "JuniperJunos",
        "FortiGate",
        "PaloAlto",
        "Mikrotik",
        "F5BIGIP",
    })),
]

# Pairs (a, b) that cannot coexist on the same service.
# Expressed as (prop_a, prop_b, reason).
_CONFLICT_PAIRS: list[tuple[str, str, str]] = [
    # Windows-only server roles cannot run on Linux
    ("Linux", "IISServer",   "IIS is a Windows-only web server"),
    ("Linux", "HyperVHost",  "Hyper-V hypervisor requires Windows Server"),
    ("Linux", "ADCS",        "AD Certificate Services is Windows-only"),
    ("Linux", "ADFS",        "AD Federation Services is Windows-only"),
    ("Linux", "MSMQServer",  "MSMQ is a Windows-only message queue"),
    # Windows OS tag with Linux distro (caught by mutex group too, but explicit is clearer)
    ("Windows", "Ubuntu",   "Ubuntu is a Linux distro"),
    ("Windows", "CentOS",   "CentOS is a Linux distro"),
    ("Windows", "Debian",   "Debian is a Linux distro"),
    ("Windows", "Alpine",   "Alpine is a Linux distro"),
    ("Windows", "Kali",     "Kali is a Linux distro"),
    ("Windows", "RedHat",   "Red Hat is a Linux distro"),
    # Endpoint vs infrastructure role conflicts
    ("Workstation",    "DomainController", "a workstation cannot also be a domain controller"),
    ("Workstation",    "NetworkDevice",    "a workstation is not a network infrastructure device"),
    ("Workstation",    "Firewall",         "a workstation is not a firewall"),
    ("DomainController", "NetworkDevice",  "a DC is a server, not a network device"),
]


def check_property_conflicts(fp: Path, data: dict) -> list[str]:
    """Detect mutually exclusive or physically impossible property combinations.

    Scans default_properties on every service against:
      _MUTEX_GROUPS  — sets where ≤1 member is allowed (e.g. OS family)
      _CONFLICT_PAIRS — explicit forbidden pairs (e.g. Linux + IISServer)

    These combinations cannot occur on real hardware and signal LLM hallucination
    or copy-paste errors. CBS does not reject them — it silently runs with the
    contradictory properties, which corrupts match_properties resolution.
    """
    issues: list[str] = []

    for svc_name, cfg in data.get("services", {}).items():
        if not isinstance(cfg, dict):
            continue
        props = frozenset(cfg.get("default_properties") or [])
        if not props:
            continue

        # Mutex group check
        for group_name, group_set in _MUTEX_GROUPS:
            overlap = props & group_set
            if len(overlap) > 1:
                issues.append(
                    f"{fp.name}: service '{svc_name}' has conflicting {group_name} "
                    f"properties {sorted(overlap)} — pick exactly one"
                )

        # Conflict pair check
        for prop_a, prop_b, reason in _CONFLICT_PAIRS:
            if prop_a in props and prop_b in props:
                issues.append(
                    f"{fp.name}: service '{svc_name}' has contradictory properties "
                    f"'{prop_a}' + '{prop_b}' — {reason}"
                )

    return issues


# ---------------------------------------------------------------------------
# Metadata consistency
# ---------------------------------------------------------------------------

_AGENT_PREFIX: dict[str, list[str]] = {
    "S_Network":  ["snet_"],
    "S_Linux":    ["slin_"],
    "S_Windows":  ["swin_"],
    "S_Identity": ["sid_"],
    "S_Lateral":  ["slat_"],
    "Meta":       ["meta_", "specialist_"],  # specialist_ is the multi-domain variant
}


def check_metadata_consistency(fp: Path, data: dict) -> list[str]:
    """Cross-field consistency checks on metadata and related top-level fields.

    Checks:
      (1) metadata.terminal_goal matches the service name with is_goal: true
      (2) start_node.service exists in the services dict
      (3) metadata.agent matches the filename prefix
      (4) entry_points[].node exists in the source domain's groups
      (5) inter_domain_constraints source/target domains exist in domains list
      (6) attack_flow leaf nodes (no outgoing edges) are the is_goal service
      (7) metadata.node_range agrees with config.min/max_total_nodes
    """
    issues: list[str] = []
    meta     = data.get("metadata") or {}
    services = data.get("services") or {}
    cfg      = data.get("config") or {}
    domains  = data.get("domains") or []

    # ── (1) terminal_goal ↔ is_goal service ───────────────────────────────────
    terminal_goal = meta.get("terminal_goal", "")
    is_goal_svcs  = [k for k, v in services.items()
                     if isinstance(v, dict) and v.get("is_goal")]
    if terminal_goal and is_goal_svcs and terminal_goal not in is_goal_svcs:
        issues.append(
            f"{fp.name}: metadata.terminal_goal='{terminal_goal}' does not match "
            f"is_goal service(s) {is_goal_svcs} "
            f"— Phase 2 BFS targets wrong node; reward signal is disconnected"
        )

    # ── (2) start_node.service in services ────────────────────────────────────
    sn_svc = (data.get("start_node") or {}).get("service", "")
    if sn_svc and sn_svc not in services:
        issues.append(
            f"{fp.name}: start_node.service='{sn_svc}' not found in services dict "
            f"— CBS env constructor crashes at runtime"
        )

    # ── (3) agent codename matches filename prefix ────────────────────────────
    agent = meta.get("agent", "")
    if agent:
        valid_prefixes = _AGENT_PREFIX.get(agent)
        if valid_prefixes and not any(fp.name.startswith(p) for p in valid_prefixes):
            issues.append(
                f"{fp.name}: metadata.agent='{agent}' expects filename prefix "
                f"one of {valid_prefixes} but file is '{fp.name}' "
                f"— Phase 2 loads wrong specialist spec and coverage report"
            )

    # ── (4) entry_points nodes exist in source domain groups ─────────────────
    domain_groups: dict[str, set[str]] = {}
    for dom in domains:
        if isinstance(dom, dict) and dom.get("name"):
            domain_groups[dom["name"]] = {
                g["name"] for g in (dom.get("groups") or [])
                if isinstance(g, dict) and g.get("name")
            }

    for ep in (data.get("entry_points") or []):
        if not isinstance(ep, dict):
            continue
        ep_dom  = ep.get("domain", "")
        ep_node = ep.get("node", "")
        if not ep_dom or not ep_node:
            continue
        grp_names = domain_groups.get(ep_dom)
        if grp_names is None:
            issues.append(
                f"{fp.name}: entry_points domain='{ep_dom}' not found in domains list "
                f"— attacker entry is wired to a nonexistent domain"
            )
        elif ep_node not in grp_names:
            issues.append(
                f"{fp.name}: entry_points node='{ep_node}' not in domain '{ep_dom}' groups "
                f"({sorted(grp_names)}) — attacker entry is wired to nothing"
            )

    # ── (5) inter_domain_constraints domains exist ────────────────────────────
    known_domains = set(domain_groups.keys())
    for idc in (data.get("inter_domain_constraints") or []):
        if not isinstance(idc, dict):
            continue
        for field in ("source_domain", "target_domain"):
            dom_name = idc.get(field, "")
            if dom_name and known_domains and dom_name not in known_domains:
                issues.append(
                    f"{fp.name}: inter_domain_constraints.{field}='{dom_name}' "
                    f"not found in domains list — constraint silently ignored by CBS"
                )

    # ── (6) attack_flow leaf nodes should be is_goal service ─────────────────
    af = data.get("attack_flow") or {}
    if isinstance(af, dict) and is_goal_svcs:
        # Collect all nodes that appear as sources and as targets
        sources: set[str] = set(af.keys())
        targets: set[str] = set()
        for successors in af.values():
            for s in (successors or []):
                if isinstance(s, str):
                    targets.add(s)
        # Leaf = source with no outgoing edges or node only in targets
        all_nodes = sources | targets
        leaves = {n for n in all_nodes if not af.get(n)}
        non_goal_leaves = leaves - set(is_goal_svcs)
        if non_goal_leaves and leaves:
            issues.append(
                f"{fp.name}: attack_flow leaf node(s) {sorted(non_goal_leaves)} "
                f"are not is_goal services {is_goal_svcs} "
                f"— attack chain terminates on unrewarded node; episode never completes"
            )

    # ── (7) metadata.node_range vs config ────────────────────────────────────
    nr = meta.get("node_range")
    cfg_min = cfg.get("min_total_nodes")
    cfg_max = cfg.get("max_total_nodes")
    if isinstance(nr, (list, tuple)) and len(nr) == 2:
        meta_min, meta_max = nr[0], nr[1]
        if isinstance(cfg_min, (int, float)) and meta_min != cfg_min:
            issues.append(
                f"{fp.name}: metadata.node_range[0]={meta_min} ≠ "
                f"config.min_total_nodes={cfg_min} "
                f"— reports show wrong size; Phase 2 uses config values"
            )
        if isinstance(cfg_max, (int, float)) and meta_max != cfg_max:
            issues.append(
                f"{fp.name}: metadata.node_range[1]={meta_max} ≠ "
                f"config.max_total_nodes={cfg_max} "
                f"— reports show wrong size; Phase 2 uses config values"
            )

    return issues


# ---------------------------------------------------------------------------
# Structural sanity (per-file)
# ---------------------------------------------------------------------------

def check_structural_sanity(fp: Path, data: dict) -> list[str]:
    """Invariants that must hold for the CBS engine to produce a valid episode.

    Checks:
      entry_node_count ≥ 1       — attacker needs a starting point
      num_goals ≥ 1              — GoalNormalizer must select at least one goal
      at most 1 is_goal service  — multiple goals make reward signal ambiguous
      intermediate_goal.value < is_goal.value — checkpoints must be worth less
                                                 than the terminal; otherwise agent
                                                 stops at a checkpoint
    """
    issues: list[str] = []
    sn  = data.get("start_node") or {}
    cfg = data.get("config") or {}

    enc = sn.get("entry_node_count")
    if isinstance(enc, (int, float)) and enc < 1:
        issues.append(
            f"{fp.name}:start_node.entry_node_count={enc} < 1 "
            f"— no entry node instantiated; attacker has no starting point"
        )

    ng = (cfg.get("goal_config") or {}).get("num_goals")
    if isinstance(ng, (int, float)) and ng < 1:
        issues.append(
            f"{fp.name}:config.goal_config.num_goals={ng} < 1 "
            f"— GoalNormalizer selects nothing; episode never terminates with reward"
        )

    is_goal_svcs = [
        k for k, v in data.get("services", {}).items()
        if isinstance(v, dict) and v.get("is_goal")
    ]
    if len(is_goal_svcs) > 1:
        issues.append(
            f"{fp.name}: multiple is_goal services {is_goal_svcs} "
            f"— GoalNormalizer selection undefined; DRL reward signal ambiguous"
        )

    if is_goal_svcs:
        max_goal_val = max(
            data["services"][k].get("value", 0)
            for k in is_goal_svcs
            if isinstance(data["services"][k], dict)
        )
        for ig in ((data.get("metadata") or {}).get("intermediate_goals") or []):
            if isinstance(ig, dict):
                iv    = ig.get("value", 0)
                iname = ig.get("name", "?")
                if isinstance(iv, (int, float)) and iv >= max_goal_val:
                    issues.append(
                        f"{fp.name}:metadata.intermediate_goals.{iname}: "
                        f"value={iv} ≥ is_goal value={max_goal_val} "
                        f"— agent stops at checkpoint instead of terminal goal"
                    )

    return issues


# ---------------------------------------------------------------------------
# Dataset-level scenario_id uniqueness
# ---------------------------------------------------------------------------

def check_scenario_id_uniqueness(file_data: list[tuple[Path, dict]]) -> list[str]:
    """Across all configs, scenario_id must be globally unique.

    Duplicates cause Phase 2 output directories to collide and overwrite each
    other silently — the later file wins and the earlier dataset is lost.
    """
    seen: dict[str, Path] = {}
    issues: list[str] = []
    for fp, raw in file_data:
        sid = (raw.get("metadata") or {}).get("scenario_id", "")
        if not sid:
            continue
        if sid in seen:
            issues.append(
                f"Duplicate scenario_id '{sid}': "
                f"{seen[sid].name} and {fp.name}"
            )
        else:
            seen[sid] = fp
    return issues


# ---------------------------------------------------------------------------
# Dataset-level cross-size consistency check
# ---------------------------------------------------------------------------

def check_cross_size_consistency(file_data: list[tuple[Path, dict]]) -> list[str]:
    """Within a scenario family, all size variants must have identical structure.

    The 4 size tiers (small/medium/large/xlarge) of a family differ only in
    node counts (min_count/max_count, min/max_total_nodes).  Service property
    sets, technique rosters, and attack_flow topology must be identical across
    tiers — otherwise:
      - Techniques present in xlarge but absent in small → DRL policy trained on
        small cannot exploit those vulnerabilities in xlarge (transfer failure)
      - Service properties differ → match_properties fire on one tier but not
        another → technique behaves differently per tier, making cross-tier
        generalisation claims invalid

    Compares per-family across variants:
      (a) services[*].default_properties  — per-service property set
      (b) solvability_vulnerabilities technique names per category
      (c) attack_flow topology (source_pattern + targets)
    """
    issues: list[str] = []
    _SIZE_RE = re.compile(r'_(small|medium|large|xlarge)_')

    # Group by family key (filename with size token removed)
    families: dict[str, list[tuple[Path, dict]]] = {}
    for fp, data in file_data:
        family = _SIZE_RE.sub('_', fp.stem)
        families.setdefault(family, []).append((fp, data))

    for family, variants in families.items():
        if len(variants) < 2:
            continue
        variants_sorted = sorted(variants, key=lambda x: x[0].name)
        ref_fp, ref_data = variants_sorted[0]

        ref_services = ref_data.get("services", {})
        ref_sv       = ref_data.get("solvability_vulnerabilities", {})
        ref_af       = ref_data.get("attack_flow", [])

        # Normalise attack_flow to comparable form: list of (src, sorted_targets)
        def _af_key(af: list) -> list[tuple[str, tuple]]:
            return sorted(
                (e.get("source_pattern", ""), tuple(sorted(e.get("targets", []) or [])))
                for e in af if isinstance(e, dict)
            )
        ref_af_key = _af_key(ref_af)

        for fp, data in variants_sorted[1:]:
            label = f"[{ref_fp.stem} vs {fp.stem}]"
            services = data.get("services", {})
            sv       = data.get("solvability_vulnerabilities", {})
            af       = data.get("attack_flow", [])

            # (a) service default_properties
            all_svcs = sorted(set(ref_services) | set(services))
            for svc_name in all_svcs:
                ref_cfg = ref_services.get(svc_name)
                cfg     = services.get(svc_name)
                if ref_cfg is None:
                    issues.append(
                        f"{label}: service '{svc_name}' present in "
                        f"{fp.stem} but missing in reference {ref_fp.stem}"
                    )
                    continue
                if cfg is None:
                    issues.append(
                        f"{label}: service '{svc_name}' present in "
                        f"reference {ref_fp.stem} but missing in {fp.stem}"
                    )
                    continue
                ref_props = sorted(ref_cfg.get("default_properties") or [])
                props     = sorted(cfg.get("default_properties") or [])
                if ref_props != props:
                    issues.append(
                        f"{label}: service '{svc_name}' default_properties differ — "
                        f"{ref_fp.stem}: {ref_props} vs {fp.stem}: {props} "
                        f"— match_properties will fire differently per tier"
                    )

            # (b) solvability technique names per category
            all_cats = sorted(set(ref_sv) | set(sv))
            for cat in all_cats:
                ref_names = sorted(
                    e.get("name", "") for e in (ref_sv.get(cat) or [])
                    if isinstance(e, dict)
                )
                names = sorted(
                    e.get("name", "") for e in (sv.get(cat) or [])
                    if isinstance(e, dict)
                )
                only_ref  = sorted(set(ref_names) - set(names))
                only_here = sorted(set(names) - set(ref_names))
                if only_ref:
                    issues.append(
                        f"{label}:solvability_vulnerabilities.{cat}: "
                        f"techniques {only_ref} in {ref_fp.stem} missing from {fp.stem} "
                        f"— cross-tier policy transfer will fail for these exploits"
                    )
                if only_here:
                    issues.append(
                        f"{label}:solvability_vulnerabilities.{cat}: "
                        f"techniques {only_here} in {fp.stem} missing from {ref_fp.stem} "
                        f"— cross-tier policy transfer will fail for these exploits"
                    )

            # (c) attack_flow topology
            af_key = _af_key(af)
            if af_key != ref_af_key:
                ref_edges = set(ref_af_key)
                edges     = set(af_key)
                for edge in sorted(ref_edges - edges):
                    issues.append(
                        f"{label}:attack_flow: edge {edge[0]}→{list(edge[1])} "
                        f"in {ref_fp.stem} missing from {fp.stem} "
                        f"— attack topology differs between size tiers"
                    )
                for edge in sorted(edges - ref_edges):
                    issues.append(
                        f"{label}:attack_flow: edge {edge[0]}→{list(edge[1])} "
                        f"in {fp.stem} missing from {ref_fp.stem} "
                        f"— attack topology differs between size tiers"
                    )

    return issues


# ---------------------------------------------------------------------------
# Dataset-level specialist spec coverage
# ---------------------------------------------------------------------------

_SPEC_FILES: dict[str, str] = {
    "s_network":  "s_network.md",
    "s_linux":    "s_linux.md",
    "s_windows":  "s_windows.md",
    "s_identity": "s_identity.md",
    "s_lateral":  "s_lateral.md",
}
_SPECS_DIR = Path(__file__).resolve().parent.parent / "prompts" / "reference" / "agents"


def _parse_spec_actions(spec_path: Path) -> dict[str, list[str]]:
    """Parse Local Vulnerabilities / Remote Vulnerabilities / Connect Ports from a spec."""
    import re as _re
    local: list[str] = []
    remote: list[str] = []
    ports: list[str] = []
    section: str | None = None
    for line in spec_path.read_text().splitlines():
        if "Local Vulnerabilities" in line:
            section = "local"
        elif "Remote Vulnerabilities" in line:
            section = "remote"
        elif "Connect Ports" in line:
            section = "ports"
        elif line.startswith("###"):
            section = None
        if section == "local":
            for m in _re.findall(r"`(Solvability\.[A-Za-z0-9_]+)`", line):
                if m not in local:
                    local.append(m)
        elif section == "remote":
            for m in _re.findall(r"`(Solvability\.[A-Za-z0-9_]+)`", line):
                if m not in remote:
                    remote.append(m)
        elif section == "ports":
            for m in _re.findall(r"`([A-Z][A-Za-z0-9]+)`", line):
                if m not in ports:
                    ports.append(m)
    return {"local": local, "remote": remote, "ports": ports}


def compute_spec_coverage(config_paths: list[Path]) -> dict[str, dict]:
    """Compute per-specialist action coverage across a set of scenario files.

    Checks three action classes per specialist spec:
      - LOCAL vulnerabilities  (Solvability.* with type LOCAL)
      - REMOTE vulnerabilities (Solvability.* with type REMOTE)
      - Connect ports          (port identifiers in the spec's port table)

    Only LIVE techniques count: a technique in a config file is live only if
    its match_properties can be satisfied by ≥1 service in that file.
    Raw string presence is not enough — dead techniques are excluded.

    Returns a dict keyed by specialist name with per-action-class results.
    """
    # ── Step 1: collect live techniques + ports from all config files ─────────
    live_techs: set[str] = set()   # Solvability.* names that are live in ≥1 file
    all_ports:  set[str] = set()   # port tokens observed across all files

    for fp in config_paths:
        try:
            data = yaml.safe_load(fp.read_text()) or {}
        except Exception:
            continue

        # Build per-service property sets
        svc_props: dict[str, frozenset[str]] = {}
        for svc_name, cfg in data.get("services", {}).items():
            if isinstance(cfg, dict):
                p: set[str] = set()
                for field in ("default_properties", "properties", "base_properties"):
                    p |= set(cfg.get(field) or [])
                svc_props[svc_name] = frozenset(p)

        # Live techniques in solvability_vulnerabilities
        for entries in data.get("solvability_vulnerabilities", {}).values():
            for e in (entries or []):
                if not isinstance(e, dict):
                    continue
                name = e.get("name", "")
                if not name.startswith("Solvability."):
                    continue
                mp = frozenset(e.get("match_properties") or [])
                is_live = not mp or any(mp <= props for props in svc_props.values())
                if is_live:
                    live_techs.add(name)

        # Ports used on services and in identifiers
        for cfg in data.get("services", {}).values():
            if isinstance(cfg, dict):
                for pf in ("port", "default_entry_port"):
                    p = cfg.get(pf)
                    if isinstance(p, str):
                        all_ports.add(p)
                for pf in ("standard_ports", "preferred_entry_ports", "standard_ports_extra"):
                    for p in (cfg.get(pf) or []):
                        if isinstance(p, str):
                            all_ports.add(p)
        for p in (data.get("identifiers", {}).get("standard_ports") or []):
            if isinstance(p, str):
                all_ports.add(p)

    # ── Step 2: per-specialist gap analysis ───────────────────────────────────
    results: dict[str, dict] = {}
    for spec_key, spec_file in _SPEC_FILES.items():
        spec_path = _SPECS_DIR / spec_file
        if not spec_path.exists():
            continue
        actions = _parse_spec_actions(spec_path)
        local_def  = set(actions["local"])
        remote_def = set(actions["remote"])
        ports_def  = set(actions["ports"])

        local_live  = local_def  & live_techs
        remote_live = remote_def & live_techs
        ports_hit   = ports_def  & all_ports

        results[spec_key] = {
            "local_defined":   local_def,
            "local_covered":   local_live,
            "local_missing":   local_def  - local_live,
            "local_pct":       100.0 * len(local_live)  / len(local_def)  if local_def  else 100.0,
            "remote_defined":  remote_def,
            "remote_covered":  remote_live,
            "remote_missing":  remote_def - remote_live,
            "remote_pct":      100.0 * len(remote_live) / len(remote_def) if remote_def else 100.0,
            "ports_defined":   ports_def,
            "ports_covered":   ports_hit,
            "ports_missing":   ports_def  - ports_hit,
            "ports_pct":       100.0 * len(ports_hit)   / len(ports_def)  if ports_def  else 100.0,
        }
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def validate_file(fp: Path, vocab: dict, catalog: dict,
                  catalog_rates: dict[str, float] | None = None) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {
        "parse": [], "vocab": [], "identifiers": [], "categories": [],
        "goals": [], "dupes": [], "values": [],
        "breach": [], "remote": [], "rates": [], "spread": [], "mono": [], "orphans": [],
        "fw_props": [], "fw_goal": [], "fw_dag": [], "fw_af": [], "fw_gate": [], "fw_remote": [],
        "dead_tech": [], "af_dangle": [], "fw_dead": [], "reachable": [],
        "path_depth": [], "dead_svc": [], "dead_prop": [], "dead_cv": [],
        "node_range": [], "domain_dupes": [], "eff_prob": [], "goal_exploit": [],
        "sr_catalog": [], "domain_refs": [], "leak_budget": [],
        "grp_bounds": [], "field_bounds": [], "sanity": [], "cred_chain": [],
        "node_budget": [], "zero_tc": [], "goal_val": [], "meta_cons": [],
        "prop_conf": [], "ig_path": [], "grp_resolve": [],
        "ig_val": [], "ng_feas": [],
    }
    try:
        data = yaml.safe_load(fp.read_text()) or {}
    except yaml.YAMLError as e:
        results["parse"].append(f"{fp.name}: YAML parse error: {e}")
        return results

    results["vocab"]       = check_vocab(fp, data, vocab)
    results["identifiers"] = check_identifiers(fp, data)
    results["categories"]  = check_categories(fp, data, catalog)
    results["goals"]       = check_goal_specialist_coverage(fp, data)
    results["dupes"]       = check_duplicates(fp, data)
    results["values"]      = check_goal_values(fp, data)
    results["breach"]      = check_breach_node(fp, data)
    results["remote"]      = check_remote_entry(fp, data)
    results["rates"]       = check_success_rates(fp, data)
    results["spread"]      = check_category_spread(fp, data)
    results["mono"]        = check_value_monotonicity(fp, data)
    results["orphans"]     = check_orphan_services(fp, data)
    results["fw_props"]    = check_firewall_consistency(fp, data)
    results["fw_goal"]     = check_firewall_not_goal(fp, data)
    results["fw_dag"]      = check_attack_flow_dag(fp, data)
    results["fw_af"]       = check_firewall_in_attack_flow(fp, data)
    results["fw_gate"]     = check_internal_nodes_gated(fp, data)
    results["fw_remote"]   = check_perimeter_fw_remote_vuln(fp, data)
    results["dead_tech"]   = check_dead_techniques(fp, data)
    results["af_dangle"]   = check_af_nodes_exist(fp, data)
    results["fw_dead"]     = check_firewall_not_deadend(fp, data)
    results["reachable"]   = check_goal_reachable(fp, data)
    results["path_depth"]  = check_attack_path_depth(fp, data)
    results["dead_svc"]    = check_dead_services(fp, data)
    results["dead_prop"]   = check_dead_properties(fp, data)
    results["dead_cv"]     = check_dead_constraint_vulns(fp, data)
    results["node_range"]  = check_node_range(fp, data)
    results["domain_dupes"] = check_domain_service_duplicates(fp, data)
    results["eff_prob"]    = check_exploit_effective_probability(fp, data)
    results["goal_exploit"] = check_goal_service_exploitability(fp, data)
    results["sr_catalog"]  = check_success_rate_consistency(
        fp, data, catalog_rates or {}
    )
    results["domain_refs"]  = check_domain_service_refs(fp, data)
    results["leak_budget"]  = check_leaked_node_feasibility(fp, data)
    results["grp_bounds"]   = check_domain_group_bounds(fp, data)
    results["field_bounds"] = check_technique_field_bounds(fp, data)
    results["sanity"]       = check_structural_sanity(fp, data)
    results["cred_chain"]   = check_credential_chain_integrity(fp, data)
    results["node_budget"]  = check_node_budget(fp, data)
    results["zero_tc"]      = check_zero_target_coverage(fp, data)
    results["goal_val"]     = check_goal_value_positive(fp, data)
    results["meta_cons"]    = check_metadata_consistency(fp, data)
    results["prop_conf"]    = check_property_conflicts(fp, data)
    results["ig_path"]      = check_intermediate_goals_on_path(fp, data)
    results["grp_resolve"]  = check_domain_constraint_groups(fp, data)
    results["ig_val"]       = check_intermediate_goal_values(fp, data)
    results["ng_feas"]      = check_num_goals_feasibility(fp, data)
    return results


_ALL_CHECKS: list[tuple[str, str]] = [
    ("parse",       "[parse]"),
    ("vocab",       "[vocab]"),
    ("identifiers", "[identifiers]"),
    ("categories",  "[categories]"),
    ("goals",       "[goals]"),
    ("dupes",       "[dupes]"),
    ("values",      "[values]"),
    ("breach",      "[breach]"),
    ("remote",      "[remote]"),
    ("rates",       "[rates]"),
    ("spread",      "[spread]"),
    ("mono",        "[mono]"),
    ("orphans",     "[orphans]"),
    ("fw_props",    "[fw_props]"),
    ("fw_goal",     "[fw_goal]"),
    ("fw_dag",      "[fw_dag]"),
    ("fw_af",       "[fw_af]"),
    ("fw_gate",     "[fw_gate]"),
    ("fw_remote",   "[fw_remote]"),
    ("dead_tech",   "[dead_tech]"),
    ("af_dangle",   "[af_dangle]"),
    ("fw_dead",     "[fw_dead]"),
    ("reachable",   "[reachable]"),
    ("path_depth",  "[path_depth]"),
    ("dead_svc",    "[dead_svc]"),
    ("dead_prop",   "[dead_prop]"),
    ("dead_cv",     "[dead_cv]"),
    ("node_range",  "[node_range]"),
    ("domain_dupes","[dom_dupes]"),
    ("eff_prob",    "[eff_prob]"),
    ("goal_exploit","[goal_expl]"),
    ("sr_catalog",  "[sr_cat]"),
    ("domain_refs",  "[dom_refs]"),
    ("leak_budget",  "[leak_bgt]"),
    ("grp_bounds",   "[grp_bnd]"),
    ("field_bounds", "[fld_bnd]"),
    ("sanity",       "[sanity]"),
    ("cred_chain",   "[cred_ch]"),
    ("node_budget",  "[nd_bgt]"),
    ("zero_tc",      "[zero_tc]"),
    ("goal_val",     "[goal_v]"),
    ("meta_cons",    "[meta_c]"),
    ("prop_conf",    "[prop_c]"),
    ("ig_path",      "[ig_path]"),
    ("grp_resolve",  "[grp_res]"),
    ("ig_val",       "[ig_val]"),
    ("ng_feas",      "[ng_feas]"),
]
_CHECK_KEYS = [k for k, _ in _ALL_CHECKS]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("configs", nargs="*", type=Path)
    parser.add_argument("--vocab", type=Path,
                        default=_CBS_VOCAB if _CBS_VOCAB.exists() else _DEFAULT_VOCAB,
                        help="Path to global_vocabulary.yaml")
    parser.add_argument("--catalog", type=Path, default=_DEFAULT_CATALOG,
                        help="Path to vulnerability_catalog.md")
    parser.add_argument("--summary", action="store_true",
                        help="Print per-file summary table only")
    parser.add_argument("--coverage", action="store_true",
                        help="Print dataset-level specialist spec coverage report")
    args = parser.parse_args()

    if args.coverage:
        if not args.configs:
            print("ERROR: --coverage requires at least one config file", file=sys.stderr)
            return 2
        cov = compute_spec_coverage(list(args.configs))
        hdr = f"\n{'Specialist':<12} {'LOCAL':>12} {'REMOTE':>12} {'PORTS':>12}"
        print(hdr)
        print("-" * 52)
        all_ok = True
        for spec, info in cov.items():
            lp = info["local_pct"]
            rp = info["remote_pct"]
            pp = info["ports_pct"]
            lc = f"{len(info['local_covered'])}/{len(info['local_defined'])} ({lp:.0f}%)"
            rc = f"{len(info['remote_covered'])}/{len(info['remote_defined'])} ({rp:.0f}%)"
            pc = f"{len(info['ports_covered'])}/{len(info['ports_defined'])} ({pp:.0f}%)"
            flag = " ✓" if (lp == 100 and rp == 100 and pp == 100) else " !"
            print(f"{spec:<12} {lc:>12} {rc:>12} {pc:>12}{flag}")
            for label, key in [("LOCAL","local_missing"),("REMOTE","remote_missing"),
                                ("PORT","ports_missing")]:
                for m in sorted(info[key]):
                    print(f"    {label} MISS: {m}")
                    all_ok = False
        print()
        if all_ok:
            print("PASS: 100% action-space coverage (LOCAL + REMOTE + ports)")
        else:
            print("WARN: gaps in specialist action coverage — see MISS lines above")
        return 0

    if not args.configs:
        print("ERROR: no config files specified", file=sys.stderr)
        return 2

    if not args.vocab.exists():
        print(f"ERROR: vocab not found: {args.vocab}", file=sys.stderr)
        return 2
    if not args.catalog.exists():
        print(f"ERROR: catalog not found: {args.catalog}", file=sys.stderr)
        return 2

    vocab          = load_global_vocab(args.vocab)
    catalog        = load_vuln_catalog(args.catalog)
    catalog_rates  = load_catalog_rates(args.catalog)

    total_issues = 0
    file_results: list[tuple[Path, dict]] = []
    raw_file_data: list[tuple[Path, dict]] = []  # (path, parsed YAML) for dataset checks

    for fp in sorted(args.configs):
        if not fp.exists():
            print(f"WARNING: file not found, skipping: {fp}", file=sys.stderr)
            continue
        results = validate_file(fp, vocab, catalog, catalog_rates)
        file_results.append((fp, results))
        n = sum(len(v) for v in results.values())
        total_issues += n
        try:
            raw_file_data.append((fp, yaml.safe_load(fp.read_text()) or {}))
        except Exception:
            raw_file_data.append((fp, {}))

    # Dataset-level check: scenario_id uniqueness across all files
    uid_issues = check_scenario_id_uniqueness(raw_file_data)
    if uid_issues:
        total_issues += len(uid_issues)

    # Dataset-level check: cross-size consistency within scenario families
    xsize_issues = check_cross_size_consistency(raw_file_data)
    if xsize_issues:
        total_issues += len(xsize_issues)

    # Output
    if args.summary:
        hdr = (f"{'File':<50} " +
               " ".join(f"{k:>7}" for k in ["parse","vocab","idents","cats","goals",
                                              "dupes","vals","breach","remote","rates",
                                              "spread","mono","orph",
                                              "fw_prop","fw_goal","fw_dag",
                                              "fw_af","fw_gate","fw_rem","TOTAL"]))
        print(hdr)
        print("-" * len(hdr))
        for fp, r in file_results:
            name = fp.name.replace("specialist_", "").replace("_v1.yaml", "")[:50]
            counts = [len(r.get(k, [])) for k in _CHECK_KEYS]
            total = sum(counts)
            flag = " ✗" if total else " ✓"
            row = f"{name:<50} " + " ".join(f"{c:>7}" for c in counts) + f" {total:>7}{flag}"
            print(row)
        if uid_issues:
            print(f"\n{'='*70}")
            print("DATASET-LEVEL: scenario_id uniqueness")
            for issue in uid_issues:
                print(f"  [uniq_id] {issue}")
        if xsize_issues:
            print(f"\n{'='*70}")
            print("DATASET-LEVEL: cross-size consistency")
            for issue in xsize_issues:
                print(f"  [xsize] {issue}")
        print(f"\nTotal issues: {total_issues}")
    else:
        for fp, r in file_results:
            all_issues = [i for k in _CHECK_KEYS for i in r.get(k, [])]
            if all_issues:
                print(f"\n{'='*70}")
                print(f"FAIL: {fp.name}")
                for check, label in _ALL_CHECKS:
                    for issue in r.get(check, []):
                        print(f"  {label} {issue.split(':', 1)[-1].strip()}")

        if uid_issues:
            print(f"\n{'='*70}")
            print("DATASET-LEVEL: scenario_id uniqueness")
            for issue in uid_issues:
                print(f"  [uniq_id] {issue}")

        if xsize_issues:
            print(f"\n{'='*70}")
            print("DATASET-LEVEL: cross-size consistency")
            for issue in xsize_issues:
                print(f"  [xsize] {issue}")

        if total_issues == 0:
            print(f"PASS: all {len(file_results)} files clean")
        else:
            print(f"\nFAIL: {total_issues} issue(s) across "
                  f"{sum(1 for _,r in file_results if any(r.values()))} file(s)")

    return 0 if total_issues == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
