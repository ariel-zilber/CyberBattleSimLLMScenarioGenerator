#!/usr/bin/env python3
"""
tools/validate_zone_coverage.py
================================
Phase 1b hard-gate: checks that a CBS config YAML represents the correct
GLOBALTECH zones as declared in data/zone_manifest.yaml.

Checks (in order):
  A. domain_count         — exact number of CBS domains
  B. required_domains     — each domain's name and subnet match manifest
  C. required_zone_groups — group name patterns present per zone
  D. required_service_properties — service properties correct for GLOBALTECH devices
  E. required_inter_domain_flows — IDC edges with correct relation + protocols exist
  F. forbidden_inter_domain_flows — topology-bypass edges must not exist
  G. attack_flow_zones    — attack path traverses each declared zone

Exit codes:
  0  All checks pass — PASS
  1  One or more hard checks failed — FAIL
  2  Config not listed in zone_manifest (no entry) — SKIP (warn, exit 0)

Usage:
  python tools/validate_zone_coverage.py data/sid_ad_standalone_v1.yaml
  python tools/validate_zone_coverage.py data/sid_ad_standalone_v1.yaml --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT  = TOOLS_DIR.parent
MANIFEST   = REPO_ROOT / "data" / "zone_manifest.yaml"


# ─────────────────────────────────────────────────────────────────────────────
# Config extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

def _domains(cfg: dict) -> list[dict]:
    return cfg.get("domains", []) or []


def _all_groups(cfg: dict) -> list[str]:
    """Return every group name from all domains (handles list-of-dicts format)."""
    groups: list[str] = []
    for domain in _domains(cfg):
        g = domain.get("groups", {})
        if isinstance(g, dict):
            groups.extend(g.keys())
        elif isinstance(g, list):
            for item in g:
                if isinstance(item, dict):
                    name = item.get("name")
                    if name:
                        groups.append(name)
    return groups


def _all_services(cfg: dict) -> dict:
    return cfg.get("services", {}) or {}


def _all_attack_flow_nodes(cfg: dict) -> list[str]:
    nodes: set[str] = set()
    for rule in cfg.get("attack_flow", []):
        if isinstance(rule, dict):
            for key in ("source", "sources", "target", "targets"):
                val = rule.get(key)
                if isinstance(val, str):
                    nodes.add(val)
                elif isinstance(val, list):
                    nodes.update(val)
    return list(nodes)


def _idc_edges(cfg: dict) -> list[dict]:
    """Return list of {source_domain, target_domain, constraints} from inter_domain_constraints."""
    return [
        e for e in (cfg.get("inter_domain_constraints") or [])
        if isinstance(e, dict)
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Pattern helpers
# ─────────────────────────────────────────────────────────────────────────────

def _matches_any(name: str, patterns: list[str]) -> bool:
    return any(re.search(p, name, re.I) for p in patterns)


def _group_matches_zone(groups: list[str], pattern_group: list[str]) -> list[str]:
    return [g for g in groups if _matches_any(g, pattern_group)]


# ─────────────────────────────────────────────────────────────────────────────
# Result collector
# ─────────────────────────────────────────────────────────────────────────────

class ZoneCoverageResult:
    def __init__(self, config_name: str):
        self.config_name = config_name
        self.findings: list[dict] = []
        self.passed = True

    def ok(self, check: str, msg: str) -> None:
        self.findings.append({"type": "pass", "check": check, "message": msg})

    def warn(self, check: str, msg: str) -> None:
        self.findings.append({"type": "warning", "check": check, "message": msg})

    def fail(self, check: str, msg: str) -> None:
        self.findings.append({"type": "fail", "check": check, "message": msg})
        self.passed = False

    def to_dict(self) -> dict:
        return {"config_name": self.config_name, "passed": self.passed, "findings": self.findings}

    def print_report(self) -> None:
        icons = {"pass": "✓", "warning": "⚠", "fail": "✗"}
        print(f"\n  Zone Coverage Validation — {self.config_name}")
        print(f"  {'─' * 64}")
        for f in self.findings:
            icon = icons.get(f["type"], "?")
            print(f"  {icon}  [{f['check']}]  {f['message']}")
        print(f"  {'─' * 64}")
        print(f"  Zone coverage: {'PASS' if self.passed else 'FAIL'}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Validation checks
# ─────────────────────────────────────────────────────────────────────────────

def _check_domain_count(cfg: dict, spec: dict, r: ZoneCoverageResult) -> None:
    """A: Verify the config has exactly the declared number of CBS domains."""
    expected = spec.get("domain_count")
    if expected is None:
        return
    actual = len(_domains(cfg))
    if actual == expected:
        r.ok("domain_count", f"Domain count = {actual} (expected {expected}) ✓")
    else:
        r.fail(
            "domain_count",
            f"Expected {expected} CBS domain(s) but found {actual}. "
            f"Each GLOBALTECH zone should map to its own CBS domain."
        )


def _check_required_domains(cfg: dict, spec: dict, r: ZoneCoverageResult) -> None:
    """B: Verify each declared domain exists with the correct name and subnet."""
    required = spec.get("required_domains", [])
    if not required:
        return

    actual_domains = {d.get("name"): d.get("subnet") for d in _domains(cfg)}

    for req in required:
        name    = req["name"]
        subnet  = req.get("subnet", "")
        zone_id = req.get("globaltech_zone", "?")

        # Name check (exact match)
        if name not in actual_domains:
            r.fail(
                "domain_names",
                f"Missing domain '{name}' (GLOBALTECH zone {zone_id}). "
                f"Actual domains: {list(actual_domains.keys())}"
            )
            continue

        r.ok("domain_names", f"Domain '{name}' present (zone {zone_id}) ✓")

        # Subnet check (exact CIDR)
        if subnet:
            actual_subnet = actual_domains[name]
            if actual_subnet == subnet:
                r.ok("domain_subnets", f"Domain '{name}' subnet = {actual_subnet} ✓")
            else:
                r.fail(
                    "domain_subnets",
                    f"Domain '{name}' has subnet '{actual_subnet}' but expected '{subnet}' "
                    f"(GLOBALTECH zone {zone_id} address space)"
                )


def _check_zone_groups(cfg: dict, spec: dict, r: ZoneCoverageResult) -> None:
    """C: Verify required group name patterns are present per zone."""
    groups = _all_groups(cfg)
    for zone_id, pattern_groups in spec.get("required_zone_groups", {}).items():
        zone_passed = True
        for pg in pattern_groups:
            matches = _group_matches_zone(groups, pg)
            if matches:
                r.ok(f"zone_groups/{zone_id}",
                     f"Pattern {pg} → {', '.join(matches[:3])}")
            else:
                r.fail(
                    f"zone_groups/{zone_id}",
                    f"No group matches {pg} — zone {zone_id} may be missing or misnamed. "
                    f"Config groups: {groups[:8]}{'...' if len(groups) > 8 else ''}"
                )
                zone_passed = False
        if zone_passed:
            r.ok(f"zone_groups/{zone_id}", f"Zone {zone_id} group coverage ✓")


def _check_service_properties(cfg: dict, spec: dict, r: ZoneCoverageResult) -> None:
    """D: Verify GLOBALTECH device properties are present on matching services."""
    services = _all_services(cfg)
    for req in spec.get("required_service_properties", []):
        svc_pattern    = req["service_pattern"]
        required_props = req["required_properties"]

        matching = {n: s for n, s in services.items() if re.search(svc_pattern, n, re.I)}
        if not matching:
            r.fail(
                "service_properties",
                f"No service matches pattern '{svc_pattern}' — expected a GLOBALTECH "
                f"device for this zone"
            )
            continue

        for svc_name, svc_def in matching.items():
            props = svc_def.get("default_properties", []) or []
            if isinstance(props, str):
                props = [props]
            missing = [p for p in required_props if p not in props]
            if missing:
                r.fail(
                    "service_properties",
                    f"Service '{svc_name}' missing GLOBALTECH properties: {missing} "
                    f"(has: {props})"
                )
            else:
                r.ok("service_properties",
                     f"Service '{svc_name}' properties {required_props} ✓")


def _check_inter_domain_flows(cfg: dict, spec: dict, r: ZoneCoverageResult) -> None:
    """E: Verify required IDC edges exist with correct relation and protocols."""
    required_flows = spec.get("required_inter_domain_flows", [])
    if not required_flows:
        return

    edges = _idc_edges(cfg)

    # Build lookup: (source_domain, target_domain) → list of constraints
    edge_map: dict[tuple[str, str], list[dict]] = {}
    for e in edges:
        key = (e.get("source_domain", ""), e.get("target_domain", ""))
        edge_map.setdefault(key, []).extend(e.get("constraints", []))

    for flow in required_flows:
        src   = flow["source_domain"]
        tgt   = flow["target_domain"]
        rel   = flow.get("required_relation", "MUST_CONNECT")
        protos = flow.get("protocols_any", [])
        desc  = flow.get("description", f"{src} → {tgt}")

        key = (src, tgt)
        if key not in edge_map:
            r.fail(
                "inter_domain_flows",
                f"Missing IDC edge {src} → {tgt} — required: {desc}"
            )
            continue

        constraints = edge_map[key]
        # Check required relation exists
        rel_matches = [c for c in constraints
                       if isinstance(c, dict) and c.get("relation") == rel]
        if not rel_matches:
            r.fail(
                "inter_domain_flows",
                f"IDC edge {src} → {tgt} exists but has no '{rel}' constraint "
                f"(found relations: {list({c.get('relation') for c in constraints})})"
            )
            continue

        # Check at least one expected protocol is used
        if protos:
            used_protos = {c.get("protocol") for c in rel_matches if c.get("protocol")}
            matched_proto = used_protos & set(protos)
            if not matched_proto:
                r.fail(
                    "inter_domain_flows",
                    f"IDC edge {src} → {tgt} ({rel}) uses protocols {used_protos} "
                    f"but expected one of {protos} — wrong network protocol for GLOBALTECH topology"
                )
            else:
                r.ok(
                    "inter_domain_flows",
                    f"IDC edge {src} → {tgt} ({rel}, proto={matched_proto}) ✓ — {desc}"
                )
        else:
            r.ok("inter_domain_flows",
                 f"IDC edge {src} → {tgt} ({rel}) ✓ — {desc}")


def _check_forbidden_flows(cfg: dict, spec: dict, r: ZoneCoverageResult) -> None:
    """F: Verify forbidden IDC edges (topology bypasses) do not exist."""
    forbidden = spec.get("forbidden_inter_domain_flows", [])
    if not forbidden:
        return

    edges = _idc_edges(cfg)
    present_edges = {(e.get("source_domain", ""), e.get("target_domain", ""))
                     for e in edges}

    for flow in forbidden:
        src  = flow["source_domain"]
        tgt  = flow["target_domain"]
        desc = flow.get("description", f"{src} → {tgt} must not exist")
        if (src, tgt) in present_edges:
            r.fail(
                "forbidden_flows",
                f"TOPOLOGY VIOLATION: IDC edge {src} → {tgt} must NOT exist — {desc}"
            )
        else:
            r.ok("forbidden_flows",
                 f"No forbidden edge {src} → {tgt} ✓")


def _check_attack_flow_zones(cfg: dict, spec: dict, r: ZoneCoverageResult) -> None:
    """G: Verify attack_flow traverses services from each declared zone."""
    flow_zones = spec.get("attack_flow_zones", [])
    if not flow_zones:
        return

    attack_nodes = _all_attack_flow_nodes(cfg)
    if not attack_nodes:
        r.warn("attack_flow", "No attack_flow nodes found — cannot verify zone traversal")
        return

    for zone_id in flow_zones:
        zone_patterns = spec.get("required_zone_groups", {}).get(zone_id, [])
        flat_patterns = [p for pg in zone_patterns for p in pg]
        hits = [n for n in attack_nodes if _matches_any(n, flat_patterns)]
        if hits:
            r.ok("attack_flow",
                 f"Zone {zone_id} in attack_flow: {hits[:3]}")
        else:
            r.warn(
                "attack_flow",
                f"Zone {zone_id} not found in attack_flow nodes {attack_nodes[:6]} — "
                f"verify the attack path traverses this zone"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Main validator
# ─────────────────────────────────────────────────────────────────────────────

def validate(config_path: Path) -> ZoneCoverageResult:
    config_name = config_path.stem
    r = ZoneCoverageResult(config_name)

    if not MANIFEST.exists():
        r.warn("manifest", f"zone_manifest.yaml not found at {MANIFEST} — skipping")
        return r

    with MANIFEST.open() as f:
        manifest = yaml.safe_load(f)

    all_configs = manifest.get("configs", {})
    if config_name not in all_configs:
        r.warn("manifest", f"No manifest entry for '{config_name}' — coverage check skipped")
        return r

    spec = all_configs[config_name]

    with config_path.open() as f:
        cfg = yaml.safe_load(f)

    _check_domain_count(cfg, spec, r)
    _check_required_domains(cfg, spec, r)
    _check_zone_groups(cfg, spec, r)
    _check_service_properties(cfg, spec, r)
    _check_inter_domain_flows(cfg, spec, r)
    _check_forbidden_flows(cfg, spec, r)
    _check_attack_flow_zones(cfg, spec, r)

    return r


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate CBS config YAML against the GLOBALTECH zone manifest"
    )
    parser.add_argument("config", help="Path to the CBS config YAML file")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of human-readable")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"ERROR: config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    result = validate(config_path)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        result.print_report()

    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
