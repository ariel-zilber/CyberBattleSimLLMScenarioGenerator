#!/usr/bin/env python3
"""
tools/check_dataset_coverage.py
================================
Dataset-level vulnerability slot coverage audit.

Two modes
---------
1. Config→instance mode (default when --config is supplied):
   Checks that every Solvability.* slot defined in the config's
   solvability_vulnerabilities section actually appears as a vulnerability
   key in at least one generated node YAML under --scenarios-dir.
   This is the definitive guarantee: config defines it → instance has it.

2. Catalog mode (legacy, used when --config is NOT supplied):
   Compares Solvability.* slots in scenario YAML files against
   vulnerability_catalog.md.  Kept for backwards compatibility.

Exit codes
----------
  0  all defined slots present in generated instances (or coverage ≥ threshold)
  1  one or more defined slots missing from generated instances (or below threshold)
  2  script error (missing files etc.)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml as _yaml

_REPO_ROOT_FOR_IMPORT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT_FOR_IMPORT not in sys.path:
    sys.path.insert(0, _REPO_ROOT_FOR_IMPORT)
from tools.slot_scan import observed_solvability_slots

REPO_ROOT     = Path(__file__).resolve().parent.parent
CATALOG_PATH  = REPO_ROOT / "prompts" / "reference" / "vulnerability_catalog.md"
SCENARIOS_DIR = REPO_ROOT / "data" / "scenarios"

_SOLV_RE = re.compile(r"Solvability\.([A-Za-z0-9_]+)")


# ---------------------------------------------------------------------------
# Mode 1 — Config → Instance guarantee check
# ---------------------------------------------------------------------------

def _config_defined_slots(config_path: Path) -> set[str]:
    """Extract every Solvability.* name from solvability_vulnerabilities in config."""
    cfg = _yaml.safe_load(config_path.read_text()) or {}
    slots: set[str] = set()
    for entries in cfg.get("solvability_vulnerabilities", {}).values():
        if not isinstance(entries, list):
            continue
        for e in entries:
            name = e.get("name", "") if isinstance(e, dict) else ""
            if name.startswith("Solvability."):
                slots.add(name)
    # Also include start_node vulnerabilities
    for v in cfg.get("start_node", {}).get("vulnerabilities", {}).values():
        name = v.get("name", "") if isinstance(v, dict) else ""
        if name.startswith("Solvability."):
            slots.add(name)
    return slots


def _instance_observed_slots(scenarios_dir: Path) -> set[str]:
    """Scan all nodes/*.yaml under scenarios_dir and collect Solvability.* keys.

    Delegates to tools.slot_scan's shared regex-based extractor (problem #10
    in the validation report): yaml.safe_load() raises ConstructorError on
    nodes/start.yaml, which serializes real Python objects (e.g.
    ipaddress.IPv4Network) via a custom PyYAML tag that safe_load refuses to
    construct. That exception used to be caught here by a bare `except:
    continue`, silently skipping the ENTIRE start.yaml file -- so any slot
    that only ever appears on the start node (e.g. a config's own
    start_node.vulnerabilities entries) was invisible to this tool, while a
    separate audit script's own regex-based scanner saw it correctly. Using
    the same shared, YAML-parse-independent extractor here means the two
    can no longer disagree for this reason.
    """
    return observed_solvability_slots(scenarios_dir)


def audit_config_vs_instances(
    config_path: Path,
    scenarios_dir: Path,
    gap_json: "Path | None" = None,
    quiet: bool = False,
) -> dict:
    """
    Guarantee check: every slot defined in config must appear in ≥1 generated node.
    Returns result dict. Exits with code 2 on file errors.
    """
    if not config_path.exists():
        print(f"ERROR: Config not found: {config_path}")
        sys.exit(2)
    if not scenarios_dir.exists():
        print(f"ERROR: Scenarios dir not found: {scenarios_dir}")
        sys.exit(2)

    defined  = _config_defined_slots(config_path)
    observed = _instance_observed_slots(scenarios_dir)

    missing  = sorted(defined - observed)
    coverage = len(defined - set(missing)) / max(len(defined), 1)
    passed   = len(missing) == 0

    result = {
        "mode":               "config_vs_instances",
        "config":             str(config_path),
        "scenarios_dir":      str(scenarios_dir),
        "defined_slots":      len(defined),
        "observed_slots":     len(observed & defined),
        "missing_slots":      missing,
        "coverage":           round(coverage, 4),
        "pass":               passed,
    }

    if not quiet:
        print(f"\n{'='*64}")
        print(f"  CONFIG → INSTANCE COVERAGE GUARANTEE")
        print(f"  Config    : {config_path.name}")
        print(f"  Instances : {scenarios_dir}")
        print(f"{'='*64}")
        status = "PASS" if passed else "FAIL"
        print(f"\n  Defined slots : {len(defined)}")
        print(f"  Observed in instances : {len(observed & defined)}")
        print(f"  Missing from instances: {len(missing)}")
        print(f"  Coverage: {coverage:.1%}  →  {status}")
        if missing:
            print(f"\n  DEAD SLOTS — defined in config but absent from all generated nodes:")
            for s in missing:
                print(f"    {s}")
        print(f"\n{'='*64}\n")

    if gap_json:
        gap_json = Path(gap_json)
        gap_json.parent.mkdir(parents=True, exist_ok=True)
        gap_json.write_text(json.dumps({
            "mode":           "config_vs_instances",
            "missing_slots":  missing,
            "coverage":       round(coverage, 4),
            "defined_total":  len(defined),
            "observed_total": len(observed & defined),
        }, indent=2))

    return result


# ---------------------------------------------------------------------------
# Mode 2 — Legacy catalog check (unchanged)
# ---------------------------------------------------------------------------

def _parse_catalog(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {f"Solvability.{m}" for m in _SOLV_RE.findall(text)}


def _slots_in_file(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {f"Solvability.{m}" for m in _SOLV_RE.findall(text)}


def _agent_from_config(path: Path) -> str:
    try:
        data = _yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data.get("metadata", {}).get("agent", "Unknown")
    except Exception:
        stem = path.stem
        for prefix, agent in [
            ("snet_", "S_Network"), ("slin_", "S_Linux"), ("swin_", "S_Windows"),
            ("sid_",  "S_Identity"), ("slat_", "S_Lateral"), ("meta_", "Meta"),
        ]:
            if stem.startswith(prefix):
                return agent
        return "Unknown"


def audit_catalog(
    scenarios_dir: Path = SCENARIOS_DIR,
    catalog_path: Path = CATALOG_PATH,
    min_coverage: float = 0.80,
    gap_json: "Path | None" = None,
    quiet: bool = False,
) -> dict:
    if not catalog_path.exists():
        print(f"ERROR: Catalog not found: {catalog_path}")
        sys.exit(2)
    if not scenarios_dir.exists():
        print(f"ERROR: Scenarios dir not found: {scenarios_dir}")
        sys.exit(2)

    catalog_slots = _parse_catalog(catalog_path)
    agent_slots:   dict[str, set[str]] = defaultdict(set)
    all_used:      set[str]            = set()
    config_count:  dict[str, int]      = defaultdict(int)

    yaml_files = list(scenarios_dir.rglob("*.yaml"))
    for cfg_path in yaml_files:
        slots = _slots_in_file(cfg_path)
        if not slots:
            continue
        agent = _agent_from_config(cfg_path)
        agent_slots[agent] |= slots
        all_used |= slots
        config_count[agent] += 1

    missing_global   = sorted(catalog_slots - all_used)
    overall_coverage = len(all_used) / max(len(catalog_slots), 1)

    result = {
        "mode":              "catalog",
        "catalog_total":     len(catalog_slots),
        "used_total":        len(all_used),
        "missing_total":     len(missing_global),
        "overall_coverage":  round(overall_coverage, 4),
        "pass":              overall_coverage >= min_coverage,
        "min_coverage":      min_coverage,
        "missing_slots":     missing_global,
        "per_agent":         {},
    }
    for agent, slots in sorted(agent_slots.items()):
        result["per_agent"][agent] = {
            "configs":    config_count[agent],
            "slots_used": len(slots),
            "slots":      sorted(slots),
        }

    if not quiet:
        print(f"\n{'='*64}")
        print(f"  DATASET COVERAGE AUDIT (catalog mode)")
        print(f"  Catalog   : {catalog_path.name}  ({len(catalog_slots)} slots)")
        print(f"  Scenarios : {scenarios_dir}  ({len(yaml_files)} files)")
        print(f"{'='*64}")
        print(f"\n  Overall: {len(all_used)}/{len(catalog_slots)} slots "
              f"({overall_coverage:.1%})  →  {'PASS' if result['pass'] else 'FAIL'}\n")
        for agent, info in sorted(result["per_agent"].items()):
            print(f"    {agent:<16} {info['slots_used']:>3} slots  ({info['configs']} configs)")
        if missing_global:
            print(f"\n  Missing ({len(missing_global)}):")
            for s in missing_global[:40]:
                print(f"    {s}")
        print(f"\n{'='*64}\n")

    if gap_json:
        gap_json = Path(gap_json)
        gap_json.parent.mkdir(parents=True, exist_ok=True)
        gap_json.write_text(json.dumps({
            "missing_slots":    missing_global,
            "overall_coverage": round(overall_coverage, 4),
            "catalog_total":    len(catalog_slots),
            "used_total":       len(all_used),
        }, indent=2))

    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit Solvability slot coverage",
    )
    parser.add_argument("--config",        type=Path, default=None,
                        help="Config YAML path — enables config→instance guarantee mode")
    parser.add_argument("--scenarios-dir", type=Path, default=SCENARIOS_DIR,
                        help="Directory containing generated scenario instances")
    parser.add_argument("--catalog",       type=Path, default=CATALOG_PATH,
                        help="Path to vulnerability_catalog.md (catalog mode only)")
    parser.add_argument("--min-coverage",  type=float, default=0.80,
                        help="Minimum coverage fraction for catalog mode (default 0.80)")
    parser.add_argument("--gap-json",      type=Path, default=None,
                        help="Write machine-readable gap list to this JSON file")
    parser.add_argument("--quiet",         action="store_true")
    args = parser.parse_args()

    if args.config:
        result = audit_config_vs_instances(
            config_path=args.config,
            scenarios_dir=args.scenarios_dir,
            gap_json=args.gap_json,
            quiet=args.quiet,
        )
    else:
        result = audit_catalog(
            scenarios_dir=args.scenarios_dir,
            catalog_path=args.catalog,
            min_coverage=args.min_coverage,
            gap_json=args.gap_json,
            quiet=args.quiet,
        )

    sys.exit(0 if result["pass"] else 1)


if __name__ == "__main__":
    main()
