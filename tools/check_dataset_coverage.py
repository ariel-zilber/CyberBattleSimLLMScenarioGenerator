#!/usr/bin/env python3
"""
tools/check_dataset_coverage.py
================================
Dataset-level vulnerability slot coverage audit.

Compares every Solvability.* slot in vulnerability_catalog.md against what
is actually declared across all scenario configs in data/scenarios/.

Reports per-agent coverage and overall coverage. Exits nonzero if overall
coverage is below --min-coverage (default 0.80).

Usage
-----
  python tools/check_dataset_coverage.py
  python tools/check_dataset_coverage.py --min-coverage 0.70
  python tools/check_dataset_coverage.py --gap-json /tmp/coverage_gap.json
  python tools/check_dataset_coverage.py --scenarios-dir data/scenarios/expanded
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT    = Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "prompts" / "reference" / "vulnerability_catalog.md"
SCENARIOS_DIR = REPO_ROOT / "data" / "scenarios"

_SOLV_RE = re.compile(r"Solvability\.([A-Za-z0-9_]+)")


def _parse_catalog(path: Path) -> set[str]:
    """Extract all Solvability.* slot names from the catalog markdown."""
    text = path.read_text(encoding="utf-8")
    return {f"Solvability.{m}" for m in _SOLV_RE.findall(text)}


def _slots_in_file(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {f"Solvability.{m}" for m in _SOLV_RE.findall(text)}


def _agent_from_config(path: Path) -> str:
    """Read metadata.agent from YAML without importing yaml (avoid dep issues)."""
    try:
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data.get("metadata", {}).get("agent", "Unknown")
    except Exception:
        # Fallback: infer from filename prefix
        stem = path.stem
        for prefix, agent in [
            ("snet_", "S_Network"), ("slin_", "S_Linux"), ("swin_", "S_Windows"),
            ("sid_",  "S_Identity"), ("slat_", "S_Lateral"), ("meta_", "Meta"),
        ]:
            if stem.startswith(prefix):
                return agent
        return "Unknown"


def audit(
    scenarios_dir: Path = SCENARIOS_DIR,
    catalog_path: Path = CATALOG_PATH,
    min_coverage: float = 0.80,
    gap_json: "Path | None" = None,
    quiet: bool = False,
) -> dict:
    """Run coverage audit. Returns result dict."""
    if not catalog_path.exists():
        print(f"ERROR: Catalog not found: {catalog_path}")
        sys.exit(2)
    if not scenarios_dir.exists():
        print(f"ERROR: Scenarios dir not found: {scenarios_dir}")
        sys.exit(2)

    catalog_slots = _parse_catalog(catalog_path)
    if not catalog_slots:
        print("ERROR: No Solvability.* slots found in catalog")
        sys.exit(2)

    # Collect slots per config file and group by agent
    agent_slots:  dict[str, set[str]] = defaultdict(set)
    all_used:     set[str]            = set()
    config_count: dict[str, int]      = defaultdict(int)

    yaml_files = list(scenarios_dir.rglob("*.yaml"))
    for cfg_path in yaml_files:
        slots = _slots_in_file(cfg_path)
        if not slots:
            continue
        agent = _agent_from_config(cfg_path)
        agent_slots[agent] |= slots
        all_used |= slots
        config_count[agent] += 1

    missing_global  = sorted(catalog_slots - all_used)
    overall_coverage = len(all_used) / len(catalog_slots)

    result = {
        "catalog_total":     len(catalog_slots),
        "used_total":        len(all_used),
        "missing_total":     len(missing_global),
        "overall_coverage":  round(overall_coverage, 4),
        "pass":              overall_coverage >= min_coverage,
        "min_coverage":      min_coverage,
        "missing_slots":     missing_global,
        "per_agent": {},
    }

    for agent, slots in sorted(agent_slots.items()):
        result["per_agent"][agent] = {
            "configs":   config_count[agent],
            "slots_used": len(slots),
            "slots":     sorted(slots),
        }

    if not quiet:
        print(f"\n{'='*64}")
        print(f"  DATASET COVERAGE AUDIT")
        print(f"  Catalog   : {catalog_path.name}  ({len(catalog_slots)} slots)")
        print(f"  Scenarios : {scenarios_dir}  ({len(yaml_files)} files)")
        print(f"{'='*64}")
        print(f"\n  Overall: {len(all_used)}/{len(catalog_slots)} slots used "
              f"({overall_coverage:.1%})  →  {'PASS' if result['pass'] else 'FAIL'} "
              f"(threshold {min_coverage:.0%})\n")

        print(f"  Per-agent breakdown:")
        for agent, info in sorted(result["per_agent"].items()):
            print(f"    {agent:<16} {info['slots_used']:>3} slots  "
                  f"({info['configs']} configs)")

        if missing_global:
            print(f"\n  Missing slots ({len(missing_global)}) — never used in any config:")
            for slot in missing_global[:40]:
                print(f"    {slot}")
            if len(missing_global) > 40:
                print(f"    ... and {len(missing_global) - 40} more")

        print(f"\n{'='*64}\n")

    if gap_json:
        gap_json = Path(gap_json)
        gap_json.parent.mkdir(parents=True, exist_ok=True)
        gap_json.write_text(json.dumps({
            "missing_slots":    missing_global,
            "overall_coverage": round(overall_coverage, 4),
            "catalog_total":    len(catalog_slots),
            "used_total":       len(all_used),
        }, indent=2), encoding="utf-8")
        if not quiet:
            print(f"  Gap JSON written → {gap_json}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit Solvability slot coverage across all scenario configs",
    )
    parser.add_argument("--scenarios-dir", type=Path, default=SCENARIOS_DIR,
                        help="Directory to scan for scenario YAML files")
    parser.add_argument("--catalog",       type=Path, default=CATALOG_PATH,
                        help="Path to vulnerability_catalog.md")
    parser.add_argument("--min-coverage",  type=float, default=0.80,
                        help="Minimum required coverage fraction (default: 0.80)")
    parser.add_argument("--gap-json",      type=Path, default=None,
                        help="Write machine-readable gap list to this JSON file")
    parser.add_argument("--quiet",         action="store_true",
                        help="Suppress human-readable output")
    args = parser.parse_args()

    result = audit(
        scenarios_dir=args.scenarios_dir,
        catalog_path=args.catalog,
        min_coverage=args.min_coverage,
        gap_json=args.gap_json,
        quiet=args.quiet,
    )
    sys.exit(0 if result["pass"] else 1)


if __name__ == "__main__":
    main()
