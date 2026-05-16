#!/usr/bin/env python3
"""
tools/phase2_generator.py
===============================
Generate a stratified dataset (§2.3) across small / medium / large / xl node-count
strata with separate train and test splits that use disjoint scenario numbering
so they are never confused.

The xl stratum (500–1000 nodes) defaults to 3 train + 1 test episodes per config
due to compute cost. Override with --train / --test as usual.

For each stratum the tool writes a temporary config YAML overriding
min_total_nodes / max_total_nodes, then calls cli.py the requested number
of times.  All outputs go under:

    <out-dir>/<domain>/<split>/<stratum>/

Usage
-----
# Generate 30 train + 10 test per stratum for Active Directory
python3 tools/phase2_generator.py \\
    --config data/active_directory.yaml \\
    --out-dir generated_data/ad_stratified \\
    --train 30 --test 10

# Only generate medium + large strata
python3 tools/phase2_generator.py \\
    --config data/active_directory.yaml \\
    --out-dir generated_data/ad_med_large \\
    --train 20 --test 5 \\
    --strata medium large

# Dry-run — show what would be generated without writing files
python3 tools/phase2_generator.py \\
    --config data/active_directory.yaml \\
    --out-dir /tmp/test \\
    --train 10 --test 2 \\
    --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

# Ensure repo root is importable for in-process generation.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# ---------------------------------------------------------------------------
# Default strata (§2.3)
# ---------------------------------------------------------------------------

DEFAULT_STRATA: Dict[str, Dict[str, int]] = {
    "small":  {"min_total_nodes": 30,  "max_total_nodes": 80},
    "medium": {"min_total_nodes": 80,  "max_total_nodes": 180},
    "large":  {"min_total_nodes": 180, "max_total_nodes": 250},
    "xl":     {"min_total_nodes": 500, "max_total_nodes": 1000},
}

# XL stratum uses fewer episodes due to compute cost.
_XL_TRAIN_DEFAULT = 3
_XL_TEST_DEFAULT  = 1

# Train seeds: 1 – 10 000    Test seeds: 10 001 – 20 000  (kept disjoint)
_TRAIN_OFFSET = 0
_TEST_OFFSET  = 10_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _scale_config(cfg: dict, scale: float) -> dict:
    """Proportionally scale all group node counts and total node bounds.

    Preserves domain structural identity: the ratio of service groups stays
    constant — only absolute numbers change. Both per-group counts and
    config.min/max_total_nodes are multiplied by scale.
    """
    if scale == 1.0:
        return cfg

    import copy
    cfg = copy.deepcopy(cfg)

    for domain in cfg.get("domains", []):
        for group in domain.get("groups", []):
            if "min_count" in group or "max_count" in group:
                lo = group.get("min_count", 1)
                hi = group.get("max_count", lo)
                group["min_count"] = max(1, round(lo * scale))
                group["max_count"] = max(1, round(hi * scale))
            elif "count" in group:
                c = group["count"]
                if isinstance(c, dict):
                    lo = c.get("min", 1)
                    hi = c.get("max", lo)
                    group["count"] = {
                        "min": max(1, round(lo * scale)),
                        "max": max(1, round(hi * scale)),
                    }
                else:
                    group["count"] = max(1, round(int(c) * scale))

    top = dict(cfg.get("config", {}))
    for key in ("min_total_nodes", "max_total_nodes"):
        if key in top:
            top[key] = max(1, round(top[key] * scale))
    cfg["config"] = top
    return cfg


def _write_temp_config(base_cfg: dict, stratum_bounds: Dict[str, int]) -> str:
    """
    Write a temporary YAML config with overridden min/max_total_nodes.
    Returns path to the temp file (caller must delete).
    """
    cfg = {k: v for k, v in base_cfg.items()}
    top_config = dict(cfg.get("config", {}))
    top_config["min_total_nodes"] = stratum_bounds["min_total_nodes"]
    top_config["max_total_nodes"] = stratum_bounds["max_total_nodes"]
    cfg["config"] = top_config

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, prefix="stratified_"
    )
    yaml.dump(cfg, tmp, default_flow_style=False, allow_unicode=True)
    tmp.close()
    return tmp.name


def _generate_one(
    config_path: str,
    out_dir: Path,
    scenario_num: int,
    prefix: str,
    dry_run: bool,
    timeout: int = 300,
) -> bool:
    """Generate one scenario in-process. Returns True on success."""
    scenario_dir = out_dir / f"{prefix}-{scenario_num:04d}"
    scenario_dir.mkdir(parents=True, exist_ok=True)

    if dry_run:
        return True

    # Derive a deterministic seed from the scenario number so each run is
    # reproducible without being identical across strata.
    seed = scenario_num

    try:
        from cli import generate_scenario
        generate_scenario(config_path, str(scenario_dir), seed=seed)
        return True
    except Exception as e:
        print(f"    ✗  Scenario {scenario_num} error: {e}")
        return False


def _run_parallel(
    jobs: List[Tuple[int, Path]],
    config_path: str,
    prefix: str,
    dry_run: bool,
    timeout: int,
    max_workers: int,
) -> int:
    """
    Execute a list of (scenario_num, out_dir) generation jobs in parallel.
    Returns the number of successful scenarios.
    """
    if dry_run:
        return len(jobs)

    success = 0
    total = len(jobs)
    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_generate_one, config_path, out_dir, num, prefix, dry_run, timeout): num
            for num, out_dir in jobs
        }
        completed = 0
        for fut in as_completed(futures):
            completed += 1
            try:
                if fut.result():
                    success += 1
            except Exception as e:
                print(f"    ✗  Worker error: {e}")
            if completed % 5 == 0 or completed == total:
                print(f"    {completed}/{total} done ({success} OK)", end="\r")
    return success


def _dry_run_stats(base_cfg: dict, stratum_bounds: Dict[str, int]) -> str:
    """Return a one-line human-readable summary of what would be generated."""
    min_n = stratum_bounds["min_total_nodes"]
    max_n = stratum_bounds["max_total_nodes"]
    raw_domains = base_cfg.get("domains", [])
    domains = [d.get("name", str(i)) for i, d in enumerate(raw_domains)] if isinstance(raw_domains, list) else list(raw_domains.keys())
    raw_services = base_cfg.get("services", {})
    services = (list(raw_services.keys())[:5] if isinstance(raw_services, dict)
                else [s.get("name", "") for s in raw_services[:5]])
    return (
        f"nodes {min_n}–{max_n}  |  "
        f"{len(domains)} domain(s): {', '.join(domains) or '—'}  |  "
        f"services: {', '.join(services) or '—'}"
        + ("…" if len(list(base_cfg.get("services", {}).keys())) > 5 else "")
    )


def _write_metadata(out_dir: Path, is_train: bool, success: int, stratum: str, config_file: str):
    meta = {
        "is_trained":    is_train,
        "stratum":       stratum,
        "success_count": success,
        "config_file":   str(config_file),
        "generated_at":  datetime.now().isoformat(),
    }
    with open(out_dir / "is_trained.json", "w") as f:
        json.dump(meta, f, indent=2)


# ---------------------------------------------------------------------------
# Core generation loop
# ---------------------------------------------------------------------------

def generate_stratum(
    base_cfg:      dict,
    stratum_name:  str,
    stratum_bounds: Dict[str, int],
    domain_name:   str,
    out_root:      Path,
    train_count:   int,
    test_count:    int,
    dry_run:       bool,
    timeout:       int,
    max_workers:   int = 4,
) -> Tuple[int, int]:
    """
    Generate train + test scenarios for one stratum in parallel.
    Returns (train_success, test_success).
    """
    tmp_config = _write_temp_config(base_cfg, stratum_bounds)

    prefix = f"CyberBattleSim-{domain_name.replace('_','-')}-{stratum_name}"

    train_dir = out_root / domain_name / "train" / stratum_name
    test_dir  = out_root / domain_name / "test"  / stratum_name
    train_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)

    stats_line = _dry_run_stats(base_cfg, stratum_bounds)
    print(f"\n  [{stratum_name.upper()}]  {stats_line}  (workers={max_workers})"
          + ("  [DRY RUN]" if dry_run else ""))

    # --- Train (parallel) ---
    print(f"    Train ({train_count} scenarios)...")
    train_jobs = [(_TRAIN_OFFSET + i, train_dir) for i in range(1, train_count + 1)]
    train_success = _run_parallel(train_jobs, tmp_config, prefix, dry_run, timeout, max_workers)
    print(f"    Train: {train_success}/{train_count} OK             ")

    # --- Test (parallel) ---
    print(f"    Test  ({test_count} scenarios)...")
    test_jobs = [(_TEST_OFFSET + i, test_dir) for i in range(1, test_count + 1)]
    test_success = _run_parallel(test_jobs, tmp_config, prefix, dry_run, timeout, max_workers)
    print(f"    Test:  {test_success}/{test_count} OK             ")

    if not dry_run:
        _write_metadata(train_dir, True,  train_success, stratum_name, tmp_config)
        _write_metadata(test_dir,  False, test_success,  stratum_name, tmp_config)

    try:
        os.unlink(tmp_config)
    except OSError:
        pass

    return train_success, test_success


# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

def _print_summary(stats: Dict[str, Tuple[int, int]], targets: Dict[str, Tuple[int, int]],
                   out_root: Path, dry_run: bool):
    print()
    print("=" * 60)
    print("  STRATIFIED GENERATION SUMMARY")
    print("=" * 60)
    print(f"  {'Stratum':<10} {'Train':>8} {'Test':>8} {'Total':>8}")
    print(f"  {'-'*10} {'-'*8} {'-'*8} {'-'*8}")
    grand_train = grand_test = grand_target_tr = grand_target_te = 0
    for stratum, (tr, te) in stats.items():
        print(f"  {stratum:<10} {tr:>8} {te:>8} {tr+te:>8}")
        grand_train += tr
        grand_test  += te
        tgt_tr, tgt_te = targets.get(stratum, (0, 0))
        grand_target_tr += tgt_tr
        grand_target_te += tgt_te
    print(f"  {'TOTAL':<10} {grand_train:>8} {grand_test:>8} {grand_train+grand_test:>8}")
    rate_tr = grand_train / grand_target_tr * 100 if grand_target_tr else 0
    rate_te = grand_test  / grand_target_te * 100 if grand_target_te else 0
    print(f"\n  Success rate — train: {rate_tr:.1f}%  test: {rate_te:.1f}%")
    if not dry_run:
        print(f"  Output: {out_root.resolve()}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a stratified CyberBattleSim dataset (§2.3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", required=True, metavar="YAML",
                        help="Domain config YAML to use as base template")
    parser.add_argument("--out-dir", required=True, metavar="DIR",
                        help="Root output directory")
    parser.add_argument("--train", type=int, default=30,
                        help="Scenarios per stratum for training split (default: 30)")
    parser.add_argument("--test", type=int, default=10,
                        help="Scenarios per stratum for test split (default: 10)")
    parser.add_argument("--strata", nargs="+",
                        choices=list(DEFAULT_STRATA.keys()),
                        default=["small", "medium", "large"],
                        help="Which strata to generate (default: small medium large; xl must be explicitly requested)")
    parser.add_argument("--xl-train", type=int, default=_XL_TRAIN_DEFAULT, metavar="N",
                        help=f"Train episodes for xl stratum (default: {_XL_TRAIN_DEFAULT})")
    parser.add_argument("--xl-test", type=int, default=_XL_TEST_DEFAULT, metavar="N",
                        help=f"Test episodes for xl stratum (default: {_XL_TEST_DEFAULT})")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Per-scenario timeout in seconds (default: 300)")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4,
                        help="Parallel worker processes for generation (default: cpu_count)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be generated without running cli.py")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing scenarios (used by actor-critic repair loop)")
    parser.add_argument("--scale", type=float, default=1.0, metavar="FACTOR",
                        help="Proportionally scale all per-group node counts and total node "
                             "bounds (default: 1.0). E.g. --scale 3 produces scenarios that "
                             "are structurally identical to the base config but 3× larger.")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.is_file():
        print(f"Error: config not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    if args.scale <= 0:
        print("Error: --scale must be > 0", file=sys.stderr)
        sys.exit(1)

    base_cfg    = _scale_config(_load_config(str(config_path)), args.scale)
    domain_name = config_path.stem
    out_root    = Path(args.out_dir)
    out_root.mkdir(parents=True, exist_ok=True)

    strata_to_run = {k: DEFAULT_STRATA[k] for k in args.strata}
    # When scaling, also scale the stratum node bounds so they stay consistent
    if args.scale != 1.0:
        strata_to_run = {
            name: {
                "min_total_nodes": max(1, round(b["min_total_nodes"] * args.scale)),
                "max_total_nodes": max(1, round(b["max_total_nodes"] * args.scale)),
            }
            for name, b in strata_to_run.items()
        }

    print("=" * 60)
    print("  STRATIFIED GENERATOR")
    print("=" * 60)
    print(f"  Config    : {config_path}")
    print(f"  Domain    : {domain_name}")
    print(f"  Out dir   : {out_root.resolve()}")
    print(f"  Strata    : {', '.join(strata_to_run.keys())}")
    print(f"  Scale     : {args.scale}×" + (" (proportional)" if args.scale != 1.0 else ""))
    print(f"  Per stratum: {args.train} train / {args.test} test")
    print(f"  Workers   : {args.workers}")
    total_scenarios = sum(
        (args.xl_train + args.xl_test) if s == "xl" else (args.train + args.test)
        for s in strata_to_run
    )
    print(f"  Total     : {total_scenarios} scenarios{'  [DRY RUN]' if args.dry_run else ''}")
    print("=" * 60)

    stats: Dict[str, Tuple[int, int]] = {}
    for stratum_name, bounds in strata_to_run.items():
        if stratum_name == "xl":
            s_train, s_test = args.xl_train, args.xl_test
        else:
            s_train, s_test = args.train, args.test
        tr, te = generate_stratum(
            base_cfg      = base_cfg,
            stratum_name  = stratum_name,
            stratum_bounds= bounds,
            domain_name   = domain_name,
            out_root      = out_root,
            train_count   = s_train,
            test_count    = s_test,
            dry_run       = args.dry_run,
            timeout       = args.timeout,
            max_workers   = args.workers,
        )
        stats[stratum_name] = (tr, te)

    targets = {
        s: (args.xl_train, args.xl_test) if s == "xl" else (args.train, args.test)
        for s in strata_to_run
    }
    _print_summary(stats, targets, out_root, args.dry_run)

    # Write a generation manifest
    if not args.dry_run:
        manifest = {
            "config":    str(config_path),
            "domain":    domain_name,
            "strata":    {
                s: {
                    "bounds":        DEFAULT_STRATA[s],
                    "train_success": stats[s][0],
                    "test_success":  stats[s][1],
                }
                for s in strata_to_run
            },
            "generated_at": datetime.now().isoformat(),
        }
        manifest_path = out_root / domain_name / "stratified_manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"\n  Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
