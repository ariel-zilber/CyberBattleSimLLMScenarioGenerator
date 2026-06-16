#!/usr/bin/env python3
"""
pipeline/phase2/generator.py
===============================
Simplified scenario generator. Generates a fixed-scale dataset based exactly
on the node counts defined in the domain config YAML.

Uses disjoint seed offsets for train and test splits to ensure evaluation
integrity.

Output structure:
    <out-dir>/<domain>/train/CyberBattleSim-<domain>-0001/nodes/...
    <out-dir>/<domain>/test/CyberBattleSim-<domain>-10001/nodes/...

Usage
-----
# Generate 30 train + 10 test scenarios
python3 pipeline/phase2/generator.py \
    --config data/active_directory.yaml \
    --out-dir generated_data/ad_dataset \
    --train 30 --test 10
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

# Ensure repo root is importable for in-process generation.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Train seeds: 1 – 10 000    Test seeds: 10 001 – 20 000  (kept disjoint)
_TRAIN_OFFSET = 0
_TEST_OFFSET  = 10_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _is_bfs_solvable(scenario_dir: Path) -> bool:
    """Return True if the generated scenario is BFS-solvable (a goal node is
    reachable from the entry via the credential/exploit graph). Used by the
    --require-solvable regeneration loop. Any evaluation error is treated as
    not-solvable so the scenario is regenerated rather than silently kept."""
    try:
        from pipeline.phase2.evaluator import evaluate_scenario
        result = evaluate_scenario(scenario_dir, include_attack_paths=False)
        return bool(result and result.get("solvable"))
    except Exception as e:
        print(f"    [solvable-check] error on {scenario_dir.name}: {e}")
        return False


def _generate_one(
    config_path: str,
    out_dir: Path,
    scenario_num: int,
    prefix: str,
    dry_run: bool,
    timeout: int = 300,
    require_solvable: bool = False,
    max_retries: int = 5,
) -> bool:
    """Generate one scenario in-process. Returns True on success.

    When ``require_solvable`` is set, the scenario is re-generated with a fresh
    (disjoint) seed up to ``max_retries`` times until it passes the BFS
    solvability check. If every attempt is unsolvable the last attempt is
    kept and the function returns False so the caller can account for it.
    """
    scenario_dir = out_dir / f"{prefix}-{scenario_num:04d}"
    scenario_dir.mkdir(parents=True, exist_ok=True)

    if dry_run:
        return True

    try:
        from cli import generate_scenario
    except Exception as e:
        print(f"    ✗  Scenario {scenario_num} import error: {e}")
        return False

    attempts = (max_retries + 1) if require_solvable else 1
    for attempt in range(attempts):
        # Disjoint seed per retry: scenario nums live in 1..20000, so adding
        # attempt*100000 keeps retry seeds out of every other scenario's range.
        seed = scenario_num + attempt * 100_000
        try:
            generate_scenario(config_path, str(scenario_dir), seed=seed)
        except Exception as e:
            print(f"    ✗  Scenario {scenario_num} (attempt {attempt+1}) error: {e}")
            continue

        if not require_solvable:
            return True

        if _is_bfs_solvable(scenario_dir):
            if attempt > 0:
                print(f"    ↻  Scenario {scenario_num} solvable after {attempt+1} attempt(s)")
            return True

        if attempt < attempts - 1:
            print(f"    ↻  Scenario {scenario_num} not solvable (attempt {attempt+1}/{attempts}) — regenerating")

    print(f"    ⚠  Scenario {scenario_num} still not BFS-solvable after {attempts} attempts — kept anyway")
    return False


def _run_parallel(
    jobs: List[Tuple[int, Path]],
    config_path: str,
    prefix: str,
    dry_run: bool,
    timeout: int,
    max_workers: int,
    require_solvable: bool = False,
    max_retries: int = 5,
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
            pool.submit(_generate_one, config_path, out_dir, num, prefix, dry_run,
                        timeout, require_solvable, max_retries): num
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
    print() # New line after progress bar
    return success


def _write_metadata(out_dir: Path, is_train: bool, success: int, config_file: str):
    meta = {
        "is_trained":    is_train,
        "success_count": success,
        "config_file":   str(config_file),
        "generated_at":  datetime.now().isoformat(),
    }
    with open(out_dir / "is_trained.json", "w") as f:
        json.dump(meta, f, indent=2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a fixed-scale CyberBattleSim dataset",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", required=True, metavar="YAML",
                        help="Domain config YAML to use")
    parser.add_argument("--out-dir", required=True, metavar="DIR",
                        help="Root output directory")
    parser.add_argument("--train", type=int, default=30,
                        help="Scenarios for training split (default: 30)")
    parser.add_argument("--test", type=int, default=10,
                        help="Scenarios for test split (default: 10)")
    parser.add_argument("--train-offset", type=int, default=0,
                        help="Start train scenario numbering after this offset (for appending)")
    parser.add_argument("--test-offset", type=int, default=0,
                        help="Start test scenario numbering after this offset (for appending)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Per-scenario timeout in seconds (default: 300)")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4,
                        help="Parallel worker processes for generation (default: cpu_count)")
    parser.add_argument("--require-solvable", action="store_true",
                        help="Force regeneration (new seed) of any scenario that is not "
                             "BFS-solvable, up to --max-retries times")
    parser.add_argument("--max-retries", type=int, default=5,
                        help="Max regeneration attempts per scenario when --require-solvable "
                             "is set (default: 5)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be generated without running cli.py")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.is_file():
        print(f"Error: config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    domain_name = config_path.stem
    out_root    = Path(args.out_dir) / "scenarios"
    out_root.mkdir(parents=True, exist_ok=True)

    prefix = f"CyberBattleSim-{domain_name.replace('_','-')}"

    print("=" * 60)
    print("  SCENARIO GENERATOR (Fixed Scale)")
    print("=" * 60)
    print(f"  Config    : {config_path}")
    print(f"  Domain    : {domain_name}")
    print(f"  Out dir   : {out_root.resolve()}")
    append_mode = args.train_offset > 0 or args.test_offset > 0
    mode_label  = f"  [APPEND from train={args.train_offset+1}]" if append_mode else ""
    print(f"  Count     : {args.train} train / {args.test} test{mode_label}")
    print(f"  Workers   : {args.workers}")
    print(f"  Total     : {args.train + args.test} new scenarios{'  [DRY RUN]' if args.dry_run else ''}")
    print("=" * 60)

    # --- Train (parallel) ---
    train_dir = out_root / "train"
    train_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n  Generating Train ({args.train} scenarios, starting at #{args.train_offset + 1})...")
    train_jobs = [(_TRAIN_OFFSET + args.train_offset + i, train_dir) for i in range(1, args.train + 1)]
    train_success = _run_parallel(train_jobs, str(config_path), prefix, args.dry_run, args.timeout,
                                  args.workers, args.require_solvable, args.max_retries)

    # --- Test (parallel) ---
    test_dir = out_root / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    print(f"  Generating Test ({args.test} scenarios, starting at #{args.test_offset + 1})...")
    test_jobs = [(_TEST_OFFSET + args.test_offset + i, test_dir) for i in range(1, args.test + 1)]
    test_success = _run_parallel(test_jobs, str(config_path), prefix, args.dry_run, args.timeout,
                                 args.workers, args.require_solvable, args.max_retries)

    if not args.dry_run:
        _write_metadata(train_dir, True,  train_success, str(config_path))
        _write_metadata(test_dir,  False, test_success,  str(config_path))

        # Accumulate counts when appending to an existing manifest.
        manifest_path = out_root / "manifest.json"
        prior_train = prior_test = 0
        if append_mode and manifest_path.exists():
            with open(manifest_path) as f:
                prior = json.load(f)
            prior_train = prior.get("train_count", 0)
            prior_test  = prior.get("test_count",  0)

        manifest = {
            "config":       str(config_path),
            "domain":       domain_name,
            "train_count":  prior_train + train_success,
            "test_count":   prior_test  + test_success,
            "total":        prior_train + train_success + prior_test + test_success,
            "generated_at": datetime.now().isoformat(),
        }
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"\n  Manifest: {manifest_path}")

    print("\n  Generation Complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
