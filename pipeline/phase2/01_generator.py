#!/usr/bin/env python3
"""
pipeline/phase2/01_generator.py
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
python3 pipeline/phase2/01_generator.py \
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

    # Use the scenario number as the random seed for reproducibility.
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
    parser.add_argument("--timeout", type=int, default=300,
                        help="Per-scenario timeout in seconds (default: 300)")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4,
                        help="Parallel worker processes for generation (default: cpu_count)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be generated without running cli.py")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.is_file():
        print(f"Error: config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    domain_name = config_path.stem
    out_root    = Path(args.out_dir) / domain_name
    out_root.mkdir(parents=True, exist_ok=True)

    prefix = f"CyberBattleSim-{domain_name.replace('_','-')}"

    print("=" * 60)
    print("  SCENARIO GENERATOR (Fixed Scale)")
    print("=" * 60)
    print(f"  Config    : {config_path}")
    print(f"  Domain    : {domain_name}")
    print(f"  Out dir   : {out_root.resolve()}")
    print(f"  Count     : {args.train} train / {args.test} test")
    print(f"  Workers   : {args.workers}")
    print(f"  Total     : {args.train + args.test} scenarios{'  [DRY RUN]' if args.dry_run else ''}")
    print("=" * 60)

    # --- Train (parallel) ---
    train_dir = out_root / "train"
    train_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n  Generating Train ({args.train} scenarios)...")
    train_jobs = [(_TRAIN_OFFSET + i, train_dir) for i in range(1, args.train + 1)]
    train_success = _run_parallel(train_jobs, str(config_path), prefix, args.dry_run, args.timeout, args.workers)
    
    # --- Test (parallel) ---
    test_dir = out_root / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    print(f"  Generating Test ({args.test} scenarios)...")
    test_jobs = [(_TEST_OFFSET + i, test_dir) for i in range(1, args.test + 1)]
    test_success = _run_parallel(test_jobs, str(config_path), prefix, args.dry_run, args.timeout, args.workers)

    if not args.dry_run:
        _write_metadata(train_dir, True,  train_success, str(config_path))
        _write_metadata(test_dir,  False, test_success,  str(config_path))

        # Write a generation manifest
        manifest = {
            "config":       str(config_path),
            "domain":       domain_name,
            "train_count":  train_success,
            "test_count":   test_success,
            "total":        train_success + test_success,
            "generated_at": datetime.now().isoformat(),
        }
        manifest_path = out_root / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"\n  Manifest: {manifest_path}")

    print("\n  Generation Complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
