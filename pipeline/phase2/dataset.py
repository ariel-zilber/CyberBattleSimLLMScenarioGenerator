#!/usr/bin/env python3
"""
tools/generate_dataset.py
==========================
Generate a fully-solvable stratified dataset.

Algorithm:
  1. Divide --count equally across all supplied configs (and strata/splits).
  2. Generate a batch in parallel.
  3. Run BFS planner on every scenario (sequential, in-process).
  4. Delete unsolvable scenarios; regenerate them with new seeds.
  5. Repeat until every slot is solvable, or --max-retries is exhausted.

The output tree is identical to phase2_generator but every scenario is
guaranteed to have is_solved=True in its run_metrics.json.

Usage
-----
# 120 solvable scenarios from one config (90 train / 30 test):
python3 tools/generate_dataset.py \\
    --config data/enterprise_ad_v5.yaml \\
    --count 120 \\
    --out-dir /content/drive/MyDrive/thesis/code/datasets/poc/claude/phase2

# 120 scenarios equally split across 3 configs (40 each):
python3 tools/generate_dataset.py \\
    --config data/enterprise_ad_v6.yaml data/jenkins_cicd_v2.yaml data/scada_ics_v2.yaml \\
    --count 120 \\
    --out-dir /tmp/multi

# Multiple configs with custom output folder names:
python3 tools/generate_dataset.py \\
    --config data/enterprise_ad_v6.yaml data/scada_ics_v2.yaml \\
    --name enterprise_ad scada_ics \\
    --count 60 \\
    --out-dir /tmp/renamed

# Only small stratum, 30 scenarios total:
python3 tools/generate_dataset.py \\
    --config data/enterprise_ad_v5.yaml \\
    --count 30 \\
    --out-dir /tmp/test \\
    --strata small
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
_TOOLS_DIR  = str(Path(__file__).resolve().parent)
for _p in (_REPO_ROOT, _TOOLS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

DEFAULT_STRATA: Dict[str, Dict[str, int]] = {
    "small":  {"min_total_nodes": 30,  "max_total_nodes": 80},
    "medium": {"min_total_nodes": 80,  "max_total_nodes": 180},
    "large":  {"min_total_nodes": 180, "max_total_nodes": 250},
}

_TRAIN_SEED_BASE = 0
_TEST_SEED_BASE  = 10_000
_RETRY_SEED_STEP = 100_000  # each retry round shifts seeds by this amount


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _scale_config(cfg: dict, scale: float) -> dict:
    """Proportionally scale all group node counts and total node bounds.

    Preserves domain structural identity: the ratio of DomainControllers to
    Workstations to FileServers stays constant — only the absolute numbers grow.
    Both per-group counts and config.min/max_total_nodes are multiplied by scale.
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
    cfg = {k: v for k, v in base_cfg.items()}
    top = dict(cfg.get("config", {}))
    top["min_total_nodes"] = stratum_bounds["min_total_nodes"]
    top["max_total_nodes"] = stratum_bounds["max_total_nodes"]
    cfg["config"] = top
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, prefix="gendataset_"
    )
    yaml.dump(cfg, tmp, default_flow_style=False, allow_unicode=True)
    tmp.close()
    return tmp.name


# ---------------------------------------------------------------------------
# Parallel generation
# ---------------------------------------------------------------------------

def _gen_one_worker(config_path: str, out_dir_str: str, seed: int) -> bool:
    """Top-level worker — must be picklable for ProcessPoolExecutor."""
    repo_root = str(Path(__file__).resolve().parent.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    out_dir = Path(out_dir_str)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        from cli import generate_scenario
        generate_scenario(config_path, str(out_dir), seed=seed)
        return True
    except Exception as exc:
        print(f"    ✗ seed={seed}: {exc}")
        shutil.rmtree(out_dir, ignore_errors=True)
        return False


def _generate_batch(
    jobs: List[Tuple[str, int]],  # (out_dir_str, seed)
    config_path: str,
    workers: int,
) -> Dict[str, bool]:            # out_dir_str -> success
    results: Dict[str, bool] = {}
    total = len(jobs)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_gen_one_worker, config_path, d, s): d
            for d, s in jobs
        }
        done = 0
        for fut in as_completed(futures):
            done += 1
            out_dir = futures[fut]
            try:
                results[out_dir] = fut.result()
            except Exception:
                results[out_dir] = False
            if done % 5 == 0 or done == total:
                print(f"    Generation: {done}/{total} complete", end="\r")
    print()
    return results


# ---------------------------------------------------------------------------
# BFS verification (sequential — one env at a time)
# ---------------------------------------------------------------------------

def _bfs_verify(
    scenario_dir: Path,
    steps: int,
    episodes: int,
    max_bfs_steps: Optional[int] = None,
    max_random_avg_steps: Optional[int] = None,
) -> bool:
    """Run BFS + random-baseline on one scenario.

    Returns True only when ALL active conditions pass:
      - BFS solves the scenario
      - steps_to_first_goal <= max_bfs_steps        (if set)
      - random baseline avg_steps <= max_random_avg_steps  (if set; None avg = never solved = fail)
    """
    from test_env_integration import test_dynamic_solve  # lazy import
    try:
        solved, _ = test_dynamic_solve(
            scenario_dir, max_steps=steps, max_episodes=episodes
        )
        if not solved:
            return False

        if max_bfs_steps is None and max_random_avg_steps is None:
            return True

        metrics_file = scenario_dir / "run_metrics.json"
        with open(metrics_file) as f:
            metrics = json.load(f)

        if max_bfs_steps is not None:
            bfs_steps = metrics.get("steps_to_first_goal") or 0
            if bfs_steps > max_bfs_steps:
                print(f"      ✗ BFS steps {bfs_steps} > limit {max_bfs_steps}")
                return False

        if max_random_avg_steps is not None:
            rb = metrics.get("greedy_baseline", {})
            avg = rb.get("avg_steps")
            if avg is None:
                print(f"      ✗ Greedy agent never solved (no avg_steps)")
                return False
            if avg > max_random_avg_steps:
                print(f"      ✗ Greedy avg steps {avg:.1f} > limit {max_random_avg_steps}")
                return False

        return True
    except Exception as exc:
        print(f"    [BFS error] {scenario_dir.name}: {exc}")
        return False


# ---------------------------------------------------------------------------
# Per-stratum loop
# ---------------------------------------------------------------------------

def _is_already_solved(slot_dir: Path) -> bool:
    """Return True if the slot already has a run_metrics.json with is_solved=True."""
    metrics_file = slot_dir / "run_metrics.json"
    if not metrics_file.exists():
        return False
    try:
        with open(metrics_file) as f:
            data = json.load(f)
        return bool(data.get("is_solved", False))
    except Exception:
        return False


def generate_stratum(
    base_cfg: dict,
    stratum_name: str,
    stratum_bounds: Dict[str, int],
    domain_name: str,
    out_root: Path,
    train_count: int,
    test_count: int,
    max_retries: int,
    episodes: int,
    steps: int,
    workers: int,
    resume: bool = False,
    max_bfs_steps: Optional[int] = None,
    max_random_avg_steps: Optional[int] = None,
) -> Tuple[int, int]:
    """
    Fill train_count + test_count solvable scenario slots for one stratum.
    Unsolvable results are deleted and regenerated with new seeds.
    Returns (train_solved, test_solved).
    """
    tmp_config = _write_temp_config(base_cfg, stratum_bounds)
    prefix = f"CyberBattleSim-{domain_name.replace('_', '-')}-{stratum_name}"
    split_results: Dict[str, int] = {}

    for split, target, seed_base in [
        ("train", train_count, _TRAIN_SEED_BASE),
        ("test",  test_count,  _TEST_SEED_BASE),
    ]:
        if target == 0:
            split_results[split] = 0
            continue

        out_dir = out_root / domain_name / split / stratum_name
        out_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n  [{stratum_name.upper()}/{split}]  target={target} solvable scenarios")

        # Skip slots that are already solved (resume mode)
        if resume:
            pending_slots = []
            already = 0
            for slot in range(1, target + 1):
                slot_dir = out_dir / f"{prefix}-{slot:04d}"
                if _is_already_solved(slot_dir):
                    already += 1
                else:
                    pending_slots.append(slot)
            if already:
                print(f"    --resume: {already} slot(s) already solved, skipping")
        else:
            pending_slots: List[int] = list(range(1, target + 1))

        retry_forever = (max_retries == 0)
        attempt = 0
        while pending_slots:
            attempt += 1
            if not retry_forever and attempt > max_retries:
                break

            seed_offset = seed_base + (attempt - 1) * _RETRY_SEED_STEP
            limit_str = "∞" if retry_forever else str(max_retries)
            print(f"\n    Attempt {attempt}/{limit_str}: filling {len(pending_slots)} slot(s) ...")

            gen_jobs: List[Tuple[str, int]] = []
            for slot in pending_slots:
                slot_dir = out_dir / f"{prefix}-{slot:04d}"
                if slot_dir.exists():
                    shutil.rmtree(slot_dir)
                gen_jobs.append((str(slot_dir), seed_offset + slot))

            gen_ok = _generate_batch(gen_jobs, tmp_config, workers)

            new_pending: List[int] = []
            for slot in pending_slots:
                slot_dir = out_dir / f"{prefix}-{slot:04d}"
                dir_ok = gen_ok.get(str(slot_dir), False)
                if not dir_ok or not slot_dir.exists():
                    print(f"    slot {slot:04d}: generation failed — will retry")
                    new_pending.append(slot)
                    continue

                print(f"    slot {slot:04d}: verifying ...", end=" ", flush=True)
                passed = _bfs_verify(
                    slot_dir, steps, episodes,
                    max_bfs_steps=max_bfs_steps,
                    max_random_avg_steps=max_random_avg_steps,
                )
                if passed:
                    print("✓ accepted")
                else:
                    print("✗ rejected — queued for regeneration")
                    shutil.rmtree(slot_dir, ignore_errors=True)
                    new_pending.append(slot)

            solved_now = target - len(new_pending)
            print(f"\n    [{stratum_name}/{split}] attempt {attempt}: {solved_now}/{target} accepted")
            pending_slots = new_pending

        if pending_slots:
            print(
                f"  [WARN] [{stratum_name}/{split}] {len(pending_slots)} slot(s) still unsolved "
                f"after {attempt} attempts — dataset slot(s) left empty."
            )

        total_solved = target - len(pending_slots)
        split_results[split] = total_solved
        _write_metadata(out_dir, split == "train", total_solved, stratum_name, tmp_config)

    try:
        os.unlink(tmp_config)
    except OSError:
        pass

    return split_results.get("train", 0), split_results.get("test", 0)


def _write_metadata(
    out_dir: Path, is_train: bool, success: int, stratum: str, config_file: str
):
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
# Summary
# ---------------------------------------------------------------------------

def _print_summary(
    stats: Dict[str, Tuple[int, int]],
    train_target: int,
    test_target: int,
    out_root: Path,
):
    print()
    print("=" * 62)
    print("  GENERATE DATASET — FINAL SUMMARY")
    print("=" * 62)
    print(f"  {'Stratum':<10} {'Train':>10} {'Test':>10} {'Total':>10}")
    print(f"  {'-'*10} {'-'*10} {'-'*10} {'-'*10}")
    grand_train = grand_test = 0
    for stratum, (tr, te) in stats.items():
        print(f"  {stratum:<10} {tr:>10} {te:>10} {tr + te:>10}")
        grand_train += tr
        grand_test  += te
    print(f"  {'TOTAL':<10} {grand_train:>10} {grand_test:>10} {grand_train + grand_test:>10}")
    n_strata = len(stats)
    target_total = (train_target + test_target) * n_strata
    achieved = grand_train + grand_test
    pct = achieved / max(target_total, 1) * 100
    print(f"\n  Achieved : {achieved}/{target_total} solvable scenarios ({pct:.1f}%)")
    print(f"  Output   : {out_root.resolve()}")
    print("=" * 62)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _distribute(total: int, n: int) -> List[int]:
    """Distribute total into n parts as evenly as possible (remainder to first parts)."""
    base, rem = divmod(total, n)
    return [base + (1 if i < rem else 0) for i in range(n)]


def main():
    parser = argparse.ArgumentParser(
        description="Generate a fully-solvable stratified CyberBattleSim dataset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--config", required=True, nargs="+", metavar="YAML",
        help="One or more domain config YAMLs. With multiple configs the total "
             "--count is divided equally across them.",
    )
    parser.add_argument(
        "--name", nargs="*", metavar="NAME", default=None,
        help="Optional output folder name(s) — one per --config, in the same order. "
             "Defaults to the config filename stem.",
    )
    parser.add_argument(
        "--count", type=int, default=120, metavar="N",
        help="Total solvable scenarios to produce across all configs and strata (default: 120)",
    )
    parser.add_argument(
        "--out-dir", required=True, metavar="DIR",
        help="Root output directory",
    )
    parser.add_argument(
        "--strata", nargs="+",
        choices=list(DEFAULT_STRATA.keys()),
        default=list(DEFAULT_STRATA.keys()),
        help="Which strata to generate (default: small medium large)",
    )
    parser.add_argument(
        "--split", type=float, default=0.75, metavar="FRAC",
        help="Train fraction of each stratum's count (default: 0.75)",
    )
    parser.add_argument(
        "--workers", type=int, default=os.cpu_count() or 4,
        help="Parallel generation workers (default: cpu_count)",
    )
    parser.add_argument(
        "--episodes", type=int, default=5,
        help="BFS episodes per scenario (default: 5)",
    )
    parser.add_argument(
        "--steps", type=int, default=10_000,
        help="BFS max steps per episode (default: 10 000)",
    )
    parser.add_argument(
        "--max-retries", type=int, default=5,
        help="Max regeneration attempts per slot (default: 5). Use 0 to retry forever.",
    )
    parser.add_argument(
        "--max-bfs-steps", type=int, default=None, metavar="N",
        help="Reject scenario if BFS steps_to_first_goal exceeds N. Retries forever when set (unless --max-retries given).",
    )
    parser.add_argument(
        "--max-random-avg-steps", type=int, default=None, metavar="N",
        help="Reject scenario if random-agent avg steps to goal exceeds N, or if random never solves it. Retries forever when set.",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Skip slots that already have is_solved=True in run_metrics.json",
    )
    parser.add_argument(
        "--scale", type=float, default=1.0, metavar="FACTOR",
        help="Proportionally scale all per-group node counts and total node bounds "
             "(default: 1.0 = no scaling). E.g. --scale 3 produces scenarios that "
             "are structurally identical to the base config but 3× larger in every "
             "service group, keeping domain identity across sizes.",
    )
    args = parser.parse_args()

    # --- Validate config paths ---
    config_paths = [Path(c) for c in args.config]
    for cp in config_paths:
        if not cp.is_file():
            print(f"Error: config not found: {cp}", file=sys.stderr)
            sys.exit(1)

    # --- Validate / build name list ---
    if args.name is not None:
        if len(args.name) != len(config_paths):
            print(
                f"Error: --name has {len(args.name)} value(s) but "
                f"--config has {len(config_paths)}. They must match.",
                file=sys.stderr,
            )
            sys.exit(1)
        domain_names = args.name
    else:
        domain_names = [cp.stem for cp in config_paths]

    if not 0.0 < args.split < 1.0:
        print("Error: --split must be between 0 and 1 exclusive", file=sys.stderr)
        sys.exit(1)
    if args.scale <= 0:
        print("Error: --scale must be > 0", file=sys.stderr)
        sys.exit(1)

    n_configs     = len(config_paths)
    out_root      = Path(args.out_dir)
    strata_to_run = {k: DEFAULT_STRATA[k] for k in args.strata}
    n_strata      = len(strata_to_run)

    # Distribute total count equally across configs
    counts_per_config = _distribute(args.count, n_configs)

    print("=" * 62)
    print("  GENERATE DATASET (BFS-verified, auto-replace)")
    print("=" * 62)
    print(f"  Configs     : {n_configs}")
    for cp, dn, cnt in zip(config_paths, domain_names, counts_per_config):
        label = f"{cp.name}" if dn == cp.stem else f"{cp.name}  →  {dn}"
        print(f"    {label}  ({cnt} scenarios)")
    print(f"  Out dir     : {out_root.resolve()}")
    print(f"  Total count : {args.count}  ({n_configs} config(s) × ~{args.count // n_configs})")
    print(f"  Strata      : {', '.join(strata_to_run)}")
    print(f"  Split       : {args.split:.0%} train / {1-args.split:.0%} test per stratum")
    print(f"  Scale       : {args.scale}×" + (" (proportional group scaling applied)" if args.scale != 1.0 else " (no scaling)"))
    print(f"  Workers     : {args.workers}")
    print(f"  BFS         : {args.episodes} ep × {args.steps} steps")
    # When a filter is set and the user didn't explicitly set max-retries, default to infinite
    if (args.max_bfs_steps is not None or args.max_random_avg_steps is not None):
        if args.max_retries == 5:  # still the default — user didn't override it
            args.max_retries = 0

    retry_label = "∞ (retry forever)" if args.max_retries == 0 else str(args.max_retries)
    print(f"  Max retries : {retry_label} per slot")
    if args.max_bfs_steps is not None:
        print(f"  Filter BFS  : steps_to_first_goal ≤ {args.max_bfs_steps}")
    if args.max_random_avg_steps is not None:
        print(f"  Filter rand : random avg_steps ≤ {args.max_random_avg_steps} (must solve at least once)")
    if args.resume:
        print("  Resume      : ON (skipping already-solved slots)")
    print("=" * 62)

    out_root.mkdir(parents=True, exist_ok=True)

    # Pre-scale strata bounds when scale != 1.0 so total node targets are consistent
    if args.scale != 1.0:
        strata_to_run = {
            name: {
                "min_total_nodes": max(1, round(b["min_total_nodes"] * args.scale)),
                "max_total_nodes": max(1, round(b["max_total_nodes"] * args.scale)),
            }
            for name, b in strata_to_run.items()
        }

    all_stats: Dict[str, Dict[str, Tuple[int, int]]] = {}  # domain -> stratum -> (tr, te)

    for config_path, domain_name, config_count in zip(
        config_paths, domain_names, counts_per_config
    ):
        base_cfg = _scale_config(_load_config(str(config_path)), args.scale)

        per_stratum = math.ceil(config_count / n_strata)
        train_per   = math.ceil(per_stratum * args.split)
        test_per    = per_stratum - train_per

        print(f"\n{'='*62}")
        print(f"  CONFIG: {config_path.name}  →  domain={domain_name}")
        print(f"  Target: {config_count} scenarios  "
              f"({n_strata} strata × {per_stratum}  |  {train_per} train + {test_per} test/stratum)")
        print(f"{'='*62}")

        stats: Dict[str, Tuple[int, int]] = {}
        for stratum_name, bounds in strata_to_run.items():
            tr, te = generate_stratum(
                base_cfg             = base_cfg,
                stratum_name         = stratum_name,
                stratum_bounds       = bounds,
                domain_name          = domain_name,
                out_root             = out_root,
                train_count          = train_per,
                test_count           = test_per,
                max_retries          = args.max_retries,
                episodes             = args.episodes,
                steps                = args.steps,
                workers              = args.workers,
                resume               = args.resume,
                max_bfs_steps        = args.max_bfs_steps,
                max_random_avg_steps = args.max_random_avg_steps,
            )
            stats[stratum_name] = (tr, te)

        all_stats[domain_name] = stats
        _print_summary(stats, train_per, test_per, out_root)

        manifest = {
            "config":         str(config_path),
            "domain":         domain_name,
            "count_target":   config_count,
            "split_ratio":    args.split,
            "bfs_episodes":   args.episodes,
            "bfs_steps":      args.steps,
            "strata": {
                s: {
                    "bounds":       DEFAULT_STRATA[s],
                    "train_solved": stats[s][0],
                    "test_solved":  stats[s][1],
                }
                for s in strata_to_run
            },
            "generated_at": datetime.now().isoformat(),
        }
        manifest_path = out_root / domain_name / "dataset_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"\n  Manifest: {manifest_path}")

    # Combined summary when multiple configs were used
    if n_configs > 1:
        grand_train = grand_test = 0
        print(f"\n{'='*62}")
        print("  COMBINED SUMMARY  (all configs)")
        print(f"{'='*62}")
        print(f"  {'Domain':<30} {'Train':>8} {'Test':>8} {'Total':>8}")
        print(f"  {'-'*30} {'-'*8} {'-'*8} {'-'*8}")
        for dn, stats in all_stats.items():
            tr = sum(v[0] for v in stats.values())
            te = sum(v[1] for v in stats.values())
            print(f"  {dn:<30} {tr:>8} {te:>8} {tr+te:>8}")
            grand_train += tr
            grand_test  += te
        print(f"  {'TOTAL':<30} {grand_train:>8} {grand_test:>8} {grand_train+grand_test:>8}")
        pct = (grand_train + grand_test) / max(args.count, 1) * 100
        print(f"\n  Achieved : {grand_train+grand_test}/{args.count} ({pct:.1f}%)")
        print(f"  Output   : {out_root.resolve()}")
        print("=" * 62)


if __name__ == "__main__":
    main()
