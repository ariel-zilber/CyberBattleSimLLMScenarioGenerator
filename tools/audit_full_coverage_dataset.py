#!/usr/bin/env python3
"""
Audit a specialist full-coverage CyberBattleSim dataset output.

The script is intentionally read-only. It compares expected specialist config
templates against a generated output root, checks physical train/test folders,
run_metrics availability, solve/full-goal status, quality scores, and
config-to-instance Solvability.* coverage.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT_FOR_IMPORT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT_FOR_IMPORT not in sys.path:
    sys.path.insert(0, _REPO_ROOT_FOR_IMPORT)
from tools.slot_scan import SOLVABILITY_RE, observed_solvability_slots


ARCHIVE_MARKERS = ("partial", "PARTIAL", "FAILED", "ARCHIVE")


def _make_tolerant_loader():
    class TolerantLoader(yaml.SafeLoader):
        pass

    def _ignore_unknown(loader, _tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_mapping(node, deep=True)

    TolerantLoader.add_multi_constructor("", _ignore_unknown)
    return TolerantLoader


TOLERANT_LOADER = _make_tolerant_loader()


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"_parse_error": str(exc)}


def read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=TOLERANT_LOADER) or {}
    except Exception as exc:
        return {"_parse_error": str(exc)}


def scenario_number(path: Path) -> int | None:
    try:
        return int(path.name.rsplit("-", 1)[-1])
    except Exception:
        return None


def config_defined_slots(config_path: Path) -> set[str]:
    cfg = read_yaml(config_path)
    slots: set[str] = set()
    for entries in cfg.get("solvability_vulnerabilities", {}).values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict):
                name = entry.get("name", "")
                if isinstance(name, str) and name.startswith("Solvability."):
                    slots.add(name)
    for vuln in cfg.get("start_node", {}).get("vulnerabilities", {}).values():
        if isinstance(vuln, dict):
            name = vuln.get("name", "")
            if isinstance(name, str) and name.startswith("Solvability."):
                slots.add(name)
    return slots


def observed_instance_slots(scenarios_dir: Path) -> set[str]:
    """Delegates to tools.slot_scan's shared extractor so this and
    check_dataset_coverage.py can never disagree on the same dataset
    (problem #10 in the validation report)."""
    return observed_solvability_slots(scenarios_dir)


def split_inventory(split_dir: Path, expected_start: int, expected_end: int) -> dict[str, Any]:
    expected = set(range(expected_start, expected_end + 1))
    dirs: list[Path] = sorted(
        [p for p in split_dir.glob("CyberBattleSim-*") if p.is_dir()],
        key=lambda p: scenario_number(p) if scenario_number(p) is not None else 10**9,
    )
    dir_nums = {n for p in dirs if (n := scenario_number(p)) is not None}
    nodes_nums = {scenario_number(p) for p in dirs if (p / "nodes").is_dir()}
    metrics_nums = {scenario_number(p) for p in dirs if (p / "run_metrics.json").exists()}
    nodes_nums.discard(None)
    metrics_nums.discard(None)
    return {
        "dir_count": len(dirs),
        "nodes_count": len(nodes_nums),
        "run_metrics_count": len(metrics_nums),
        "missing_expected_dirs": sorted(expected - dir_nums),
        "extra_dirs": sorted(dir_nums - expected),
        "dirs_without_nodes": sorted(dir_nums - nodes_nums),
        "dirs_without_run_metrics": sorted(dir_nums - metrics_nums),
        "run_metrics_ids": sorted(metrics_nums),
    }


def collect_run_metrics(scenarios_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    metrics: list[dict[str, Any]] = []
    parse_errors: list[str] = []
    for path in sorted(scenarios_dir.rglob("run_metrics.json")):
        data = read_json(path)
        if "_parse_error" in data:
            parse_errors.append(str(path))
            continue
        data["_path"] = str(path)
        data["_split"] = "train" if "/train/" in str(path) else "test" if "/test/" in str(path) else "unknown"
        metrics.append(data)
    return metrics, parse_errors


def summarize_metrics(metrics: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(metrics)
    solved = sum(1 for m in metrics if m.get("is_solved") is True)
    full_goals = sum(1 for m in metrics if m.get("goals_captured_ratio", 0) == 1.0)
    by_split: dict[str, Counter[str]] = defaultdict(Counter)
    for m in metrics:
        split = m.get("_split", "unknown")
        by_split[split]["total"] += 1
        if m.get("is_solved") is True:
            by_split[split]["solved"] += 1
        if m.get("goals_captured_ratio", 0) == 1.0:
            by_split[split]["full_goals"] += 1

    def mean(path: tuple[str, ...], default: float = 0.0) -> float:
        vals: list[float] = []
        for m in metrics:
            cur: Any = m
            for key in path:
                if not isinstance(cur, dict):
                    cur = None
                    break
                cur = cur.get(key)
            if isinstance(cur, (int, float)):
                vals.append(float(cur))
        return round(sum(vals) / len(vals), 4) if vals else default

    outcomes = Counter()
    difficulty = []
    replay_rates = []
    for m in metrics:
        outcomes.update(m.get("action_outcomes", {}))
        diff = m.get("difficulty", {})
        if isinstance(diff, dict) and isinstance(diff.get("score"), (int, float)):
            difficulty.append(float(diff["score"]))
        replay = m.get("replay_verification", {})
        if isinstance(replay, dict) and isinstance(replay.get("success_rate"), (int, float)):
            replay_rates.append(float(replay["success_rate"]))

    return {
        "run_metrics": total,
        "solved": solved,
        "full_goals": full_goals,
        "solve_rate_from_files": round(solved / total, 4) if total else 0.0,
        "full_goal_rate_from_files": round(full_goals / total, 4) if total else 0.0,
        "by_split": {k: dict(v) for k, v in sorted(by_split.items())},
        "mean_node_count": mean(("topology_metrics", "routing", "node_count")),
        "mean_diameter": mean(("topology_metrics", "routing", "diameter")),
        "mean_density": mean(("topology_metrics", "routing", "density")),
        "mean_credentials_discovered": mean(("credentials_discovered",)),
        "mean_steps_taken": mean(("steps_taken",)),
        "difficulty_score_mean": round(sum(difficulty) / len(difficulty), 4) if difficulty else 0.0,
        "difficulty_score_min": round(min(difficulty), 4) if difficulty else 0.0,
        "difficulty_score_max": round(max(difficulty), 4) if difficulty else 0.0,
        "replay_success_rate_mean": round(sum(replay_rates) / len(replay_rates), 4) if replay_rates else None,
        "outcome_totals": dict(outcomes),
    }


def classify_status(template: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    manifest = template.get("manifest", {})
    train_manifest = manifest.get("train_count")
    test_manifest = manifest.get("test_count")
    train = template["train"]
    test = template["test"]
    metrics = template["metrics_summary"]
    quality = template.get("quality", {})
    coverage = template.get("coverage", {})

    if train_manifest != 40 or test_manifest != 10:
        issues.append("manifest_not_40_10")
    if train["dir_count"] != 40 or test["dir_count"] != 10:
        issues.append("physical_count_not_40_10")
    if train["run_metrics_count"] != train["dir_count"] or test["run_metrics_count"] != test["dir_count"]:
        issues.append("missing_run_metrics")
    if metrics["run_metrics"] != 50:
        issues.append("evaluated_count_not_50")
    if metrics["solved"] != metrics["run_metrics"]:
        issues.append("unsolved_instances")
    if metrics["full_goals"] != metrics["run_metrics"]:
        issues.append("partial_goal_instances")
    score = quality.get("overall_score")
    if not isinstance(score, (int, float)):
        issues.append("missing_quality_score")
    elif score < 8.0:
        issues.append("quality_below_8")
    if coverage and coverage.get("missing_slots"):
        issues.append("config_slots_missing_in_instances")
    step_manifest = template.get("step_manifest", {})
    terminal = step_manifest.get("4", {}).get("status")
    if terminal not in (None, "completed"):
        issues.append(f"step4_{terminal}")
    return issues


def audit_template(output_root: Path, config_path: Path) -> dict[str, Any]:
    name = config_path.stem
    domain_root = output_root / name
    manifest = read_json(domain_root / "scenarios" / "manifest.json")
    metrics, parse_errors = collect_run_metrics(domain_root / "scenarios")
    quality = read_json(domain_root / "metrics" / "quality_evaluation.json")
    bfs = read_json(domain_root / "metrics" / "bfs_metrics.json")
    step_manifest = read_json(domain_root / "metrics" / "step_manifest.json")
    config_final = domain_root / "config" / "02_enriched.yaml"
    config_for_slots = config_final if config_final.exists() else config_path
    defined = config_defined_slots(config_for_slots)
    observed = observed_instance_slots(domain_root / "scenarios")
    missing_slots = sorted(defined - observed)
    coverage = {
        "defined_slots": len(defined),
        "observed_defined_slots": len(defined & observed),
        "missing_slots": missing_slots,
        "coverage": round(len(defined & observed) / max(len(defined), 1), 4),
        "pass": not missing_slots,
    }
    cfg = read_yaml(config_for_slots)
    result = {
        "name": name,
        "present": domain_root.is_dir(),
        "config": str(config_path),
        "final_config": str(config_final) if config_final.exists() else None,
        "agent": cfg.get("metadata", {}).get("agent"),
        "fixed_specialists": cfg.get("metadata", {}).get("fixed_specialists")
        or cfg.get("metadata", {}).get("primary_specialists")
        or [],
        "terminal_goal": cfg.get("metadata", {}).get("terminal_goal"),
        "manifest": manifest,
        "train": split_inventory(domain_root / "scenarios" / "train", 1, 40),
        "test": split_inventory(domain_root / "scenarios" / "test", 10001, 10010),
        "run_metrics_parse_errors": parse_errors,
        "metrics_summary": summarize_metrics(metrics),
        "bfs_metrics": {
            "n_scenarios": bfs.get("n_scenarios"),
            "solved": bfs.get("solved"),
            "solve_rate": bfs.get("solve_rate"),
            "goal_full_pct": bfs.get("goal_completeness", {}).get("pct_scenarios_all_goals")
            if isinstance(bfs.get("goal_completeness"), dict)
            else None,
            "mean_diameter": bfs.get("mean_diameter"),
            "mean_density": bfs.get("mean_density"),
            "mean_node_count": bfs.get("mean_node_count"),
            "mean_creds": bfs.get("mean_creds"),
            "outcome_totals": bfs.get("outcome_totals", {}),
        },
        "quality": {
            "overall_score": quality.get("overall_score"),
            "overall_grade": quality.get("overall_grade"),
            "dimension_scores": {
                key: value.get("score")
                for key, value in quality.get("dimensions", {}).items()
                if isinstance(value, dict)
            },
        },
        "coverage": coverage,
        "step_manifest": step_manifest,
        "reports": {
            "phase1_summary": (domain_root / "reports" / "phase1_summary.txt").exists(),
            "phase2_eda_txt": (domain_root / "reports" / "phase2_eda.txt").exists(),
            "phase2_eda_pdf": (domain_root / "reports" / "phase2_eda.pdf").exists(),
            "figures_count": len(list((domain_root / "reports" / "figures").glob("*")))
            if (domain_root / "reports" / "figures").is_dir()
            else 0,
        },
    }
    result["issues"] = classify_status(result)
    return result


def aggregate(templates: list[dict[str, Any]], output_root: Path, expected_names: set[str]) -> dict[str, Any]:
    final_dirs = [
        p.name
        for p in output_root.iterdir()
        if p.is_dir() and p.name.startswith("specialist_") and not any(marker in p.name for marker in ARCHIVE_MARKERS)
    ]
    archive_dirs = [
        p.name
        for p in output_root.iterdir()
        if p.is_dir() and p.name.startswith("specialist_") and any(marker in p.name for marker in ARCHIVE_MARKERS)
    ]
    scores = [
        t["quality"]["overall_score"]
        for t in templates
        if isinstance(t["quality"].get("overall_score"), (int, float))
    ]
    dimension_values: dict[str, list[float]] = defaultdict(list)
    for t in templates:
        for dim, score in t["quality"].get("dimension_scores", {}).items():
            if isinstance(score, (int, float)):
                dimension_values[dim].append(float(score))

    issue_counts = Counter(issue for t in templates for issue in t["issues"])
    outcome_totals = Counter()
    for t in templates:
        outcome_totals.update(t["metrics_summary"].get("outcome_totals", {}))

    intended = 50 * len(expected_names)
    physical = sum(t["train"]["dir_count"] + t["test"]["dir_count"] for t in templates)
    evaluated = sum(t["metrics_summary"]["run_metrics"] for t in templates)
    solved = sum(t["metrics_summary"]["solved"] for t in templates)
    full_goals = sum(t["metrics_summary"]["full_goals"] for t in templates)

    return {
        "expected_templates": len(expected_names),
        "final_dirs": len(final_dirs),
        "archive_or_partial_dirs": sorted(archive_dirs),
        "missing_final_dirs": sorted(expected_names - set(final_dirs)),
        "unexpected_final_dirs": sorted(set(final_dirs) - expected_names),
        "intended_scenarios": intended,
        "physical_scenario_dirs": physical,
        "evaluated_scenarios": evaluated,
        "solved_evaluated_scenarios": solved,
        "full_goal_evaluated_scenarios": full_goals,
        "physical_coverage_rate": round(physical / intended, 4) if intended else 0.0,
        "evaluation_coverage_rate": round(evaluated / intended, 4) if intended else 0.0,
        "solve_rate_over_evaluated": round(solved / evaluated, 4) if evaluated else 0.0,
        "full_goal_rate_over_evaluated": round(full_goals / evaluated, 4) if evaluated else 0.0,
        "quality_score": {
            "count": len(scores),
            "min": min(scores) if scores else None,
            "max": max(scores) if scores else None,
            "mean": round(statistics.mean(scores), 4) if scores else None,
            "below_8": sum(1 for s in scores if s < 8.0),
        },
        "dimension_score_summary": {
            dim: {
                "min": min(vals),
                "max": max(vals),
                "mean": round(statistics.mean(vals), 4),
            }
            for dim, vals in sorted(dimension_values.items())
        },
        "issue_counts": dict(issue_counts),
        "outcome_totals": dict(outcome_totals),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("output_specialists_full_coverage_20260628_014243"),
        help="Generated output root to audit.",
    )
    parser.add_argument(
        "--configs",
        type=Path,
        default=Path("data/scenarios/specialists"),
        help="Directory containing expected specialist config YAMLs.",
    )
    parser.add_argument("--out", type=Path, default=None, help="Write JSON audit to this path.")
    args = parser.parse_args()

    configs = sorted(args.configs.glob("*.yaml"))
    expected_names = {p.stem for p in configs}
    templates = [audit_template(args.root, config) for config in configs]
    result = {
        "output_root": str(args.root),
        "configs_dir": str(args.configs),
        "summary": aggregate(templates, args.root, expected_names),
        "templates": templates,
    }

    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
