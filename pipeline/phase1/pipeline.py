#!/usr/bin/env python3
"""
pipeline/phase1/pipeline.py
===========================
Standardized single-domain generation pipeline. 
Executes: fetch → merge → validate → visualise → generate → evaluate.

Follows the Standardized Pipeline Output Structure (specs/output_structure.md).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_env() -> dict:
    cfg: dict = {}
    env_path = REPO_ROOT / ".env"
    if env_path.exists():
        for raw in env_path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip()
    for k, v in os.environ.items():
        cfg[k] = v
    return cfg


_ENV = _load_env()
_DEFAULT_OUT_DIR = str(Path(_ENV.get("DATASET_ROOT", str(REPO_ROOT / "output"))))

# Map domain name → NVD keyword query + optional CPE fragment
DOMAIN_CVE_CONFIG: Dict[str, Dict[str, Any]] = {
    "active_directory": {
        "query":    "windows active directory kerberos lateral movement",
        "min_cvss": 7.0,
        "limit":    15,
    },
    "ot_scada": {
        "query":    "siemens s7 plc scada modbus industrial control",
        "min_cvss": 6.0,
        "limit":    15,
    },
    "web_application": {
        "query":    "web application sql injection remote code execution",
        "min_cvss": 7.0,
        "limit":    15,
    },
}

DEFAULT_DOMAIN_CVE = {
    "query":    "remote code execution privilege escalation",
    "min_cvss": 7.0,
    "limit":    10,
}

# ─────────────────────────────────────────────────────────────────────────────
# Colours / printing helpers
# ─────────────────────────────────────────────────────────────────────────────

class C:
    GREEN  = "\033[92m"; YELLOW = "\033[93m"; RED    = "\033[91m"
    BLUE   = "\033[94m"; BOLD   = "\033[1m";  END    = "\033[0m"
    CYAN   = "\033[96m"

def _hdr(step: int, title: str):
    bar = "═" * 64
    print(f"\n{C.BOLD}{C.BLUE}{bar}{C.END}")
    print(f"{C.BOLD}{C.BLUE}  STEP {step}: {title}{C.END}")
    print(f"{C.BOLD}{C.BLUE}{bar}{C.END}")

def _ok(msg):   print(f"  {C.GREEN}✓{C.END}  {msg}")
def _warn(msg): print(f"  {C.YELLOW}⚠{C.END}  {msg}")
def _err(msg):  print(f"  {C.RED}✗{C.END}  {msg}")
def _info(msg): print(f"  {C.CYAN}→{C.END}  {msg}")

# ─────────────────────────────────────────────────────────────────────────────
# Steps
# ─────────────────────────────────────────────────────────────────────────────

def step_fetch_vulns(domain: str, out_path: Path) -> bool:
    """Call nvd_scraper.py to get CVE templates."""
    cve_cfg = DOMAIN_CVE_CONFIG.get(domain, DEFAULT_DOMAIN_CVE)
    query   = cve_cfg["query"]
    limit   = cve_cfg["limit"]
    min_cvss= cve_cfg["min_cvss"]

    cmd = [
        sys.executable,
        str(REPO_ROOT / "pipeline" / "data_preprocessing" / "nvd_scraper.py"),
        "--query", query,
        "--min-cvss", str(min_cvss),
        "--limit",    str(limit),
        "--out",      str(out_path),
    ]
    _info(f"Fetching CVEs for query: '{query}'")

    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=120
    )
    if result.returncode != 0:
        _err(f"CVE fetch failed: {result.stderr}")
        return False

    if out_path.exists():
        _ok(f"Fetched CVE templates → {out_path.name}")
        return True
    return False


def step_merge_config(base_path: Path, vulns_path: Path, out_path: Path) -> int:
    """Call trivy_to_config.py to merge NVD data into the domain config."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "pipeline" / "data_preprocessing" / "trivy_to_config.py"),
        "--domain-config", str(base_path),
        "--trivy-json",    str(vulns_path),
        "--output",        str(out_path),
    ]
    _info("Merging vulnerability templates into domain config")
    
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=30
    )
    if result.returncode != 0:
        _err(f"Merge failed: {result.stderr}")
        return 0

    # Count vulns in resulting yaml
    try:
        with open(out_path) as f:
            cfg = yaml.safe_load(f)
            n = len(cfg.get("solvability_vulnerabilities", {}).get("remote_access", []))
            _ok(f"Enriched config ({n} remote vulns) → {out_path.name}")
            return n
    except Exception:
        return 0


def step_check_config(path: Path, out_json: Path) -> Tuple[int, int, dict]:
    """Call config_checker.py to validate the final YAML."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "pipeline" / "phase1" / "config_checker.py"),
        str(path),
    ]
    _info("Running static configuration checks")

    # The script prints to stdout and returns non-zero on error.
    # We want to capture the output but not fail the whole pipeline.
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=30
    )
    
    # We create a dummy JSON because the current config_checker doesn't output JSON yet.
    # (In a real refactor, config_checker.py would have a --json flag).
    data = {
        "valid":   result.returncode == 0,
        "stdout":  result.stdout,
        "stderr":  result.stderr,
        "errors":  [l for l in result.stdout.splitlines() if "✗" in l or "[error]" in l.lower()],
        "warnings": [l for l in result.stdout.splitlines() if "⚠" in l or "[warn]" in l.lower()]
    }
    with open(out_json, "w") as f:
        json.dump(data, f, indent=2)

    return len(data["errors"]), len(data["warnings"]), data


def step_visualise(config_path: Path, out_html: Path) -> bool:
    """Generate high-level DAG visualisation of the attack flow."""
    cmd = [
        sys.executable,
        str(REPO_ROOT / "pipeline" / "reporting" / "scenario_graph.py"),
        str(config_path),
        "--config",
        "--out",    str(out_html),
    ]
    _info("Generating topology visualization")
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=30
    )
    if result.returncode == 0:
        _ok(f"Visualization → {out_html.name}")
        return True
    else:
        _warn(f"Visualiser failed: {result.stderr}")
        return False


def step_generate(
    config_path: Path,
    out_dir: Path,
    train_count: int,
    test_count: int,
) -> Tuple[int, int]:
    """
    Call generator.py. Returns (total_train, total_test).
    """
    cmd = [
        sys.executable,
        str(REPO_ROOT / "pipeline" / "phase2" / "generator.py"),
        "--config",  str(config_path),
        "--out-dir", str(out_dir),
        "--train",   str(train_count),
        "--test",    str(test_count),
    ]
    _info(f"Generating {train_count} train + {test_count} test scenarios (Fixed Scale)")

    result = subprocess.run(
        cmd, text=True,
        cwd=str(REPO_ROOT), timeout=3600
    )

    if result.returncode != 0:
        _err("Generation step failed")
        return 0, 0

    # Count what was actually produced
    total_train = total_test = 0
    # Scenarios are now in out_dir/scenarios/[train|test]
    scenarios_root = out_dir / "scenarios"
    if scenarios_root.is_dir():
        for split in ["train", "test"]:
            split_root = scenarios_root / split
            if not split_root.is_dir():
                continue
            count = sum(1 for d in split_root.iterdir() if d.is_dir())
            if split == "train":
                total_train += count
            else:
                total_test  += count

    _ok(f"Generated {total_train} train scenarios")
    _ok(f"Generated {total_test} test scenarios")
    return total_train, total_test


def step_evaluate(
    scenarios_dir: Path,
    out_path: Path,
) -> dict:
    """
    Call evaluator.py to compute graph metrics.
    """
    cmd = [
        sys.executable,
        str(REPO_ROOT / "pipeline" / "phase2" / "evaluator.py"),
        "--data-dir", str(scenarios_dir),
        "--json",
    ]
    _info("Evaluating topological solvability and quality metrics")
    
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=1200
    )
    if result.returncode != 0:
        _err(f"Evaluation failed: {result.stderr}")
        return {}

    try:
        data = json.loads(result.stdout)
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        _ok(f"Metrics exported → {out_path.name}")
        return data
    except Exception as exc:
        _err(f"Failed to parse evaluation output: {exc}")
        return {}


def step_report(
    out_dir: Path,
    domain: str,
    eval_data: Optional[dict],
    check_data: dict,
    train_count: int,
    test_count: int,
    fetch_ok: bool,
    vulns_added: int,
    start_ts: float,
):
    """Generate the Phase 1 human-readable summary report."""
    report_path = out_dir / "reports" / "phase1_summary.txt"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    
    status = "SUCCESS" if eval_data and eval_data.get("aggregate", {}).get("solve_rate", 0) > 0.5 else "PARTIAL"
    
    lines = [
        "╔" + "═" * 66 + "╗",
        f"  PIPELINE REPORT: {domain.upper()}",
        f"  Status   : {status}",
        f"  Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "╚" + "═" * 66 + "╝",
        "",
        "GENERATION SUMMARY:",
        "─" * 66,
        f"  CVE Fetch    : {'✓' if fetch_ok else '✗'}",
        f"  Vulns Added  : {vulns_added}",
        f"  Train Count  : {train_count}",
        f"  Test Count   : {test_count}",
        f"  Duration     : {round(time.time()-start_ts, 1)}s",
        "",
    ]
    
    if eval_data:
        agg = eval_data.get("aggregate", {})
        lines += [
            "RUNTIME METRICS:",
            "─" * 66,
            f"  Solve Rate   : {agg.get('solve_rate', 0)*100:.1f}%",
            f"  Mean Steps   : {agg.get('mean_steps', 'N/A')}",
            f"  Mean Density : {agg.get('mean_density', 0):.3f}",
            f"  Mean Diameter: {agg.get('mean_diameter', 0):.1f}",
            "",
        ]

    report_path.write_text("\n".join(lines), encoding="utf-8")
    _ok(f"Final report → {report_path.relative_to(REPO_ROOT)}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Standardized CyberBattleSim Generation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--domain", help="Domain keyword (active_directory, ot_scada, web_application). "
                          "Looks for data/<domain>.yaml automatically.")
    src.add_argument("--config", metavar="YAML",
                     help="Explicit path to a domain config YAML")

    parser.add_argument("--train",  type=int, default=5,
                        help="Train scenarios (default: 5)")
    parser.add_argument("--test",   type=int, default=2,
                        help="Test scenarios (default: 2)")
    parser.add_argument("--out-dir", metavar="DIR", default=_DEFAULT_OUT_DIR,
                        help=f"Root output directory")
    parser.add_argument("--skip-fetch", action="store_true",
                        help="Skip NVD/EPSS fetch, use base config as-is")
    parser.add_argument("--skip-generate", action="store_true",
                        help="Skip scenario generation (evaluate existing scenarios)")
    args = parser.parse_args()

    # Resolve config path and domain name
    if args.config:
        config_path = Path(args.config).resolve()
        domain = config_path.stem
    elif args.domain:
        domain = args.domain
        config_path = REPO_ROOT / "data" / f"{domain}.yaml"
    else:
        domain = "active_directory"
        config_path = REPO_ROOT / "data" / "active_directory.yaml"

    if not config_path.is_file():
        print(f"Error: config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # NEW STRUCTURE: output/<domain>/
    domain_root = Path(args.out_dir) / domain
    config_dir  = domain_root / "config"
    sc_dir      = domain_root / "scenarios" # this will contain scenarios/train and scenarios/test
    metric_dir  = domain_root / "metrics"
    rep_dir     = domain_root / "reports"

    for d in [config_dir, sc_dir, metric_dir, rep_dir]:
        d.mkdir(parents=True, exist_ok=True)

    start_ts = time.time()

    print(f"\n{C.BOLD}{C.BLUE}{'═'*64}{C.END}")
    print(f"{C.BOLD}{C.BLUE}  CyberBattleSim Generation Pipeline (Monolithic){C.END}")
    print(f"{C.BOLD}{C.BLUE}{'═'*64}{C.END}")
    print(f"  Domain   : {domain}")
    print(f"  Config   : {config_path}")
    print(f"  Out dir  : {domain_root.resolve()}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Step 1+2: Fetch CVEs ──────────────────────────────────────────────────
    _hdr(1, "FETCH CVEs FROM NVD + EPSS + CISA KEV")
    fetched_path = config_dir / "01_fetched_vulns.yaml"
    enriched_path = config_dir / "02_enriched.yaml"
    fetch_ok = False
    vulns_added = 0

    if args.skip_fetch:
        _info("--skip-fetch: skipping vulnerability enrichment")
        shutil.copy(config_path, enriched_path)
        # Create a dummy fetched file for completeness
        fetched_path.write_text("solvability_vulnerabilities: {}\n")
        fetch_ok = True
    else:
        fetch_ok = step_fetch_vulns(domain, fetched_path)
        if fetch_ok:
            _hdr(3, "MERGE FETCHED VULNS INTO DOMAIN CONFIG")
            vulns_added = step_merge_config(config_path, fetched_path, enriched_path)
        else:
            _warn("CVE fetch failed — using base config for generation")
            shutil.copy(config_path, enriched_path)

    # ── Step 4: Validate config ───────────────────────────────────────────────
    _hdr(4, "VALIDATE ENRICHED CONFIG")
    check_json = config_dir / "03_validation.json"
    n_errors, n_warnings, check_data = step_check_config(enriched_path, check_json)

    if n_errors > 0:
        _warn(f"Config has {n_errors} errors — check {check_json.name}")

    # ── Step 5: Visualise ─────────────────────────────────────────────────────
    _hdr(5, "VISUALISE TOPOLOGY → SVG SCHEMA")
    html_path = config_dir / "schema_diagram.svg"
    step_visualise(enriched_path, html_path)

    # ── Step 6: Generate ──────────────────────────────────────────────────────
    if not args.skip_generate:
        _hdr(6, "GENERATE SCENARIOS (WYSIWYG)")
        gen_train, gen_test = step_generate(
            enriched_path, domain_root, args.train, args.test
        )
    else:
        _hdr(6, "GENERATE SCENARIOS  [skipped]")

    # ── Step 7: Evaluate ──────────────────────────────────────────────────────
    _hdr(7, "EVALUATE SCENARIO QUALITY")
    eval_json = metric_dir / "bfs_metrics.json"

    # scenarios are in domain_root/scenarios/scenarios/... (due to generator.py adding /scenarios)
    # wait, generator.py now adds /scenarios to out-dir
    scenarios_actual_root = domain_root / "scenarios"
    
    if scenarios_actual_root.is_dir() and any(scenarios_actual_root.rglob("nodes")):
        eval_data = step_evaluate(scenarios_actual_root, eval_json)
    else:
        _warn("No generated scenarios found to evaluate")
        eval_data = None

    # ── Step 8: Final report ──────────────────────────────────────────────────
    step_report(
        out_dir     = domain_root,
        domain      = domain,
        eval_data   = eval_data,
        check_data  = check_data,
        train_count = args.train,
        test_count  = args.test,
        fetch_ok    = fetch_ok,
        vulns_added = vulns_added,
        start_ts    = start_ts,
    )

    print(f"\n{C.BOLD}{C.GREEN}  Pipeline complete in {round(time.time()-start_ts,1)}s{C.END}")
    print(f"  All outputs in: {C.CYAN}{domain_root.resolve()}{C.END}\n")


if __name__ == "__main__":
    main()
