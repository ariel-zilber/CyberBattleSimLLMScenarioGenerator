#!/usr/bin/env python3
"""
tools/phase1_pipeline.py
==================
Full end-to-end pipeline from live CVE data to evaluated scenarios.

Steps
-----
  1  Fetch CVEs from NVD API + EPSS scores + CISA KEV flag
  2  Convert CVEs → solvability_vulnerability YAML snippets
  3  Merge fetched vulns into a copy of the base domain config
  4  Validate the enriched config (config_checker)
  5  Visualise the topology as an interactive HTML DAG
  6  Generate scenarios (stratified across size strata)
  7  Evaluate generated scenarios (structural quality + fairness)
  8  Write a combined final report

Usage
-----
  # Active Directory, small run (5 train / 2 test per stratum, small stratum only)
  python3 tools/phase1_pipeline.py --domain active_directory

  # OT/SCADA, larger run
  python3 tools/phase1_pipeline.py --domain ot_scada --train 20 --test 5 --strata small medium

  # Skip the live CVE fetch (use existing data/active_directory.yaml unchanged)
  python3 tools/phase1_pipeline.py --domain active_directory --skip-fetch

  # Custom config path
  python3 tools/phase1_pipeline.py --config data/hybrid_2domain_web_to_ad.yaml --train 5 --test 2

Output
------
  <DATASET_ROOT>/phase1/<domain>/
    01_fetched_vulns.yaml       raw vulnerability templates from NVD
    02_config_enriched.yaml     base config + fetched vulns merged
    03_config_check.json        config checker result
    04_topology.html            interactive DAG (open in browser)
    05_scenarios/               generated scenario directories
    06_evaluation.json          per-scenario structural metrics
    07_pipeline_report.txt      human-readable final summary

  DATASET_ROOT is read from .env (key: DATASET_ROOT).
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

REPO_ROOT = Path(__file__).resolve().parent.parent


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
_DEFAULT_OUT_DIR = str(Path(_ENV.get("DATASET_ROOT", str(REPO_ROOT / "datasets"))) / "phase1")

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
    "network_infrastructure": {
        "query":    "cisco router switch juniper bgp ospf",
        "min_cvss": 6.5,
        "limit":    15,
    },
    "cloud_infrastructure": {
        "query":    "aws kubernetes cloud iam privilege escalation",
        "min_cvss": 7.0,
        "limit":    15,
    },
    "proxy_infrastructure": {
        "query":    "proxy firewall squid nginx reverse proxy",
        "min_cvss": 6.5,
        "limit":    12,
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
# Step 1+2: Fetch CVEs and generate vulnerability templates
# ─────────────────────────────────────────────────────────────────────────────

def step_fetch_vulns(domain: str, out_path: Path) -> bool:
    """
    Call vuln_to_template.py to pull CVEs from NVD + EPSS + KEV and write
    solvability_vulnerabilities YAML to out_path.
    Returns True on success.
    """
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
    _info(f"Query: \"{query}\"  min-cvss={min_cvss}  limit={limit}")
    _info(f"Fetching from NVD API + EPSS + CISA KEV …")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            cwd=str(REPO_ROOT), timeout=120
        )
        if result.returncode == 0 and out_path.exists():
            # Count templates written
            with open(out_path) as f:
                raw = yaml.safe_load(f) or {}
            total = sum(
                len(v) for v in raw.get("solvability_vulnerabilities", {}).values()
                if isinstance(v, list)
            )
            _ok(f"Fetched {total} vulnerability templates → {out_path.name}")
            if result.stdout.strip():
                for line in result.stdout.strip().splitlines()[-4:]:
                    _info(f"  {line}")
            return True
        else:
            _warn("Fetch returned no results or timed out — using empty template")
            if result.stderr:
                _warn(result.stderr[:200])
            # Write empty placeholder so later steps don't crash
            out_path.write_text(
                "# Auto-generated — NVD fetch returned no results\n"
                "solvability_vulnerabilities: {}\n"
            )
            return False
    except subprocess.TimeoutExpired:
        _warn("NVD fetch timed out (120 s) — skipping enrichment")
        out_path.write_text("solvability_vulnerabilities: {}\n")
        return False
    except Exception as e:
        _warn(f"Fetch error: {e} — skipping enrichment")
        out_path.write_text("solvability_vulnerabilities: {}\n")
        return False

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Merge fetched vulns into base config
# ─────────────────────────────────────────────────────────────────────────────

def _deep_merge_vulns(base_solv: Dict, patch_solv: Dict) -> Dict:
    """
    Merge patch solvability_vulnerabilities into base, deduplicating by name.
    Returns the merged dict.
    """
    merged = {k: list(v) for k, v in base_solv.items() if isinstance(v, list)}
    for category, vulns in patch_solv.items():
        if not isinstance(vulns, list):
            continue
        existing_names = {v.get("name") for v in merged.get(category, [])}
        for vuln in vulns:
            if vuln.get("name") not in existing_names:
                merged.setdefault(category, []).append(vuln)
                existing_names.add(vuln.get("name"))
    return merged


def step_merge_config(base_config_path: Path,
                      fetched_vulns_path: Path,
                      out_path: Path) -> int:
    """
    Write a copy of base_config with fetched vulns merged into
    solvability_vulnerabilities.  Returns number of new vulns added.
    """
    with open(base_config_path) as f:
        cfg = yaml.safe_load(f) or {}

    with open(fetched_vulns_path) as f:
        patch = yaml.safe_load(f) or {}

    patch_solv = patch.get("solvability_vulnerabilities", {})
    base_solv  = cfg.get("solvability_vulnerabilities", {})

    before_count = sum(
        len(v) for v in base_solv.values() if isinstance(v, list)
    )
    merged_solv = _deep_merge_vulns(base_solv, patch_solv)
    after_count = sum(
        len(v) for v in merged_solv.values() if isinstance(v, list)
    )
    added = after_count - before_count

    cfg["solvability_vulnerabilities"] = merged_solv
    # Tag the config so we know it was enriched
    cfg.setdefault("config", {})["enriched_at"] = datetime.now().isoformat()
    cfg["config"]["source_config"] = str(base_config_path)

    with open(out_path, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    _ok(f"Base config: {before_count} solvability vulns")
    _ok(f"After merge: {after_count} solvability vulns  (+{added} from NVD)")
    _ok(f"Enriched config → {out_path.name}")
    return added

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Config checker
# ─────────────────────────────────────────────────────────────────────────────

def step_check_config(config_path: Path, out_path: Path) -> Tuple[int, int, dict]:
    """
    Run config_checker.py --json.  Returns (n_errors, n_warnings, result_dict).
    """
    cmd = [
        sys.executable,
        str(REPO_ROOT / "pipeline" / "phase1" / "02_config_checker.py"),
        str(config_path),
        "--json",
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=30
    )

    try:
        data = json.loads(result.stdout)
    except Exception:
        data = {"errors": [], "warnings": [], "depth_report": {}, "passed": False}

    out_path.write_text(json.dumps(data, indent=2))

    errors   = data.get("errors",   [])
    warnings = data.get("warnings", [])

    if errors:
        _warn(f"{len(errors)} config errors:")
        for e in errors[:5]:
            _warn(f"    {e}")
        if len(errors) > 5:
            _warn(f"    … and {len(errors)-5} more (see {out_path.name})")
    else:
        _ok("No config errors")

    if warnings:
        _warn(f"{len(warnings)} config warnings:")
        for w in warnings[:3]:
            _warn(f"    {w}")
        if len(warnings) > 3:
            _warn(f"    … and {len(warnings)-3} more")
    else:
        _ok("No config warnings")

    depth = data.get("depth_report", {})
    if depth:
        _info("Attack flow depth to goal services:")
        for svc, d in sorted(depth.items(), key=lambda x: (x[1] or 0)):
            marker = "✓" if (d is not None and d >= 2) else "⚠"
            depth_str = str(d) if d is not None else "unreachable"
            print(f"       {marker}  {svc:<30} → {depth_str} hop(s)")

    return len(errors), len(warnings), data

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Visualise
# ─────────────────────────────────────────────────────────────────────────────

def step_visualise(config_path: Path, out_html: Path) -> bool:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "pipeline" / "reporting" / "01_scenario_graph.py"),
        "--config", str(config_path),
        "--out",    str(out_html),
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=30
    )
    if result.returncode == 0 and out_html.exists():
        _ok(f"Interactive DAG → {out_html.name}")
        _info(f"Open in browser: file://{out_html.resolve()}")
        return True
    else:
        _warn(f"Visualiser failed: {result.stderr[:120]}")
        return False

# ─────────────────────────────────────────────────────────────────────────────
# Step 6: Generate scenarios
# ─────────────────────────────────────────────────────────────────────────────

def step_generate(
    config_path: Path,
    out_dir: Path,
    strata: List[str],
    train_count: int,
    test_count: int,
) -> Tuple[int, int]:
    """
    Call phase2_generator.py.  Returns (total_train, total_test).
    """
    cmd = [
        sys.executable,
        str(REPO_ROOT / "pipeline" / "phase2" / "01_generator.py"),
        "--config",  str(config_path),
        "--out-dir", str(out_dir),
        "--train",   str(train_count),
        "--test",    str(test_count),
        "--strata",  *strata,
    ]
    _info(f"Strata: {strata}  |  {train_count} train + {test_count} test per stratum")
    _info(f"Total target: {(train_count + test_count) * len(strata)} scenarios")

    result = subprocess.run(
        cmd, text=True,
        cwd=str(REPO_ROOT), timeout=3600
    )

    if result.returncode != 0:
        _err("Generation step failed")
        return 0, 0

    # Count what was actually produced
    total_train = total_test = 0
    domain_dir = out_dir / config_path.stem
    if domain_dir.is_dir():
        for split in ["train", "test"]:
            split_root = domain_dir / split
            if not split_root.is_dir():
                continue
            for stratum_dir in split_root.iterdir():
                if stratum_dir.is_dir():
                    count = sum(1 for d in stratum_dir.iterdir() if d.is_dir())
                    if split == "train":
                        total_train += count
                    else:
                        total_test  += count

    _ok(f"Generated {total_train} train scenarios")
    _ok(f"Generated {total_test} test scenarios")
    return total_train, total_test

# ─────────────────────────────────────────────────────────────────────────────
# Step 7: Evaluate
# ─────────────────────────────────────────────────────────────────────────────

def step_evaluate(scenarios_dir: Path, out_json: Path) -> Optional[dict]:
    """
    Run phase2_evaluator.py on all generated scenarios.
    Returns the parsed JSON result or None on failure.
    """
    cmd = [
        sys.executable,
        str(REPO_ROOT / "pipeline" / "phase2" / "03_evaluator.py"),
        "--data-dir", str(scenarios_dir),
        "--out",      str(out_json),
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=600
    )

    # Print evaluator output (filtered to key lines)
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("  ✓") or "PASS" in stripped or "FAIL" in stripped or "═" in stripped:
            print(f"  {stripped}")

    if not out_json.exists():
        _warn("Evaluator produced no output file")
        return None

    try:
        with open(out_json) as f:
            return json.load(f)
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# Step 8: Final report
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_metric(label: str, value, threshold=None, invert=False) -> str:
    """Format a metric line with pass/fail colouring."""
    if threshold is not None:
        passes = (value >= threshold) if not invert else (value <= threshold)
        color = C.GREEN if passes else C.RED
        verdict = "✓" if passes else "✗"
    else:
        color = C.CYAN
        verdict = "·"
    return f"  {color}{verdict}{C.END}  {label:<38} {color}{value}{C.END}"


def step_report(
    out_dir: Path,
    domain: str,
    eval_data: Optional[dict],
    check_data: dict,
    train_count: int,
    test_count: int,
    strata: List[str],
    fetch_ok: bool,
    vulns_added: int,
    html_path: Path,
    start_ts: float,
) -> Path:

    scenarios     = (eval_data or {}).get("scenarios", [])
    fairness      = (eval_data or {}).get("fairness",  {})

    n_pass    = sum(1 for s in scenarios if s.get("passes"))
    n_fail    = len(scenarios) - n_pass
    solvable  = sum(1 for s in scenarios if s.get("solvable"))

    mean_depth = (
        round(sum(s.get("mean_goal_depth", 0) for s in scenarios) / len(scenarios), 2)
        if scenarios else 0.0
    )
    mean_cred = (
        round(sum(s.get("cred_chain_ratio", 0) for s in scenarios) / len(scenarios), 3)
        if scenarios else 0.0
    )
    mean_disc = (
        round(sum(s.get("discovery_ratio", 0) for s in scenarios) / len(scenarios), 3)
        if scenarios else 0.0
    )
    min_depths = [s.get("min_goal_depth", 0) for s in scenarios]
    any_depth_lt2 = any(d < 2 for d in min_depths if isinstance(d, (int, float)))

    elapsed = round(time.time() - start_ts, 1)

    _hdr(8, "FINAL REPORT")

    print(f"\n  {C.BOLD}Pipeline Summary{C.END}")
    print(f"  {'─'*50}")
    print(f"  Domain        : {domain}")
    print(f"  Base config   : data/{domain}.yaml")
    print(f"  CVE fetch     : {'✓ succeeded' if fetch_ok else '⚠ skipped/failed'}")
    print(f"  New vulns     : +{vulns_added} from NVD/EPSS/KEV")
    print(f"  Config errors : {len(check_data.get('errors', []))}")
    print(f"  Config warns  : {len(check_data.get('warnings', []))}")
    print(f"  Strata        : {', '.join(strata)}")
    print(f"  Scenarios     : {train_count} train + {test_count} test × {len(strata)} strata")
    print(f"  Elapsed       : {elapsed}s")

    print(f"\n  {C.BOLD}Dataset Quality Metrics (§3.2 thresholds){C.END}")
    print(f"  {'─'*50}")
    print(_fmt_metric("Total scenarios evaluated",   len(scenarios)))
    print(_fmt_metric("Solvable scenarios",          solvable,    len(scenarios)))
    print(_fmt_metric("Pass all thresholds",         n_pass,      len(scenarios)))
    print(_fmt_metric("Mean cred chain ratio",       mean_cred,   0.55))
    print(_fmt_metric("Mean discovery ratio",        mean_disc,   0.70))
    print(_fmt_metric("Mean goal depth",             mean_depth,  2.5))
    print(_fmt_metric("Any goal depth < 2",          any_depth_lt2, False, invert=False))

    if fairness:
        gini = fairness.get("difficulty_gini", 1.0)
        cv   = fairness.get("cv_mean_depth",   1.0)
        print(f"\n  {C.BOLD}Cross-Domain Fairness (§3.3){C.END}")
        print(f"  {'─'*50}")
        print(_fmt_metric("Difficulty Gini coefficient",  round(gini, 3), threshold=None))
        print(_fmt_metric("CV of mean depth",             round(cv,   3), threshold=None))
        gini_color = C.GREEN if gini < 0.15 else (C.YELLOW if gini < 0.25 else C.RED)
        print(f"  {gini_color}{'Balanced (< 0.15)' if gini < 0.15 else 'Borderline' if gini < 0.25 else 'Unbalanced'}{C.END}")

    print(f"\n  {C.BOLD}Output Files{C.END}")
    print(f"  {'─'*50}")
    for name, desc in [
        ("01_fetched_vulns.yaml",  "Vulnerability templates from NVD/EPSS/KEV"),
        ("02_config_enriched.yaml","Enriched domain config"),
        ("03_config_check.json",   "Config checker results"),
        ("04_topology.html",       "Interactive DAG (open in browser)"),
        ("05_scenarios/",          "Generated scenario directories"),
        ("06_evaluation.json",     "Full per-scenario metrics"),
        ("07_pipeline_report.txt", "This report (plain text)"),
    ]:
        p = out_dir / name
        exists = p.exists() or (out_dir / name.rstrip("/")).is_dir()
        mark = f"{C.GREEN}✓{C.END}" if exists else f"{C.YELLOW}·{C.END}"
        print(f"  {mark}  {name:<35} {desc}")

    print()

    # Write plain-text version
    report_path = out_dir / "07_pipeline_report.txt"
    lines = [
        "CyberBattleSim Pipeline Report",
        f"Generated: {datetime.now().isoformat()}",
        f"Domain   : {domain}",
        "=" * 60,
        f"CVE fetch         : {'OK' if fetch_ok else 'skipped'}",
        f"New vulns added   : {vulns_added}",
        f"Config errors     : {len(check_data.get('errors', []))}",
        f"Config warnings   : {len(check_data.get('warnings', []))}",
        f"Scenarios eval'd  : {len(scenarios)}",
        f"Solvable          : {solvable}/{len(scenarios)}",
        f"Pass all thresholds: {n_pass}/{len(scenarios)}",
        f"Mean cred ratio   : {mean_cred}",
        f"Mean discovery    : {mean_disc}",
        f"Mean goal depth   : {mean_depth}",
        f"Difficulty Gini   : {fairness.get('difficulty_gini', 'N/A')}",
        f"Elapsed           : {elapsed}s",
        "=" * 60,
    ]
    if check_data.get("errors"):
        lines.append("\nConfig Errors:")
        for e in check_data["errors"]:
            lines.append(f"  ✗  {e}")
    if check_data.get("warnings"):
        lines.append("\nConfig Warnings:")
        for w in check_data["warnings"]:
            lines.append(f"  ⚠  {w}")
    if scenarios:
        lines.append("\nFailed Scenarios:")
        fails = [s for s in scenarios if not s.get("passes")]
        for s in fails[:10]:
            lines.append(f"  ✗  {Path(s['scenario']).name}")
            for v in s.get("violations", []):
                lines.append(f"       → {v}")

    report_path.write_text("\n".join(lines) + "\n")
    _ok(f"Report written → {report_path}")
    return report_path

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="End-to-end pipeline: CVE fetch → config enrich → generate → evaluate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    src = parser.add_mutually_exclusive_group()
    src.add_argument("--domain", metavar="NAME",
                     help="Domain name (e.g. active_directory, ot_scada). "
                          "Looks for data/<domain>.yaml automatically.")
    src.add_argument("--config", metavar="YAML",
                     help="Explicit path to a domain config YAML")

    parser.add_argument("--train",  type=int, default=5,
                        help="Train scenarios per stratum (default: 5)")
    parser.add_argument("--test",   type=int, default=2,
                        help="Test scenarios per stratum (default: 2)")
    parser.add_argument("--strata", nargs="+",
                        choices=["small", "medium", "large"],
                        default=["small"],
                        help="Size strata to generate (default: small)")
    parser.add_argument("--out-dir", metavar="DIR", default=_DEFAULT_OUT_DIR,
                        help=f"Root output directory (default: DATASET_ROOT/phase1 from .env)")
    parser.add_argument("--skip-fetch", action="store_true",
                        help="Skip NVD/EPSS fetch, use base config as-is")
    parser.add_argument("--skip-generate", action="store_true",
                        help="Skip scenario generation (evaluate existing scenarios)")
    args = parser.parse_args()

    # Resolve config path and domain name
    if args.config:
        config_path = Path(args.config)
        domain = config_path.stem
    elif args.domain:
        domain = args.domain
        config_path = REPO_ROOT / "data" / f"{domain}.yaml"
    else:
        # Default to active_directory if nothing specified
        domain = "active_directory"
        config_path = REPO_ROOT / "data" / "active_directory.yaml"

    if not config_path.is_file():
        print(f"Error: config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out_dir) / domain
    out_dir.mkdir(parents=True, exist_ok=True)

    start_ts = time.time()

    print(f"\n{C.BOLD}{C.BLUE}{'═'*64}{C.END}")
    print(f"{C.BOLD}{C.BLUE}  CyberBattleSim End-to-End Pipeline{C.END}")
    print(f"{C.BOLD}{C.BLUE}{'═'*64}{C.END}")
    print(f"  Domain   : {domain}")
    print(f"  Config   : {config_path}")
    print(f"  Out dir  : {out_dir.resolve()}")
    print(f"  Strata   : {args.strata}")
    print(f"  Scenarios: {args.train} train + {args.test} test per stratum")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Step 1+2: Fetch CVEs ──────────────────────────────────────────────────
    _hdr(1, "FETCH CVEs FROM NVD + EPSS + CISA KEV")
    fetched_path = out_dir / "01_fetched_vulns.yaml"
    fetch_ok = False
    vulns_added = 0

    if args.skip_fetch:
        _info("--skip-fetch: copying base config directly")
        shutil.copy(config_path, out_dir / "01_fetched_vulns.yaml")
        fetched_path.write_text("solvability_vulnerabilities: {}\n")
        fetch_ok = True
    else:
        fetch_ok = step_fetch_vulns(domain, fetched_path)

    # ── Step 3: Merge into config ─────────────────────────────────────────────
    _hdr(3, "MERGE FETCHED VULNS INTO DOMAIN CONFIG")
    enriched_path = out_dir / "02_config_enriched.yaml"
    vulns_added = step_merge_config(config_path, fetched_path, enriched_path)

    # ── Step 4: Validate config ───────────────────────────────────────────────
    _hdr(4, "VALIDATE ENRICHED CONFIG")
    check_json = out_dir / "03_config_check.json"
    n_errors, n_warnings, check_data = step_check_config(enriched_path, check_json)

    if n_errors > 0:
        _warn(f"Config has {n_errors} errors — generation will continue but results may be degraded")

    # ── Step 5: Visualise ─────────────────────────────────────────────────────
    _hdr(5, "VISUALISE TOPOLOGY → HTML DAG")
    html_path = out_dir / "04_topology.html"
    step_visualise(enriched_path, html_path)

    # ── Step 6: Generate ──────────────────────────────────────────────────────
    scenarios_dir = out_dir / "05_scenarios"
    if not args.skip_generate:
        _hdr(6, "GENERATE STRATIFIED SCENARIOS")
        scenarios_dir.mkdir(parents=True, exist_ok=True)
        gen_train, gen_test = step_generate(
            enriched_path, scenarios_dir, args.strata, args.train, args.test
        )
        if gen_train + gen_test == 0:
            _err("No scenarios were generated — check cli.py and config")
    else:
        _hdr(6, "GENERATE STRATIFIED SCENARIOS  [skipped]")
        _info("--skip-generate: evaluating existing scenarios in " + str(scenarios_dir))

    # ── Step 7: Evaluate ──────────────────────────────────────────────────────
    _hdr(7, "EVALUATE SCENARIO QUALITY (§3.1 + §3.3)")
    eval_json = out_dir / "06_evaluation.json"

    if scenarios_dir.is_dir() and any(scenarios_dir.rglob("nodes")):
        eval_data = step_evaluate(scenarios_dir, eval_json)
        if eval_data is None:
            _warn("Evaluation produced no results")
    else:
        _warn("No generated scenarios found to evaluate")
        eval_data = None

    # ── Step 8: Final report ──────────────────────────────────────────────────
    step_report(
        out_dir     = out_dir,
        domain      = domain,
        eval_data   = eval_data,
        check_data  = check_data,
        train_count = args.train,
        test_count  = args.test,
        strata      = args.strata,
        fetch_ok    = fetch_ok,
        vulns_added = vulns_added,
        html_path   = html_path,
        start_ts    = start_ts,
    )

    print(f"\n{C.BOLD}{C.GREEN}  Pipeline complete in {round(time.time()-start_ts,1)}s{C.END}")
    print(f"  All outputs in: {C.CYAN}{out_dir.resolve()}{C.END}\n")


if __name__ == "__main__":
    main()
