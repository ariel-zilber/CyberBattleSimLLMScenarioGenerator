#!/usr/bin/env python3
"""
mcp_server/domain_generator_mcp.py
=====================================
MCP server for the CyberBattleSim Domain Generator.

Exposes a tract-style generation → evaluation → fix loop as MCP tools:

  1. generate_template_yaml   — Given a natural-language description, return a
                                complete starter YAML template pre-populated with
                                the correct schema.
  2. run_pipeline             — Run the full generation+evaluation pipeline on a
                                config file. Stores output in a timestamped folder.
  3. get_pipeline_summary     — Return the human-readable pipeline report and
                                structured metrics from the last pipeline run.
  4. fix_template             — Given a pipeline summary, apply targeted fixes to
                                the domain config YAML and return the patched YAML.
  5. validate_config          — Run the config checker on a YAML file and return
                                any errors/warnings.
  6. list_configs             — List all available domain config YAML files.
  7. read_prompt_file         — Read any file from the prompts/ reference library.

Install:
  pip install mcp pyyaml

Run:
  python mcp_server/domain_generator_mcp.py

Or register in Claude Desktop's claude_desktop_config.json:
  {
    "mcpServers": {
      "cyberbattlesim": {
        "command": "python",
        "args": ["/abs/path/to/mcp_server/domain_generator_mcp.py"]
      }
    }
  }
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from mcp.server.fastmcp import FastMCP

# ─────────────────────────────────────────────────────────────────────────────
# Paths & environment config
# ─────────────────────────────────────────────────────────────────────────────

REPO_ROOT     = Path(__file__).resolve().parent.parent
DATA_DIR      = REPO_ROOT / "data" / "scenarios"
PROMPTS_DIR   = REPO_ROOT / "prompts"
TOOLS_DIR         = REPO_ROOT / "pipeline"
PHASE1_DIR        = TOOLS_DIR / "phase1"
PIPELINE_DATA_DIR = REPO_ROOT / "pipeline" / "data_preprocessing"


def _load_env() -> dict:
    """Parse .env from repo root; env vars take precedence over file."""
    cfg: dict = {}
    env_path = REPO_ROOT / ".env"
    if env_path.exists():
        for raw in env_path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip()
    # OS env vars override .env
    for k, v in os.environ.items():
        cfg[k] = v
    return cfg


_ENV = _load_env()

# All pipeline outputs go under DATASET_ROOT (configured in .env)
_DEFAULT_DATASET_ROOT = REPO_ROOT / "datasets"
DATASET_ROOT = Path(_ENV.get("DATASET_ROOT", str(_DEFAULT_DATASET_ROOT)))
OUTPUT_ROOT  = DATASET_ROOT / "phase1"   # Phase 1 pipeline output
PHASE2_ROOT  = DATASET_ROOT / "phase2"   # Phase 2 scenario output

MAX_RETRIES         = int(_ENV.get("MAX_RETRIES",          "10"))
PHASE1_MIN_SCORE    = float(_ENV.get("PHASE1_MIN_SCORE",   "7.0"))
PHASE2_MIN_SOLVE    = float(_ENV.get("PHASE2_MIN_SOLVE_RATE", "0.50"))
PHASE2_TRAIN_COUNT  = int(_ENV.get("PHASE2_TRAIN_COUNT",   "5"))
PHASE2_TEST_COUNT   = int(_ENV.get("PHASE2_TEST_COUNT",    "2"))
PHASE2_STRATA       = _ENV.get("PHASE2_STRATA",            "small")
PHASE2_MAX_STEPS    = int(_ENV.get("PHASE2_MAX_STEPS",     "5000"))
PHASE2_NUM_AGENTS   = int(_ENV.get("PHASE2_NUM_AGENTS",    "3"))
PHASE2_MAX_EPISODES = int(_ENV.get("PHASE2_MAX_EPISODES",  "3"))

# ─────────────────────────────────────────────────────────────────────────────
# MCP server instance
# ─────────────────────────────────────────────────────────────────────────────

mcp = FastMCP(
    "CyberBattleSim Domain Generator",
    instructions=(
        "Tools for generating, running, evaluating, and fixing CyberBattleSim "
        "domain configuration YAML files used as DRL training environments. "
        "The typical workflow is: generate_template_yaml → run_pipeline → "
        "get_pipeline_summary → fix_template → run_pipeline (repeat until passing)."
    ),
)

# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────

def _read_file(path: Path) -> str:
    """Read a text file. Returns empty string if missing."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _run_subprocess(
    cmd: List[str],
    timeout: int = 300,
    extra_env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Run a subprocess and return stdout, stderr, and return code."""
    try:
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        result = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": "Timeout expired", "success": False}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e), "success": False}


def _load_json(path: Path) -> Optional[dict]:
    """Load JSON file. Returns None if missing or invalid."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _load_yaml(path: Path) -> Optional[dict]:
    """Load YAML file. Returns None if missing or invalid."""
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Tool 1: generate_template_yaml
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def generate_template_yaml(
    scenario_description: str,
    scenario_name: str,
    architecture: str = "single",
) -> str:
    """
    Generate a starter YAML template for a new CyberBattleSim domain scenario.

    This tool returns the system prompt, architecture rules, and golden examples
    that an LLM should use to produce a valid domain configuration. Feed the
    returned content directly to your LLM generation call.

    Args:
        scenario_description: Natural-language description of the target network
            (e.g., "Enterprise Active Directory with legacy workstations and
            modern endpoints. Goal is to compromise the Domain Controller.").
        scenario_name: Filename-safe name for the config (e.g., "enterprise_ad").
            The config will be saved to data/<scenario_name>.yaml.
        architecture: "single" for a single-domain config, "multi" for a
            three-tier DMZ → AppTier → Core config.

    Returns:
        A structured prompt package containing: the system prompt, the relevant
        golden example, vulnerability catalog, allowed properties, and the
        save path for the output file.
    """
    # Determine which golden example to include
    golden_path = (
        PROMPTS_DIR / "examples" / "golden_cross_domain.yaml"
        if architecture == "multi"
        else PROMPTS_DIR / "examples" / "golden_single_domain.yaml"
    )

    system_prompt   = _read_file(PROMPTS_DIR / "system_prompt.md")
    anti_patterns   = _read_file(PROMPTS_DIR / "anti_patterns.md")
    vuln_catalog    = _read_file(PROMPTS_DIR / "docs" / "reference" / "vulnerability_catalog.md")
    properties_dict = _read_file(PROMPTS_DIR / "reference" / "allowed_properties.md")
    schema_def      = _read_file(PROMPTS_DIR / "schema" / "definition.md")
    arch_rules      = _read_file(PROMPTS_DIR / "schema" / "architecture.md")
    golden_example  = _read_file(golden_path)
    validation_list = _read_file(PROMPTS_DIR / "evaluation" / "validation_checklist.md")

    output_path = DATA_DIR / f"{scenario_name}.yaml"

    prompt_package = f"""# CyberBattleSim Domain Generation Package
Generated: {datetime.now().isoformat()}
Architecture: {architecture}
Output path: {output_path}

═══════════════════════════════════════════════════════════
SYSTEM PROMPT (Master Instructions)
═══════════════════════════════════════════════════════════

{system_prompt}

═══════════════════════════════════════════════════════════
SCHEMA DEFINITION (Field Reference)
═══════════════════════════════════════════════════════════

{schema_def}

═══════════════════════════════════════════════════════════
DOMAIN ARCHITECTURE RULES
═══════════════════════════════════════════════════════════

{arch_rules}

═══════════════════════════════════════════════════════════
ALLOWED PROPERTIES DICTIONARY
═══════════════════════════════════════════════════════════

{properties_dict}

═══════════════════════════════════════════════════════════
VULNERABILITY CATALOG
═══════════════════════════════════════════════════════════

{vuln_catalog}

═══════════════════════════════════════════════════════════
ANTI-PATTERNS TO AVOID
═══════════════════════════════════════════════════════════

{anti_patterns}

═══════════════════════════════════════════════════════════
GOLDEN EXAMPLE ({architecture.upper()} DOMAIN)
═══════════════════════════════════════════════════════════

{golden_example}

═══════════════════════════════════════════════════════════
VALIDATION CHECKLIST (Apply Before Writing)
═══════════════════════════════════════════════════════════

{validation_list}

═══════════════════════════════════════════════════════════
YOUR TASK
═══════════════════════════════════════════════════════════

Generate a complete, valid YAML domain configuration based on the following scenario description.
Save the output to: {output_path}

SCENARIO DESCRIPTION:
{scenario_description}

REQUIREMENTS:
- Architecture: {architecture} ({'single internal domain' if architecture == 'single' else 'three-tier DMZ → AppTier → CoreDomain'})
- Must pass all 10 validation checklist points
- Must follow all rules from the system prompt
- Must use only properties from the allowed properties dictionary
- Must use only vulnerability patterns from the vulnerability catalog
"""

    return prompt_package


# ─────────────────────────────────────────────────────────────────────────────
# Tool 2: run_pipeline
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def run_pipeline(
    config_path: str,
    train_count: int = 5,
    test_count: int = 2,
    skip_fetch: bool = True,
) -> Dict[str, Any]:
    """
    Run the full generation + evaluation pipeline on a domain config YAML file.

    This executes: config validation → scenario generation → quality evaluation.
    Output is written to a timestamped folder under DATASET_ROOT/phase1/ (from .env).

    Args:
        config_path: Path to the domain config YAML file. Can be absolute or
            relative to the repo root. If only a domain name is given (e.g.,
            "active_directory"), looks for data/<name>.yaml automatically.
        train_count: Number of training scenarios to generate.
        test_count: Number of test scenarios to generate.
        skip_fetch: If True, skip the NVD/EPSS CVE fetch step (faster).

    Returns:
        Dict with keys:
          - run_id: Unique identifier for this pipeline run
          - output_dir: Path to the pipeline output directory
          - config_errors: Number of config errors found
          - config_warnings: Number of config warnings found
          - scenarios_generated: Total number of generated scenarios
          - scenarios_passing: Number of scenarios passing all thresholds
          - summary: Human-readable pipeline report text
          - evaluation: Structured evaluation metrics dict
          - status: "success", "partial", or "failed"
    """
    # Resolve config path
    p = Path(config_path)
    if not p.is_absolute():
        # Try relative to repo root
        candidate = REPO_ROOT / p
        if not candidate.exists():
            # Try data/ directory
            candidate = DATA_DIR / f"{config_path}.yaml"
        p = candidate

    if not p.exists():
        return {
            "status": "failed",
            "error": f"Config file not found: {config_path}. "
                     f"Available configs: {[f.stem for f in DATA_DIR.glob('*.yaml')]}",
        }

    # Build unique run ID and output dir
    run_id = f"{p.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    out_dir = OUTPUT_ROOT / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build pipeline command
    cmd = [
        sys.executable,
        str(TOOLS_DIR / "phase1" / "pipeline.py"),
        "--config",  str(p),
        "--train",   str(train_count),
        "--test",    str(test_count),
        "--out-dir", str(out_dir.parent),  # phase1_pipeline.py appends domain name itself
    ]
    if skip_fetch:
        cmd.append("--skip-fetch")

    # Run pipeline
    result = _run_subprocess(cmd, timeout=600)

    # The actual output directory has the domain name appended by phase1_pipeline.py
    domain_out_dir = out_dir.parent / p.stem
    if not domain_out_dir.exists():
        domain_out_dir = out_dir

    # Read outputs
    check_data  = _load_json(domain_out_dir / "03_config_check.json") or {}
    eval_data   = _load_json(domain_out_dir / "06_evaluation.json")   or {}
    report_text = _read_file(domain_out_dir / "07_pipeline_report.txt")

    # Count results
    scenarios      = eval_data.get("scenarios", [])
    n_pass         = sum(1 for s in scenarios if s.get("passes", False))
    n_total        = len(scenarios)
    config_errors  = len(check_data.get("errors", []))
    config_warnings= len(check_data.get("warnings", []))

    # Compute aggregate metrics
    mean_depth = (
        round(sum(s.get("mean_goal_depth", 0) for s in scenarios) / n_total, 2)
        if n_total else 0.0
    )
    mean_cred = (
        round(sum(s.get("cred_chain_ratio", 0) for s in scenarios) / n_total, 3)
        if n_total else 0.0
    )
    solvable_count = sum(1 for s in scenarios if s.get("solvable", False))

    status = "success" if (n_pass == n_total and n_total > 0 and config_errors == 0) else \
             "partial" if (n_pass > 0 or n_total > 0) else "failed"

    return {
        "run_id":              run_id,
        "output_dir":          str(domain_out_dir.resolve()),
        "config_path":         str(p.resolve()),
        "config_errors":       config_errors,
        "config_warnings":     config_warnings,
        "config_error_list":   check_data.get("errors", []),
        "config_warning_list": check_data.get("warnings", []),
        "scenarios_generated": n_total,
        "scenarios_passing":   n_pass,
        "scenarios_solvable":  solvable_count,
        "mean_goal_depth":     mean_depth,
        "mean_cred_ratio":     mean_cred,
        "summary":             report_text or result["stdout"],
        "evaluation":          eval_data,
        "status":              status,
        "pipeline_stdout":     result["stdout"][-3000:] if result["stdout"] else "",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 3: get_pipeline_summary
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def get_pipeline_summary(output_dir: str) -> Dict[str, Any]:
    """
    Read and parse the results from a completed pipeline run.

    Args:
        output_dir: Path to the pipeline output directory (returned by run_pipeline).

    Returns:
        A structured summary dict containing:
          - report: Human-readable pipeline report
          - config_issues: List of errors and warnings from config checker
          - scenario_results: Per-scenario evaluation metrics
          - failed_scenarios: Scenarios that failed thresholds, with violations
          - recommendations: Auto-generated list of fix recommendations
          - fairness: Cross-domain fairness metrics (if multi-domain)
    """
    out = Path(output_dir)

    report_text = _read_file(out / "07_pipeline_report.txt")
    check_data  = _load_json(out / "03_config_check.json") or {}
    eval_data   = _load_json(out / "06_evaluation.json")   or {}

    scenarios = eval_data.get("scenarios", [])
    failed    = [s for s in scenarios if not s.get("passes", True)]

    # Generate recommendations based on failures
    recommendations = _generate_fix_recommendations(
        check_data.get("errors", []),
        check_data.get("warnings", []),
        failed,
    )

    return {
        "report":           report_text,
        "config_issues": {
            "errors":   check_data.get("errors",   []),
            "warnings": check_data.get("warnings", []),
            "depth_report": check_data.get("depth_report", {}),
        },
        "scenario_results": scenarios,
        "failed_scenarios": [
            {
                "name":       Path(s["scenario"]).name,
                "violations": s.get("violations", []),
                "metrics": {
                    "solvable":          s.get("solvable"),
                    "cred_chain_ratio":  s.get("cred_chain_ratio"),
                    "discovery_ratio":   s.get("discovery_ratio"),
                    "min_goal_depth":    s.get("min_goal_depth"),
                    "mean_goal_depth":   s.get("mean_goal_depth"),
                    "goal_ratio":        s.get("goal_ratio"),
                    "remote_goals":      s.get("remote_exploitable_goals"),
                },
            }
            for s in failed
        ],
        "fairness":          eval_data.get("fairness", {}),
        "recommendations":   recommendations,
    }


def _generate_fix_recommendations(
    errors: List[str],
    warnings: List[str],
    failed_scenarios: List[dict],
) -> List[Dict[str, str]]:
    """Translate errors and metric violations into actionable YAML fixes."""
    recs = []

    # Config error recommendations
    error_patterns = [
        (r"breach_node",                   "AP-010", "Add 'breach_node' to identifiers.base_properties"),
        (r"is_goal.*true",                 "AP-011", "Add 'is_goal: true' to at least one service definition"),
        (r"Unauthenticated.*goal",         "AP-012", "Remove 'Unauthenticated' from the default_properties of goal services"),
        (r"not in base_properties",        "AP-009", "Add the missing property to identifiers.base_properties"),
        (r"service name.*group",           "AP-004", "Change constraint source/target to use the GroupName (plural), not ServiceName"),
        (r"inter_domain|cross.domain",     "AP-005", "Move cross-domain rules to the inter_domain_constraints block"),
        (r"reward.*int|integer",           "AP-007", "Change all reward fields to descriptive strings (not integers)"),
        (r"probability.*missing",          "AP-013", "Add 'probability: 0.65' to each solvability_vulnerabilities item"),
        (r"success_rate.*1\.0",            "AP-014", "Lower success_rate on exploits to 0.40–0.80 range"),
    ]
    for err in errors:
        for pattern, ap_code, fix in error_patterns:
            if re.search(pattern, err, re.I):
                recs.append({
                    "priority":    "HIGH",
                    "issue":       err,
                    "anti_pattern": ap_code,
                    "fix":         fix,
                })
                break
        else:
            recs.append({"priority": "HIGH", "issue": err, "fix": "Review the error and correct the YAML structure"})

    # Metric violation recommendations
    for s in failed_scenarios:
        for v in s.get("violations", []):
            if "cred_chain_ratio" in v:
                recs.append({
                    "priority": "MEDIUM",
                    "issue":    f"Low credential chain coverage: {v}",
                    "fix":      "Increase node_probability in constraint_vulnerabilities.leak_known_credentials "
                                "to 0.60+, or add more LEAK_KNOWN_CREDENTIALS constraints between groups.",
                })
            elif "discovery_ratio" in v:
                recs.append({
                    "priority": "MEDIUM",
                    "issue":    f"Low discovery coverage: {v}",
                    "fix":      "Increase node_probability in constraint_vulnerabilities.leak_neighbors "
                                "to 0.65+ and/or add more KNOWS constraints. Add more discovery solvability vulns.",
                })
            elif "goal_depth" in v:
                recs.append({
                    "priority": "HIGH",
                    "issue":    f"Goal too easily reachable: {v}",
                    "fix":      "Add an intermediate tier between the entry point and the goal. "
                                "Ensure goal nodes are not directly connected to the entry point group.",
                })
            elif "solvable=False" in v:
                recs.append({
                    "priority": "CRITICAL",
                    "issue":    "Scenario is unsolvable — agent cannot reach goal",
                    "fix":      "Check that there is a complete credential/exploit chain from entry to goal. "
                                "Ensure solvability_rules.auto_fix_enabled is true. "
                                "Verify match_properties on goal_access vulns match the goal service's default_properties.",
                })
            elif "remote_exploitable_goals" in v:
                recs.append({
                    "priority": "HIGH",
                    "issue":    f"No remote-exploitable goal: {v}",
                    "fix":      "Add a REMOTE type vulnerability to the goal service in solvability_vulnerabilities.goal_access.",
                })

    # Deduplicate by fix text
    seen = set()
    unique_recs = []
    for r in recs:
        key = r["fix"]
        if key not in seen:
            seen.add(key)
            unique_recs.append(r)

    return unique_recs


# ─────────────────────────────────────────────────────────────────────────────
# Tool 4: fix_template
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def fix_template(
    config_path: str,
    output_dir: str,
    apply_auto_fixes: bool = True,
) -> Dict[str, Any]:
    """
    Analyze a pipeline summary and apply automatic fixes to the domain config YAML.

    This implements the "tract-style" feedback loop:
    1. Reads the pipeline evaluation results from output_dir
    2. Identifies fixable structural issues in the config
    3. Applies safe, mechanical fixes directly to the YAML
    4. Returns the list of applied changes and the new config content

    Args:
        config_path: Path to the domain config YAML to fix.
        output_dir: Path to the pipeline output directory containing evaluation results.
        apply_auto_fixes: If True, write fixed YAML back to a new file
            (<original_name>_fixed.yaml). If False, return the proposed changes only.

    Returns:
        Dict with keys:
          - fixes_applied: List of changes made with descriptions
          - fixes_skipped: List of issues that require manual intervention
          - new_config_path: Path of the written fixed config (if apply_auto_fixes=True)
          - new_config_yaml: The complete fixed YAML as a string
          - next_steps: Instructions for re-running the pipeline
    """
    p = Path(config_path)
    if not p.is_absolute():
        candidate = REPO_ROOT / p
        if not candidate.exists():
            candidate = DATA_DIR / f"{config_path}.yaml"
        p = candidate

    if not p.exists():
        return {"error": f"Config file not found: {config_path}"}

    # Load existing config
    cfg_text = p.read_text(encoding="utf-8")
    try:
        cfg = yaml.safe_load(cfg_text) or {}
    except yaml.YAMLError as e:
        return {"error": f"Invalid YAML in {p}: {e}"}

    # Load pipeline results
    out = Path(output_dir)
    check_data = _load_json(out / "03_config_check.json") or {}
    eval_data  = _load_json(out / "06_evaluation.json")   or {}

    errors   = check_data.get("errors",   [])
    warnings = check_data.get("warnings", [])
    scenarios = eval_data.get("scenarios", [])
    failed   = [s for s in scenarios if not s.get("passes", True)]

    fixes_applied = []
    fixes_skipped = []

    # ── Fix 1: Ensure breach_node is in base_properties ──────────────────────
    base_props = cfg.get("identifiers", {}).get("base_properties", [])
    if "breach_node" not in base_props:
        base_props.insert(0, "breach_node")
        cfg.setdefault("identifiers", {})["base_properties"] = base_props
        fixes_applied.append({
            "type":        "add_property",
            "description": "Added 'breach_node' to identifiers.base_properties",
            "anti_pattern": "AP-010",
        })

    # ── Fix 2: Ensure probability field on solvability vulns ─────────────────
    solv = cfg.get("solvability_vulnerabilities", {})
    if isinstance(solv, dict):
        for category in ["remote_access", "credential_leak", "discovery", "goal_access"]:
            for vuln in solv.get(category, []):
                if isinstance(vuln, dict) and "probability" not in vuln:
                    vuln["probability"] = 0.65
                    fixes_applied.append({
                        "type":        "add_field",
                        "description": f"Added 'probability: 0.65' to {category} vuln '{vuln.get('name', '?')}'",
                        "anti_pattern": "AP-013",
                    })

    # ── Fix 3: Convert integer rewards to strings ────────────────────────────
    def _fix_rewards(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "reward" and isinstance(v, (int, float)):
                    obj[k] = f"Reward value {v} — describe this action here"
                    fixes_applied.append({
                        "type":        "fix_reward_type",
                        "description": f"Converted integer reward ({v}) to string at {path}.{k}",
                        "anti_pattern": "AP-007",
                    })
                else:
                    _fix_rewards(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _fix_rewards(item, f"{path}[{i}]")

    _fix_rewards(cfg)

    # ── Fix 4: Ensure solvability_rules has auto_fix_enabled ─────────────────
    sol_rules = cfg.get("solvability_rules", {})
    if not sol_rules.get("auto_fix_enabled", False):
        sol_rules["auto_fix_enabled"] = True
        if "auto_fix_strategies" not in sol_rules:
            sol_rules["auto_fix_strategies"] = [
                "add_remote_vulnerability_to_entry",
                "add_credential_leakage",
                "add_lateral_movement_vulnerabilities",
            ]
        cfg["solvability_rules"] = sol_rules
        fixes_applied.append({
            "type":        "enable_auto_fix",
            "description": "Enabled solvability_rules.auto_fix_enabled = true with standard strategies",
            "anti_pattern": "N/A",
        })

    # ── Fix 5: Boost low credential chain coverage ───────────────────────────
    for s in failed:
        for v in s.get("violations", []):
            if "cred_chain_ratio" in v:
                cv = cfg.get("constraint_vulnerabilities", {})
                lkc = cv.get("leak_known_credentials", {})
                if isinstance(lkc, dict):
                    current = lkc.get("node_probability", 0.45)
                    if current < 0.60:
                        lkc["node_probability"] = min(current + 0.15, 0.75)
                        fixes_applied.append({
                            "type":        "increase_node_probability",
                            "description": f"Increased leak_known_credentials.node_probability "
                                           f"from {current} to {lkc['node_probability']} to improve cred chain coverage",
                            "anti_pattern": "N/A",
                        })
                break  # Only apply once per violation type

    # ── Fix 6: Boost low discovery coverage ──────────────────────────────────
    for s in failed:
        for v in s.get("violations", []):
            if "discovery_ratio" in v:
                cv = cfg.get("constraint_vulnerabilities", {})
                ln = cv.get("leak_neighbors", {})
                if isinstance(ln, dict):
                    current = ln.get("node_probability", 0.55)
                    if current < 0.70:
                        ln["node_probability"] = min(current + 0.15, 0.80)
                        fixes_applied.append({
                            "type":        "increase_discovery_probability",
                            "description": f"Increased leak_neighbors.node_probability "
                                           f"from {current} to {ln['node_probability']} to improve discovery coverage",
                            "anti_pattern": "N/A",
                        })
                break

    # ── Issues requiring manual intervention ─────────────────────────────────
    manual_patterns = [
        (r"not in base_properties", "Missing property — add to identifiers.base_properties manually"),
        (r"group.*name|source.*target", "Constraint uses wrong name type — check group vs service names"),
        (r"solvable.*False|unsolvable", "Scenario unsolvable — verify complete exploit chain from entry to goal"),
        (r"goal_depth.*<.*2", "Goal too shallow — add an intermediate pivot tier"),
    ]
    all_issues = errors + warnings + [v for s in failed for v in s.get("violations", [])]
    for issue in all_issues:
        for pattern, manual_fix in manual_patterns:
            if re.search(pattern, issue, re.I):
                fixes_skipped.append({
                    "issue":      issue,
                    "reason":     "Requires manual YAML editing",
                    "suggestion": manual_fix,
                })
                break

    # M-4: normalise floats to 2 decimal places before serialisation
    def _round_floats(obj, dp=2):
        if isinstance(obj, float):
            return round(obj, dp)
        if isinstance(obj, dict):
            return {k: _round_floats(v, dp) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_round_floats(v, dp) for v in obj]
        return obj

    cfg = _round_floats(cfg)

    # Serialize fixed config
    new_yaml = yaml.dump(cfg, default_flow_style=False, allow_unicode=True, sort_keys=False)
    new_config_path = None

    if apply_auto_fixes and fixes_applied:
        stem = p.stem
        suffix = "_fixed"
        new_path = p.parent / f"{stem}{suffix}.yaml"
        # Avoid overwriting existing fixed files
        counter = 1
        while new_path.exists():
            new_path = p.parent / f"{stem}{suffix}_{counter}.yaml"
            counter += 1
        new_path.write_text(new_yaml, encoding="utf-8")
        new_config_path = str(new_path.resolve())

    return {
        "fixes_applied":    fixes_applied,
        "fixes_skipped":    fixes_skipped,
        "new_config_path":  new_config_path,
        "new_config_yaml":  new_yaml if not apply_auto_fixes else None,
        "next_steps": (
            f"Re-run the pipeline on {new_config_path or p} "
            f"using run_pipeline(config_path='{new_config_path or p}') "
            "to verify the fixes resolved the issues. "
            "Address the manual fixes in fixes_skipped before re-running."
            if fixes_applied or fixes_skipped
            else "No fixes were needed or could be automatically applied."
        ),
    }


def _check_exploit_costs(cfg: dict, errors: list, warnings: list) -> None:
    """Append cost-bound errors/warnings for any exploit whose cost is outside [0.5, 5.0]."""
    _COST_MIN, _COST_MAX = 0.5, 5.0
    for section in ("vulnerabilities", "solvability_vulnerabilities", "constraint_vulnerabilities"):
        section_data = cfg.get(section, {})
        items = section_data if isinstance(section_data, list) else (
            item for group in section_data.values() for item in (group if isinstance(group, list) else [])
            if isinstance(item, dict)
        )
        for item in items:
            if not isinstance(item, dict):
                continue
            cost = item.get("cost")
            if cost is None:
                continue
            try:
                c = float(cost)
            except (TypeError, ValueError):
                warnings.append(f"Exploit '{item.get('name', '?')}' has non-numeric cost: {cost!r}")
                continue
            if c < _COST_MIN:
                errors.append(
                    f"Exploit '{item.get('name', '?')}' cost {c} is below minimum {_COST_MIN}"
                )
            elif c > _COST_MAX:
                warnings.append(
                    f"Exploit '{item.get('name', '?')}' cost {c} exceeds recommended maximum {_COST_MAX}"
                )


# ─────────────────────────────────────────────────────────────────────────────
# Tool 5: validate_config
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def validate_config(config_path: str) -> Dict[str, Any]:
    """
    Run the config checker on a domain YAML file and return all errors/warnings.

    This is faster than run_pipeline — it only performs structural validation
    without generating scenarios. Use this for rapid iteration.

    Args:
        config_path: Path to the domain config YAML file.

    Returns:
        Dict with keys:
          - passed: bool — True if no errors
          - errors: List of error strings
          - warnings: List of warning strings
          - depth_report: Dict mapping service names to their attack-flow depth
          - recommendations: List of recommended fixes
    """
    p = Path(config_path)
    if not p.is_absolute():
        candidate = REPO_ROOT / p
        if not candidate.exists():
            candidate = DATA_DIR / f"{config_path}.yaml"
        p = candidate

    if not p.exists():
        return {"passed": False, "errors": [f"Config file not found: {config_path}"], "warnings": []}

    cmd = [
        sys.executable,
        str(TOOLS_DIR / "phase1" / "02_config_checker.py"),
        str(p),
        "--json",
    ]
    result = _run_subprocess(cmd, timeout=30)

    try:
        data = json.loads(result["stdout"])
    except (json.JSONDecodeError, KeyError):
        data = {
            "errors":       [result["stderr"][:500]] if result["stderr"] else ["Unknown error"],
            "warnings":     [],
            "depth_report": {},
            "passed":       False,
        }

    errors   = list(data.get("errors",   []))
    warnings = list(data.get("warnings", []))

    # M-3: validate exploit cost bounds [0.5, 5.0]
    try:
        cfg_raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        _check_exploit_costs(cfg_raw, errors, warnings)
    except Exception:
        pass

    recommendations = _generate_fix_recommendations(errors, warnings, [])

    return {
        "passed":          len(errors) == 0,
        "errors":          errors,
        "warnings":        warnings,
        "depth_report":    data.get("depth_report", {}),
        "recommendations": recommendations,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 6: list_configs
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_configs() -> Dict[str, Any]:
    """
    List all available domain configuration YAML files and recent pipeline runs.

    Returns:
        Dict with keys:
          - configs: List of available domain config names and paths
          - recent_runs: List of the 5 most recent pipeline output directories
    """
    configs = []
    if DATA_DIR.is_dir():
        for f in sorted(DATA_DIR.glob("*.yaml")):
            stat = f.stat()
            configs.append({
                "name":         f.stem,
                "path":         str(f.resolve()),
                "size_kb":      round(stat.st_size / 1024, 1),
                "modified":     datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })

    recent_runs = []
    if OUTPUT_ROOT.is_dir():
        run_dirs = sorted(
            [d for d in OUTPUT_ROOT.iterdir() if d.is_dir()],
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )[:5]
        for d in run_dirs:
            report = _read_file(d / "07_pipeline_report.txt")
            status = "unknown"
            if report:
                if "solvable_count" in report or "PASS" in report:
                    status = "completed"
                elif "error" in report.lower():
                    status = "errors"
            recent_runs.append({
                "run_dir":  str(d.resolve()),
                "modified": datetime.fromtimestamp(d.stat().st_mtime).isoformat(),
                "status":   status,
            })

    return {
        "configs":     configs,
        "recent_runs": recent_runs,
        "data_dir":    str(DATA_DIR.resolve()),
        "output_dir":  str(OUTPUT_ROOT.resolve()),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 7: read_prompt_file
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def read_prompt_file(file_name: str) -> str:
    """
    Read any file from the prompts/ reference library.

    Available files:
      - system_prompt.md
      - anti_patterns.md
      - schema/definition.md
      - schema/architecture.md
      - reference/allowed_properties.md
      - reference/vulnerability_catalog.md
      - evaluation/validation_checklist.md
      - examples/golden_single_domain.yaml
      - examples/golden_cross_domain.yaml

    Args:
        file_name: Relative path within the prompts/ directory
            (e.g., "system_prompt.md").

    Returns:
        The file content as a string, or an error message if not found.
    """
    path = PROMPTS_DIR / file_name
    if not path.exists():
        available = [
            str(f.relative_to(PROMPTS_DIR))
            for f in PROMPTS_DIR.rglob("*")
            if f.is_file()
        ]
        return (
            f"File not found: {file_name}\n\n"
            f"Available files:\n" + "\n".join(f"  - {a}" for a in sorted(available))
        )
    return _read_file(path)


# ─────────────────────────────────────────────────────────────────────────────
# Tool 8: evaluate_scenario_quality
# ─────────────────────────────────────────────────────────────────────────────

def _format_quality_report(result: dict) -> str:
    """Render a quality evaluation result as a human-readable text report."""
    lines = []
    name    = result.get("config_name", "unknown")
    overall = result.get("overall_score", 0)
    grade   = result.get("overall_grade", "?")
    labels  = {"A+": "EXCELLENT", "A": "GOOD", "B": "ABOVE AVERAGE",
               "C": "AVERAGE",    "D": "BELOW AVERAGE", "F": "POOR"}

    lines += [
        "╔══════════════════════════════════════════════════════════════╗",
        f"  SCENARIO QUALITY REPORT: {name}",
        f"  Overall Score: {overall}/10   Grade: {grade}  ({labels.get(grade,'')})",
        "╚══════════════════════════════════════════════════════════════╝",
        "",
        "DIMENSION SCORES:",
        "─" * 62,
    ]

    for dim in result.get("dimensions", {}).values():
        score = dim["score"]
        bar   = "█" * score + "░" * (10 - score)
        lines.append(f"  {dim['name']:<40} {score:>2}/10 ({dim['grade']}) [{bar}]")

    lines += ["", "DETAILED FINDINGS:", "─" * 62]

    icons = {"pass": "✓", "warning": "⚠", "fail": "✗", "critical": "✗✗"}
    for dim in result.get("dimensions", {}).values():
        lines.append(f"\n  ── {dim['name']} ──")
        for f in dim.get("findings", []):
            icon    = icons.get(f["type"], "?")
            ref_str = f"  [→ {f['ref']}]" if f.get("ref") else ""
            ded_str = f"  (-{f['deduction']} pts)" if f.get("deduction", 0) > 0 else ""
            lines.append(f"    {icon}  {f['message']}{ref_str}{ded_str}")

    lines += ["", "TOP ISSUES:", "─" * 62]
    top = result.get("top_issues", [])
    if top:
        for i, issue in enumerate(top, 1):
            ref_str = f"  [{issue['ref']}]" if issue.get("ref") else ""
            lines.append(f"  {i}. [{issue['severity']}] {issue['dimension']}: {issue['message']}{ref_str}")
    else:
        lines.append("  No critical issues found — scenario looks realistic!")

    lines += ["", f"SUMMARY: {result.get('summary', '')}", ""]
    return "\n".join(lines)


@mcp.tool()
def evaluate_scenario_quality(config_path: str) -> Dict[str, Any]:
    """
    Evaluate the realism quality of a CyberBattleSim domain configuration YAML.

    Performs static analysis across 5 dimensions — no pipeline execution required.
    Use this for rapid realism feedback during or after generation, before committing
    to the full run_pipeline call.

    Dimensions evaluated (each scored 0–10):
      1. Network Topology Realism  — subnet segmentation, OS distribution, node count
      2. Properties & Vulnerabilities Realism — exploit names, success rates, match_properties
      3. Scenario Difficulty       — attack depth, goal density, lateral movement requirements
      4. Firewall Rules Realism    — protocol specificity, tier isolation, entry point placement
      5. General Realism           — service naming, asset values, service diversity

    Args:
        config_path: Path to the domain config YAML. Accepts absolute paths,
            repo-relative paths, or bare domain names (resolved to data/<name>.yaml).

    Returns:
        Dict with keys:
          - config_name: Name of the evaluated configuration
          - overall_score: Average across all 5 dimensions (0–10, one decimal)
          - overall_grade: Letter grade (A+/A/B/C/D/F)
          - dimensions: Per-dimension dict with score, grade, and findings list
          - top_issues: Up to 10 critical/fail findings sorted by severity
          - summary: One-paragraph human-readable summary
          - formatted_report: Full text report ready to display
    """
    p = Path(config_path)
    if not p.is_absolute():
        candidate = REPO_ROOT / p
        if not candidate.exists():
            candidate = DATA_DIR / f"{config_path}.yaml"
        p = candidate

    if not p.exists():
        return {
            "error": (
                f"Config file not found: {config_path}. "
                f"Available: {[f.stem for f in DATA_DIR.glob('*.yaml')]}"
            )
        }

    cfg = _load_yaml(p)
    if not cfg:
        return {"error": f"Failed to parse YAML: {p}"}

    # Import evaluator from pipeline/phase1/
    if str(PHASE1_DIR) not in sys.path:
        sys.path.insert(0, str(PHASE1_DIR))
    try:
        from quality_evaluator import ScenarioQualityEvaluator
    except ImportError as exc:
        return {"error": f"Could not import quality_evaluator: {exc}"}

    evaluator = ScenarioQualityEvaluator(cfg, config_name=p.stem)
    result    = evaluator.evaluate()
    result["formatted_report"] = _format_quality_report(result)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Tool 9: build_critique_prompt
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def build_critique_prompt(
    original_description: str,
    yaml_path: str,
    validation_errors: List[str],
    validation_warnings: List[str],
    quality_result: dict,
    iteration: int = 1,
    max_iterations: int = 3,
) -> str:
    """
    Build a structured critique + regeneration prompt from validation and quality results.

    Call this after validate_config and evaluate_scenario_quality have been run on a
    generated YAML. The returned prompt should be fed back to the LLM as the context
    for the next generation iteration, together with the original prompt package from
    generate_template_yaml.

    Args:
        original_description: The original natural-language scenario request.
        yaml_path: Path to the generated YAML file that was evaluated.
        validation_errors: List of structural errors from validate_config.
        validation_warnings: List of structural warnings from validate_config.
        quality_result: Full dict returned by evaluate_scenario_quality.
        iteration: Current iteration number (1-based).
        max_iterations: Maximum allowed iterations.

    Returns:
        A structured critique prompt string ready to prepend to the regeneration request.
    """
    overall  = quality_result.get("overall_score", 0)
    grade    = quality_result.get("overall_grade", "?")
    dims     = quality_result.get("dimensions", {})
    top_issues = quality_result.get("top_issues", [])

    lines = [
        f"# GENERATION CRITIQUE — Iteration {iteration}/{max_iterations}",
        "",
        "You previously generated a domain configuration YAML. It has been evaluated",
        "and found to have issues that must be fixed before this iteration is complete.",
        "Study the findings below carefully, then regenerate the COMPLETE YAML with all",
        "issues resolved. Do NOT just patch individual fields — rewrite the full config.",
        "",
        "═" * 66,
        f"  SCENARIO REQUEST (unchanged): {original_description}",
        f"  Generated file:  {yaml_path}",
        f"  Overall quality: {overall}/10  Grade: {grade}",
        "═" * 66,
        "",
    ]

    # Structural errors — must fix first
    if validation_errors:
        lines += [
            "## STRUCTURAL ERRORS (parser will fail — fix ALL of these first)",
            "",
        ]
        for i, err in enumerate(validation_errors, 1):
            lines.append(f"  {i}. {err}")

        # Map errors to anti-pattern refs
        ap_map = [
            (r"solvability_vulnerabilities.*list",        "AP-001: solvability_vulnerabilities must be a DICT with 4 keys"),
            (r"constraint_vulnerabilities.*list",         "AP-002: constraint_vulnerabilities must be a DICT with 2 keys"),
            (r"start_node.*vulnerabilities.*list",        "AP-003: start_node.vulnerabilities must be a DICT with 2 keys"),
            (r"group.*service|source.*target.*service",   "AP-004: constraints source/target must be GROUP NAMES, not service names"),
            (r"breach_node",                              "AP-010: Add 'breach_node' to identifiers.base_properties"),
            (r"is_goal",                                  "AP-011: At least one service must have is_goal: true"),
            (r"Unauthenticated.*goal",                    "AP-012: Remove 'Unauthenticated' from goal service default_properties"),
            (r"not in base_properties",                   "AP-009: Declare every used property in identifiers.base_properties"),
            (r"reward.*int|integer.*reward",              "AP-007: All reward fields must be descriptive strings, not integers"),
            (r"probability.*missing",                     "AP-013: Every solvability vuln must have a probability field"),
            (r"success_rate.*1\.0",                       "AP-014: Exploit success_rate must be 0.40–0.80, not 1.0"),
        ]
        hinted = set()
        for err in validation_errors:
            for pattern, hint in ap_map:
                if re.search(pattern, err, re.I) and hint not in hinted:
                    lines.append(f"  → Hint: {hint}")
                    hinted.add(hint)
        lines.append("")

    if validation_warnings:
        lines += ["## STRUCTURAL WARNINGS", ""]
        for w in validation_warnings[:5]:
            lines.append(f"  ⚠ {w}")
        lines.append("")

    # Realism issues per dimension
    lines += [
        "## QUALITY DIMENSION SCORES (target: every dimension ≥ 7/10)",
        "",
    ]
    icons = {"A+": "✓✓", "A": "✓", "B": "~", "C": "✗", "D": "✗✗", "F": "✗✗✗"}
    for dim in dims.values():
        icon = icons.get(dim["grade"], "?")
        lines.append(f"  {icon} {dim['name']:<42} {dim['score']:>2}/10  ({dim['grade']})")
    lines.append("")

    # Critical and fail findings with specific fixes
    critical_findings = [
        (d_name, f)
        for d_name, d_data in dims.items()
        for f in d_data.get("findings", [])
        if f["type"] in ("critical", "fail")
    ]
    warning_findings = [
        (d_name, f)
        for d_name, d_data in dims.items()
        for f in d_data.get("findings", [])
        if f["type"] == "warning"
    ]

    if critical_findings:
        lines += ["## CRITICAL & FAIL FINDINGS — must resolve in next iteration", ""]
        for dim_key, f in critical_findings:
            dim_name = dims[dim_key]["name"]
            ref_str  = f"  [→ {f['ref']}]" if f.get("ref") else ""
            lines.append(f"  ✗ [{dim_name}] {f['message']}{ref_str}")
        lines.append("")

    if warning_findings:
        lines += ["## WARNINGS — address where possible", ""]
        for dim_key, f in warning_findings[:8]:
            dim_name = dims[dim_key]["name"]
            lines.append(f"  ⚠ [{dim_name}] {f['message']}")
        lines.append("")

    # Specific regeneration instructions
    lines += [
        "## REGENERATION INSTRUCTIONS",
        "",
        "1. Fix ALL structural errors above — these prevent the parser from loading the config.",
        "2. For each CRITICAL/FAIL quality finding, make the specific change described.",
        "3. Re-read the MASTER DIRECTIVES from the system prompt before writing — especially:",
        "   - Strict network segmentation (no DMZ→Core direct connections)",
        "   - Attacker on public internet (start_node.subnet = 0.0.0.0/0)",
        "   - Probabilistic exploits (success_rate 0.40–0.80)",
        "   - match_properties specific to OS and role",
        "   - All rewards are descriptive strings",
        "4. Generate the COMPLETE YAML from scratch — do not just patch the existing one.",
        f"5. Save to: data/{Path(yaml_path).stem.rsplit('_v', 1)[0]}_v{iteration + 1}.yaml",
        "",
        f"Iteration {iteration + 1}/{max_iterations}. "
        + ("This is the FINAL iteration — make it correct." if iteration + 1 >= max_iterations else
           f"{max_iterations - iteration - 1} iteration(s) remaining after this."),
        "",
    ]

    # Read anti-patterns file for inline reference
    anti_patterns = _read_file(PROMPTS_DIR / "anti_patterns.md")
    if anti_patterns:
        lines += [
            "## ANTI-PATTERNS REFERENCE (review before regenerating)",
            "",
            anti_patterns[:3000],  # First 3000 chars to stay within context
            "",
        ]

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Tool 10: generate_phase1_report
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def generate_phase1_report(
    scenario_description: str,
    scenario_name: str,
    iterations: List[Dict[str, Any]],
    final_yaml_path: str,
    passed: bool,
) -> Dict[str, Any]:
    """
    Generate the Phase 1 completion report after the automated generation loop finishes.

    This summarises the full iterative generation process: quality scores at each
    iteration, issues that were resolved, remaining warnings, and the verdict.

    Args:
        scenario_description: The original scenario request.
        scenario_name: The config name (e.g., "enterprise_ad").
        iterations: List of per-iteration result dicts, each containing:
            - iteration (int)
            - yaml_path (str)
            - overall_score (float)
            - overall_grade (str)
            - passed_validation (bool)
            - validation_error_count (int)
            - validation_errors (list of str)
            - dimension_scores (dict: topology_realism/vulnerability_realism/etc → int, optional)
            - dimensions (full dict from evaluate_scenario_quality, used if dimension_scores absent)
            - top_issues (list of issue dicts from evaluate_scenario_quality)
        final_yaml_path: Path to the final accepted YAML.
        passed: True if the final iteration meets all thresholds (validation pass + quality ≥ 7.0).

    Returns:
        Dict with keys:
          - passed: bool
          - total_iterations: int
          - final_score: float
          - final_grade: str
          - formatted_report: Full text Phase 1 report
          - final_yaml_path: str
          - summary: one-sentence summary
    """
    n_iter  = len(iterations)
    final   = iterations[-1] if iterations else {}
    f_score = final.get("overall_score", 0)
    f_grade = final.get("overall_grade", "?")

    dim_labels = {
        "topology_realism":      "Network Topology Realism",
        "vulnerability_realism": "Properties & Vulnerabilities Realism",
        "scenario_difficulty":   "Scenario Difficulty",
        "firewall_realism":      "Firewall Rules Realism",
        "general_realism":       "General Realism",
    }

    verdict = "PHASE 1 COMPLETE ✓  — Configuration meets quality thresholds." if passed \
              else "PHASE 1 INCOMPLETE ✗ — Max iterations reached; manual review required."

    labels = {"A+": "EXCELLENT", "A": "GOOD", "B": "ABOVE AVERAGE",
              "C": "AVERAGE",    "D": "BELOW AVERAGE", "F": "POOR"}

    lines = [
        "╔══════════════════════════════════════════════════════════════════╗",
        f"  PHASE 1 GENERATION REPORT",
        f"  Scenario : {scenario_name}",
        f"  Request  : {scenario_description[:72]}",
        f"  Iterations: {n_iter}   Final Score: {f_score}/10 ({f_grade})",
        "╚══════════════════════════════════════════════════════════════════╝",
        "",
        "ITERATION HISTORY:",
        "─" * 66,
    ]

    for it in iterations:
        idx         = it.get("iteration", "?")
        score       = it.get("overall_score", 0)
        grade       = it.get("overall_grade", "?")
        n_errors    = it.get("validation_error_count", 0)
        top         = it.get("top_issues", [])
        n_critical  = sum(1 for i in top if i.get("severity") in ("CRITICAL", "FAIL"))
        status      = "✓ PASS" if (it.get("passed_validation") and score >= 7.0) else "✗"
        lines.append(
            f"  Iter {idx}: {score:>4}/10 ({grade:<2}) {status:<8}  "
            f"{n_errors} validation error(s), {n_critical} critical quality issue(s)"
        )

    lines += [
        "",
        "FINAL DIMENSION SCORES:",
        "─" * 66,
    ]

    final_dims = final.get("dimension_scores", {})
    # If dimension_scores is missing or all-zero, fall back to extracting from
    # the full `dimensions` dict that evaluate_scenario_quality returns.
    if not final_dims or all(v == 0 for v in final_dims.values()):
        full_dims = final.get("dimensions", {})
        if full_dims:
            final_dims = {k: int(v["score"]) if isinstance(v, dict) else int(v)
                          for k, v in full_dims.items()}
    for key, label in dim_labels.items():
        score = int(final_dims.get(key, 0))
        bar   = "█" * score + "░" * (10 - score)
        lines.append(f"  {label:<44} {score:>2}/10  [{bar}]")

    # Issues resolved: things that were critical/fail in iter 1 but not in final
    first   = iterations[0] if iterations else {}
    first_issues   = {i["message"] for i in first.get("top_issues", [])}
    final_issues   = {i["message"] for i in final.get("top_issues", [])}
    resolved       = first_issues - final_issues
    still_open     = final_issues

    if resolved:
        lines += ["", "ISSUES RESOLVED ACROSS ITERATIONS:", "─" * 66]
        for msg in sorted(resolved):
            lines.append(f"  ✓ {msg}")

    if still_open:
        lines += ["", "REMAINING ISSUES (for manual review):", "─" * 66]
        for msg in sorted(still_open):
            lines.append(f"  ⚠ {msg}")

    lines += [
        "",
        "FINAL CONFIGURATION:",
        "─" * 66,
        f"  Path: {final_yaml_path}",
        "",
        "─" * 66,
        f"  VERDICT: {verdict}",
        "─" * 66,
        "",
    ]

    report_text = "\n".join(lines)

    summary = (
        f"Phase 1 {'passed' if passed else 'incomplete'} after {n_iter} iteration(s). "
        f"Final quality: {f_score}/10 ({f_grade} — {labels.get(f_grade, '')}). "
        f"Config saved to {final_yaml_path}."
    )

    # Save report to file
    report_dir  = OUTPUT_ROOT / scenario_name
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "phase1_report.txt"
    report_path.write_text(report_text, encoding="utf-8")

    return {
        "passed":           passed,
        "total_iterations": n_iter,
        "final_score":      f_score,
        "final_grade":      f_grade,
        "formatted_report": report_text,
        "report_path":      str(report_path.resolve()),
        "final_yaml_path":  final_yaml_path,
        "summary":          summary,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 11: run_phase2_generation
# ─────────────────────────────────────────────────────────────────────────────

def _find_scenario_dirs(root: Path) -> List[Path]:
    """Return all scenario directories (parent of a nodes/ dir) under root."""
    return sorted(set(p.parent for p in root.rglob("nodes") if p.is_dir()))


@mcp.tool()
def run_phase2_generation(
    config_path: str,
    output_dir: str = "",
    train_count: int = 5,
    test_count: int = 2,
) -> Dict[str, Any]:
    """
    Phase 2, Step 1: Generate train/test scenarios from a domain config.

    Calls phase2_generator.py to produce scenario directories under a
    structured output folder (phase2_output/<domain_name>/ by default).
    Each scenario directory contains a nodes/ subdirectory of per-node YAML files
    that can be loaded directly by CyberBattleSim.

    Output structure:
        phase2_output/<domain_name>/
          train/CyberBattleSim-<domain>-0001/nodes/...
          train/CyberBattleSim-<domain>-0002/nodes/...
          test/CyberBattleSim-<domain>-10001/nodes/...

    Args:
        config_path: Phase 1 domain config YAML. Accepts absolute path,
            repo-relative path, bare name (→ data/<name>.yaml), or versioned
            name like "enterprise_ad_v2" (→ data/enterprise_ad_v2.yaml).
        output_dir: Root for scenario output. Defaults to phase2_output/.
        train_count: Training scenarios.
        test_count: Test scenarios.

    Returns:
        Dict with keys:
          - domain_name: Derived from config filename
          - config_path: Resolved absolute config path
          - scenarios_dir: Absolute path to the domain scenario folder
          - train_count: Number of train scenarios found on disk
          - test_count: Number of test scenarios found on disk
          - total_scenarios: Train + test
          - scenario_paths: List of all scenario directory paths (up to 30)
          - status: "success", "partial", or "failed"
    """
    p = Path(config_path)
    if not p.is_absolute():
        candidate = REPO_ROOT / p
        if not candidate.exists():
            candidate = DATA_DIR / f"{config_path}.yaml"
        p = candidate

    if not p.exists():
        return {"status": "failed", "error": f"Config file not found: {config_path}"}

    # Strip _v1/_v2 Phase 1 version suffix from domain name
    domain_name = re.sub(r"_v\d+$", "", p.stem)

    out_root = Path(output_dir) if output_dir else PHASE2_ROOT
    out_root.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(TOOLS_DIR / "phase2" / "01_generator.py"),
        "--config",   str(p),
        "--out-dir",  str(out_root),
        "--train",    str(train_count),
        "--test",     str(test_count),
    ]

    result = _run_subprocess(cmd, timeout=900)

    scenarios_dir   = out_root / domain_name
    scenario_paths  = _find_scenario_dirs(scenarios_dir) if scenarios_dir.is_dir() else []
    n_train         = sum(1 for p in scenario_paths if "/train/" in str(p) or "\\train\\" in str(p))
    n_test          = sum(1 for p in scenario_paths if "/test/"  in str(p) or "\\test\\"  in str(p))

    status = "success" if result["success"] and scenario_paths else \
             "partial" if scenario_paths else "failed"

    return {
        "domain_name":     domain_name,
        "config_path":     str(p.resolve()),
        "scenarios_dir":   str(scenarios_dir.resolve()),
        "output_root":     str(out_root.resolve()),
        "strata":          strata_list,
        "train_count":     n_train,
        "test_count":      n_test,
        "total_scenarios": len(scenario_paths),
        "scenario_paths":  [str(s.resolve()) for s in scenario_paths[:30]],
        "status":          status,
        "stdout":          result["stdout"][-2000:] if result["stdout"] else "",
        "stderr":          result["stderr"][-500:]  if result["stderr"] else "",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 12: run_phase2_evaluation
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def run_phase2_evaluation(
    scenarios_dir: str,
    max_steps: int = 5000,
    num_agents: int = 3,
    max_episodes: int = 3,
) -> Dict[str, Any]:
    """
    Phase 2, Step 2: Run runtime evaluation on all generated scenarios.

    Deploys a cooperative heuristic agent swarm against every scenario found
    under scenarios_dir (locates them via nodes/ subdirectories). Requires
    CyberBattleSim to be installed in the Python environment.

    Per-scenario output: <scenario_dir>/run_metrics.json
    Dataset summary:     <scenarios_dir>/DATASET_EVALUATION_PROMPT.txt

    The DATASET_EVALUATION_PROMPT.txt is an LLM-ready analysis request covering
    topological realism, lateral movement health, and generator feedback.

    Args:
        scenarios_dir: Root directory containing scenario folders (returned by
            run_phase2_generation as "scenarios_dir").
        max_steps: Max steps per episode — lower is faster (5000 is a good balance).
        num_agents: Unused (kept for backward compatibility). BFSPlannerAgent is
            single-agent; this parameter no longer affects evaluation.
        max_episodes: Independent episodes per scenario — more episodes improve
            robustness against probabilistic vulnerability outcomes.

    Returns:
        Dict with keys:
          - total_scenarios: Scenarios evaluated
          - solved_count: Scenarios where the swarm reached all goals
          - solve_rate: solved / total (0.0–1.0)
          - per_scenario_metrics: List of run_metrics.json content per scenario
          - aggregate: Dict of aggregate statistics (mean steps, reward, topology)
          - summary_prompt_path: Path to DATASET_EVALUATION_PROMPT.txt
          - status: "success", "partial", "failed", or "dependency_missing"
    """
    sp = Path(scenarios_dir)
    if not sp.is_dir():
        return {"status": "failed", "error": f"Scenarios directory not found: {scenarios_dir}"}

    scenario_dirs = _find_scenario_dirs(sp)
    if not scenario_dirs:
        return {"status": "failed", "error": f"No scenarios (nodes/ dirs) found under {scenarios_dir}"}

    # Generous timeout: steps × episodes × scenarios, floored at 5 min
    timeout = max(300, max_steps * max_episodes * len(scenario_dirs) // 200 + 300)

    cmd = [
        "/home/ariel/miniconda3/envs/cybersim/bin/python",
        str(TOOLS_DIR / "phase2" / "02_test_env_integration.py"),
        "--data-dir",   str(sp),
        "--steps",      str(max_steps),
        "--num-agents", str(num_agents),
        "--episodes",   str(max_episodes),
    ]

    # Clear any inherited PYTHONPATH so the cybersim env isn't polluted
    result = _run_subprocess(cmd, timeout=timeout, extra_env={"PYTHONPATH": ""})

    if "Failed to import cyberbattle" in (result.get("stderr", "") + result.get("stdout", "")):
        return {
            "status": "dependency_missing",
            "error":  "CyberBattleSim is not installed.",
            "hint": (
                f"Install CyberBattleSim, then run manually:\n"
                f"  python pipeline/phase2/test_env_integration.py "
                f"--data-dir {sp} --steps {max_steps} "
                f"--num-agents {num_agents} --episodes {max_episodes}"
            ),
        }

    # Collect per-scenario metrics written by test_env_integration.py
    per_scenario: List[dict] = []
    for sc_dir in scenario_dirs:
        mf = sc_dir / "run_metrics.json"
        if mf.exists():
            try:
                with open(mf) as f:
                    per_scenario.append(json.load(f))
            except Exception:
                pass

    solved     = [m for m in per_scenario if m.get("is_solved")]
    n_total    = len(per_scenario) or len(scenario_dirs)
    n_solved   = len(solved)
    solve_rate = round(n_solved / n_total, 3) if n_total else 0.0

    def _avg(key: str) -> float:
        vals = [m.get(key, 0) for m in per_scenario if key in m]
        return round(sum(vals) / len(vals), 2) if vals else 0.0

    topo_vals = [m.get("topology_metrics", {}).get("routing", {}) for m in per_scenario]
    aggregate: Dict[str, Any] = {
        "total_scenarios":  n_total,
        "solved_scenarios": n_solved,
        "solve_rate":       solve_rate,
        "mean_steps":       _avg("steps_taken"),
        "mean_reward":      _avg("total_reward"),
        "mean_nodes_owned": _avg("nodes_owned"),
        "mean_creds_found": _avg("credentials_discovered"),
    }
    if topo_vals:
        aggregate["mean_node_count"]    = round(sum(t.get("node_count", 0) for t in topo_vals) / len(topo_vals), 1)
        aggregate["mean_graph_density"] = round(sum(t.get("density",    0) for t in topo_vals) / len(topo_vals), 4)
        aggregate["mean_diameter"]      = round(sum(max(0, t.get("diameter", 0)) for t in topo_vals) / len(topo_vals), 1)

    summary_path = sp / "DATASET_EVALUATION_PROMPT.txt"
    status = "success" if result["returncode"] == 0 else \
             "partial" if per_scenario else "failed"

    return {
        "total_scenarios":      n_total,
        "solved_count":         n_solved,
        "solve_rate":           solve_rate,
        "per_scenario_metrics": per_scenario,
        "aggregate":            aggregate,
        "summary_prompt_path":  str(summary_path) if summary_path.exists() else "",
        "status":               status,
        "stdout":               result["stdout"][-2000:] if result["stdout"] else "",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 13: generate_phase2_report
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def generate_phase2_report(
    scenario_name: str,
    config_path: str,
    generation_result: Dict[str, Any],
    evaluation_result: Dict[str, Any],
    phase1_score: float = 0.0,
    phase1_grade: str = "",
) -> Dict[str, Any]:
    """
    Generate the Phase 2 completion report.

    Combines scenario generation results with runtime evaluation metrics
    into a structured human-readable report. Saves the report to
    phase2_output/<scenario_name>/phase2_report.txt.

    Args:
        scenario_name: Name of the scenario (e.g., "enterprise_ad").
        config_path: Path to the Phase 1 domain config YAML.
        generation_result: Full dict returned by run_phase2_generation.
        evaluation_result: Full dict returned by run_phase2_evaluation.
        phase1_score: Phase 1 overall quality score (0–10).
        phase1_grade: Phase 1 letter grade (A+/A/B/C/D/F).

    Returns:
        Dict with keys:
          - passed: True if generation succeeded and solve_rate ≥ 0.50
          - formatted_report: Full text report
          - report_path: Absolute path where the report was saved
          - summary: One-sentence summary
          - solve_rate: Final solve rate (0.0–1.0)
    """
    gen = generation_result
    ev  = evaluation_result
    agg = ev.get("aggregate", {})

    n_total    = agg.get("total_scenarios", 0)
    n_solved   = agg.get("solved_scenarios", 0)
    solve_rate = agg.get("solve_rate", 0.0)

    dep_missing = ev.get("status") == "dependency_missing"
    gen_ok      = gen.get("status") != "failed"
    passed      = gen_ok and (dep_missing or solve_rate >= 0.50)

    if dep_missing:
        verdict = "PHASE 2 PARTIAL ✓ — Scenarios generated. Runtime evaluation requires CyberBattleSim."
    elif passed:
        verdict = f"PHASE 2 COMPLETE ✓ — {n_solved}/{n_total} scenarios solved ({solve_rate*100:.0f}%)."
    else:
        verdict = f"PHASE 2 NEEDS REVIEW ✗ — Solve rate {solve_rate*100:.0f}% is below the 50% threshold."

    lines = [
        "╔══════════════════════════════════════════════════════════════════╗",
        f"  PHASE 2 REPORT: {scenario_name}",
        f"  Phase 1 Quality : {phase1_score}/10 ({phase1_grade})",
        f"  Config Used     : {config_path}",
        "╚══════════════════════════════════════════════════════════════════╝",
        "",
        "SCENARIO GENERATION:",
        "─" * 66,
        f"  Output folder  : {gen.get('scenarios_dir', '?')}",
        f"  Train scenarios: {gen.get('train_count', 0)}",
        f"  Test scenarios : {gen.get('test_count', 0)}",
        f"  Total          : {gen.get('total_scenarios', 0)}",
        f"  Status         : {gen.get('status', '?').upper()}",
        "",
    ]

    if dep_missing:
        lines += [
            "RUNTIME EVALUATION:",
            "─" * 66,
            "  ⚠ CyberBattleSim is not installed — skipping runtime evaluation.",
            "",
            "  To run evaluation manually after installing CyberBattleSim:",
            f"    python pipeline/phase2/test_env_integration.py \\",
            f"      --data-dir {gen.get('scenarios_dir', '<dir>')} \\",
            f"      --steps 5000 --num-agents 3 --episodes 3",
            "",
        ]
    else:
        lines += [
            "RUNTIME EVALUATION:",
            "─" * 66,
            f"  Scenarios tested  : {n_total}",
            f"  Solved            : {n_solved}/{n_total}  ({solve_rate*100:.1f}%)",
            f"  Mean steps        : {agg.get('mean_steps', 0):.0f}",
            f"  Mean reward       : {agg.get('mean_reward', 0):.2f}",
            f"  Mean nodes owned  : {agg.get('mean_nodes_owned', 0):.1f}",
            f"  Mean creds found  : {agg.get('mean_creds_found', 0):.1f}",
            "",
            "  AVERAGE TOPOLOGY:",
            f"    Node count    : {agg.get('mean_node_count', 0):.1f}",
            f"    Graph density : {agg.get('mean_graph_density', 0):.4f}",
            f"    Diameter      : {agg.get('mean_diameter', 0):.1f}",
            "",
        ]

        per = ev.get("per_scenario_metrics", [])
        if per:
            lines += ["  PER-SCENARIO RESULTS:", "  " + "─" * 62]
            for m in per:
                icon   = "✓" if m.get("is_solved") else "✗"
                name   = m.get("scenario_name", "?")[:36]
                steps  = m.get("steps_taken", 0)
                reward = m.get("total_reward", 0.0)
                goals  = m.get("goals_captured", "?")
                creds  = m.get("credentials_discovered", 0)
                lines.append(
                    f"  {icon} {name:<36} {steps:>6} steps  "
                    f"reward={reward:>8.1f}  goals={goals}  creds={creds}"
                )
            lines.append("")

    summary_path = ev.get("summary_prompt_path", "")
    if summary_path:
        lines += [
            "DATASET EVALUATION PROMPT:",
            "─" * 66,
            f"  Saved to: {summary_path}",
            "  This file contains an LLM analysis request covering topological",
            "  realism, lateral movement health, node role distribution, and",
            "  specific generator improvement recommendations.",
            "",
        ]

    lines += [
        "─" * 66,
        f"  VERDICT: {verdict}",
        "─" * 66,
        "",
    ]

    report_text = "\n".join(lines)

    # Persist report inside the scenario folder
    sc_dir = Path(gen.get("scenarios_dir", PHASE2_ROOT / scenario_name))
    report_dir = sc_dir
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "phase2_report.txt"
    report_path.write_text(report_text, encoding="utf-8")

    summary = (
        f"Phase 2 {'complete' if passed else 'needs review'}: "
        f"{gen.get('total_scenarios', 0)} scenarios generated"
        + (f", {n_solved}/{n_total} solved ({solve_rate*100:.0f}% solve rate)." if not dep_missing
           else "; runtime evaluation pending CyberBattleSim install.")
    )

    return {
        "passed":           passed,
        "formatted_report": report_text,
        "report_path":      str(report_path.resolve()),
        "summary":          summary,
        "solve_rate":       solve_rate,
        "total_scenarios":  n_total,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 14: generate_human_report
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def generate_human_report(
    scenarios_dir: str,
    phase2_report_path: str = "",
    split: str = "all",
    config_path: str = "",
) -> Dict[str, Any]:
    """
    Phase 2, Step 3 (human): Append EDA analysis to phase2_report.txt and
    save all plots as PNGs. Intended for human review — NOT fed into LLM context.

    Runs DomainAnalysis + all cbs_eda_graphs plot suites on the generated
    scenario tree, saves every figure as a PNG under <report_dir>/figures/, and
    appends a structured EDA section to the existing phase2_report.txt.

    When config_path is provided, also generates 4 CVE grounding figures
    (success_rate distribution, attack surface map, exploit-cost distribution,
    CVE property coverage scorecard) saved to <figures_dir>/cve_grounding/.

    IMPORTANT: This tool deliberately returns only file *paths* — it never
    returns image data, base64, or plot content so that graphs cannot
    accidentally appear in LLM context.

    Args:
        scenarios_dir: Root directory of generated scenarios
            (e.g., phase2_output/enterprise_ad_3tier_v1).
        phase2_report_path: Path to the existing phase2_report.txt to append to.
            Defaults to <scenarios_dir>/phase2_report.txt.
        split: Which scenario split to analyse: "train", "test", or "all".
        config_path: Optional path to the Phase 1 domain config YAML.
            When provided, 4 CVE grounding graphs are generated and added to the PDF.

    Returns:
        Dict with keys:
          - report_path: Absolute path to phase2_report.txt (with EDA appended)
          - figures_dir: Absolute path to the figures/ directory
          - plots_saved: Number of PNG figures written
          - cve_plots_saved: Number of CVE grounding PNGs written
          - plot_names: List of figure filenames (names only, no data)
          - scenarios_analysed: Number of scenario dirs processed
          - solve_rate: Runtime solve rate (from run_metrics.json)
          - status: "success", "partial", or "failed"
    """
    sp = Path(scenarios_dir)
    if not sp.is_dir():
        return {"status": "failed", "error": f"scenarios_dir not found: {scenarios_dir}"}

    if not phase2_report_path:
        phase2_report_path = str(sp / "phase2_report.txt")

    if split not in ("train", "test", "all"):
        split = "all"

    cmd = [
        "/home/ariel/miniconda3/envs/cybersim/bin/python",
        str(TOOLS_DIR / "reporting" / "02_human_report.py"),
        "--scenarios-dir", str(sp),
        "--append-to",     phase2_report_path,
        "--split",         split,
    ]
    if config_path:
        p = Path(config_path)
        if not p.is_absolute():
            candidate = REPO_ROOT / p
            if not candidate.exists():
                candidate = DATA_DIR / f"{config_path}.yaml"
            p = candidate
        if p.exists():
            cmd += ["--config", str(p)]

    timeout = 600
    result  = _run_subprocess(cmd, timeout=timeout)

    # Parse the JSON summary emitted after __SUMMARY_JSON__ marker
    stdout  = result.get("stdout", "")
    summary: Dict[str, Any] = {}
    marker  = "__SUMMARY_JSON__"
    if marker in stdout:
        try:
            json_part = stdout.split(marker, 1)[1].strip()
            summary   = json.loads(json_part.split("\n")[0])
        except Exception:
            pass

    if result["returncode"] != 0 and not summary:
        return {
            "status":  "failed",
            "error":   result.get("stderr", "")[-500:] or result.get("stdout", "")[-500:],
        }

    return {
        "report_path":        summary.get("report_path", ""),
        "pdf_path":           summary.get("pdf_path", ""),
        "per_scenario_pdfs":  summary.get("per_scenario_pdfs", 0),
        "figures_dir":        summary.get("figures_dir", ""),
        "plots_saved":        summary.get("plots_saved", 0),
        "cve_plots_saved":    summary.get("cve_plots_saved", 0),
        "plot_names":         summary.get("plot_names", []),
        "scenarios_analysed": summary.get("scenarios_analysed", 0),
        "solve_rate":         summary.get("solve_rate", 0.0),
        "status":             summary.get("status", "partial" if summary else "failed"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 15: get_pipeline_config
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def get_pipeline_config() -> Dict[str, Any]:
    """
    Return the active pipeline configuration loaded from .env.

    Shows DATASET_ROOT, MAX_RETRIES, and all Phase 1 / Phase 2 thresholds.
    Call this at the start of any pipeline run so the LLM knows where outputs
    will be written and what the pass/fail thresholds are.

    Returns:
        Dict with keys:
          - dataset_root: Absolute path where all outputs are written
          - phase1_output_root: Subtree for Phase 1 pipeline output
          - phase2_output_root: Subtree for Phase 2 scenario output
          - max_retries: Full-pipeline retry limit
          - phase1_min_score: Quality score threshold to proceed to Phase 2
          - phase2_min_solve_rate: Heuristic solve-rate threshold to accept Phase 2
          - phase2_defaults: Dict of Phase 2 generation/evaluation defaults
          - env_file: Path to the .env file (may not exist)
    """
    return {
        "dataset_root":        str(DATASET_ROOT),
        "phase1_output_root":  str(OUTPUT_ROOT),
        "phase2_output_root":  str(PHASE2_ROOT),
        "max_retries":         MAX_RETRIES,
        "phase1_min_score":    PHASE1_MIN_SCORE,
        "phase2_min_solve_rate": PHASE2_MIN_SOLVE,
        "phase2_defaults": {
            "train_count":  PHASE2_TRAIN_COUNT,
            "test_count":   PHASE2_TEST_COUNT,
            "strata":       PHASE2_STRATA,
            "max_steps":    PHASE2_MAX_STEPS,
            "num_agents":   PHASE2_NUM_AGENTS,
            "max_episodes": PHASE2_MAX_EPISODES,
        },
        "env_file": str(REPO_ROOT / ".env"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 16: run_phase2_pipeline
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def run_phase2_pipeline(
    config_path: str,
    scenario_name: str,
    attempt: int = 1,
    phase1_score: float = 0.0,
    phase1_grade: str = "",
    train_count: int = 0,
    test_count: int = 0,
    strata: str = "",
    max_steps: int = 0,
    num_agents: int = 0,
    max_episodes: int = 0,
) -> Dict[str, Any]:
    """
    Run the complete Phase 2 pipeline in one call:
      1. Generate stratified scenarios  (run_phase2_generation)
      2. Evaluate with heuristic agents (run_phase2_evaluation)
      3. Write LLM-facing Phase 2 report (generate_phase2_report)
      4. Append EDA analysis + figures  (generate_human_report)

    Outputs go to DATASET_ROOT/phase2/<scenario_name>/attempt_<N>/.
    Pass/fail verdict uses PHASE2_MIN_SOLVE_RATE from .env.

    IMPORTANT: This tool deliberately does NOT return image data — generate_human_report
    saves figures as PNG files and only paths are returned.

    Args:
        config_path: Path to the Phase 1 domain config YAML.
        scenario_name: Short name for the domain (e.g. "enterprise_ad_3tier").
        attempt: Which retry attempt this is (1-based). Used for output sub-folder.
        phase1_score: Phase 1 quality score (0–10) — included in the report header.
        phase1_grade: Phase 1 letter grade — included in the report header.
        train_count / test_count / strata / max_steps / num_agents / max_episodes:
            Override .env defaults (0 / "" means use env default).

    Returns:
        Dict with keys:
          - passed: True if solve_rate >= PHASE2_MIN_SOLVE_RATE
          - solve_rate: Heuristic agent solve rate (0–1)
          - scenarios_dir: Path to the scenario directory
          - report_path: Path to phase2_report.txt (LLM + EDA combined)
          - figures_dir: Path to figures/ directory (PNG plots — not read back)
          - plots_saved: Number of PNG figures written
          - generation_result: Full generation dict
          - evaluation_result: Full evaluation dict (no image data)
          - attempt: Which attempt this was
          - status: "passed", "failed", or "error"
          - error: Error message if status == "error"
    """
    cfg = get_pipeline_config()

    # Resolve output dir for this attempt
    attempt_dir = PHASE2_ROOT / scenario_name / f"attempt_{attempt:02d}"
    attempt_dir.mkdir(parents=True, exist_ok=True)

    # Apply .env defaults for unset params
    train_count  = train_count  or PHASE2_TRAIN_COUNT
    test_count   = test_count   or PHASE2_TEST_COUNT
    strata       = strata       or PHASE2_STRATA
    max_steps    = max_steps    or PHASE2_MAX_STEPS
    num_agents   = num_agents   or PHASE2_NUM_AGENTS
    max_episodes = max_episodes or PHASE2_MAX_EPISODES

    # ── Step 1: Generate scenarios ──────────────────────────────────────────
    gen_result = run_phase2_generation(
        config_path=config_path,
        output_dir=str(attempt_dir),
        train_count=train_count,
        test_count=test_count,
        strata=strata,
    )
    if gen_result.get("status") == "failed":
        return {
            "passed": False, "attempt": attempt,
            "status": "error", "error": f"Generation failed: {gen_result}",
        }

    scenarios_dir = gen_result.get("scenarios_dir", str(attempt_dir))

    # ── Step 2: Evaluate ────────────────────────────────────────────────────
    eval_result = run_phase2_evaluation(
        scenarios_dir=scenarios_dir,
        max_steps=max_steps,
        num_agents=num_agents,
        max_episodes=max_episodes,
    )

    # ── Step 3: LLM-facing Phase 2 report ──────────────────────────────────
    report_result = generate_phase2_report(
        scenario_name=scenario_name,
        config_path=config_path,
        generation_result=gen_result,
        evaluation_result=eval_result,
        phase1_score=phase1_score,
        phase1_grade=phase1_grade,
    )
    report_path = report_result.get("report_path", "")

    # ── Step 4: Human EDA report (appended to phase2_report.txt) ───────────
    human_result = generate_human_report(
        scenarios_dir=scenarios_dir,
        phase2_report_path=report_path,
        config_path=config_path,
    )

    solve_rate = eval_result.get("solve_rate", 0.0)
    passed     = solve_rate >= PHASE2_MIN_SOLVE

    return {
        "passed":            passed,
        "solve_rate":        solve_rate,
        "scenarios_dir":     scenarios_dir,
        "report_path":       report_path,
        "pdf_path":          human_result.get("pdf_path", ""),
        "figures_dir":       human_result.get("figures_dir", ""),
        "plots_saved":       human_result.get("plots_saved", 0),
        "cve_plots_saved":   human_result.get("cve_plots_saved", 0),
        "generation_result": gen_result,
        "evaluation_result": {k: v for k, v in eval_result.items()
                              if k != "per_scenario_metrics"},
        "attempt":           attempt,
        "status":            "passed" if passed else "failed",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 17: generate_config_from_bitnami
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def generate_config_from_bitnami(
    scenario_description: str,
    chart_names: List[str],
    config_name: str = "",
) -> Dict[str, Any]:
    """
    Generate a rich config prompt grounded in real Bitnami chart CVEs and
    properties, using the pre-built dataset in data/vulnerability_db/.

    This is the fast path — no cloning or scanning needed. The dataset was
    built by scanning bitnami/charts (136 charts) with Trivy across 7 key
    images (postgresql, redis, nginx, mongodb, wordpress, kafka, keycloak),
    yielding 1 463 unique CVEs.

    Args:
        scenario_description: Natural-language description of the attack scenario.
        chart_names:          Bitnami charts to include (e.g. ["postgresql","redis","nginx"]).
                              Available: postgresql, redis, nginx, mongodb, wordpress,
                              kafka, keycloak.  Pass [] to include all scanned charts.
        config_name:          Desired config file name (auto-derived if empty).

    Returns:
        Dict with keys:
          - config_prompt:  Ready for generate_template_yaml as scenario_description
          - summary:        One-page intelligence summary
          - cve_count:      CVEs included from selected charts
          - properties:     Detected CyberBattleSim properties
          - tiers:          Inferred network tiers
    """
    if str(PIPELINE_DATA_DIR) not in sys.path:
        sys.path.insert(0, str(PIPELINE_DATA_DIR))
    try:
        from trivy_to_config import (load_bitnami_dataset, filter_dataset_for_charts,
                                     build_config_prompt, build_intelligence_summary)
    except ImportError as exc:
        return {"error": f"Could not import trivy_to_config: {exc}"}

    scan_data, analysis_data = load_bitnami_dataset()

    if chart_names:
        scan_data, analysis_data = filter_dataset_for_charts(
            scan_data, analysis_data, chart_names
        )

    if not config_name:
        config_name = "_".join(chart_names[:3]) if chart_names else "bitnami_scenario"

    prompt  = build_config_prompt(scan_data, analysis_data, scenario_description, config_name)
    summary = build_intelligence_summary(scan_data, analysis_data)

    return {
        "config_prompt": prompt,
        "summary":       summary,
        "cve_count":     scan_data.get("cve_count", 0),
        "properties":    analysis_data.get("all_properties", []),
        "tiers":         analysis_data.get("tiers", {}),
        "config_name":   config_name,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 18: scan_repo_with_trivy
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def scan_repo_with_trivy(
    repo_url: str,
    min_severity: str = "MEDIUM",
    keep_clone: bool = False,
) -> Dict[str, Any]:
    """
    Clone a public git repository and run Trivy to extract real CVE data.

    Trivy scans all package manifests (npm, pip, maven, gradle, go.mod, Cargo.toml,
    etc.) and returns structured CVE findings including CVSS scores, attack vectors,
    and normalised success_rate values ready for CyberBattleSim configs.

    Args:
        repo_url:     Full git clone URL (https or ssh).
        min_severity: Minimum severity to include: CRITICAL | HIGH | MEDIUM | LOW.
                      Default MEDIUM. Use HIGH for less noise.
        keep_clone:   If True, keep the cloned repo on disk (returned in repo_dir).

    Returns:
        Dict with keys:
          - repo_url, repo_dir, error (None if successful)
          - cve_count, critical, high, network_exploitable
          - pkg_managers: list of detected package ecosystems
          - top_cves: list of up to 20 CVEs sorted by CVSS score, each with:
              cve_id, pkg_name, severity, cvss_score, attack_vector,
              attack_complexity, success_rate, exploit_cost, description, references
    """
    if str(PIPELINE_DATA_DIR) not in sys.path:
        sys.path.insert(0, str(PIPELINE_DATA_DIR))
    try:
        from trivy_scanner import TrivyScanner, scan_result_to_dict
    except ImportError as exc:
        return {"error": f"Could not import trivy_scanner: {exc}"}

    work_dir = REPO_ROOT / ".trivy_workdir"
    work_dir.mkdir(parents=True, exist_ok=True)

    scanner = TrivyScanner(work_dir=work_dir, keep_clone=keep_clone)
    result  = scanner.scan(repo_url, min_severity=min_severity)
    data    = scan_result_to_dict(result)

    if result.error:
        return {"error": result.error, **data}

    return data


# ─────────────────────────────────────────────────────────────────────────────
# Tool 18: analyze_repo_structure
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def analyze_repo_structure(
    repo_path: str,
) -> Dict[str, Any]:
    """
    Analyse a cloned repository directory to extract tech stack, service
    boundaries, and CyberBattleSim property suggestions.

    Walks all package manifests and docker-compose files to identify:
      - Which services exist (web, db, auth, worker, file, etc.)
      - What OS/platform each uses (Linux/Windows, NodeJS/Java/Python/…)
      - How they map to CyberBattleSim node-group properties
      - Inferred network tiers (WebTier, DataTier, AuthTier, …)

    Args:
        repo_path: Absolute path to the cloned repository directory.
                   Use the repo_dir returned by scan_repo_with_trivy.

    Returns:
        Dict with keys:
          - repo_dir
          - subprojects: list of {path, pkg_manager, packages, properties, service_type}
          - docker_services: list of {name, image, ports, properties}
          - all_properties: flat list of all detected CyberBattleSim properties
          - service_map: {service_name → [properties]}
          - tiers: {WebTier/DataTier/… → [service_names]}
    """
    if str(PIPELINE_DATA_DIR) not in sys.path:
        sys.path.insert(0, str(PIPELINE_DATA_DIR))
    try:
        from repo_analyzer import RepoAnalyzer, repo_analysis_to_dict
    except ImportError as exc:
        return {"error": f"Could not import repo_analyzer: {exc}"}

    p = Path(repo_path)
    if not p.is_dir():
        return {"error": f"repo_path does not exist or is not a directory: {repo_path}"}

    analyzer = RepoAnalyzer()
    analysis = analyzer.analyze(p)
    return repo_analysis_to_dict(analysis)


# ─────────────────────────────────────────────────────────────────────────────
# Tool 19: build_repo_config_prompt
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def build_repo_config_prompt(
    repo_url: str,
    scenario_description: str,
    config_name: str = "",
    min_severity: str = "HIGH",
    keep_clone: bool = False,
) -> Dict[str, Any]:
    """
    Full pipeline: clone repo → Trivy scan → structural analysis → generate a
    rich intelligence prompt ready for generate_template_yaml.

    This is the main entry point for the Trivy-grounded config generation workflow:

      1. Clones the repo (shallow, depth=1)
      2. Runs Trivy to extract real CVEs with CVSS scores and attack vectors
      3. Analyses package manifests and docker-compose files to detect tech stack
      4. Combines everything into a detailed prompt that includes:
           - Real CVE IDs, CVSS scores, and normalised success_rates
           - Detected properties (NodeJS, Java, PostgreSQL, etc.)
           - Inferred network tiers and attack flow suggestions
           - YAML seed for solvability_vulnerabilities

    The returned `config_prompt` should be passed as `scenario_description` to
    generate_template_yaml. The LLM then uses this grounded data to generate
    a realistic domain config YAML, which flows through the normal
    validate → evaluate → fix loop.

    Args:
        repo_url:             Git clone URL (e.g. https://github.com/org/repo).
        scenario_description: Human description of the attack scenario intent.
        config_name:          Desired config name (defaults to repo name).
        min_severity:         Minimum Trivy severity (default HIGH to reduce noise).
        keep_clone:           Keep the cloned repo on disk after analysis.

    Returns:
        Dict with keys:
          - config_prompt:   Full prompt string for generate_template_yaml
          - summary:         One-page intelligence summary (display to user)
          - scan_data:       Raw scan result dict
          - analysis_data:   Raw repo analysis dict
          - config_name:     Resolved config name
          - error:           None if successful
    """
    if str(PIPELINE_DATA_DIR) not in sys.path:
        sys.path.insert(0, str(PIPELINE_DATA_DIR))
    try:
        from trivy_scanner  import TrivyScanner, scan_result_to_dict
        from repo_analyzer  import RepoAnalyzer,  repo_analysis_to_dict
        from trivy_to_config import build_config_prompt, build_intelligence_summary
    except ImportError as exc:
        return {"error": f"Import failed: {exc}. Ensure pipeline/ is on PYTHONPATH."}

    # Derive config name from repo URL if not provided
    if not config_name:
        name = repo_url.rstrip("/").split("/")[-1]
        config_name = name[:-4] if name.endswith(".git") else name

    work_dir = REPO_ROOT / ".trivy_workdir"
    work_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Trivy scan ────────────────────────────────────────────────────
    scanner = TrivyScanner(work_dir=work_dir, keep_clone=True)   # keep for step 2
    scan_result = scanner.scan(repo_url, min_severity=min_severity)

    if scan_result.error and "trivy" not in scan_result.error.lower():
        return {"error": f"Clone/scan failed: {scan_result.error}"}

    scan_data = scan_result_to_dict(scan_result)

    # ── Step 2: Repo structure analysis ──────────────────────────────────────
    repo_dir = work_dir / (repo_url.rstrip("/").split("/")[-1].removesuffix(".git"))
    analysis_data: dict = {}
    if repo_dir.is_dir():
        analyzer = RepoAnalyzer()
        analysis = analyzer.analyze(repo_dir)
        analysis_data = repo_analysis_to_dict(analysis)
        if not keep_clone:
            import shutil
            shutil.rmtree(repo_dir, ignore_errors=True)
    else:
        analysis_data = {
            "repo_dir": str(repo_dir),
            "subprojects": [], "docker_services": [],
            "all_properties": [], "service_map": {}, "tiers": {},
        }

    # ── Step 3: Build prompt ──────────────────────────────────────────────────
    prompt = build_config_prompt(
        scan_data   = scan_data,
        analysis    = analysis_data,
        description = scenario_description,
        config_name = config_name,
    )
    summary = build_intelligence_summary(scan_data, analysis_data)

    return {
        "config_prompt":  prompt,
        "summary":        summary,
        "scan_data":      scan_data,
        "analysis_data":  analysis_data,
        "config_name":    config_name,
        "error":          scan_result.error,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 21: scrape_windows_cves
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def scrape_windows_cves(
    api_key: str = "",
    min_severity: str = "HIGH",
    out_path: str = "",
) -> dict:
    """
    Query the NVD API v2 to collect Windows-specific CVE data and save it to
    data/vulnerability_db/windows_cves.json.

    Fetches two sets:
      1. Curated well-known Windows exploits (EternalBlue, ZeroLogon, BlueKeep,
         PrintNightmare, ProxyShell, etc.) by CVE ID.
      2. Recent HIGH/CRITICAL CVEs for SMB, RDP, AD, IIS, Exchange, MSSQL,
         Print Spooler, NTLM relay, and credential categories via keyword search.

    Args:
        api_key:      NVD API key (optional, increases rate limit 10×).
        min_severity: Minimum severity to collect (default: HIGH).
        out_path:     Output JSON path (default: data/vulnerability_db/windows_cves.json).
    """
    import sys
    sys.path.insert(0, str(PIPELINE_DATA_DIR))
    from nvd_scraper import NVDScraper, save_dataset

    dest = Path(out_path) if out_path else (
        Path(__file__).resolve().parent.parent
        / "data" / "vulnerability_db" / "windows_cves.json"
    )

    scraper = NVDScraper(api_key=api_key or None, min_severity=min_severity)
    cves    = scraper.scrape()
    data    = save_dataset(cves, dest)

    from collections import Counter
    sev_counts = Counter(c["severity"] for c in data["cves"])
    av_counts  = Counter(c["attack_vector"] for c in data["cves"])
    cat_counts = Counter(c["category"] for c in data["cves"])

    return {
        "status":         "success",
        "cve_count":      data["unique_cve_count"],
        "severity":       dict(sev_counts),
        "attack_vectors": dict(av_counts),
        "categories":     dict(cat_counts),
        "output_path":    str(dest),
        "sample": [
            {"cve_id": c["cve_id"], "cvss_score": c["cvss_score"],
             "success_rate": c["success_rate"], "category": c["category"]}
            for c in data["cves"][:10]
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 22: load_windows_cves_summary
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def load_windows_cves_summary(
    categories: str = "",
    min_cvss: float = 6.5,
) -> dict:
    """
    Load and summarise the pre-built Windows CVE dataset from
    data/vulnerability_db/windows_cves.json.

    Returns CVE-backed parameters ready for use in CBS YAML vulnerability
    definitions, grouped by product category (smb, rdp, active_directory,
    iis, exchange, mssql, print_spooler, credential, adcs, ntlm_relay).

    Args:
        categories: Comma-separated list of categories to include (default: all).
        min_cvss:   Minimum CVSS score filter (default: 6.5).
    """
    import sys
    sys.path.insert(0, str(PIPELINE_DATA_DIR))
    from nvd_scraper import load_windows_dataset, filter_windows_cves, build_windows_config_prompt

    data = load_windows_dataset()
    if not data:
        return {"error": "Windows CVE dataset not found. Run scrape_windows_cves first."}

    cats = [c.strip() for c in categories.split(",")] if categories else None
    filtered = filter_windows_cves(data, categories=cats, min_cvss=min_cvss)

    prompt_section = build_windows_config_prompt(
        data, "Windows enterprise scenario", categories=cats, min_cvss=min_cvss
    )

    from collections import Counter
    return {
        "total_cves":       data["unique_cve_count"],
        "filtered_cves":    len(filtered),
        "categories":       data.get("categories", []),
        "severity_breakdown": dict(Counter(c["severity"] for c in filtered)),
        "top_cves": [
            {
                "cve_id":       c["cve_id"],
                "label":        c.get("label", ""),
                "category":     c["category"],
                "cvss_score":   c["cvss_score"],
                "attack_vector":c["attack_vector"],
                "success_rate": c["success_rate"],
                "exploit_cost": c["exploit_cost"],
                "cbs_type":     c["cbs_type"],
                "probability":  c["probability"],
                "cbs_properties": c["cbs_properties"],
                "description":  c["description"][:200],
            }
            for c in filtered[:20]
        ],
        "config_prompt_section": prompt_section,
        "category_map": data.get("category_vuln_map", {}),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 23: scan_additional_bitnami_images
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def scan_additional_bitnami_images(
    images: str = "",
    merge_with_existing: bool = True,
) -> dict:
    """
    Scan additional container images with Trivy and merge results into the
    existing bitnami CVE dataset (data/vulnerability_db/bitnami_cves.json).

    Covers the missing enterprise service tiers:
      AppTier:  jenkins, grafana, vault, kong
      DataTier: mariadb, mysql, elasticsearch
      WorkerTier: rabbitmq, airflow

    Args:
        images: Comma-separated list of extra images to scan (overrides defaults).
        merge_with_existing: If True, merge into existing bitnami_cves.json.
    """
    import sys, subprocess, shutil, tempfile
    sys.path.insert(0, str(PIPELINE_DATA_DIR))
    from trivy_scanner import TrivyScanner, scan_result_to_dict, SEVERITY_RANK
    from repo_analyzer import image_to_props

    DEFAULT_IMAGES = [
        # AppTier
        ("jenkins",      "jenkins/jenkins:lts-jdk21",                     ["AppServer", "Java", "Linux"]),
        ("grafana",      "grafana/grafana:11.4.0",                         ["AppServer", "Linux", "GoRuntime"]),
        ("vault",        "hashicorp/vault:1.17.3",                         ["AppServer", "Linux", "GoRuntime"]),
        ("kong",         "kong:3.8",                                        ["APIGateway", "Linux"]),
        # DataTier
        ("mariadb",      "mariadb:11.4",                                   ["DatabaseServer", "MySQL", "Linux"]),
        ("mysql",        "mysql:8.4",                                      ["DatabaseServer", "MySQL", "Linux"]),
        ("elasticsearch","docker.elastic.co/elasticsearch/elasticsearch:8.17.0", ["DatabaseServer", "Java", "Linux"]),
        # WebTier
        ("haproxy",      "haproxy:3.1",                                    ["LoadBalancer", "Linux"]),
        ("drupal",       "drupal:11-php8.3-apache",                        ["WebServer", "PHP", "Linux"]),
        # WorkerTier
        ("rabbitmq",     "rabbitmq:4.0-management",                        ["MessageBroker", "WorkerNode", "Linux"]),
        ("airflow",      "apache/airflow:2.10.4",                          ["WorkerNode", "Python", "Linux"]),
        # AuthTier
        ("oauth2-proxy", "quay.io/oauth2-proxy/oauth2-proxy:v7.7.1",      ["AuthServer", "Linux", "GoRuntime"]),
    ]

    if images:
        image_list = []
        for img_str in images.split(","):
            img_str = img_str.strip()
            name = img_str.split("/")[-1].split(":")[0]
            props = list(image_to_props(name)) or ["Linux"]
            image_list.append((name, img_str, props))
    else:
        image_list = DEFAULT_IMAGES

    if not shutil.which("trivy"):
        return {"error": "trivy not found on PATH. Install from https://github.com/aquasecurity/trivy#installation"}

    results: list[dict] = []
    errors:  list[str]  = []

    for chart_name, image_ref, chart_props in image_list:
        print(f"  Scanning {image_ref} …")
        try:
            proc = subprocess.run(
                ["trivy", "image", "--format", "json", "--scanners", "vuln", "--quiet", image_ref],
                capture_output=True, text=True, timeout=600,
            )
            if proc.returncode not in (0, 1):
                errors.append(f"{image_ref}: exit {proc.returncode} — {proc.stderr[:200]}")
                continue
            raw = json.loads(proc.stdout) if proc.stdout.strip() else {}
            threshold = SEVERITY_RANK.get("MEDIUM", 2)
            cves_found = []
            for result in raw.get("Results", []):
                for v in result.get("Vulnerabilities") or []:
                    sev = (v.get("Severity") or "UNKNOWN").upper()
                    if SEVERITY_RANK.get(sev, 0) < threshold:
                        continue
                    from trivy_scanner import _parse_cvss, TrivyCVE
                    score, av, ac, pr = _parse_cvss(v)
                    c = TrivyCVE(
                        cve_id             = v.get("VulnerabilityID", ""),
                        pkg_name           = v.get("PkgName", ""),
                        installed_version  = v.get("InstalledVersion", ""),
                        fixed_version      = v.get("FixedVersion", ""),
                        severity           = sev,
                        cvss_score         = score,
                        attack_vector      = av,
                        attack_complexity  = ac,
                        privileges_required= pr,
                        description        = (v.get("Description") or "")[:350],
                        target_file        = result.get("Target", image_ref),
                        references         = (v.get("References") or [])[:4],
                    )
                    if c.cve_id:
                        cves_found.append({
                            "cve_id":           c.cve_id,
                            "pkg_name":         c.pkg_name,
                            "installed_version":c.installed_version,
                            "fixed_version":    c.fixed_version,
                            "severity":         c.severity,
                            "cvss_score":       c.cvss_score,
                            "attack_vector":    c.attack_vector,
                            "attack_complexity":c.attack_complexity,
                            "success_rate":     c.normalised_success_rate,
                            "exploit_cost":     c.exploit_cost,
                            "description":      c.description,
                            "chart":            chart_name,
                            "app_version":      image_ref.split(":")[-1],
                            "chart_properties": chart_props,
                            "target":           result.get("Target", image_ref),
                        })
            results.append({
                "chart": chart_name,
                "image": image_ref,
                "cve_count": len(cves_found),
                "cves": cves_found,
            })
            print(f"    → {len(cves_found)} CVEs")
        except subprocess.TimeoutExpired:
            errors.append(f"{image_ref}: scan timed out after 600s")
        except Exception as exc:
            errors.append(f"{image_ref}: {exc}")

    # Merge into existing dataset
    merged_count = 0
    if merge_with_existing:
        db_path = Path(__file__).resolve().parent.parent / "data" / "vulnerability_db" / "bitnami_cves.json"
        if db_path.exists():
            existing = json.loads(db_path.read_text())
            seen_ids = {c["cve_id"] for c in existing["cves"]}
            new_cves = []
            for r in results:
                for c in r["cves"]:
                    if c["cve_id"] not in seen_ids or (
                        c["cve_id"] in seen_ids and
                        c["cvss_score"] > next((x["cvss_score"] for x in existing["cves"] if x["cve_id"] == c["cve_id"]), 0)
                    ):
                        seen_ids.add(c["cve_id"])
                        new_cves.append(c)
            existing["cves"].extend(new_cves)
            # Deduplicate keeping highest score
            deduped: dict[str, dict] = {}
            for c in existing["cves"]:
                if c["cve_id"] not in deduped or c["cvss_score"] > deduped[c["cve_id"]]["cvss_score"]:
                    deduped[c["cve_id"]] = c
            existing["cves"] = list(deduped.values())
            existing["unique_cve_count"] = len(existing["cves"])
            existing["charts_scanned"] = list({
                c.get("chart", "") for c in existing["cves"]
            })
            db_path.write_text(json.dumps(existing, indent=2))
            merged_count = len(new_cves)

    return {
        "status":          "success" if not errors else "partial",
        "images_scanned":  len(results),
        "new_cves_merged": merged_count,
        "per_image": [
            {"chart": r["chart"], "image": r["image"], "cve_count": r["cve_count"]}
            for r in results
        ],
        "errors": errors,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 24: generate_cve_graphs
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def generate_cve_graphs(
    config_path: str,
    out_dir: str = "",
    prefix: str = "",
) -> Dict[str, Any]:
    """
    Generate 4 CVE-grounding visualisation figures for a domain config YAML.

    Evaluates the config with ScenarioQualityEvaluator (which now includes the
    cve_grounding dimension) and renders:
      1. cve_01_success_rate.png  — SR histogram by category + implied CVSS
      2. cve_02_attack_surface.png — REMOTE vs LOCAL per category + SR scatter
      3. cve_03_cost_os_coverage.png — exploit-cost tier pie + OS coverage bar
      4. cve_04_grounding_scorecard.png — property frequency + CVE grounding gauge

    IMPORTANT: Returns only file paths — never image data or base64 content.

    Args:
        config_path: Path to the domain config YAML (absolute or relative to repo root).
        out_dir:     Directory to write PNG files.
                     Default: phase2_output/<config_stem>/cve_graphs/
        prefix:      Optional filename prefix (e.g. scenario name or attempt number).

    Returns:
        Dict with keys:
          - figures: Dict mapping graph name → absolute path
          - cve_grounding_score: int — score from the CVE grounding dimension (0–10)
          - cve_grounding_grade: str — letter grade (A+/A/B/C/D/F)
          - cve_metrics: structured CVE metrics extracted from the config
          - status: "success" or "failed"
    """
    p = Path(config_path)
    if not p.is_absolute():
        candidate = REPO_ROOT / p
        if not candidate.exists():
            candidate = DATA_DIR / f"{config_path}.yaml"
        p = candidate

    if not p.exists():
        return {"status": "failed", "error": f"Config file not found: {config_path}"}

    if str(PHASE1_DIR) not in sys.path:
        sys.path.insert(0, str(PHASE1_DIR))
    _reporting_dir = TOOLS_DIR / "reporting"
    if str(_reporting_dir) not in sys.path:
        sys.path.insert(0, str(_reporting_dir))

    try:
        import yaml as _yaml
        from quality_evaluator import ScenarioQualityEvaluator
        from cve_scenario_graphs import generate_cve_graphs as _gen_cve_graphs
    except ImportError as exc:
        return {"status": "failed", "error": f"Import error: {exc}"}

    try:
        cfg = _yaml.safe_load(p.read_text(encoding="utf-8"))
        eval_result = ScenarioQualityEvaluator(cfg, config_name=p.stem).evaluate()
    except Exception as exc:
        return {"status": "failed", "error": f"Evaluation failed: {exc}"}

    dest = Path(out_dir) if out_dir else (PHASE2_ROOT / p.stem / "cve_graphs")
    dest.mkdir(parents=True, exist_ok=True)

    try:
        paths = _gen_cve_graphs(eval_result, dest, prefix=prefix or p.stem)
    except Exception as exc:
        return {"status": "failed", "error": f"Graph generation failed: {exc}"}

    cve_dim = eval_result.get("dimensions", {}).get("cve_grounding", {})

    return {
        "figures": {name: str(path.resolve()) for name, path in paths.items()},
        "cve_grounding_score": cve_dim.get("score", 0),
        "cve_grounding_grade": cve_dim.get("grade", "?"),
        "cve_metrics":         eval_result.get("cve_metrics", {}),
        "out_dir":             str(dest.resolve()),
        "status":              "success",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
