#!/usr/bin/env python3
"""
pipeline/run.py
==========================
Structured, step-locked pipeline runner for CyberBattleSim domain generation.
Integrates an actor-critic improvement loop into Phase 2 (runtime).

Phase 1 — format validation only
  1  Config structural check (schema, identifiers, BFS reachability)
  2  Generate phase1_report.txt

Phase 2 — runtime actor-critic loop
  3  Generate stratified scenarios
  4  BFS heuristic-agent evaluation
  5  LLM quality evaluation (YAML + runtime metrics → 6-dimension score)
     Actor: apply_critic_fixes.repair_config()
     Critic: ScenarioQualityEvaluator.evaluate_with_llm(runtime_metrics)
     Stops when score ≥ --target-score or --max-bfs-rounds hit
  6  EDA report + figures
  7  Topology graphs (SVG + combined PDF)

Cross-domain (optional)
  8  Executive summary report (all domains)

Usage
-----
  # Single pass (original behaviour)
  python pipeline/run.py data/scenarios/swin_serverfarm_standalone_v1.yaml

  # With actor-critic improvement loop
  python pipeline/run.py data/scenarios/swin_serverfarm_standalone_v1.yaml \\
      --target-score 8.0 --max-bfs-rounds 2
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

from constants import (
    BFS_EPISODES,
    BFS_MAX_STEPS,
    BFS_NUM_AGENTS,
    MAX_BFS_ROUNDS,
    MAX_REPAIR_ATTEMPTS,
    MIN_SOLVE_RATE,
    REPLACEMENT_MAX_ATTEMPTS,
    SOLVE_RATE_DESIGN_THRESHOLD,
    TARGET_SCORE,
)

TOOLS_DIR       = Path(__file__).resolve().parent
REPO_ROOT       = TOOLS_DIR.parent
CYBERSIM_PYTHON = Path("/home/ariel/miniconda3/envs/cybersim/bin/python")
FALLBACK_PYTHON = Path(sys.executable)

sys.path.insert(0, str(TOOLS_DIR))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _python() -> str:
    return str(CYBERSIM_PYTHON) if CYBERSIM_PYTHON.exists() else str(FALLBACK_PYTHON)


def _read_env(key: str, default: str = "") -> str:
    """Read a variable from .env file, falling back to os.environ."""
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{key}=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip()
    return os.environ.get(key, default)


def _dataset_root() -> Path:
    val = _read_env("DATASET_ROOT")
    if val:
        return Path(val)
    raise RuntimeError("DATASET_ROOT not found in .env or environment")


def _phase2_strata() -> list[str]:
    """Return list of strata from PHASE2_STRATA env var (comma-separated)."""
    raw = _read_env("PHASE2_STRATA", "small")
    return [s.strip() for s in raw.split(",") if s.strip()]



# ─────────────────────────────────────────────────────────────────────────────
# Pipeline runner
# ─────────────────────────────────────────────────────────────────────────────

class PipelineRunner:
    def __init__(
        self,
        config_path:    Path,
        dataset_root:   Path,
        target_score:   float | None = None,              # None = single-pass
        max_bfs_rounds: int          = MAX_BFS_ROUNDS,    # Phase 2 loop limit
        min_solve_rate: float        = MIN_SOLVE_RATE,    # Minimum fraction of solvable scenarios
        user_prompt:    str          = "",      # Natural-language generation request to persist
    ):
        self._active_config  = config_path.resolve()
        self._initial_domain = config_path.stem   # fixed label for log file
        self.dataset_root    = dataset_root
        self.target_score    = target_score
        self.max_bfs_rounds  = max_bfs_rounds
        self.min_solve_rate  = min_solve_rate
        self.user_prompt     = user_prompt

        self.logs_dir = dataset_root / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = self.logs_dir / f"{self._initial_domain}_{ts}.log"
        self._log_fh  = self.log_path.open("w", encoding="utf-8", buffering=1)
        self._step    = 0
        self._errors: list = []
        
        # ── Telemetry storage ────────────────────────────────────────────────
        self.telemetry = {
            "start_time": datetime.datetime.now().isoformat(),
            "tools":      [],  # list of {name, duration, success, cmd}
            "retries":    [],  # list of {step, attempt, count}
            "config":     str(self._active_config),
        }

    # ── Dynamic paths (follow active config version) ────────────────────────

    @property
    def config_path(self) -> Path:
        return self._active_config

    @property
    def domain(self) -> str:
        return self._active_config.stem

    @property
    def phase1_out(self) -> Path:
        return self.dataset_root / "phase1" / self.domain

    @property
    def phase2_out(self) -> Path:
        return self.dataset_root / "phase2" / self.domain

    def _advance_config(self, new_path: Path) -> None:
        old = self._active_config.name
        self._active_config = new_path.resolve()
        self._log(f"  → Config advanced: {old} → {self._active_config.name}")

    # ── Logging / output ────────────────────────────────────────────────────

    def _ts(self) -> str:
        return datetime.datetime.now().strftime("%H:%M:%S")

    def _log(self, text: str, tee: bool = True) -> None:
        self._log_fh.write(text + "\n")
        if tee:
            print(text)

    def _header(self, step: int | str, label: str, round_info: str = "") -> None:
        self._step = step
        bar  = "─" * 64
        tag  = f"  [{round_info}]" if round_info else ""
        self._log(f"\n{bar}")
        self._log(f"  STEP {step}{tag}  [{self._ts()}]  {label}")
        self._log(bar)

    def _ok(self, msg: str = "OK") -> None:
        self._log(f"  ✓  {msg}")

    def _warn(self, msg: str) -> None:
        self._log(f"  ⚠  {msg}")

    def _fail(self, msg: str) -> None:
        self._log(f"  ✗  {msg}")
        self._errors.append(f"Step {self._step}: {msg}")

    def _run(self, cmd: list, cwd: Path = REPO_ROOT,
             abort_on_error: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
        self._log(f"  $ {' '.join(str(c) for c in cmd)}")
        run_env = {**os.environ, **(env or {})}
        
        start_t = time.perf_counter()
        result  = subprocess.run(
            [str(c) for c in cmd],
            capture_output=True, text=True, cwd=str(cwd), env=run_env,
        )
        duration = round(time.perf_counter() - start_t, 2)
        
        # Log to telemetry
        tool_name = Path(cmd[1]).name if "python" in str(cmd[0]) else Path(cmd[0]).name
        self.telemetry["tools"].append({
            "step":     self._step,
            "name":     tool_name,
            "duration": duration,
            "success":  result.returncode == 0,
            "cmd":      " ".join(str(c) for c in cmd)
        })

        if result.stdout:
            for line in result.stdout.splitlines():
                self._log(f"    {line}")
        if result.stderr:
            for line in result.stderr.splitlines():
                if line.strip():
                    self._log(f"    [stderr] {line}")
        if result.returncode != 0 and abort_on_error:
            self._fail(f"Command exited with code {result.returncode}")
            raise RuntimeError(f"Step {self._step} failed")
        return result

    # ── Actor: call repair_config as subprocess ──────────────────────────────

    def _repair(self) -> Path | None:
        """Call apply_critic_fixes on the current config. Returns new config path or None."""
        self._log("  → ACTOR: calling repair_config ...")
        result = subprocess.run(
            [_python(), "pipeline/phase2/_05_apply_critic_fixes.py",
             str(self.config_path), "--max-attempts", str(MAX_REPAIR_ATTEMPTS),
             "--phase2-out", str(self.phase2_out)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        for line in result.stdout.splitlines():
            self._log(f"      {line}")

        # Parse the fixed config path from output
        fixed: Path | None = None
        for line in result.stdout.splitlines():
            if "Fixed config:" in line:
                candidate = Path(line.split("Fixed config:")[-1].strip())
                if not candidate.is_absolute():
                    candidate = REPO_ROOT / candidate
                if candidate.exists():
                    fixed = candidate
                    break
        return fixed

    # ── Critic: collect aggregate BFS runtime metrics ────────────────────────

    _OUTCOME_KEYS = [
        "LeakedCredentials", "LeakedNodesId", "LateralMove",
        "PrivilegeEscalation", "AdminEscalation", "SystemEscalation",
        "ProbeSucceeded", "ExploitFailed",
    ]

    def _collect_runtime_metrics(self) -> dict:
        """Aggregate all run_metrics.json files into a comprehensive metrics dict.

        Covers: episode stats, graph structure, segmentation, payload/property
        distribution, action stats, action outcomes, firewall metrics, and
        per-stratum breakdowns.  Saved to bfs_metrics.json and passed verbatim
        to the LLM evaluation prompt.
        """
        from collections import Counter as _Counter

        all_metrics = []
        for jf in self.phase2_out.rglob("run_metrics.json"):
            try:
                all_metrics.append(json.loads(jf.read_text()))
            except Exception:
                continue

        n = len(all_metrics)
        if n == 0:
            return {"n_scenarios": 0, "total": 0, "solved": 0, "solve_rate": 0.0,
                    "mean_density": 0.0, "mean_diameter": 0.0, "mean_node_count": 0.0}

        def _r(m: dict, k: str) -> float:
            return m.get("topology_metrics", {}).get("routing", {}).get(k, 0)
        def _seg(m: dict, k: str) -> float:
            return m.get("topology_metrics", {}).get("segmentation", {}).get(k, 0)
        def _pay(m: dict, k: str):
            return m.get("topology_metrics", {}).get("payloads", {}).get(k, 0)
        def _fw(m: dict, k: str):
            return m.get("firewall_metrics", {}).get(k, 0)
        def _as(m: dict, k: str) -> float:
            return m.get("action_stats", {}).get(k, 0)

        import statistics as _stats

        solved      = [m for m in all_metrics if m.get("is_solved")]
        avg_nodes   = sum(_r(m, "node_count") for m in all_metrics) / n
        avg_density = sum(_r(m, "density")    for m in all_metrics) / n

        def _pct_bucket(vals: list, buckets: list) -> dict:
            """Count how many values fall into each label bucket."""
            result = {str(b): 0 for b in buckets}
            result[f"{buckets[-1]}+"] = 0
            for v in vals:
                placed = False
                for b in buckets[:-1]:
                    if v <= b:
                        result[str(b)] = result.get(str(b), 0) + 1
                        placed = True
                        break
                if not placed:
                    result[f"{buckets[-1]}+"] = result.get(f"{buckets[-1]}+", 0) + 1
            return result

        # ── Graph structure ───────────────────────────────────────────────────
        diameters_all = [int(_r(m, "diameter")) for m in all_metrics]
        diam_dist: dict = {}
        for d in diameters_all:
            key = str(d) if d <= 6 else "7+"
            diam_dist[key] = diam_dist.get(key, 0) + 1

        graph = {
            "mean_node_count":   round(avg_nodes, 1),
            "mean_edge_count":   round(sum(_r(m, "edge_count")     for m in all_metrics) / n, 1),
            "mean_density":      round(avg_density, 4),
            "mean_diameter":     round(sum(_r(m, "diameter")        for m in all_metrics) / n, 1),
            "min_diameter":      min(diameters_all, default=0),
            "max_diameter":      max(diameters_all, default=0),
            "diameter_distribution": diam_dist,
            "mean_avg_in_deg":   round(sum(_r(m, "avg_in_degree")   for m in all_metrics) / n, 2),
            "mean_avg_out_deg":  round(sum(_r(m, "avg_out_degree")  for m in all_metrics) / n, 2),
            "max_in_degree_avg": round(sum(_r(m, "max_in_degree")   for m in all_metrics) / n, 1),
            "tree_ratio":        round(avg_density * max(avg_nodes, 2), 2),
            "topology_types":    dict(_Counter(
                m.get("network_structure", {}).get("topology_type", "unknown")
                for m in all_metrics
            )),
        }

        # ── Network segmentation ──────────────────────────────────────────────
        segmentation = {
            "mean_isolated_subnets": round(sum(_seg(m, "isolated_subnets_count")      for m in all_metrics) / n, 2),
            "mean_routing_zones":    round(sum(_seg(m, "two_way_routing_zones_count") for m in all_metrics) / n, 2),
        }

        # ── Attack path metrics ───────────────────────────────────────────────
        steps_first  = [m.get("steps_to_first_goal", 0) for m in solved if m.get("steps_to_first_goal")]
        steps_final  = [m.get("steps_to_final_goal", 0) for m in solved if m.get("steps_to_final_goal")]
        steps_all    = [m.get("steps_taken", 0)          for m in solved]
        nodes_owned  = [m.get("nodes_owned", 0)           for m in all_metrics]
        nodes_disc   = [m.get("nodes_discovered", 0)      for m in all_metrics]
        pct_owned    = [m.get("owned_percentage", 0)       for m in all_metrics]
        pct_disc     = [m.get("discovered_percentage", 0)  for m in all_metrics]
        goals_ratio  = [m.get("goals_captured_ratio", 0)   for m in all_metrics]

        def _dist(vals: list) -> dict:
            if not vals: return {}
            s = sorted(vals)
            mid = len(s) // 2
            return {
                "min":    round(min(s), 3),
                "p25":    round(s[len(s) // 4], 3),
                "median": round(s[mid], 3),
                "p75":    round(s[3 * len(s) // 4], 3),
                "max":    round(max(s), 3),
                "mean":   round(sum(s) / len(s), 3),
            }

        attack_paths = {
            "mean_steps_to_first_goal":  round(sum(steps_first) / max(len(steps_first), 1), 1),
            "mean_steps_to_final_goal":  round(sum(steps_final) / max(len(steps_final), 1), 1),
            "steps_distribution":        _dist(steps_all),
            "mean_goals_captured_ratio": round(sum(goals_ratio) / n, 3),
            "mean_nodes_owned":          round(sum(nodes_owned) / n, 2),
            "mean_nodes_discovered":     round(sum(nodes_disc)  / n, 2),
            "mean_pct_owned":            round(sum(pct_owned)   / n, 4),
            "mean_pct_discovered":       round(sum(pct_disc)    / n, 4),
            "nodes_owned_distribution":  _dist(nodes_owned),
        }

        # ── Credential metrics ────────────────────────────────────────────────
        creds_disc  = [m.get("credentials_discovered", 0)     for m in all_metrics]
        creds_cache = [m.get("credentials_in_cache", 0)        for m in all_metrics]
        creds_pct   = [m.get("credentials_discovered_pct", 0)  for m in all_metrics]

        credentials = {
            "mean_creds_discovered":     round(sum(creds_disc)  / n, 1),
            "mean_creds_in_cache":       round(sum(creds_cache) / n, 1),
            "mean_creds_pct":            round(sum(creds_pct)   / n, 4),
            "creds_discovered_distribution": _dist(creds_disc),
        }

        # ── Payload / vulnerability distribution ──────────────────────────────
        all_props: _Counter = _Counter()
        for m in all_metrics:
            for prop, cnt in (_pay(m, "property_counts") or {}).items():
                if prop != "breach_node":
                    all_props[prop] += cnt
        payloads = {
            "mean_vuln_instances": round(sum(_pay(m, "total_vulnerability_instances") for m in all_metrics) / n, 1),
            "mean_unique_vulns":   round(sum(_pay(m, "unique_vulnerabilities")        for m in all_metrics) / n, 1),
            "mean_unique_props":   round(sum(_pay(m, "unique_properties")             for m in all_metrics) / n, 1),
            "top_properties":      dict(all_props.most_common(15)),
        }

        # ── Firewall metrics ──────────────────────────────────────────────────
        allowed_ports: _Counter = _Counter()
        for m in all_metrics:
            for p in m.get("firewall_metrics", {}).get("allowed_ports", []):
                if p != "*":
                    allowed_ports[p] += 1
        firewall = {
            "mean_rules_per_node":    round(sum(_fw(m, "avg_rules_per_node")  for m in all_metrics) / n, 2),
            "mean_firewall_coverage": round(sum(_fw(m, "firewall_coverage")   for m in all_metrics) / n, 3),
            "mean_allow_rules":       round(sum(_fw(m, "allow_rules")         for m in all_metrics) / n, 1),
            "mean_block_rules":       round(sum(_fw(m, "block_rules")         for m in all_metrics) / n, 1),
            "common_allowed_ports":   dict(allowed_ports.most_common(10)),
        }

        # ── Action stats (agent behaviour) ───────────────────────────────────
        action_stats = {
            "mean_local_attack_sr":   round(sum(_as(m, "local_attacks_success_rate")    for m in all_metrics) / n, 3),
            "mean_remote_attack_sr":  round(sum(_as(m, "remote_attacks_success_rate")   for m in all_metrics) / n, 3),
            "mean_port_conn_sr":      round(sum(_as(m, "port_connections_success_rate") for m in all_metrics) / n, 3),
            "mean_overall_sr":        round(sum(_as(m, "overall_actions_success_rate")  for m in all_metrics) / n, 3),
        }

        # ── Full action outcomes ──────────────────────────────────────────────
        all_outcome_keys: set = set()
        for m in all_metrics:
            all_outcome_keys.update(m.get("action_outcomes", {}).keys())
        outcome_totals = {
            k: sum(m.get("action_outcomes", {}).get(k, 0) for m in all_metrics)
            for k in sorted(all_outcome_keys)
        }

        # ── Per-stratum breakdown ─────────────────────────────────────────────
        strata: dict = {}
        for m in all_metrics:
            strata.setdefault(m.get("stratum", "unknown"), []).append(m)
        stratum_stats = {}
        for s, ms in strata.items():
            ns    = len(ms)
            sol_s = [x for x in ms if x.get("is_solved")]
            d_s   = [int(_r(x, "diameter")) for x in ms]
            stratum_stats[s] = {
                "total":              ns,
                "solved":             len(sol_s),
                "solve_rate":         round(len(sol_s) / ns, 3),
                "mean_diameter":      round(sum(d_s) / ns, 1),
                "diameter_distribution": {str(d) if d <= 6 else "7+": d_s.count(d)
                                          for d in sorted(set(d_s))},
                "mean_density":       round(sum(_r(x, "density")    for x in ms) / ns, 4),
                "mean_nodes":         round(sum(_r(x, "node_count") for x in ms) / ns, 1),
                "mean_steps":         round(sum(x.get("steps_taken", 0) for x in sol_s) / max(len(sol_s), 1)),
                "mean_creds":         round(sum(x.get("credentials_discovered", 0) for x in ms) / ns, 1),
                "mean_nodes_owned":   round(sum(x.get("nodes_owned", 0) for x in ms) / ns, 2),
            }

        return {
            # ── summary (executive report compatible) ─────────────────────────
            "n_scenarios":    n,
            "total":          n,
            "solved":         len(solved),
            "solve_rate":     round(len(solved) / n, 3),
            "mean_steps":     round(sum(m.get("steps_taken",  0) for m in solved) / max(len(solved), 1)),
            "mean_reward":    round(sum(m.get("total_reward", 0) for m in all_metrics) / n, 1),
            "mean_nodes":     round(sum(m.get("nodes_owned",  0) for m in all_metrics) / n, 1),
            "mean_creds":     round(sum(m.get("credentials_discovered", 0) for m in all_metrics) / n, 1),
            "mean_density":   graph["mean_density"],
            "mean_diameter":  graph["mean_diameter"],
            "mean_node_count": graph["mean_node_count"],
            "tree_ratio":     graph["tree_ratio"],
            "outcome_totals": outcome_totals,
            # ── detailed sections ─────────────────────────────────────────────
            "graph":          graph,
            "segmentation":   segmentation,
            "attack_paths":   attack_paths,
            "credentials":    credentials,
            "payloads":       payloads,
            "firewall":       firewall,
            "action_stats":   action_stats,
            "by_stratum":     stratum_stats,
        }

    # ── Step implementations ─────────────────────────────────────────────────

    def step1_phase1_validate(self, round_info: str = "") -> None:
        self._header(1, "Phase 1 — Config validation + structural check", round_info)
        self.phase1_out.mkdir(parents=True, exist_ok=True)
        self._run([
            _python(), "pipeline/phase1/pipeline.py",
            "--config", str(self.config_path),
            "--skip-fetch",
            "--train", "3", "--test", "1",
            "--strata", "small",
        ])
        self._ok(f"Config validated — output in phase1/{self.domain}")

    def step1b_zone_coverage_validate(self) -> None:
        """Hard-gate: verify config covers the correct GLOBALTECH zones per zone_manifest.yaml."""
        self._header("1b", "Phase 1 — GLOBALTECH zone coverage check")
        result = self._run(
            [_python(), "pipeline/phase1/03_validate_zone_coverage.py", str(self.config_path)],
            abort_on_error=False,
        )
        if result.returncode == 1:
            self._fail("Zone coverage check FAILED — config does not represent the required GLOBALTECH zones")
            raise RuntimeError("Step 1b failed: zone coverage")
        elif result.returncode == 0:
            self._ok("Zone coverage check passed")
        # exit 2 = no manifest entry → warn and continue
        else:
            self._warn("No manifest entry for this config — zone coverage check skipped")

    def step2_phase1_report(self) -> None:
        """Write a simple Phase 1 validation summary (no quality score — that runs in Phase 2)."""
        self._header(2, "Phase 1 — Generate phase1_report.txt")
        report_path = self.phase1_out / "phase1_report.txt"
        lines_raw = self.config_path.read_text(encoding="utf-8").splitlines()
        desc = next(
            (l.lstrip("#").strip() for l in lines_raw[3:15]
             if l.strip().lstrip("#").strip() and not l.strip().lstrip("#").strip().startswith("=")),
            self.domain,
        )
        report = "\n".join([
            "╬" + "═" * 66 + "╬",
            "  PHASE 1 VALIDATION REPORT",
            f"  Scenario : {self.domain}",
            f"  Config   : {self.config_path}",
            f"  Request  : {desc[:72]}",
            "╚" + "═" * 66 + "╝",
            "",
            "─" * 66,
            "  VERDICT: PHASE 1 COMPLETE — structural validation passed.",
            "  Quality evaluation will run after Phase 2 agent evaluation.",
            "─" * 66,
            "",
        ])
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")
        self._ok(f"phase1_report.txt written → {report_path}")

    def step3_phase2_generate(self, round_info: str = "") -> None:
        self._header(3, "Phase 2 — Generate scenarios", round_info)
        # Persist generation request so the executive report can display it
        if self.user_prompt:
            self.phase2_out.mkdir(parents=True, exist_ok=True)
            (self.phase2_out / "user_prompt.txt").write_text(
                self.user_prompt.strip(), encoding="utf-8"
            )
        env = {"DATASET_ROOT": str(self.dataset_root)}
        self._run([
            _python(), "pipeline/phase2/01_generator.py",
            "--config", str(self.config_path),
            "--out-dir", str(self.dataset_root / "phase2"),
            "--train", str(int(_read_env("PHASE2_TRAIN_COUNT", "5"))),
            "--test",  str(int(_read_env("PHASE2_TEST_COUNT",  "2"))),
            "--workers", "4",
        ], env=env)
        manifest = self.phase2_out / "manifest.json"
        if manifest.exists():
            self._ok(f"Manifest: {manifest}")
        else:
            self._warn("manifest.json not found after generation")

    def _llm_evaluate(self, round_num: int = 1) -> dict:
        """Run LLM quality evaluation in-process with current runtime metrics.

        Saves per-round snapshots (bfs_metrics_rN.json, quality_evaluation_rN.json)
        and appends the round record to pipeline_iterations.json.
        Always overwrites bfs_metrics.json / quality_evaluation.json with the
        latest values so the executive report reads the final result.
        """
        import yaml as _yaml
        from quality_evaluator import ScenarioQualityEvaluator
        cfg = _yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        rm  = self._collect_runtime_metrics()

        # ── Persist BFS metrics ───────────────────────────────────────────────
        rm_json = json.dumps(rm, indent=2, default=str)
        (self.phase2_out / "bfs_metrics.json").write_text(rm_json, encoding="utf-8")
        (self.phase2_out / f"bfs_metrics_r{round_num}.json").write_text(rm_json, encoding="utf-8")

        self._log(
            f"\n  Runtime metrics (round {round_num}): "
            f"solved={rm['solved']}/{rm['n_scenarios']} ({rm['solve_rate']:.0%})  "
            f"diameter={rm['mean_diameter']:.1f}  density={rm['mean_density']:.3f}"
        )
        if rm.get("by_stratum"):
            for s, stats in rm["by_stratum"].items():
                self._log(
                    f"    [{s}] solve={stats['solve_rate']:.0%}  "
                    f"diameter={stats['mean_diameter']:.1f}  "
                    f"density={stats['mean_density']:.3f}"
                )

        # ── LLM quality evaluation ────────────────────────────────────────────
        self._log("  → CRITIC: calling LLM quality evaluator ...")
        result = ScenarioQualityEvaluator(cfg, config_name=self.domain).evaluate_with_llm(
            graph_metrics=rm,
            save_dir=str(self.phase2_out),
            round_num=round_num,
        )
        score = result["overall_score"]
        grade = result["overall_grade"]

        # ── Log dimension scores ──────────────────────────────────────────────
        self._log(f"\n  ╔══ LLM Quality Score: {score}/10  Grade: {grade}  (round {round_num}) ══")
        self._log(  "  ║  DIMENSION SCORES:")
        icons = {"pass": "✓", "warning": "⚠", "fail": "✗", "critical": "✗✗"}
        for dim in result.get("dimensions", {}).values():
            bar = "█" * dim["score"] + "░" * (10 - dim["score"])
            self._log(f"  ║    {dim['name']:<40} {dim['score']:>2}/10 ({dim['grade']}) [{bar}]")

        top = result.get("top_issues", [])
        if top:
            self._log("  ║")
            self._log("  ║  TOP ISSUES:")
            for issue in top:
                self._log(f"  ║    [{issue['severity']}] {issue['dimension']}: {issue['message']}")

        self._log("  ║")
        self._log("  ║  FINDINGS BY DIMENSION:")
        for dim in result.get("dimensions", {}).values():
            findings = dim.get("findings", [])
            if not findings:
                continue
            self._log(f"  ║  ── {dim['name']} ──")
            for f in findings:
                self._log(f"  ║      {icons.get(f['type'], '?')}  {f['message']}")

        self._log(f"  ╚══ Summary: {result.get('summary', '')}")

        # ── Persist quality evaluation ────────────────────────────────────────
        q_json = json.dumps(result, indent=2, default=str)
        (self.phase2_out / "quality_evaluation.json").write_text(q_json, encoding="utf-8")
        (self.phase2_out / f"quality_evaluation_r{round_num}.json").write_text(q_json, encoding="utf-8")

        # ── Append round to pipeline_iterations.json ──────────────────────────
        iter_path = self.phase2_out / "pipeline_iterations.json"
        try:
            iterations = json.loads(iter_path.read_text(encoding="utf-8")) if iter_path.exists() else []
        except Exception:
            iterations = []
        iterations.append({
            "round":          round_num,
            "timestamp":      datetime.datetime.now().isoformat(),
            "config":         self.config_path.name,
            "bfs_metrics":    rm,
            "quality": {
                "overall_score": score,
                "overall_grade": grade,
                "dimensions": {
                    k: {"score": v["score"], "grade": v["grade"]}
                    for k, v in result.get("dimensions", {}).items()
                },
                "top_issues":  result.get("top_issues", []),
                "summary":     result.get("summary", ""),
            },
        })
        iter_path.write_text(json.dumps(iterations, indent=2, default=str), encoding="utf-8")

        result["bfs_metrics"] = rm
        return result

    def _replace_unsolved_scenarios(self, max_attempts: int = 3) -> bool:
        """Replace unsolved scenarios with fresh regenerations.

        If solve_rate ≥ 0.40 the YAML config is structurally sound — unsolved
        scenarios are just bad random seeds.  Delete them and regenerate until
        every scenario in the dataset is solvable (or max_attempts exhausted).

        Returns True if all scenarios are now solvable, False otherwise.
        """
        for attempt in range(1, max_attempts + 1):
            # ── Find unsolved scenarios ────────────────────────────────────────
            unsolved: list[tuple[Path, str]] = []
            for mf in self.phase2_out.rglob("run_metrics.json"):
                try:
                    data = json.loads(mf.read_text())
                except Exception:
                    continue
                if not data.get("is_solved", False):
                    unsolved.append((mf.parent, data.get("stratum", "small")))

            if not unsolved:
                self._ok("All scenarios solvable — no replacement needed")
                return True

            self.telemetry["retries"].append({
                "step":    self._step,
                "attempt": attempt,
                "count":   len(unsolved)
            })

            self._log(
                f"\n  [Replacement {attempt}/{max_attempts}] "
                f"{len(unsolved)} unsolved scenario(s) — deleting and regenerating ..."
            )

            # Count by split (train/test)
            n_train = 0
            n_test  = 0
            for scenario_dir, _ in unsolved:
                if "/train/" in str(scenario_dir) or "\\train\\" in str(scenario_dir):
                    n_train += 1
                else:
                    n_test += 1

            # Delete unsolved scenario directories
            for scenario_dir, _ in unsolved:
                if scenario_dir.exists():
                    shutil.rmtree(scenario_dir)

            if n_train > 0 or n_test > 0:
                self._log(
                    f"    Regenerating {n_train} train + {n_test} test "
                    f"replacement scenario(s) ..."
                )
                self._run([
                    _python(), "pipeline/phase2/01_generator.py",
                    "--config",  str(self.config_path),
                    "--out-dir", str(self.phase2_out.parent),
                    "--train",   str(n_train),
                    "--test",    str(n_test),
                    "--workers", "4",
                ], abort_on_error=False)

            # Re-run BFS on all scenarios (fast re-check for the new ones)
            import yaml as _yaml
            _cfg_meta2 = _yaml.safe_load(self.config_path.read_text()) or {}
            _agent_type2 = _cfg_meta2.get("metadata", {}).get("agent", "")
            _recheck_cmd = [
                _python(), "pipeline/phase2/02_test_env_integration.py",
                "--data-dir", str(self.phase2_out),
                "--steps", str(BFS_MAX_STEPS),
                "--num-agents", str(BFS_NUM_AGENTS),
                "--episodes", str(BFS_EPISODES),
            ]
            if _agent_type2:
                _recheck_cmd += ["--agent-type", _agent_type2, "--config", str(self.config_path)]
            self._run(_recheck_cmd, abort_on_error=False)

        # Final check
        remaining = sum(
            1 for mf in self.phase2_out.rglob("run_metrics.json")
            if not json.loads(mf.read_text()).get("is_solved", False)
        )
        return remaining == 0

    def step4_phase2_evaluate(self) -> None:
        """Phase 2 runtime actor-critic loop: BFS eval → LLM quality check → repair → repeat."""
        loop_mode  = self.target_score is not None
        max_rounds = self.max_bfs_rounds if loop_mode else 1

        for rnd in range(1, max_rounds + 1):
            round_tag = f"R{rnd}/{max_rounds}" if loop_mode else ""
            self._header(4, "Phase 2 — Heuristic-agent evaluation", round_tag)

            # ── BFS evaluation ───────────────────────────────────────────────
            import yaml as _yaml
            _cfg_meta = _yaml.safe_load(self.config_path.read_text()) or {}
            _agent_type = _cfg_meta.get("metadata", {}).get("agent", "")
            bfs_cmd = [
                _python(), "pipeline/phase2/02_test_env_integration.py",
                "--data-dir", str(self.phase2_out),
                "--steps", str(BFS_MAX_STEPS),
                "--num-agents", str(BFS_NUM_AGENTS),
                "--episodes", str(BFS_EPISODES),
            ]
            if _agent_type:
                bfs_cmd += ["--agent-type", _agent_type, "--config", str(self.config_path)]
            bfs_result = self._run(bfs_cmd, abort_on_error=False)

            if bfs_result.returncode == 0:
                self._ok("BFS evaluation complete — all scenarios solved")
            else:
                self._warn("BFS evaluation complete — partial solve rate (realistic for harder configs)")

            # ── Scenario replacement: if design is sound but some seeds failed ─
            # Quick check: read solve_rate from bfs_metrics before calling LLM
            _rm_quick = self._collect_runtime_metrics()
            _sr_quick = _rm_quick.get("solve_rate", 0.0)

            if loop_mode and SOLVE_RATE_DESIGN_THRESHOLD <= _sr_quick < self.min_solve_rate:
                self._log(
                    f"\n  Solve rate {_sr_quick:.0%} ≥ {SOLVE_RATE_DESIGN_THRESHOLD:.0%} — YAML design is sound. "
                    f"Replacing unsolved scenarios instead of LLM repair ..."
                )
                all_solved = self._replace_unsolved_scenarios(max_attempts=REPLACEMENT_MAX_ATTEMPTS)
                if all_solved:
                    self._ok(f"All scenarios solvable after replacement")
                else:
                    self._warn("Some scenarios still unsolvable after max replacements")

            # ── LLM critic: 6-dimension quality assessment ───────────────────
            self._header(4, "Phase 2 — LLM quality evaluation", round_tag)
            eval_result = self._llm_evaluate(round_num=rnd)
            score      = eval_result["overall_score"]
            solve_rate = eval_result.get("bfs_metrics", {}).get("solve_rate", 1.0)

            if not loop_mode:
                break

            score_ok    = score      >= self.target_score
            solvable_ok = solve_rate >= self.min_solve_rate
            quality_ok  = score_ok and solvable_ok

            if quality_ok or rnd == max_rounds:
                if quality_ok:
                    self._ok(
                        f"Quality target met ({score}/10 ≥ {self.target_score}, "
                        f"solve={solve_rate:.0%} ≥ {self.min_solve_rate:.0%})"
                    )
                else:
                    reasons = []
                    if not score_ok:
                        reasons.append(f"score={score}/10 < {self.target_score}")
                    if not solvable_ok:
                        reasons.append(f"solve={solve_rate:.0%} < {self.min_solve_rate:.0%}")
                    self._warn(
                        f"Quality below target after {max_rounds} rounds "
                        f"({', '.join(reasons)})"
                    )
                break

            reasons = []
            if not score_ok:
                reasons.append(f"score={score}/10 < {self.target_score}")
            if not solvable_ok:
                reasons.append(f"solve={solve_rate:.0%} < {self.min_solve_rate:.0%}")
            self._log(
                f"\n  Not converged ({', '.join(reasons)}) — invoking ACTOR repair ..."
            )

            # ── Actor repair using LLM critic signal ─────────────────────────
            fixed = self._repair()
            if fixed is None:
                self._warn("Repair produced no improvement — keeping current config")
                break
            self._advance_config(fixed)

            # Regenerate scenarios for new config before next round
            try:
                self.step3_phase2_generate(round_info=f"R{rnd+1}/{max_rounds}")
            except RuntimeError:
                self._warn("Scenario generation failed after repair — keeping previous results")
                self._active_config = REPO_ROOT / "data" / f"{self._initial_domain}.yaml"
                break

    def step5_phase2_report(self) -> None:
        self._header(5, "Phase 2 — EDA report + figures")
        report_txt  = self.phase2_out / "phase2_report.txt"
        phase1_report = self.phase1_out / "phase1_report.txt"
        report_txt.touch()
        cmd = [
            _python(), "pipeline/reporting/02_human_report.py",
            "--scenarios-dir", str(self.phase2_out),
            "--append-to",     str(report_txt),
            "--config",        str(self.config_path),
        ]
        if phase1_report.exists():
            cmd += ["--phase1-report", str(phase1_report)]
        self._run(cmd)
        self._ok(f"EDA report → {report_txt.parent.name}/phase2_report.pdf")

    def step6_phase2_graphs(self) -> None:
        self._header(6, "Phase 2 — Topology graphs (SVG + combined PDF)")
        self._run([
            _python(), "pipeline/reporting/01_scenario_graph.py",
            "--recursive", "--pdf",
            str(self.phase2_out),
        ])
        combined = self.phase2_out / "all_scenarios_combined.pdf"
        if combined.exists():
            self._ok(f"Combined PDF → {combined.name}")

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self) -> bool:
        loop_mode = self.target_score is not None
        self._log("=" * 66)
        self._log("  CyberBattleSim Pipeline Runner")
        self._log(f"  Domain         : {self._initial_domain}")
        self._log(f"  Config         : {self.config_path}")
        self._log(f"  Output         : {self.dataset_root}")
        self._log(f"  Log            : {self.log_path}")
        if loop_mode:
            self._log(f"  Target score   : {self.target_score}/10")
            self._log(f"  Max BFS rounds : {self.max_bfs_rounds}")
        self._log(f"  Mode           : {'actor-critic loop' if loop_mode else 'single-pass'}")
        self._log(f"  Started        : {datetime.datetime.now().isoformat()}")
        self._log("=" * 66)

        try:
            # ── Phase 1: format validation only ──────────────────────────────
            self.step1_phase1_validate()
            self.step1b_zone_coverage_validate()
            self.step2_phase1_report()

            # ── Phase 2: generate → BFS → LLM eval actor-critic loop ─────────
            self.step3_phase2_generate()
            self.step4_phase2_evaluate()  # ← actor-critic loop (BFS + LLM)
            self.step5_phase2_report()
            self.step6_phase2_graphs()

        except RuntimeError as exc:
            self._fail(str(exc))
            self._log("\n  Pipeline aborted — see errors above.")
            self._log_fh.close()
            return False

        self._log("\n" + "=" * 66)
        self._log(f"  PIPELINE COMPLETE  [{self._ts()}]")
        self._log(f"  Initial config : {self._initial_domain}.yaml")
        self._log(f"  Final config   : {self.config_path.name}")
        self._log(f"  Log saved      : {self.log_path}")
        
        # ── Finalize Telemetry ───────────────────────────────────────────────
        self._write_telemetry()
        
        self._log("=" * 66)
        self._log_fh.close()
        return True

    def _write_telemetry(self) -> None:
        """Export tool metrics and retry data to telemetry.json."""
        self.telemetry["end_time"] = datetime.datetime.now().isoformat()
        self.telemetry["total_duration"] = round(
            sum(t["duration"] for t in self.telemetry["tools"]), 2
        )
        self.telemetry["final_config"] = str(self.config_path)
        
        # Calculate totals
        self.telemetry["summary"] = {
            "total_tools_called": len(self.telemetry["tools"]),
            "failed_tool_calls":  len([t for t in self.telemetry["tools"] if not t["success"]]),
            "total_retries":      len(self.telemetry["retries"]),
            "scenarios_replaced": sum(r["count"] for r in self.telemetry["retries"])
        }

        # Save to phase2 directory if it exists, otherwise logs_dir
        out_dir = self.phase2_out if self.phase2_out.exists() else self.logs_dir
        out_path = out_dir / "telemetry.json"
        
        try:
            out_path.write_text(json.dumps(self.telemetry, indent=2), encoding="utf-8")
            self._log(f"  Telemetry      : {out_path.name}")
        except Exception as e:
            self._log(f"  [WARN] Failed to write telemetry: {e}")

    def close(self) -> None:
        if not self._log_fh.closed:
            self._log_fh.close()


# ─────────────────────────────────────────────────────────────────────────────
# Executive report (Step 8 — cross-domain)
# ─────────────────────────────────────────────────────────────────────────────

def run_executive_report(dataset_root: Path, title: str, log_path: Path) -> None:
    print("\n" + "=" * 66)
    print("  STEP 7  — Phase 3: Executive summary report (all domains)")
    print("=" * 66)
    output = dataset_root / "reports" / "executive_report.pdf"
    cmd = [
        _python(), "pipeline/reporting/02_executive.py",
        "--phase2-root", str(dataset_root / "phase2"),
        "--output", str(output),
        "--title", title,
    ]
    print(f"  $ {' '.join(cmd)}")
    with log_path.open("a", encoding="utf-8") as lf:
        result = subprocess.run(
            [str(c) for c in cmd],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        for line in result.stdout.splitlines():
            lf.write(line + "\n")
            print(f"    {line}")
        for line in result.stderr.splitlines():
            if line.strip():
                lf.write(f"[stderr] {line}\n")
    if output.exists():
        print(f"  ✓  Executive report → {output}")
    else:
        print(f"  ✗  Executive report not generated")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberBattleSim pipeline runner with integrated actor-critic loops",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Single-pass (default):
              python pipeline/run.py data/scenarios/swin_serverfarm_standalone_v1.yaml

            With actor-critic improvement loop:
              python pipeline/run.py data/scenarios/swin_serverfarm_standalone_v1.yaml \\
                  --target-score 8.0 --max-bfs-rounds 2

            Multiple domains:
              python pipeline/run.py data/scenarios/*.yaml --target-score 8.0
        """),
    )
    parser.add_argument("configs", nargs="+", help="Path(s) to domain config YAML file(s)")
    parser.add_argument("--target-score",   type=float, default=None,
                        help="Enable actor-critic loop: stop when LLM quality ≥ this score")
    parser.add_argument("--max-bfs-rounds", type=int,   default=MAX_BFS_ROUNDS,
                        help=f"Max Phase 2 BFS+repair iterations (default: {MAX_BFS_ROUNDS})")
    parser.add_argument("--min-solve-rate", type=float, default=MIN_SOLVE_RATE,
                        help=f"Minimum fraction of scenarios that must be solvable (default: {MIN_SOLVE_RATE})")
    parser.add_argument("--skip-exec-report",  action="store_true",
                        help="Skip Step 7 (executive report)")
    parser.add_argument("--exec-report-title", default="CyberBattleSim Scenario Dataset",
                        help="Title for the executive report")
    parser.add_argument("--user-prompt", default="",
                        help="Natural-language request that led to this scenario (saved to user_prompt.txt)")
    args = parser.parse_args()

    try:
        dataset_root = _dataset_root()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    config_paths = [Path(p) for p in args.configs]
    for cp in config_paths:
        if not cp.exists():
            print(f"ERROR: config not found: {cp}", file=sys.stderr)
            sys.exit(1)

    failed: list = []
    log_paths: list = []

    for config_path in config_paths:
        runner = PipelineRunner(
            config_path,
            dataset_root,
            target_score   = args.target_score,
            max_bfs_rounds = args.max_bfs_rounds,
            min_solve_rate = args.min_solve_rate,
            user_prompt    = args.user_prompt,
        )
        ok = runner.run()
        log_paths.append(runner.log_path)
        if not ok:
            failed.append(config_path.stem)

    if not args.skip_exec_report and log_paths:
        exec_log = dataset_root / "logs" / \
            f"executive_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        run_executive_report(dataset_root, args.exec_report_title, exec_log)

    if failed:
        print(f"\n  FAILED domains: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\n  All {len(config_paths)} domain(s) completed successfully.")


if __name__ == "__main__":
    main()
