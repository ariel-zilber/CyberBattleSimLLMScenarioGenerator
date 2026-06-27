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
import time
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
    """Read a variable from os.environ, falling back to .env file."""
    if key in os.environ:
        return os.environ[key]
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{key}=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip()
    return default


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
        append_train:   int          = 0,       # >0: add N more train scenarios, keep existing
        expand_topology: bool        = True,    # Inject canonical background zones before Phase 2
        skip_phase2_report: bool      = False,   # Skip expensive EDA/PDF report generation
        skip_graphs: bool             = False,   # Skip topology graph/PDF generation
        skip_image: bool              = False,   # Skip representative image generation
    ):
        self._active_config  = config_path.resolve()
        self._initial_domain = config_path.stem   # fixed label for log file
        self.dataset_root    = dataset_root
        self.target_score    = target_score
        self.max_bfs_rounds  = max_bfs_rounds
        self.min_solve_rate  = min_solve_rate
        self.user_prompt      = user_prompt
        self.append_train     = append_train
        self.expand_topology  = expand_topology
        self.skip_phase2_report = skip_phase2_report
        self.skip_graphs        = skip_graphs
        self.skip_image         = skip_image

        # ── MLflow tracking ──────────────────────────────────────────────────
        from pipeline.mlflow_tracker import PipelineTracker as _PT
        _tracking_uri = _read_env("MLFLOW_TRACKING_URI") or None
        self.tracker = _PT(self._active_config, self.dataset_root, _tracking_uri)
        _ts_run = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        _parts = self._initial_domain.split("_")
        _size = next((p for p in reversed(_parts) if p in ("small","medium","large","xlarge")), "unknown")
        self.tracker.start_run(run_name=f"{_size}_{_ts_run}")

        self.logs_dir = dataset_root / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = self.logs_dir / f"{self._initial_domain}_{ts}.log"
        self._log_fh  = self.log_path.open("w", encoding="utf-8", buffering=1)
        self._step    = 0
        self._errors: list = []
        self._step_manifest: dict = {}  # step_id -> {status, ts_start, ts_end, note}
        
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
    def domain_root(self) -> Path:
        return self.dataset_root / self.domain

    @property
    def config_out(self) -> Path:
        return self.domain_root / "config"

    @property
    def scenarios_out(self) -> Path:
        return self.domain_root / "scenarios"

    @property
    def metrics_out(self) -> Path:
        return self.domain_root / "metrics"

    @property
    def reports_out(self) -> Path:
        return self.domain_root / "reports"

    # Deprecated path aliases (for backward compatibility during migration)
    @property
    def phase1_out(self) -> Path:
        return self.config_out

    @property
    def phase2_out(self) -> Path:
        return self.scenarios_out

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

    def _mark_step(self, step_id: str, status: str, note: str = "") -> None:
        if step_id not in self._step_manifest:
            self._step_manifest[step_id] = {"status": status, "ts_start": self._ts(), "note": note}
        else:
            self._step_manifest[step_id]["status"] = status
            self._step_manifest[step_id]["ts_end"]  = self._ts()
            if note:
                self._step_manifest[step_id]["note"] = note
        self._flush_manifest()

    def _flush_manifest(self) -> None:
        try:
            out = self.metrics_out
            out.mkdir(parents=True, exist_ok=True)
            (out / "step_manifest.json").write_text(
                json.dumps(self._step_manifest, indent=2), encoding="utf-8"
            )
        except Exception:
            pass

    def _header(self, step: int | str, label: str, round_info: str = "") -> None:
        self._step = step
        bar  = "─" * 64
        tag  = f"  [{round_info}]" if round_info else ""
        self._log(f"\n{bar}")
        self._log(f"  STEP {step}{tag}  [{self._ts()}]  {label}")
        self._log(bar)
        self._mark_step(str(step), "running")

    def _ok(self, msg: str = "OK") -> None:
        self._log(f"  ✓  {msg}")
        self._mark_step(str(self._step), "completed", msg)

    def _warn(self, msg: str) -> None:
        self._log(f"  ⚠  {msg}")

    def _fail(self, msg: str) -> None:
        self._log(f"  ✗  {msg}")
        self._errors.append(f"Step {self._step}: {msg}")
        self._mark_step(str(self._step), "failed", msg)

    def _run(self, cmd: list, cwd: Path = REPO_ROOT,
             abort_on_error: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
        self._log(f"  $ {' '.join(str(c) for c in cmd)}")
        # Merge provided env with current env, and force DATASET_ROOT
        run_env = {**os.environ, **(env or {})}
        run_env["DATASET_ROOT"] = str(self.dataset_root)
        # Ensure repo root is in path for consolidated packages
        run_env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + run_env.get("PYTHONPATH", "")
        
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

    def _coverage_gap_slots(self) -> list:
        """Read tail_slots from bfs_metrics.json vocab_coverage as coverage gap."""
        bfs_path = self.metrics_out / "bfs_metrics.json"
        if not bfs_path.exists():
            return []
        try:
            bfs = json.loads(bfs_path.read_text(encoding="utf-8"))
            return bfs.get("vocab_coverage", {}).get("tail_slots", [])
        except Exception:
            return []

    def _repair(self) -> Path | None:
        """Call apply_critic_fixes on the current config. Returns new config path or None."""
        self._log("  → ACTOR: calling repair_config ...")
        run_env = {**os.environ}
        run_env["DATASET_ROOT"] = str(self.dataset_root)
        run_env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + run_env.get("PYTHONPATH", "")

        gap_slots = self._coverage_gap_slots()
        coverage_gap_args = []
        if gap_slots:
            self._log(f"  → Coverage gap: {len(gap_slots)} under-represented slots passed to actor")
            coverage_gap_args = ["--coverage-gap", json.dumps(gap_slots)]

        result = subprocess.run(
            [_python(), "pipeline/phase2/_05_apply_critic_fixes.py",
             str(self.config_path), "--max-attempts", str(MAX_REPAIR_ATTEMPTS),
             "--phase2-out", str(self.metrics_out),
             *coverage_gap_args],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
            env=run_env,
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
        for jf in self.scenarios_out.rglob("run_metrics.json"):
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

        # ── Vocabulary slot coverage (batch-level) ────────────────────────────
        batch_slot_counts: _Counter = _Counter()
        mean_entropy_vals = []
        for m in all_metrics:
            sc = m.get("slot_coverage", {})
            batch_slot_counts.update(sc.get("slot_coverage", {}))
            e = sc.get("vuln_entropy", None)
            if e is not None:
                mean_entropy_vals.append(e)

        # Slots seen across the full batch; absent slots are simply not in batch_slot_counts.
        # Compare unique_slots_seen against the expected 50 (per-agent) or 170 (all agents)
        # to measure coverage gap. tail_slots = bottom 10% by cumulative node-count.
        seen_slots = set(batch_slot_counts.keys())
        sorted_slots = sorted(batch_slot_counts.items(), key=lambda x: x[1])
        tail_n = max(1, len(sorted_slots) // 10)
        tail_slots = [s for s, _ in sorted_slots[:tail_n]]

        vocab_coverage = {
            "batch_size":        n,
            "unique_slots_seen": len(seen_slots),
            "tail_slots":        tail_slots,          # lowest-frequency 10% — likely under-trained
            "mean_vuln_entropy": round(sum(mean_entropy_vals) / max(len(mean_entropy_vals), 1), 4),
            "slot_node_counts":  dict(sorted(batch_slot_counts.items(), key=lambda x: x[1], reverse=True)),
        }

        # ── Difficulty metrics ────────────────────────────────────────────────
        diff_scores = [m["difficulty"]["score"] for m in all_metrics
                       if isinstance(m.get("difficulty"), dict) and "score" in m["difficulty"]]
        diff_ratings: _Counter = _Counter(
            m["difficulty"].get("rating", "UNKNOWN") for m in all_metrics
            if isinstance(m.get("difficulty"), dict)
        )
        diff_subs: dict = {k: [] for k in ["stochastic_resistance", "topological_depth",
                                            "operational_overhead", "stochastic_volatility"]}
        for m in all_metrics:
            sub = m.get("difficulty", {}).get("metrics", {}) or {}
            for k in diff_subs:
                if k in sub:
                    diff_subs[k].append(sub[k])
        difficulty = {
            "mean_score": round(sum(diff_scores) / max(len(diff_scores), 1), 3),
            "min_score":  round(min(diff_scores, default=0), 3),
            "max_score":  round(max(diff_scores, default=0), 3),
            "rating_distribution": dict(diff_ratings),
            **{f"mean_{k}": round(sum(v) / max(len(v), 1), 3) for k, v in diff_subs.items()},
        }

        # ── DRL hardness metrics ──────────────────────────────────────────────
        drl_cred  = [m["drl_hardness"]["min_cred_harvest_sequence"]  for m in all_metrics
                     if isinstance(m.get("drl_hardness"), dict) and "min_cred_harvest_sequence" in m["drl_hardness"]]
        drl_snr   = [m["drl_hardness"]["action_signal_to_noise_ratio"] for m in all_metrics
                     if isinstance(m.get("drl_hardness"), dict) and "action_signal_to_noise_ratio" in m["drl_hardness"]]
        drl_steps = [m["drl_hardness"]["avg_steps_between_rewards"]  for m in all_metrics
                     if isinstance(m.get("drl_hardness"), dict) and "avg_steps_between_rewards" in m["drl_hardness"]]
        drl_hardness_agg = {
            "mean_min_cred_harvest_sequence": round(sum(drl_cred)  / max(len(drl_cred),  1), 2),
            "mean_action_snr":                round(sum(drl_snr)   / max(len(drl_snr),   1), 4),
            "mean_avg_steps_between_rewards": round(sum(drl_steps) / max(len(drl_steps), 1), 2),
            "cred_seq_distribution":          _dist(drl_cred),
            "snr_distribution":               _dist(drl_snr),
        }

        # ── Goal completeness ─────────────────────────────────────────────────
        # goals_captured is a string "X/Y" — parse numerator and denominator
        def _parse_goals(m: dict) -> tuple[int, int]:
            raw = m.get("goals_captured", "0/0")
            if isinstance(raw, str) and "/" in raw:
                parts = raw.split("/", 1)
                try:
                    return int(parts[0]), int(parts[1])
                except ValueError:
                    pass
            return 0, 0

        goals_data  = [_parse_goals(m) for m in all_metrics]
        all_goals_n = [d for cap, tot in goals_data for d in [tot] if tot > 0]
        num_goals_expected = max(all_goals_n, default=3)  # most-common denominator
        full_capture = sum(1 for cap, tot in goals_data if tot > 0 and cap == tot)
        partial      = sum(1 for cap, tot in goals_data if tot > 0 and 0 < cap < tot)
        zero_capture = sum(1 for cap, tot in goals_data if cap == 0)
        mean_ratio   = sum(m.get("goals_captured_ratio", 0) for m in all_metrics) / n

        goal_completeness = {
            "num_goals_expected":             num_goals_expected,
            "pct_scenarios_all_goals":        round(full_capture / n, 3),
            "pct_scenarios_partial_goals":    round(partial      / n, 3),
            "pct_scenarios_zero_goals":       round(zero_capture / n, 3),
            "n_full_capture":                 full_capture,
            "n_partial_capture":              partial,
            "n_zero_capture":                 zero_capture,
            "mean_goals_captured_ratio":      round(mean_ratio, 3),
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
            "vocab_coverage": vocab_coverage,
            "difficulty":        difficulty,
            "drl_hardness":      drl_hardness_agg,
            "goal_completeness": goal_completeness,
        }

    # ── Step implementations ─────────────────────────────────────────────────

    def _collect_config_metrics(self) -> dict:
        """Static structural metrics from the config YAML — computed once after phase 1."""
        import yaml as _yaml
        import statistics as _stats
        try:
            cfg = _yaml.safe_load(self.config_path.read_text()) or {}
        except Exception:
            return {}

        meta = cfg.get("metadata", {})
        services = cfg.get("services", {})
        sv = cfg.get("solvability_vulnerabilities", {})
        attack_flow = cfg.get("attack_flow", []) or []

        all_vulns = [v for entries in sv.values() for v in (entries or []) if isinstance(v, dict)]
        success_rates = [float(v["success_rate"]) for v in all_vulns if "success_rate" in v]

        # Build adjacency for attack_flow DAG → compute longest path depth
        edges: dict = {}
        if isinstance(attack_flow, list):
            for edge in attack_flow:
                if isinstance(edge, dict):
                    src = edge.get("source_pattern", "")
                    for tgt in (edge.get("targets") or []):
                        edges.setdefault(src, set()).add(str(tgt))

        def _dag_depth(graph: dict) -> int:
            memo: dict = {}
            def dfs(node: str) -> int:
                if node in memo:
                    return memo[node]
                children = graph.get(node, set())
                result = 1 + (max(dfs(c) for c in children) if children else 0)
                memo[node] = result
                return result
            return max((dfs(n) for n in graph), default=0)

        specialists = meta.get("fixed_specialists") or meta.get("primary_specialists") or []
        intermediate_goals = meta.get("intermediate_goals") or []
        cat_counts = {cat: len(entries or []) for cat, entries in sv.items()}

        return {
            "num_services":           len(services),
            "num_vuln_catalog":       len(all_vulns),
            "num_attack_flow_edges":  sum(len(v) for v in edges.values()),
            "attack_flow_depth":      _dag_depth(edges),
            "num_intermediate_goals": len(intermediate_goals),
            "num_specialists":        len(specialists),
            "success_rate_mean":      round(sum(success_rates) / max(len(success_rates), 1), 3),
            "success_rate_min":       round(min(success_rates, default=0), 3),
            "success_rate_max":       round(max(success_rates, default=0), 3),
            "success_rate_std":       round(_stats.stdev(success_rates) if len(success_rates) > 1 else 0.0, 3),
            "vuln_by_category":       cat_counts,
        }

    def _collect_diversity_metrics(self) -> dict:
        """Pairwise Jaccard similarity and train/test overlap from node vuln sets.

        Reads node/*.yaml files for each scenario to build per-scenario vuln name
        sets, then computes all-pairs Jaccard (diversity) and cross-split Jaccard
        (train/test contamination).  Called once in the finally block.
        """
        import yaml as _yaml

        def _vuln_set(metrics_json: Path) -> frozenset:
            nodes_dir = metrics_json.parent / "nodes"
            names: set = set()
            if nodes_dir.exists():
                for nf in nodes_dir.glob("*.yaml"):
                    try:
                        nd = _yaml.safe_load(nf.read_text()) or {}
                        vulns = nd.get("vulnerabilities", {})
                        if isinstance(vulns, dict):
                            names.update(vulns.keys())
                    except Exception:
                        continue
            return frozenset(names)

        def _jaccard(a: frozenset, b: frozenset) -> float:
            if not a and not b:
                return 1.0
            return len(a & b) / len(a | b)

        all_files  = list(self.scenarios_out.rglob("run_metrics.json"))
        train_files = [f for f in all_files if "/train/" in str(f) or "\\train\\" in str(f)]
        test_files  = [f for f in all_files if "/test/"  in str(f) or "\\test\\"  in str(f)]

        all_sets   = [_vuln_set(f) for f in all_files]
        train_sets = [_vuln_set(f) for f in train_files]
        test_sets  = [_vuln_set(f) for f in test_files]

        pairwise = [
            _jaccard(all_sets[i], all_sets[j])
            for i in range(len(all_sets))
            for j in range(i + 1, len(all_sets))
        ]
        cross = [_jaccard(tv, tev) for tv in train_sets for tev in test_sets]
        all_vuln_union = set().union(*all_sets) if all_sets else set()

        return {
            "pairwise_jaccard_mean":   round(sum(pairwise) / max(len(pairwise), 1), 4),
            "pairwise_jaccard_min":    round(min(pairwise, default=0), 4),
            "pairwise_jaccard_max":    round(max(pairwise, default=0), 4),
            "train_test_overlap_mean": round(sum(cross) / max(len(cross), 1), 4),
            "train_test_overlap_max":  round(max(cross, default=0), 4),
            "n_unique_vuln_slots":     len(all_vuln_union),
            "n_scenarios_train":       len(train_sets),
            "n_scenarios_test":        len(test_sets),
        }

    def step0_preflight_validate(self) -> None:
        """Hard gate before Phase 1: static validation + generator feasibility."""
        self._header(0, "Preflight — Static generation gate")
        self._run([
            _python(), "tools/preflight_static_gate.py",
            str(self.config_path),
        ])
        self._ok("Preflight static gate passed")
        self.tracker.log_step_status("0", "completed")

        # Log per-category issue counts from static_validation to MLflow.
        # Re-run with --json so we get machine-readable output without affecting
        # the gate result (gate already passed at this point).
        try:
            _pf = subprocess.run(
                [_python(), "tools/preflight_static_gate.py",
                 str(self.config_path), "--json"],
                capture_output=True, text=True, cwd=str(REPO_ROOT),
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
            )
            if _pf.stdout.strip():
                _pf_data = json.loads(_pf.stdout)
                self.tracker.log_preflight(_pf_data)
        except Exception as _e:
            self._warn(f"Preflight JSON parse for MLflow failed: {_e}")

    def _parse_phase1_substeps(self) -> None:
        """Read 03_validation.json written by phase1/pipeline.py, record per-check substeps.
        Pure observation — no logic side effects."""
        val_json = self.config_out / "03_validation.json"
        if not val_json.exists():
            return
        try:
            data = json.loads(val_json.read_text(encoding="utf-8"))
        except Exception:
            return
        errors   = " ".join(data.get("errors",   []))
        warnings = " ".join(data.get("warnings", []))
        SUBSTEPS = [
            ("1.1", "Metadata block"),
            ("1.2", "Config settings"),
            ("1.3", "Identifiers completeness"),
            ("1.4", "Service / group consistency"),
            ("1.5", "Attack flow depth"),
            ("1.6", "Vulnerability coverage"),
            ("1.7", "Agent-category allowlist"),
            ("1.8", "Constraint soundness"),
            ("1.9", "Specialist vocab coverage"),
        ]
        for sid, label in SUBSTEPS:
            if label.lower() in errors.lower():
                self._mark_step(sid, "failed", label)
            elif label.lower() in warnings.lower():
                self._mark_step(sid, "warned", label)
            else:
                self._mark_step(sid, "completed", label)

    def step1_phase1_validate(self, round_info: str = "") -> None:
        self._header(1, "Phase 1 — Config validation + structural check", round_info)
        self.config_out.mkdir(parents=True, exist_ok=True)
        self._run([
            _python(), "pipeline/phase1/pipeline.py",
            "--config", str(self.config_path),
            "--skip-fetch",
            "--skip-generate",
            "--train", "3", "--test", "1",
        ])
        self._ok(f"Config validated — output in phase1/{self.domain}")
        self._parse_phase1_substeps()
        self.tracker.log_phase1(self.config_out / "03_validation.json")
        self.tracker.log_step_status("1", "completed")
        _cfg_metrics = self._collect_config_metrics()
        self.tracker.log_config_metrics(_cfg_metrics)

    def step1b_zone_coverage_validate(self) -> None:
        """Hard-gate: verify config covers the correct GLOBALTECH zones per zone_manifest.yaml."""
        self._header("1b", "Phase 1 — GLOBALTECH zone coverage check")
        result = self._run(
            [_python(), "pipeline/phase1/validate_zone_coverage.py", str(self.config_path)],
            abort_on_error=False,
        )
        if result.returncode == 1:
            self._fail("Zone coverage check FAILED — config does not represent the required GLOBALTECH zones")
            self.tracker.log_step_status("1b", "failed")
            raise RuntimeError("Step 1b failed: zone coverage")
        elif result.returncode == 0:
            self._ok("Zone coverage check passed")
            self.tracker.log_step_status("1b", "completed")
        # exit 2 = no manifest entry → warn and continue
        else:
            self._warn("No manifest entry for this config — zone coverage check skipped")
            self.tracker.log_step_status("1b", "warned")

    def step2_phase1_report(self) -> None:
        """Write a simple Phase 1 validation summary and generate the schema diagram."""
        self._header(2, "Phase 1 — Generate phase1_summary.txt + diagram")
        self.reports_out.mkdir(parents=True, exist_ok=True)
        report_path = self.reports_out / "phase1_summary.txt"
        
        # 1. Write Text Report
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
        report_path.write_text(report, encoding="utf-8")
        
        self._ok(f"phase1_summary.txt written → {report_path.parent.name}/{report_path.name}")
        self.tracker.log_artifacts([report_path])
        self.tracker.log_step_status("2", "completed")

        # 2. Generate Schema Diagram (PNG) — skipped when --skip-graphs is set
        if self.skip_graphs:
            self._warn("Skipping schema diagram (--skip-graphs)")
            return
        self.config_out.mkdir(parents=True, exist_ok=True)
        diag_path = self.config_out / "schema_diagram.png"
        self._run([
            _python(), "pipeline/reporting/scenario_graph.py",
            str(self.config_path),
            "--config", "--schema-png",
            "--out", str(diag_path),
        ], abort_on_error=False)
        if diag_path.exists():
            self._ok(f"Schema diagram generated → {diag_path.parent.name}/{diag_path.name}")
        else:
            self._warn("Schema diagram skipped (inkscape not found or rendering failed)")

    def step3_phase2_generate(self, round_info: str = "") -> None:
        self._header(3, "Phase 2 — Generate scenarios", round_info)
        # Persist generation request so the executive report can display it
        if self.user_prompt:
            self.scenarios_out.mkdir(parents=True, exist_ok=True)
            (self.scenarios_out / "user_prompt.txt").write_text(
                self.user_prompt.strip(), encoding="utf-8"
            )
        env = {"DATASET_ROOT": str(self.dataset_root)}

        if self.append_train > 0:
            # Count existing train scenarios to compute the offset.
            train_dir = self.scenarios_out / "train"
            existing = len(list(train_dir.glob("*/nodes"))) if train_dir.exists() else 0
            cmd_extra = ["--train", str(self.append_train),
                         "--train-offset", str(existing),
                         "--test", "0"]
            self._log(f"  → Append mode: adding {self.append_train} train scenarios after {existing} existing")
        else:
            cmd_extra = [
                "--train", str(int(_read_env("PHASE2_TRAIN_COUNT", "5"))),
                "--test",  str(int(_read_env("PHASE2_TEST_COUNT",  "2"))),
            ]

        self._mark_step("3.1", "running", "instantiating scenarios")
        self._run([
            _python(), "pipeline/phase2/generator.py",
            "--config", str(self.config_path),
            "--out-dir", str(self.domain_root),
            *cmd_extra,
            "--workers", "4",
        ], env=env)
        manifest = self.scenarios_out / "manifest.json"
        if manifest.exists():
            self._ok(f"Manifest: {manifest}")
            self._mark_step("3.1", "completed", "manifest written")
            try:
                mdata      = json.loads(manifest.read_text(encoding="utf-8"))
                n_train    = mdata.get("train_count", len(list((self.scenarios_out / "train").glob("*/nodes"))) if (self.scenarios_out / "train").exists() else 0)
                n_test     = mdata.get("test_count",  len(list((self.scenarios_out / "test").glob("*/nodes")))  if (self.scenarios_out / "test").exists()  else 0)
                self._mark_step("3.2", "completed", f"{n_train} train scenarios")
                self._mark_step("3.3", "completed", f"{n_test} test scenarios")
            except Exception:
                self._mark_step("3.2", "completed", "train scenarios")
                self._mark_step("3.3", "completed", "test scenarios")
            self.tracker.log_manifest(manifest)
            self.tracker.log_step_status("3", "completed")
        else:
            self._warn("manifest.json not found after generation")
            self._mark_step("3.1", "failed", "manifest.json not found")
            self.tracker.log_step_status("3", "warned")

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
        (self.metrics_out / "bfs_metrics.json").write_text(rm_json, encoding="utf-8")
        (self.metrics_out / f"bfs_metrics_r{round_num}.json").write_text(rm_json, encoding="utf-8")

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
            save_dir=str(self.config_out),
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
        (self.metrics_out / "quality_evaluation.json").write_text(q_json, encoding="utf-8")
        (self.metrics_out / f"quality_evaluation_r{round_num}.json").write_text(q_json, encoding="utf-8")

        # ── Append round to pipeline_iterations.json ──────────────────────────
        iter_path = self.metrics_out / "pipeline_iterations.json"
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
            for mf in self.scenarios_out.rglob("run_metrics.json"):
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
                    _python(), "pipeline/phase2/generator.py",
                    "--config",  str(self.config_path),
                    "--out-dir", str(self.scenarios_out.parent),
                    "--train",   str(n_train),
                    "--test",    str(n_test),
                    "--workers", "4",
                ], abort_on_error=False)

            # Re-run BFS on all scenarios (fast re-check for the new ones)
            import yaml as _yaml
            _cfg_meta2 = _yaml.safe_load(self.config_path.read_text()) or {}
            _agent_type2 = _cfg_meta2.get("metadata", {}).get("agent", "")
            _recheck_cmd = [
                _python(), "pipeline/phase2/test_env_integration.py",
                "--data-dir", str(self.scenarios_out),
                "--steps", str(BFS_MAX_STEPS),
                "--num-agents", str(BFS_NUM_AGENTS),
                "--episodes", str(BFS_EPISODES),
            ]
            if _agent_type2:
                _recheck_cmd += ["--agent-type", _agent_type2, "--config", str(self.config_path)]
            self._run(_recheck_cmd, abort_on_error=False)

        # Final check
        remaining = sum(
            1 for mf in self.scenarios_out.rglob("run_metrics.json")
            if not json.loads(mf.read_text()).get("is_solved", False)
        )
        return remaining == 0

    def _replace_incomplete_goal_scenarios(self, max_attempts: int = 3) -> bool:
        """Replace scenarios that captured fewer goals than expected.

        A scenario with goals_captured='1/3' has partial credit but is not a
        valid training sample for the full 3-goal objective.  Delete and
        regenerate until every instance has goals_captured_ratio == 1.0 or
        max_attempts is exhausted.

        Returns True if all scenarios have full goal capture, False otherwise.
        """
        for attempt in range(1, max_attempts + 1):
            incomplete: list[tuple[Path, str]] = []
            for mf in self.scenarios_out.rglob("run_metrics.json"):
                try:
                    data = json.loads(mf.read_text())
                except Exception:
                    continue
                ratio = data.get("goals_captured_ratio", 1.0)
                if ratio < 1.0:
                    incomplete.append((mf.parent, data.get("stratum", "small")))

            if not incomplete:
                self._ok("All scenarios have full goal capture")
                return True

            self._log(
                f"\n  [Goal-fix {attempt}/{max_attempts}] "
                f"{len(incomplete)} scenario(s) with partial goal capture — deleting and regenerating ..."
            )
            self.telemetry["retries"].append({
                "step":    self._step,
                "attempt": attempt,
                "count":   len(incomplete),
                "reason":  "partial_goal_capture",
            })

            n_train = sum(1 for d, _ in incomplete if "/train/" in str(d) or "\\train\\" in str(d))
            n_test  = len(incomplete) - n_train
            for scenario_dir, _ in incomplete:
                if scenario_dir.exists():
                    shutil.rmtree(scenario_dir)

            if n_train > 0 or n_test > 0:
                self._run([
                    _python(), "pipeline/phase2/generator.py",
                    "--config",  str(self.config_path),
                    "--out-dir", str(self.scenarios_out.parent),
                    "--train",   str(n_train),
                    "--test",    str(n_test),
                    "--workers", "4",
                ], abort_on_error=False)

            # Re-run BFS so run_metrics.json reflects the new scenarios
            import yaml as _yaml
            _cfg_meta3 = _yaml.safe_load(self.config_path.read_text()) or {}
            _agent_type3 = _cfg_meta3.get("metadata", {}).get("agent", "")
            _recheck = [
                _python(), "pipeline/phase2/test_env_integration.py",
                "--data-dir", str(self.scenarios_out),
                "--steps", str(BFS_MAX_STEPS),
                "--num-agents", str(BFS_NUM_AGENTS),
                "--episodes", str(BFS_EPISODES),
            ]
            if _agent_type3:
                _recheck += ["--agent-type", _agent_type3, "--config", str(self.config_path)]
            self._run(_recheck, abort_on_error=False)

        # Final check
        remaining = sum(
            1 for mf in self.scenarios_out.rglob("run_metrics.json")
            if json.loads(mf.read_text()).get("goals_captured_ratio", 1.0) < 1.0
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
                _python(), "pipeline/phase2/test_env_integration.py",
                "--data-dir", str(self.scenarios_out),
                "--steps", str(BFS_MAX_STEPS),
                "--num-agents", str(BFS_NUM_AGENTS),
                "--episodes", str(BFS_EPISODES),
            ]
            if _agent_type:
                bfs_cmd += ["--agent-type", _agent_type, "--config", str(self.config_path)]
            self._mark_step(f"4.{rnd}.bfs", "running", f"round {rnd} BFS evaluation")
            bfs_result = self._run(bfs_cmd, abort_on_error=False)

            if bfs_result.returncode == 0:
                self._ok("BFS evaluation complete — all scenarios solved")
                self._mark_step(f"4.{rnd}.bfs", "completed", "all scenarios solved")
            else:
                self._warn("BFS evaluation complete — partial solve rate (realistic for harder configs)")
                self._mark_step(f"4.{rnd}.bfs", "completed", "partial solve rate")

            # ── Scenario replacement: if design is sound but some seeds failed ─
            # Quick check: read solve_rate from bfs_metrics before calling LLM
            self._mark_step(f"4.{rnd}.collect", "running", "collecting runtime metrics")
            _rm_quick = self._collect_runtime_metrics()
            _sr_quick = _rm_quick.get("solve_rate", 0.0)
            self._mark_step(f"4.{rnd}.collect", "completed", f"solve_rate={_sr_quick:.0%}")

            if loop_mode and SOLVE_RATE_DESIGN_THRESHOLD <= _sr_quick < self.min_solve_rate:
                self._log(
                    f"\n  Solve rate {_sr_quick:.0%} ≥ {SOLVE_RATE_DESIGN_THRESHOLD:.0%} — YAML design is sound. "
                    f"Replacing unsolved scenarios instead of LLM repair ..."
                )
                self._mark_step(f"4.{rnd}.replace", "running", "replacing unsolved scenarios")
                all_solved = self._replace_unsolved_scenarios(max_attempts=REPLACEMENT_MAX_ATTEMPTS)
                if all_solved:
                    self._ok(f"All scenarios solvable after replacement")
                    self._mark_step(f"4.{rnd}.replace", "completed", "all scenarios now solvable")
                else:
                    self._warn("Some scenarios still unsolvable after max replacements")
                    self._mark_step(f"4.{rnd}.replace", "warned", "some scenarios still unsolvable")
            else:
                self._mark_step(f"4.{rnd}.replace", "skipped", f"solve_rate={_sr_quick:.0%} outside replacement band")

            # ── Goal completeness enforcement ─────────────────────────────────
            # After solve-rate replacement, check that every scenario captured
            # all expected goals (goals_captured_ratio == 1.0).  Partial-goal
            # scenarios are invalid training data — replace them too.
            _gc = _rm_quick.get("goal_completeness", {})
            _goal_pct = _gc.get("pct_scenarios_all_goals", 1.0)
            _n_partial = _gc.get("n_partial_capture", 0) + _gc.get("n_zero_capture", 0)
            if _n_partial > 0:
                self._warn(
                    f"  {_n_partial} scenario(s) have incomplete goal capture "
                    f"({_goal_pct:.0%} full-capture) — replacing ..."
                )
                self._mark_step(f"4.{rnd}.goal_fix", "running",
                                 f"{_n_partial} partial-goal scenarios")
                all_goals_ok = self._replace_incomplete_goal_scenarios(
                    max_attempts=REPLACEMENT_MAX_ATTEMPTS
                )
                # Refresh metrics after replacement
                _rm_quick = self._collect_runtime_metrics()
                if all_goals_ok:
                    self._ok("All scenarios now have full goal capture")
                    self._mark_step(f"4.{rnd}.goal_fix", "completed", "all goals captured")
                else:
                    _remaining = _rm_quick.get("goal_completeness", {}).get("n_partial_capture", 0)
                    self._warn(f"{_remaining} scenario(s) still have partial goal capture after max attempts")
                    self._mark_step(f"4.{rnd}.goal_fix", "warned",
                                     f"{_remaining} partial-goal scenarios remain")
            else:
                self._mark_step(f"4.{rnd}.goal_fix", "skipped", "all scenarios have full goal capture")

            self.tracker.log_bfs_round(rnd, _rm_quick)

            # ── LLM critic: 6-dimension quality assessment ───────────────────
            self._header(4, "Phase 2 — LLM quality evaluation", round_tag)
            self._mark_step(f"4.{rnd}.critic", "running", f"round {rnd} LLM quality evaluation")
            eval_result = self._llm_evaluate(round_num=rnd)
            score      = eval_result["overall_score"]
            self.tracker.log_quality_round(rnd, eval_result)
            solve_rate = eval_result.get("bfs_metrics", {}).get("solve_rate", 1.0)
            self._mark_step(f"4.{rnd}.critic", "completed", f"score={score}/10 solve={solve_rate:.0%}")

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
                    self._mark_step("4", "completed", f"converged at round {rnd}, score={score}/10")
                    self.tracker.log_step_status("4", "completed")
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
                    self._mark_step("4", "warned", f"max rounds hit, {', '.join(reasons)}")
                    self.tracker.log_step_status("4", "warned")
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
            self._mark_step(f"4.{rnd}.repair", "running", f"round {rnd} actor repair")
            fixed = self._repair()
            if fixed is None:
                self._warn("Repair produced no improvement — keeping current config")
                self._mark_step(f"4.{rnd}.repair", "warned", "repair returned None — kept config")
                self._mark_step("4", "completed", f"repair returned None at round {rnd} — kept current config")
                self.tracker.log_step_status("4", "warned")
                break
            self._mark_step(f"4.{rnd}.repair", "completed", f"new config: {fixed.name}")
            self._advance_config(fixed)
            self.tracker.log_repair_round(rnd, self.config_path)

            # ── Preflight re-validation on repaired config ────────────────────
            # Actor may introduce new vocab/goal/duplicate issues — catch before
            # committing to another expensive BFS + LLM round.
            self._mark_step(f"4.{rnd}.preflight", "running", "static validation on repaired config")
            _pf_r = subprocess.run(
                [_python(), "tools/preflight_static_gate.py", str(self.config_path)],
                capture_output=True, text=True, cwd=str(REPO_ROOT),
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT),
                     "DATASET_ROOT": str(self.dataset_root)},
            )
            if _pf_r.returncode != 0:
                self._warn(
                    f"Repaired config failed preflight — reverting to previous config\n"
                    f"  {_pf_r.stdout[-400:].strip()}"
                )
                self._mark_step(f"4.{rnd}.preflight", "failed",
                                 "repaired config invalid — reverted")
                self._advance_config(self.config_path.parent /
                                     self.config_path.name.replace(f"_r{rnd}", "")
                                     if f"_r{rnd}" in self.config_path.name
                                     else self.config_path)
            else:
                self._ok("Repaired config passes preflight")
                self._mark_step(f"4.{rnd}.preflight", "completed", "repaired config valid")
            # Log per-category counts either way
            try:
                _pf_json = subprocess.run(
                    [_python(), "tools/preflight_static_gate.py",
                     str(self.config_path), "--json"],
                    capture_output=True, text=True, cwd=str(REPO_ROOT),
                    env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
                )
                if _pf_json.stdout.strip():
                    self.tracker.log_preflight(json.loads(_pf_json.stdout))
            except Exception:
                pass

            # Regenerate scenarios for new config before next round
            try:
                self.step3_phase2_generate(round_info=f"R{rnd+1}/{max_rounds}")
            except RuntimeError:
                self._warn("Scenario generation failed after repair — keeping previous results")
                self._active_config = REPO_ROOT / "data" / f"{self._initial_domain}.yaml"
                self._mark_step("4", "completed", f"regen failed after repair at round {rnd} — reverted config")
                self.tracker.log_step_status("4", "warned")
                break

    def step5_phase2_report(self) -> None:
        self._header(5, "Phase 2 — EDA report + figures")
        self.reports_out.mkdir(parents=True, exist_ok=True)
        report_txt  = self.reports_out / "phase2_eda.txt"
        phase1_report = self.reports_out / "phase1_summary.txt"
        report_txt.touch()
        cmd = [
            _python(), "pipeline/reporting/human_report.py",
            "--scenarios-dir", str(self.scenarios_out),
            "--append-to",     str(report_txt),
            "--config",        str(self.config_path),
        ]
        if phase1_report.exists():
            cmd += ["--phase1-report", str(phase1_report)]
        self._run(cmd)
        
        # Human report saves PDF to report_txt.with_suffix(".pdf")
        self._ok(f"EDA report → {self.reports_out.name}/phase2_eda.pdf")
        self.tracker.log_step_status("5", "completed")

    def step6_phase2_graphs(self) -> None:
        self._header(6, "Phase 2 — Topology graphs (SVG + combined PDF)")
        self.reports_out.mkdir(parents=True, exist_ok=True)
        self._run([
            _python(), "pipeline/reporting/scenario_graph.py",
            "--recursive", "--pdf",
            str(self.scenarios_out),
        ], abort_on_error=False)
        # Find the combined PDF and move it to reports_out if it's not there
        combined = self.scenarios_out / "all_scenarios_combined.pdf"
        if combined.exists():
            shutil.move(combined, self.reports_out / "all_scenarios_combined.pdf")
            self._ok(f"Combined PDF → {self.reports_out.name}/all_scenarios_combined.pdf")
        self.tracker.log_step_status("6", "completed")

    def step8_standardize_topology(self) -> None:
        """Inject canonical GLOBALTECH background zones into the final validated config.

        Runs after the full actor-critic loop so quality scoring is never affected
        by background noise. The expanded YAML is written alongside the final config
        as <domain>_expanded.yaml — this is the standardized training artifact that
        ensures every scenario in the dataset shares the same GLOBALTECH topology
        skeleton, with only the attack-path zones differing between scenarios.
        """
        self._header(8, "Topology standardization — inject GLOBALTECH background zones")
        try:
            from pipeline.cbsim.scenario_expander import expand, expansion_summary
        except ImportError as e:
            self._warn(f"scenario_expander not available — skipping ({e})")
            self.tracker.log_step_status("8", "skipped")
            return

        info = expansion_summary(self.config_path)
        covered  = info["covered"]
        will_add = info["will_add"]

        self._log(f"  Final config : {self.config_path.name}")
        self._log(f"  Active zones : {', '.join(covered) if covered else '(none — flat domain)'}")

        if not will_add:
            self._ok("All canonical zones already present — no background injection needed")
            self.tracker.log_step_status("8", "completed")
            return

        self._log(f"  Injecting    : {', '.join(will_add)}")
        self.config_out.mkdir(parents=True, exist_ok=True)
        dest = self.config_out / f"{self.config_path.stem}_expanded.yaml"
        expand(self.config_path, dest)
        self._ok(f"Standardized config → {dest.parent.name}/{dest.name}")
        self.tracker.log_step_status("8", "completed")
        self._log(
            "  NOTE: training scenarios were generated from the original config.\n"
            "  Use the expanded YAML for DRL training to include background-zone noise."
        )

    def step7_representative_image(self) -> None:
        self._header(7, "Phase 2 — Gemini representative image")
        self.reports_out.mkdir(parents=True, exist_ok=True)
        self._run([
            _python(), "pipeline/reporting/gemini_image.py",
            "--config", str(self.config_path),
            "--output-dir", str(self.reports_out),
            "--user-prompt-file", str(self.scenarios_out / "user_prompt.txt"),
        ], abort_on_error=False)
        image_path = self.reports_out / "gemini_representative_image.png"
        prompt_path = self.reports_out / "gemini_image_prompt.txt"
        if image_path.exists():
            self._ok(f"Gemini image → {self.reports_out.name}/{image_path.name}")
            self.tracker.log_artifacts([image_path])
            self.tracker.log_step_status("7", "completed")
        elif prompt_path.exists():
            self._warn("Gemini image not generated; prompt artifact was written")
            self.tracker.log_step_status("7", "warned")
        else:
            self.tracker.log_step_status("7", "warned")

    def step9_coverage_audit(self) -> None:
        """Dataset-level vulnerability slot coverage audit (non-fatal)."""
        self._header(9, "Dataset coverage audit — Solvability slot coverage")
        audit_script = REPO_ROOT / "tools" / "check_dataset_coverage.py"
        if not audit_script.exists():
            self._warn("check_dataset_coverage.py not found — skipping")
            self._mark_step("9", "skipped", "audit script not found")
            self.tracker.log_step_status("9", "skipped")
            return
        gap_json = self.metrics_out / "coverage_gap.json"
        result = subprocess.run(
            [_python(), str(audit_script),
             "--scenarios-dir", str(self.scenarios_out),
             "--gap-json", str(gap_json)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        for line in result.stdout.splitlines():
            self._log(f"    {line}")
        if result.stderr.strip():
            self._log(f"    [stderr] {result.stderr.strip()[:400]}")
        if result.returncode == 0:
            self._ok("Coverage above threshold")
            self._mark_step("9", "completed", "coverage OK")
            self.tracker.log_step_status("9", "completed")
        elif result.returncode == 1:
            self._fail("Coverage below threshold — see coverage_gap.json for missing slots; regenerate with more diverse vulns")
            self._mark_step("9", "failed", "coverage below threshold")
            self.tracker.log_step_status("9", "failed")
        else:
            self._warn(f"Coverage audit script error (exit {result.returncode})")
            self._mark_step("9", "warned", f"audit script exit={result.returncode}")
            self.tracker.log_step_status("9", "warned")
        self.tracker.log_coverage_audit(gap_json)

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

        success = False
        try:
            # ── Step 0: hard preflight before expensive pipeline work ───────
            self.step0_preflight_validate()

            # ── Phase 1: format validation only ──────────────────────────────
            self.step1_phase1_validate()
            self.step1b_zone_coverage_validate()
            self.step2_phase1_report()

            # ── Phase 2: generate → BFS → LLM eval actor-critic loop ─────────
            self.step3_phase2_generate()
            self.step4_phase2_evaluate()  # ← actor-critic loop (BFS + LLM)
            if self.skip_phase2_report:
                self._mark_step("5", "skipped", "--skip-phase2-report")
                self._warn("Skipping Step 5 Phase 2 EDA report")
                self.tracker.log_step_status("5", "skipped")
            else:
                self.step5_phase2_report()
            if self.skip_graphs:
                self._mark_step("6", "skipped", "--skip-graphs")
                self._warn("Skipping Step 6 topology graphs")
                self.tracker.log_step_status("6", "skipped")
            else:
                self.step6_phase2_graphs()
            if self.skip_image:
                self._mark_step("7", "skipped", "--skip-image")
                self._warn("Skipping Step 7 representative image")
                self.tracker.log_step_status("7", "skipped")
            else:
                self.step7_representative_image()

            # ── Step 8: standardize topology (post quality loop) ─────────────
            if self.expand_topology:
                self.step8_standardize_topology()
            else:
                self._mark_step("8", "skipped", "--no-expand")
                self.tracker.log_step_status("8", "skipped")

            # ── Step 9: dataset-level coverage audit (non-fatal) ─────────────
            self.step9_coverage_audit()

            success = True

        except RuntimeError as exc:
            self._fail(str(exc))
            self._log("\n  Pipeline aborted — see errors above.")

        finally:
            # ── Always write telemetry + manifest, always print step summary ─
            self._write_telemetry()
            self.tracker.log_telemetry(self.telemetry)
            _final_bfs, _final_quality = {}, {}
            try:
                _bm = self.metrics_out / "bfs_metrics.json"
                _qe = self.metrics_out / "quality_evaluation.json"
                if _bm.exists(): _final_bfs = json.loads(_bm.read_text())
                if _qe.exists(): _final_quality = json.loads(_qe.read_text())
            except Exception:
                pass
            self.tracker.log_final(_final_bfs, _final_quality)
            try:
                _div = self._collect_diversity_metrics()
                self.tracker.log_diversity_metrics(_div)
            except Exception as _e:
                print(f"[MLflow] WARNING: diversity metrics failed: {_e}", file=sys.stderr)
            self.tracker.log_artifacts([
                self.metrics_out / "bfs_metrics.json",
                self.metrics_out / "quality_evaluation.json",
                self.metrics_out / "telemetry.json",
                self.metrics_out / "pipeline_iterations.json",
                self.reports_out / "phase1_summary.txt",
                self.config_out / "02_enriched.yaml",
                self.domain_root / "step_manifest.json",
            ])
            # Per-round BFS + quality snapshots
            for _snap in self.metrics_out.glob("bfs_metrics_r*.json"):
                self.tracker.log_artifacts([_snap])
            for _snap in self.metrics_out.glob("quality_evaluation_r*.json"):
                self.tracker.log_artifacts([_snap])
            # LLM prompt/response artifacts from quality evaluator (saved to config_out)
            for _txt in sorted(self.config_out.glob("llm_*.txt")):
                self.tracker.log_artifacts([_txt])
            # Topology SVG + schema diagram + EDA/combined PDFs
            for _svg in self.reports_out.glob("*.svg"):
                self.tracker.log_artifacts([_svg])
                break
            self.tracker.log_artifacts([
                self.config_out / "schema_diagram.png",
                self.reports_out / "phase2_eda.pdf",
                self.reports_out / "all_scenarios_combined.pdf",
            ])
            # Expanded topology YAML from step8 (if generated)
            for _exp in self.config_out.glob("*_expanded.yaml"):
                self.tracker.log_artifacts([_exp])
                break
            self._flush_manifest()
            self._print_step_summary()
            # Close log file first, then upload it — must be flushed before artifact
            self._log_fh.close()
            self.tracker.log_artifacts([self.log_path])
            self.tracker.end_run()

        return success

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

        # Save to metrics directory
        out_dir = self.metrics_out
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "telemetry.json"
        
        try:
            out_path.write_text(json.dumps(self.telemetry, indent=2), encoding="utf-8")
            self._log(f"  Telemetry      : {out_path.name}")
        except Exception as e:
            self._log(f"  [WARN] Failed to write telemetry: {e}")

    def _print_step_summary(self) -> None:
        ICONS = {
            "completed": "✓", "failed": "✗", "skipped": "○",
            "running": "~", "warned": "⚠", "unknown": "?",
        }
        EXPECTED = [
            ("0",  "Preflight static gate"),
            ("1",  "Phase 1 validate"),
            ("1b", "Zone coverage check"),
            ("2",  "Phase 1 report"),
            ("3",  "Phase 2 generate"),
            ("4",  "BFS + LLM eval (actor-critic)"),
            ("5",  "Phase 2 EDA report"),
            ("6",  "Topology graphs"),
            ("7",  "Representative image"),
            ("8",  "Standardize topology"),
            ("9",  "Dataset coverage audit"),
        ]
        self._log("\n" + "─" * 64)
        self._log("  STEP MANIFEST")
        self._log("─" * 64)
        for step_id, label in EXPECTED:
            entry  = self._step_manifest.get(step_id, {})
            status = entry.get("status", "not_reached")
            icon   = ICONS.get(status, "?")
            note   = f"  ({entry['note']})" if entry.get("note") else ""
            self._log(f"  {icon}  STEP {step_id:<4} {label:<40} [{status}]{note}")
            # Print substeps indented — any manifest key that starts with step_id + "."
            for sub_id, sub_entry in sorted(self._step_manifest.items()):
                if not sub_id.startswith(step_id + "."):
                    continue
                sub_status = sub_entry.get("status", "?")
                sub_icon   = ICONS.get(sub_status, "?")
                sub_note   = f"  ({sub_entry['note']})" if sub_entry.get("note") else ""
                sub_label  = sub_id[len(step_id) + 1:]
                self._log(f"       {sub_icon}  {sub_id:<8} {sub_label:<36} [{sub_status}]{sub_note}")
        self._log("─" * 64)

        not_reached = [sid for sid, _ in EXPECTED
                       if self._step_manifest.get(sid, {}).get("status", "not_reached") == "not_reached"]
        failed      = [sid for sid, _ in EXPECTED
                       if self._step_manifest.get(sid, {}).get("status") == "failed"]
        failed_subs = [sid for sid in self._step_manifest
                       if "." in sid and self._step_manifest[sid].get("status") == "failed"]
        if not_reached:
            self._log(f"  ⚠  Steps never reached: {', '.join(not_reached)}")
        if failed:
            self._log(f"  ✗  Steps failed: {', '.join(failed)}")
        if failed_subs:
            self._log(f"  ✗  Substeps failed: {', '.join(failed_subs)}")
        if not not_reached and not failed and not failed_subs:
            self._log("  ✓  All steps reached")
        self._log("─" * 64)

    def close(self) -> None:
        if not self._log_fh.closed:
            self._log_fh.close()


# ─────────────────────────────────────────────────────────────────────────────
# Executive report (Step 8 — cross-domain)
# ─────────────────────────────────────────────────────────────────────────────

def run_presentation_report(dataset_root: Path, configs_root: Path, title: str, log_path: Path) -> None:
    print("\n" + "=" * 66)
    print("  STEP 8  — Phase 3: Presentation report (Beamer PDF)")
    print("=" * 66)
    output = dataset_root / "reports" / "presentation.pdf"
    cmd = [
        _python(), "pipeline/reporting/presentation.py",
        "--phase2-root", str(dataset_root),
        "--configs-root", str(configs_root),
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
        print(f"  ✓  Presentation → {output}")
    else:
        print(f"  ✗  Presentation not generated")


def run_executive_report(dataset_root: Path, title: str, log_path: Path) -> None:
    print("\n" + "=" * 66)
    print("  STEP 7  — Phase 3: Executive summary report (all domains)")
    print("=" * 66)
    output = dataset_root / "reports" / "executive_report.pdf"
    cmd = [
        _python(), "pipeline/reporting/executive_report.py",
        "--phase2-root", str(dataset_root),
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
    parser.add_argument("--skip-presentation", action="store_true",
                        help="Skip Step 8 (Beamer presentation PDF)")
    parser.add_argument("--skip-phase2-report", action="store_true",
                        help="Skip Step 5 (Phase 2 EDA report and PDF figures)")
    parser.add_argument("--skip-graphs", action="store_true",
                        help="Skip Step 6 (topology SVG/PDF graph generation)")
    parser.add_argument("--skip-image", action="store_true",
                        help="Skip Step 7 (representative image generation)")
    parser.add_argument("--presentation-title", default="Data Generation for CyberBattleSim — Current Status",
                        help="Title for the Beamer presentation")
    parser.add_argument("--user-prompt", default="",
                        help="Natural-language request that led to this scenario (saved to user_prompt.txt)")
    parser.add_argument("--append-train", type=int, default=0,
                        help="Add N more train scenarios to existing output instead of regenerating (keeps existing scenarios intact)")
    parser.add_argument("--no-expand", action="store_true",
                        help="Skip topology expansion (step 2b) — use original scenario YAML as-is for Phase 2")
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
            target_score    = args.target_score,
            max_bfs_rounds  = args.max_bfs_rounds,
            min_solve_rate  = args.min_solve_rate,
            user_prompt     = args.user_prompt,
            append_train    = args.append_train,
            expand_topology = not args.no_expand,
            skip_phase2_report = args.skip_phase2_report,
            skip_graphs        = args.skip_graphs,
            skip_image         = args.skip_image,
        )
        ok = runner.run()
        log_paths.append(runner.log_path)
        if not ok:
            failed.append(config_path.stem)

    if not args.skip_exec_report and log_paths:
        exec_log = dataset_root / "logs" / \
            f"executive_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        run_executive_report(dataset_root, args.exec_report_title, exec_log)

    if not args.skip_presentation and log_paths:
        pres_log = dataset_root / "logs" / \
            f"presentation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        configs_root = REPO_ROOT / "data" / "scenarios"
        run_presentation_report(dataset_root, configs_root, args.presentation_title, pres_log)

    if failed:
        print(f"\n  FAILED domains: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\n  All {len(config_paths)} domain(s) completed successfully.")


if __name__ == "__main__":
    main()
