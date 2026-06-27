"""
pipeline/mlflow_tracker.py
==========================
Thin MLflow wrapper for PipelineRunner in pipeline/run.py.

Isolates all MLflow imports so the rest of the pipeline never touches mlflow
directly.  Every public method is a no-op when MLFLOW_ENABLED=false.  Every
mlflow call is wrapped in a try/except so a tracking failure can never crash
the pipeline.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml  # pyyaml — already a pipeline dependency

# ──────────────────────────────────────────────────────────────────────────────
# Enabled check — must run at import time
# ──────────────────────────────────────────────────────────────────────────────

_ENABLED = os.environ.get("MLFLOW_ENABLED", "true").lower() not in ("false", "0", "no")

if _ENABLED:
    try:
        import mlflow
    except ImportError:
        raise ImportError(
            "MLflow is not installed but MLFLOW_ENABLED=true. "
            "Run: pip install mlflow  or set MLFLOW_ENABLED=false to disable tracking."
        )


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _warn(msg: str) -> None:
    """Print a non-fatal warning to stderr."""
    print(f"[MLflow] WARNING: {msg}", file=sys.stderr)


def _try(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Call *fn* with *args*/*kwargs*, swallowing any exception."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        _warn(str(exc))
        return None


# ──────────────────────────────────────────────────────────────────────────────
# PipelineTracker
# ──────────────────────────────────────────────────────────────────────────────

class PipelineTracker:
    """MLflow experiment tracker for a single pipeline run.

    All public methods are safe to call regardless of whether MLflow is
    enabled or installed — they become no-ops when *_ENABLED* is False, and
    every mlflow call is wrapped in try/except so tracking failures never
    propagate to the caller.
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        config_path: Path,
        dataset_root: Path,
        tracking_uri: str | None = None,
    ) -> None:
        self.config_path = config_path
        self.dataset_root = dataset_root
        self._run = None

        if not _ENABLED:
            return

        # ── Parse family / size / scenario_id from the stem ───────────────
        stem = config_path.stem  # e.g. specialist_branch_to_hq_lateral_movement_small_v1

        # Strip leading "specialist_" prefix (optional)
        working = re.sub(r"^specialist_", "", stem)

        # Strip trailing "_vN" version suffix
        working = re.sub(r"_v\d+$", "", working)

        # The last token is "size"; everything before it is "family"
        tokens = working.split("_")
        size = tokens[-1] if tokens else "unknown"
        family = "_".join(tokens[:-1]) if len(tokens) > 1 else working

        self.experiment_name = f"cyberbattlesim_{family}"

        # ── Tracking URI ───────────────────────────────────────────────────
        uri = tracking_uri or f"file://{dataset_root}/mlruns"
        _try(mlflow.set_tracking_uri, uri)

        # ── Read primary_specialists from YAML metadata ────────────────────
        try:
            cfg = yaml.safe_load(config_path.read_text())
            specialists: list[str] = (
                cfg.get("metadata", {}).get("primary_specialists", []) or []
            )
        except Exception as exc:  # noqa: BLE001
            _warn(f"Could not read config YAML for tags: {exc}")
            specialists = []

        self._tags: dict[str, str] = {
            "family": family,
            "size": size,
            "scenario_id": stem,
            "primary_specialists": ",".join(str(s) for s in specialists),
        }

    # ------------------------------------------------------------------
    # Run lifecycle
    # ------------------------------------------------------------------

    def start_run(self, run_name: str | None = None) -> None:
        """Create (and activate) a new MLflow run."""
        if not _ENABLED:
            return

        def _start() -> None:
            mlflow.set_experiment(self.experiment_name)
            self._run = mlflow.start_run(run_name=run_name)
            for key, value in self._tags.items():
                mlflow.set_tag(key, value)

        _try(_start)

    def end_run(self) -> None:
        """End the active MLflow run."""
        if not _ENABLED:
            return

        def _end() -> None:
            mlflow.end_run()
            self._run = None

        _try(_end)

    def log_step_status(self, name: str, status: str) -> None:
        """Log step completion status.

        *name*   — step identifier, e.g. ``"0"``, ``"1b"``, ``"4"``.
        *status* — ``"completed"`` | ``"skipped"`` | ``"failed"`` | ``"warned"``.

        Logs both:
        - numeric metric ``step.<name>.status``  (1=completed, 0=failed, -1=skipped, 2=warned)
        - string tag     ``step.<name>``          (human-readable)
        """
        if not _ENABLED:
            return
        _STATUS_MAP = {"completed": 1, "warned": 2, "skipped": -1, "failed": 0}
        numeric = _STATUS_MAP.get(status, -99)

        def _log() -> None:
            mlflow.log_metric(f"step.{name}.status", numeric)
            mlflow.set_tag(f"step.{name}", status)

        _try(_log)

    def log_preflight(self, preflight_data: dict) -> None:
        """Log per-category issue counts from preflight_static_gate --json output.

        Expected keys: ``passed`` (bool), ``errors`` (list of {check, message}),
        ``warnings`` (list).  Each error ``check`` is of the form
        ``static_validation.<category>`` or ``config_checker.<check>``.
        """
        if not _ENABLED or not preflight_data:
            return

        def _log() -> None:
            passed = preflight_data.get("passed", False)
            mlflow.set_tag("preflight.passed", str(passed))

            errors   = preflight_data.get("errors", []) or []
            warnings = preflight_data.get("warnings", []) or []
            mlflow.log_metric("preflight.total_errors",   len(errors))
            mlflow.log_metric("preflight.total_warnings", len(warnings))

            # Count per static_validation category
            cat_counts: dict[str, int] = {}
            for item in errors + warnings:
                check = item.get("check", "") if isinstance(item, dict) else ""
                if check.startswith("static_validation."):
                    cat = check.split(".", 1)[1]
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
                elif check.startswith("config_checker."):
                    cat = "config_checker." + check.split(".", 2)[-1]
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1

            for cat, cnt in cat_counts.items():
                mlflow.log_metric(f"preflight.{cat}", cnt)

            # Explicit zeros for expected categories so they always appear in MLflow
            for cat in ("vocab", "identifiers", "categories", "goals", "dupes"):
                if cat not in cat_counts:
                    mlflow.log_metric(f"preflight.{cat}", 0)

        _try(_log)

    def log_config_metrics(self, metrics: dict) -> None:
        """Log static config structural metrics from the YAML (called once after phase 1)."""
        if not _ENABLED or not metrics:
            return

        def _log() -> None:
            for key in [
                "num_services", "num_vuln_catalog", "num_attack_flow_edges",
                "attack_flow_depth", "num_intermediate_goals", "num_specialists",
                "success_rate_mean", "success_rate_min", "success_rate_max", "success_rate_std",
            ]:
                if key in metrics:
                    mlflow.log_metric(f"config.{key}", metrics[key])
            for cat, cnt in metrics.get("vuln_by_category", {}).items():
                mlflow.log_metric(f"config.vulns.{cat}", cnt)

        _try(_log)

    def log_diversity_metrics(self, metrics: dict) -> None:
        """Log dataset diversity and train/test overlap metrics."""
        if not _ENABLED or not metrics:
            return

        def _log() -> None:
            for key in [
                "pairwise_jaccard_mean", "pairwise_jaccard_min", "pairwise_jaccard_max",
                "train_test_overlap_mean", "train_test_overlap_max",
                "n_unique_vuln_slots", "n_scenarios_train", "n_scenarios_test",
            ]:
                if key in metrics:
                    mlflow.log_metric(f"diversity.{key}", metrics[key])

        _try(_log)

    # ------------------------------------------------------------------
    # Phase 1 logging
    # ------------------------------------------------------------------

    def log_phase1(self, validation_json_path: Path) -> None:
        """Log phase-1 validation results.

        Reads the JSON produced by pipeline/phase1/config_checker.py:
        ``{"valid": bool, "errors": [...], "warnings": [...], "stdout": "..."}``
        """
        if not _ENABLED:
            return

        def _log() -> None:
            data: dict = json.loads(validation_json_path.read_text())

            valid: bool = data.get("valid", False)
            errors: list = data.get("errors", [])
            warnings: list = data.get("warnings", [])
            stdout: str = data.get("stdout", "")

            # Count errors, excluding any trailing summary line
            error_count = len([e for e in errors if e])
            warning_count = len([w for w in warnings if w])

            mlflow.log_metric("phase1.validation_errors", error_count)
            mlflow.log_metric("phase1.validation_warnings", warning_count)
            mlflow.set_tag("phase1.valid", str(valid))

            # Parse "Min depth" from stdout
            m = re.search(r"Min depth[^\d]*(\d+)", stdout, re.IGNORECASE)
            if m:
                mlflow.log_metric("phase1.bfs_depth_to_goal", int(m.group(1)))

            # Parse "Services defined"
            m = re.search(r"Services defined[^\d]*(\d+)", stdout, re.IGNORECASE)
            if m:
                mlflow.log_metric("phase1.services_defined", int(m.group(1)))

            # Parse "Solvability vulns"
            m = re.search(r"Solvability vulns[^\d]*(\d+)", stdout, re.IGNORECASE)
            if m:
                mlflow.log_metric("phase1.solvability_vulns", int(m.group(1)))

        _try(_log)

    # ------------------------------------------------------------------
    # BFS round logging
    # ------------------------------------------------------------------

    def log_bfs_round(self, round_num: int, metrics: dict) -> None:
        """Log BFS heuristic-agent metrics for one round (full _collect_runtime_metrics dict)."""
        if not _ENABLED:
            return

        def _log() -> None:
            s = round_num

            def m(key: str, val: Any, step: int = s) -> None:
                if val is not None:
                    mlflow.log_metric(key, val, step=step)

            # ── Top-level summary ─────────────────────────────────────────────
            m("bfs.solve_rate",    metrics.get("solve_rate", 0))
            m("bfs.mean_steps",    metrics.get("mean_steps", 0))
            m("bfs.mean_reward",   metrics.get("mean_reward", 0))
            m("bfs.n_scenarios",   metrics.get("n_scenarios", 0))
            m("bfs.solved",        metrics.get("solved", 0))
            m("bfs.mean_nodes",    metrics.get("mean_nodes", 0))
            m("bfs.mean_creds",    metrics.get("mean_creds", 0))
            m("bfs.mean_density",  metrics.get("mean_density", 0))
            m("bfs.mean_diameter", metrics.get("mean_diameter", 0))
            m("bfs.tree_ratio",    metrics.get("tree_ratio", 0))

            # ── Graph structure ───────────────────────────────────────────────
            g: dict = metrics.get("graph", {})
            m("bfs.graph.mean_node_count",   g.get("mean_node_count"))
            m("bfs.graph.mean_edge_count",   g.get("mean_edge_count"))
            m("bfs.graph.mean_density",      g.get("mean_density"))
            m("bfs.graph.mean_diameter",     g.get("mean_diameter"))
            m("bfs.graph.min_diameter",      g.get("min_diameter"))
            m("bfs.graph.max_diameter",      g.get("max_diameter"))
            m("bfs.graph.mean_avg_in_deg",   g.get("mean_avg_in_deg"))
            m("bfs.graph.mean_avg_out_deg",  g.get("mean_avg_out_deg"))
            m("bfs.graph.tree_ratio",        g.get("tree_ratio"))

            # ── Segmentation ──────────────────────────────────────────────────
            seg: dict = metrics.get("segmentation", {})
            m("bfs.seg.mean_isolated_subnets", seg.get("mean_isolated_subnets"))
            m("bfs.seg.mean_routing_zones",    seg.get("mean_routing_zones"))

            # ── Attack paths ──────────────────────────────────────────────────
            ap: dict = metrics.get("attack_paths", {})
            m("bfs.ap.mean_steps_to_first_goal",  ap.get("mean_steps_to_first_goal"))
            m("bfs.ap.mean_steps_to_final_goal",  ap.get("mean_steps_to_final_goal"))
            m("bfs.ap.mean_goals_captured_ratio", ap.get("mean_goals_captured_ratio"))
            m("bfs.ap.mean_nodes_owned",          ap.get("mean_nodes_owned"))
            m("bfs.ap.mean_nodes_discovered",     ap.get("mean_nodes_discovered"))
            m("bfs.ap.mean_pct_owned",            ap.get("mean_pct_owned"))
            m("bfs.ap.mean_pct_discovered",       ap.get("mean_pct_discovered"))

            # ── Credentials ───────────────────────────────────────────────────
            creds: dict = metrics.get("credentials", {})
            m("bfs.creds.mean_discovered", creds.get("mean_creds_discovered"))
            m("bfs.creds.mean_in_cache",   creds.get("mean_creds_in_cache"))
            m("bfs.creds.mean_pct",        creds.get("mean_creds_pct"))

            # ── Firewall ──────────────────────────────────────────────────────
            fw: dict = metrics.get("firewall", {})
            m("bfs.fw.mean_rules_per_node",    fw.get("mean_rules_per_node"))
            m("bfs.fw.mean_firewall_coverage", fw.get("mean_firewall_coverage"))
            m("bfs.fw.mean_allow_rules",       fw.get("mean_allow_rules"))
            m("bfs.fw.mean_block_rules",       fw.get("mean_block_rules"))

            # ── Action stats ──────────────────────────────────────────────────
            ast: dict = metrics.get("action_stats", {})
            m("bfs.actions.local_attack_sr",  ast.get("mean_local_attack_sr"))
            m("bfs.actions.remote_attack_sr", ast.get("mean_remote_attack_sr"))
            m("bfs.actions.port_conn_sr",     ast.get("mean_port_conn_sr"))
            m("bfs.actions.overall_sr",       ast.get("mean_overall_sr"))

            # ── Payload / vuln distribution ───────────────────────────────────
            pay: dict = metrics.get("payloads", {})
            m("bfs.payloads.mean_vuln_instances", pay.get("mean_vuln_instances"))
            m("bfs.payloads.mean_unique_vulns",   pay.get("mean_unique_vulns"))
            m("bfs.payloads.mean_unique_props",   pay.get("mean_unique_props"))

            # ── Vocabulary / slot coverage ────────────────────────────────────
            vocab: dict = metrics.get("vocab_coverage", {})
            m("bfs.vocab.unique_slots_seen",  vocab.get("unique_slots_seen"))   # was slot_count — fixed
            m("bfs.vocab.mean_vuln_entropy",  vocab.get("mean_vuln_entropy"))
            tail_slots: list = vocab.get("tail_slots", [])
            m("bfs.vocab.tail_slot_count",    len(tail_slots))

            # ── Per-stratum breakdown ─────────────────────────────────────────
            by_stratum: dict = metrics.get("by_stratum", {})   # was "strata" — fixed
            for stratum_name, stratum_data in by_stratum.items():
                if not isinstance(stratum_data, dict):
                    continue
                pfx = f"bfs.stratum.{stratum_name}"
                m(f"{pfx}.solve_rate",       stratum_data.get("solve_rate"))
                m(f"{pfx}.mean_steps",       stratum_data.get("mean_steps"))
                m(f"{pfx}.mean_diameter",    stratum_data.get("mean_diameter"))
                m(f"{pfx}.mean_density",     stratum_data.get("mean_density"))
                m(f"{pfx}.mean_nodes",       stratum_data.get("mean_nodes"))
                m(f"{pfx}.mean_creds",       stratum_data.get("mean_creds"))
                m(f"{pfx}.mean_nodes_owned", stratum_data.get("mean_nodes_owned"))

            # ── Difficulty metrics ───────────────────────────────────────────
            diff = metrics.get("difficulty", {})
            if diff:
                for k in ["mean_score", "min_score", "max_score",
                           "mean_stochastic_resistance", "mean_topological_depth",
                           "mean_operational_overhead", "mean_stochastic_volatility"]:
                    if k in diff:
                        mlflow.log_metric(f"difficulty.{k}", diff[k], step=round_num)
                for rating, cnt in diff.get("rating_distribution", {}).items():
                    mlflow.log_metric(f"difficulty.rating.{rating}", cnt, step=round_num)

            # ── DRL hardness metrics ─────────────────────────────────────────
            drl = metrics.get("drl_hardness", {})
            if drl:
                for k in ["mean_min_cred_harvest_sequence", "mean_action_snr",
                           "mean_avg_steps_between_rewards"]:
                    if k in drl:
                        mlflow.log_metric(f"drl_hardness.{k}", drl[k], step=round_num)

            # ── Goal completeness ─────────────────────────────────────────────
            gc = metrics.get("goal_completeness", {})
            if gc:
                mlflow.log_metric("goals.pct_all_captured",    gc.get("pct_scenarios_all_goals", 1.0), step=round_num)
                mlflow.log_metric("goals.pct_partial",         gc.get("pct_scenarios_partial_goals", 0.0), step=round_num)
                mlflow.log_metric("goals.pct_zero",            gc.get("pct_scenarios_zero_goals", 0.0), step=round_num)
                mlflow.log_metric("goals.n_full_capture",      gc.get("n_full_capture", 0), step=round_num)
                mlflow.log_metric("goals.n_partial_capture",   gc.get("n_partial_capture", 0), step=round_num)
                mlflow.log_metric("goals.n_zero_capture",      gc.get("n_zero_capture", 0), step=round_num)
                mlflow.log_metric("goals.mean_captured_ratio", gc.get("mean_goals_captured_ratio", 0.0), step=round_num)
                mlflow.log_metric("goals.num_expected",        gc.get("num_goals_expected", 0), step=round_num)

        _try(_log)

    # ------------------------------------------------------------------
    # Quality round logging
    # ------------------------------------------------------------------

    def log_quality_round(self, round_num: int, eval_result: dict) -> None:
        """Log LLM quality evaluation results for one round.

        *eval_result* keys: ``overall_score`` (float 0-10),
        ``dimensions`` (dict of dimension dicts with ``score`` and ``grade``).
        """
        if not _ENABLED:
            return

        def _log() -> None:
            step = round_num

            mlflow.log_metric("quality.overall_score", eval_result.get("overall_score", 0), step=step)
            overall_grade = eval_result.get("overall_grade", "")
            if overall_grade:
                mlflow.set_tag("quality.overall_grade", str(overall_grade))

            dimensions: dict = eval_result.get("dimensions", {})
            for dim_name, dim_data in dimensions.items():
                if not isinstance(dim_data, dict):
                    continue
                mlflow.log_metric(f"quality.dim.{dim_name}", dim_data.get("score", 0), step=step)
                grade = dim_data.get("grade", "")
                if grade:
                    mlflow.set_tag(f"quality.grade.{dim_name}", str(grade))

            # ── CVE / vulnerability metrics from the config (static, logged once) ─
            cve: dict = eval_result.get("cve_metrics", {})
            if cve:
                mlflow.log_metric("quality.cve.total_vulns",       cve.get("total_vulns", 0),       step=step)
                mlflow.log_metric("quality.cve.cve_named_count",   cve.get("cve_named_count", 0),   step=step)
                mlflow.log_metric("quality.cve.remote_count",      cve.get("remote_count", 0),      step=step)
                mlflow.log_metric("quality.cve.local_count",       cve.get("local_count", 0),       step=step)
                mlflow.log_metric("quality.cve.windows_count",     cve.get("windows_count", 0),     step=step)
                mlflow.log_metric("quality.cve.linux_count",       cve.get("linux_count", 0),       step=step)
                mlflow.log_metric("quality.cve.formula_rate_count",cve.get("formula_rate_count", 0),step=step)

        _try(_log)

    # ------------------------------------------------------------------
    # Repair round logging
    # ------------------------------------------------------------------

    def log_repair_round(self, round_num: int, config_path: Path) -> None:
        """Log repaired config + repair_log metrics for *round_num*."""
        if not _ENABLED:
            return

        def _log() -> None:
            # Config YAML artifact
            mlflow.log_artifact(str(config_path), artifact_path=f"config_r{round_num}")

            # repair_log.json: original_score → fixed_score + per-dimension diffs
            repair_log_path = config_path.parent / f"{config_path.stem}_repair_log.json"
            if repair_log_path.exists():
                rl: dict = json.loads(repair_log_path.read_text())
                orig = rl.get("original_score")
                fixed = rl.get("fixed_score")
                if orig is not None:
                    mlflow.log_metric("repair.original_score", orig, step=round_num)
                if fixed is not None:
                    mlflow.log_metric("repair.fixed_score", fixed, step=round_num)
                if orig is not None and fixed is not None:
                    mlflow.log_metric("repair.score_delta", round(fixed - orig, 2), step=round_num)
                for dim, scores in rl.get("dimension_scores", {}).items():
                    if isinstance(scores, dict):
                        b = scores.get("before")
                        a = scores.get("after")
                        if b is not None:
                            mlflow.log_metric(f"repair.dim.{dim}.before", b, step=round_num)
                        if a is not None:
                            mlflow.log_metric(f"repair.dim.{dim}.after", a, step=round_num)
                mlflow.log_artifact(str(repair_log_path), artifact_path=f"repair_r{round_num}")

        _try(_log)

    # ------------------------------------------------------------------
    # Telemetry logging
    # ------------------------------------------------------------------

    def log_telemetry(self, telemetry: dict) -> None:
        """Log pipeline-level telemetry counters.

        Reads from ``telemetry["summary"]`` (preferred) and top-level keys.
        """
        if not _ENABLED:
            return

        def _log() -> None:
            summary: dict = telemetry.get("summary", telemetry)

            def _metric(key: str, telem_key: str) -> None:
                value = summary.get(telem_key, telemetry.get(telem_key, 0))
                if value is not None:
                    mlflow.log_metric(key, value)

            _metric("pipeline.total_duration",    "total_duration")
            _metric("pipeline.total_tools_called", "total_tools_called")
            _metric("pipeline.failed_tool_calls",  "failed_tool_calls")
            _metric("pipeline.total_retries",      "total_retries")
            _metric("pipeline.scenarios_replaced", "scenarios_replaced")

        _try(_log)

    # ------------------------------------------------------------------
    # Final scalar logging
    # ------------------------------------------------------------------

    def log_final(self, bfs_metrics: dict, quality_eval: dict) -> None:
        """Log final (no step) scalar summary for the completed run."""
        if not _ENABLED:
            return

        def _log() -> None:
            def _m(key: str, val: Any) -> None:
                if val is not None:
                    mlflow.log_metric(key, val)

            # BFS summary
            _m("final_solve_rate",    bfs_metrics.get("solve_rate"))
            _m("final_mean_steps",    bfs_metrics.get("mean_steps"))
            _m("final_mean_reward",   bfs_metrics.get("mean_reward"))
            _m("final_mean_nodes",    bfs_metrics.get("mean_nodes"))
            _m("final_mean_creds",    bfs_metrics.get("mean_creds"))
            _m("final_mean_diameter", bfs_metrics.get("mean_diameter"))
            _m("final_tree_ratio",    bfs_metrics.get("tree_ratio"))
            _m("final_fw_coverage",   bfs_metrics.get("firewall", {}).get("mean_firewall_coverage"))
            _m("final_vocab_slots",   bfs_metrics.get("vocab_coverage", {}).get("unique_slots_seen"))
            _m("final_vuln_entropy",  bfs_metrics.get("vocab_coverage", {}).get("mean_vuln_entropy"))
            ap = bfs_metrics.get("attack_paths", {})
            _m("final_steps_to_first_goal", ap.get("mean_steps_to_first_goal"))
            _m("final_steps_to_final_goal", ap.get("mean_steps_to_final_goal"))
            _m("final_pct_owned",           ap.get("mean_pct_owned"))

            # Quality
            _m("final_overall_score", quality_eval.get("overall_score"))
            dimensions: dict = quality_eval.get("dimensions", {})
            for dim_name, dim_data in dimensions.items():
                if not isinstance(dim_data, dict):
                    continue
                _m(f"final_dim_{dim_name}", dim_data.get("score"))

        _try(_log)

    # ------------------------------------------------------------------
    # Manifest logging (train/test counts from step3)
    # ------------------------------------------------------------------

    def log_manifest(self, manifest_json_path: Path) -> None:
        """Log scenario counts from manifest.json written by phase2/generator.py."""
        if not _ENABLED:
            return

        def _log() -> None:
            data: dict = json.loads(manifest_json_path.read_text())
            train = data.get("train_count", len(data.get("train", [])))
            test  = data.get("test_count",  len(data.get("test",  [])))
            mlflow.log_metric("pipeline.train_count", train)
            mlflow.log_metric("pipeline.test_count",  test)
            mlflow.log_metric("pipeline.total_scenarios", train + test)

        _try(_log)

    # ------------------------------------------------------------------
    # Coverage audit logging (step9)
    # ------------------------------------------------------------------

    def log_coverage_audit(self, coverage_gap_json_path: Path) -> None:
        """Log dataset-level slot coverage gap metrics from step9."""
        if not _ENABLED:
            return

        def _log() -> None:
            if not coverage_gap_json_path.exists():
                return
            data: dict = json.loads(coverage_gap_json_path.read_text())
            # coverage_gap.json structure: {gap_slots: [...], coverage_pct: float, ...}
            gap_slots = data.get("gap_slots", data.get("tail_slots", []))
            mlflow.log_metric("coverage.gap_slot_count", len(gap_slots))
            pct = data.get("coverage_pct", data.get("coverage", None))
            if pct is not None:
                mlflow.log_metric("coverage.pct", pct)
            mlflow.set_tag("coverage.gap_slots", ",".join(str(s) for s in gap_slots[:20]))
            mlflow.log_artifact(str(coverage_gap_json_path))

        _try(_log)

    # ------------------------------------------------------------------
    # Artifact logging
    # ------------------------------------------------------------------

    def log_artifacts(self, paths: list[Path]) -> None:
        """Log each existing path as an MLflow artifact."""
        if not _ENABLED:
            return

        for path in paths:
            def _log(p: Path = path) -> None:
                if p.exists():
                    mlflow.log_artifact(str(p))

            _try(_log)
