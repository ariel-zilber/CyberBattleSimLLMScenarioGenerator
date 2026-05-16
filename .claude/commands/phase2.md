# Phase 2: Scenario Generation & Runtime Evaluation

Takes a Phase 1 domain config YAML and runs the full Phase 2 pipeline via the
single `run_phase2_pipeline` tool: generate scenarios → evaluate → LLM report →
EDA human report (figures saved as PNG, not fed to LLM context).

Output location and defaults are controlled by `.env` (read via `get_pipeline_config`).

---

## Arguments

`$ARGUMENTS` format:
```
<config_path_or_name>  [attempt=N]  [phase1_score=X]  [phase1_grade=Y]
```

Examples:
```
/phase2 data/enterprise_ad_v2.yaml
/phase2 enterprise_ad_3tier_v1  phase1_score=8.2  phase1_grade=A
/phase2 data/healthcare_iot_v1.yaml  attempt=2  phase1_score=7.1  phase1_grade=B
```

---

## Your Task

Run the complete Phase 2 pipeline for the domain config given in `$ARGUMENTS`.

---

## Step 0: Load config & parse arguments

Call `get_pipeline_config` and display:
```
DATASET_ROOT : <path>
PHASE2_ROOT  : <path>
Min solve rate: <value>
```

Parse from `$ARGUMENTS`:
- `config_path` — resolve to `data/<name>.yaml` if bare name given
- `scenario_name` — strip `_v<N>` suffix from config filename
- `attempt` — default 1
- `phase1_score` / `phase1_grade` — default 0.0 / ""

---

## Step 1: Run `run_phase2_pipeline`

Call:
```
run_phase2_pipeline(
    config_path   = <config_path>,
    scenario_name = <scenario_name>,
    attempt       = <attempt>,
    phase1_score  = <phase1_score>,
    phase1_grade  = <phase1_grade>,
)
```

This single call covers: scenario generation → heuristic evaluation →
Phase 2 LLM report → EDA analysis + PNG figures.

Display progress:
```
PHASE 2 PIPELINE — attempt <N>
  Config      : <config_path>
  Output root : <scenarios_dir>
  ...
```

---

## Step 2: Display results

Show the key metrics from the result:
```
RESULTS:
  Solve rate  : X/N (Y%)   [PASSED / FAILED]
  Report      : <report_path>
  Figures     : <figures_dir>  (<plots_saved> PNGs)
```

---

## Step 3: Verdict

**If `passed = True` (solve_rate ≥ threshold):**
- "Phase 2 complete. Dataset ready for DRL training."
- Show scenarios_dir and report_path.

**If `passed = False`:**
- Show solve rate vs threshold.
- Summarise the failure pattern from evaluation_result.
- Suggest specific fixes to the domain config.

---

## Arguments

$ARGUMENTS
