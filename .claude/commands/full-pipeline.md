# Full Pipeline: Auto-Generate → Phase 2 → Evaluate → Retry

Runs the complete end-to-end pipeline:
**Phase 1** (auto-generate YAML config) →
**Phase 2** (generate scenarios + evaluate + human EDA report) →
**Evaluate combined result** →
**Retry from Phase 1** if not passing, up to `MAX_RETRIES` from `.env`.

All outputs are written to `DATASET_ROOT` (configured in `.env`).

---

## Arguments

`$ARGUMENTS` format:
```
<scenario description>  [name=<file_name>]  [arch=single|multi]
```

Examples:
```
/full-pipeline Enterprise Active Directory with 3 tiers, legacy workstations, and Domain Controller goal
/full-pipeline Healthcare IT with legacy on-prem workstations  name=healthcare_it
/full-pipeline Cloud-native Kubernetes with lateral movement paths  name=k8s_cloud  arch=multi
```

---

## Your Task

Run the complete iterative pipeline described in `$ARGUMENTS`.

---

## Step 0: Load config

Call `get_pipeline_config`. Display:
```
═══════════════════════════════════════════════
  FULL PIPELINE
  DATASET_ROOT  : <path>
  MAX_RETRIES   : <N>
  Phase 1 min   : <score>/10
  Phase 2 min   : <solve_rate>
═══════════════════════════════════════════════
```

Parse from `$ARGUMENTS`:
- `scenario_description` — everything before keyword args
- `scenario_name` — from `name=<x>`, else auto-derive from description
- `arch` — "single" or "multi", default "single"

Set `attempt = 1`, `max_retries` from config.

---

## Loop: repeat until passed or attempt > max_retries

### Phase 1 — Auto-Generate Domain Config

Run the Phase 1 auto-generation pipeline (same as `/auto-generate` skill):
1. Call `generate_template_yaml` with scenario_description
2. Fill in the template for the given scenario
3. Save to `data/<scenario_name>_v<attempt>.yaml`
4. Call `run_pipeline(config_path)` — validate & evaluate
5. Check quality with `evaluate_scenario_quality`
6. If score < `phase1_min_score`: call `fix_template` and retry within Phase 1
   (up to 5 inner iterations)
7. Call `generate_phase1_report` with all iteration data
8. Save Phase 1 report to `DATASET_ROOT/phase1/<scenario_name>/attempt_<N>/phase1_report.txt`

Display Phase 1 result:
```
PHASE 1 — attempt <N>
  Score : <X>/10 (<grade>)  [PASSED / BELOW THRESHOLD]
  Config: data/<scenario_name>_v<attempt>.yaml
```

If Phase 1 score < `phase1_min_score` after max inner iterations:
- Note the score and top issues
- Increment attempt, retry the full loop

### Phase 2 — Scenarios + Evaluation + Reports

Call `run_phase2_pipeline`:
```
run_phase2_pipeline(
    config_path   = "data/<scenario_name>_v<attempt>.yaml",
    scenario_name = <scenario_name>,
    attempt       = <attempt>,
    phase1_score  = <phase1_score>,
    phase1_grade  = <phase1_grade>,
)
```

Display Phase 2 result:
```
PHASE 2 — attempt <N>
  Solve rate : X/N (Y%)  [PASSED / FAILED]
  Report     : <report_path>
  Figures    : <figures_dir>  (<N> PNGs)
```

### Evaluate combined result

A pipeline attempt **PASSES** when BOTH:
- Phase 1 score ≥ `phase1_min_score`
- Phase 2 solve_rate ≥ `phase2_min_solve_rate`

**If PASSED:**
```
═══════════════════════════════════════════════
  ✓ PIPELINE COMPLETE — attempt <N>/<max>
  Config  : data/<scenario_name>_v<attempt>.yaml
  Report  : <report_path>
  Figures : <figures_dir>
═══════════════════════════════════════════════
```
→ **STOP the loop.**

**If FAILED and attempt < max_retries:**
- Summarise what failed (Phase 1 score, Phase 2 solve rate)
- Identify the top issues from Phase 1 evaluation + Phase 2 evaluation
- Note them as context for the next Phase 1 attempt
- Increment attempt, continue loop

**If FAILED and attempt == max_retries:**
```
═══════════════════════════════════════════════
  ✗ PIPELINE EXHAUSTED — <max> attempts used
  Best solve rate : X%  (attempt N)
  Best P1 score   : X/10 (attempt N)
  Last report     : <report_path>
═══════════════════════════════════════════════
```
→ Show the best attempt's report path and suggest manual review.

---

## Post-loop summary

After the loop ends (passed or exhausted), show:
- Total attempts made
- Best Phase 1 score across attempts
- Best Phase 2 solve rate across attempts
- Path to the best output directory

---

## Arguments

$ARGUMENTS
