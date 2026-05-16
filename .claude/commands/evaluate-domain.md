# Evaluate a CyberBattleSim Domain Configuration

Run the full evaluation pipeline on a domain configuration and report findings.
**Follow each step exactly in order. Do not skip steps or add analysis beyond what is specified.**

## STRICT STEP SEQUENCE

### Step 1 — Resolve config path (NO autonomous search)

From `$ARGUMENTS`:
- If a full path is given, use it exactly.
- If just a name like `swin_serverfarm_standalone_v1` is given, use `data/scenarios/<name>.yaml`.
- If no argument given, list `data/scenarios/*.yaml` and STOP — ask the user to pick one before continuing.

**Do NOT proceed if the file does not exist. Report the missing file and stop.**

### Step 2 — Run pipeline validation

Run EXACTLY this command, nothing else:

```bash
python pipeline/phase1/pipeline.py --config <path> --skip-fetch --train 3 --test 1 --strata small
```

Wait for it to complete. Record exit code and output.

**If exit code ≠ 0: show the error output and STOP. Do not attempt auto-fix.**

### Step 3 — Read results (read ALL three files, no interpretation yet)

Read EXACTLY these three files:
1. `DATASET_ROOT/phase1/<domain>/03_config_check.json`
2. `DATASET_ROOT/phase1/<domain>/06_evaluation.json`
3. `DATASET_ROOT/phase1/<domain>/07_pipeline_report.txt`

### Step 4 — Run quality evaluator

Run EXACTLY this command:

```bash
python pipeline/phase1/04_quality_evaluator.py data/<name>.yaml
```

Record the output verbatim.

### Step 5 — Check thresholds (mechanical check only)

For each metric in `06_evaluation.json`, check against these FIXED thresholds:

| Metric | Threshold | Pass condition |
|--------|-----------|----------------|
| `solvable` | — | must be `true` |
| `cred_chain_ratio` | ≥ 0.55 | |
| `discovery_ratio` | ≥ 0.70 | |
| `min_goal_depth` | ≥ 2 | |
| `mean_goal_depth` | ≥ 2.5 | |
| `goal_ratio` | ≤ 0.15 | |
| `remote_exploitable_goals` | ≥ 1 | |

Mark each as ✓ PASS or ✗ FAIL. No interpretation — just the check.

### Step 6 — Cross-reference errors with anti-patterns

For each config error or warning in `03_config_check.json`:
- Look it up in `prompts/anti_patterns.md`.
- Record the anti-pattern ID (AP-XXX) if found.

Only report what is there. Do not invent additional issues.

### Step 7 — Output the structured report (EXACT FORMAT REQUIRED)

Output EXACTLY this format, no additions:

```
EVALUATION REPORT: <config_name>
================================
Status: PASS / FAIL

QUALITY METRICS:
  ✓/✗ Solvable: true/false
  ✓/✗ Cred chain ratio: 0.XX (threshold ≥ 0.55)
  ✓/✗ Discovery ratio: 0.XX (threshold ≥ 0.70)
  ✓/✗ Min goal depth: N (threshold ≥ 2)
  ✓/✗ Mean goal depth: N.N (threshold ≥ 2.5)
  ✓/✗ Goal ratio: 0.XX (threshold ≤ 0.15)
  ✓/✗ Remote exploitable goals: N (threshold ≥ 1)

QUALITY EVALUATOR: N.N/10 (Grade)
  Topology Realism:      N/10
  Vulnerability Realism: N/10
  Scenario Difficulty:   N/10
  Firewall Realism:      N/10
  General Realism:       N/10
  CVE Grounding:         N/10

CONFIG ISSUES:
  ✗ [Error or warning text] → AP-XXX (if applicable)
     Fix: [Exact YAML change — field name, old value, new value]

RECOMMENDATIONS (max 3):
  1. [Highest priority fix — one sentence]
  2. [Second priority fix]
  3. [Third priority fix, if any]
```

### Step 8 — Ask before any changes

After outputting the report, ask EXACTLY:
> "Apply these fixes to `data/<name>.yaml`? (yes / no)"

**Wait for explicit user confirmation before making ANY file changes.**
If the user says yes, apply only the specific fixes listed in the report — nothing else.
If the user says no, stop.

### Step 9 — If fixes applied: re-run from Step 2

Run the pipeline again with the same command. Report changes vs previous run (metric deltas only).

---

## Rules

- **Do not add commentary, analysis, or suggestions beyond the format above.**
- **Do not run any commands not listed in this document.**
- **Do not apply fixes without explicit "yes" in Step 8.**
- **Do not retry or workaround pipeline errors — report and stop.**
- **Each step must complete before the next starts.**

## Arguments

$ARGUMENTS
