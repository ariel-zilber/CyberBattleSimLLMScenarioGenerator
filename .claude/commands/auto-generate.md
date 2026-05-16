# Auto-Generate CyberBattleSim Domain Configuration (Phase 1 Pipeline)

Automated iterative pipeline: **generate → validate → evaluate → critique → improve → report**.

Runs until the generated config passes all quality thresholds or the iteration limit is reached,
then produces a structured Phase 1 report.

---

## Arguments

`$ARGUMENTS` format (all optional except description):
```
<scenario description>  [name=<file_name>]  [arch=single|multi]  [iterations=N]
```

Examples:
```
/auto-generate Enterprise Active Directory with 3 tiers, legacy workstations, and Domain Controller goal
/auto-generate Cloud-native Kubernetes cluster  name=k8s_cloud  arch=multi  iterations=4
```

---

## Your Task

Run the complete Phase 1 automated generation pipeline for the scenario described in `$ARGUMENTS`.

---

## Step 0: Parse Arguments

Extract from `$ARGUMENTS`:
- `scenario_description` — the full natural-language description (required)
- `scenario_name` — file-safe name for the config; derive from description if missing
  (e.g., "Enterprise AD" → `enterprise_ad`)
- `architecture` — `"single"` (default) or `"multi"`
- `max_iterations` — integer, default `3`, maximum `5`

Initialise state:
```
iteration    = 1
history      = []
current_yaml = null
critique     = null   # null on first iteration
```

---

## Step 1: Get the Generation Prompt Package

Call `generate_template_yaml(scenario_description, scenario_name, architecture)`.

Store the returned prompt package — you will use it as the base context for generation
(and re-use it in every iteration together with the critique).

---

## Step 2: Generate YAML

**Input context** (combine both when re-iterating):
- The full prompt package from Step 1
- The critique from `build_critique_prompt` (empty on iteration 1)

Generate a complete, valid YAML domain configuration.

**Never violate these rules** (parser will crash):
- `solvability_vulnerabilities` → DICT with exactly 4 keys: `remote_access`, `credential_leak`, `discovery`, `goal_access`
- `constraint_vulnerabilities` → DICT with exactly 2 keys: `leak_known_credentials`, `leak_neighbors`
- `start_node.vulnerabilities` → DICT with exactly 2 keys: `discovery`, `credential_leak`
- All `reward` fields → descriptive STRINGS, never integers
- All properties used anywhere → declared in `identifiers.base_properties`
- `identifiers.base_properties` → must include `breach_node`
- Constraint `source`/`target` → GROUP NAMES (plural), not service names
- Exploit `success_rate` → 0.40–0.80 (never 1.0)
- At least one service → `is_goal: true`
- Goal services → must NOT have `Unauthenticated` in `default_properties`
- Every `solvability_vulnerabilities` item → must have `probability` field
- `start_node.subnet` → must be `0.0.0.0/0` or `203.0.113.0/24` (public internet)
- DMZ → must NEVER connect directly to Core/Data tier

**Save the YAML to:** `data/<scenario_name>_v<iteration>.yaml`

---

## Step 3: Validate & Evaluate

Run both quality checks on the saved file:

**3a. Structural validation:**
```
validate_config("data/<scenario_name>_v<iteration>.yaml")
```

**3b. Realism quality evaluation:**
```
evaluate_scenario_quality("data/<scenario_name>_v<iteration>.yaml")
```

Display the `formatted_report` from the quality evaluation.

**Record this iteration:**
```python
history.append({
    "iteration": iteration,
    "yaml_path": f"data/{scenario_name}_v{iteration}.yaml",
    "overall_score": quality_result["overall_score"],
    "overall_grade": quality_result["overall_grade"],
    "passed_validation": validation_result["passed"],
    "validation_error_count": len(validation_result["errors"]),
    "validation_errors": validation_result["errors"],
    "dimension_scores": {
        "topology_realism":      quality_result["dimensions"]["topology_realism"]["score"],
        "vulnerability_realism": quality_result["dimensions"]["vulnerability_realism"]["score"],
        "scenario_difficulty":   quality_result["dimensions"]["scenario_difficulty"]["score"],
        "firewall_realism":      quality_result["dimensions"]["firewall_realism"]["score"],
        "general_realism":       quality_result["dimensions"]["general_realism"]["score"],
    },
    "top_issues": quality_result["top_issues"],
})
```

---

## Step 4: Decide — Pass or Critique

**Phase 1 PASSES if ALL of the following are true:**
- `validation_result["passed"] == True` (zero structural errors)
- `quality_result["overall_score"] >= 7.0`
- No `critical` findings in any quality dimension

**If PASSES → go to Step 5 (report).**

**If FAILS AND `iteration < max_iterations`:**

Call `build_critique_prompt`:
```
build_critique_prompt(
    original_description = scenario_description,
    yaml_path            = "data/<scenario_name>_v<iteration>.yaml",
    validation_errors    = validation_result["errors"],
    validation_warnings  = validation_result["warnings"],
    quality_result       = quality_result,
    iteration            = iteration,
    max_iterations       = max_iterations,
)
```

Store the returned critique. Set `iteration = iteration + 1`. Return to **Step 2**.

**If FAILS AND `iteration >= max_iterations`:**

Proceed to Step 5 with `passed = False`.

---

## Step 5: Generate Phase 1 Report

Use the final accepted YAML path (last entry in `history`).

Call `generate_phase1_report`:
```
generate_phase1_report(
    scenario_description = scenario_description,
    scenario_name        = scenario_name,
    iterations           = history,
    final_yaml_path      = history[-1]["yaml_path"],
    passed               = <True if thresholds met, False otherwise>,
)
```

Display the full `formatted_report` from the result.

---

## Step 6: Post-Report Actions

After displaying the Phase 1 report:

1. **If passed:** Offer to run the full pipeline for deeper scenario generation:
   ```
   run_pipeline(config_path="data/<scenario_name>_v<final>.yaml", train_count=5, test_count=2)
   ```

2. **If not passed:** List the remaining issues from the final iteration and ask the user:
   - "Apply manual fixes and re-run?" → they can edit the YAML and call `/evaluate-quality`
   - "Continue with more iterations?" → re-run `/auto-generate` with `iterations=2`

---

## Quality Thresholds Reference

| Metric | Threshold | Source |
|--------|-----------|--------|
| Structural validation | Zero errors | `validate_config` |
| Overall quality score | ≥ 7.0 / 10 | `evaluate_scenario_quality` |
| Network Topology Realism | ≥ 6 / 10 | dimension score |
| Properties & Vulnerabilities | ≥ 6 / 10 | dimension score |
| Scenario Difficulty | ≥ 6 / 10 | dimension score |
| Firewall Rules Realism | ≥ 6 / 10 | dimension score |
| General Realism | ≥ 6 / 10 | dimension score |

---

## Example Output

```
═══════════════════════════════════════════════════
AUTO-GENERATE: enterprise_ad
Iteration 1/3 — Generating...
═══════════════════════════════════════════════════

[Generates YAML → saves data/enterprise_ad_v1.yaml]

QUALITY REPORT (Iteration 1):
  Overall: 5.8/10 (D)
  Network Topology Realism          7/10 (B)
  Properties & Vulnerabilities      4/10 (F)  ← needs fix
  Scenario Difficulty               6/10 (C)
  Firewall Rules Realism            5/10 (D)  ← needs fix
  General Realism                   7/10 (B)

Issues found — generating critique for iteration 2...

═══════════════════════════════════════════════════
Iteration 2/3 — Regenerating with critique...
═══════════════════════════════════════════════════

[Generates improved YAML → saves data/enterprise_ad_v2.yaml]

QUALITY REPORT (Iteration 2):
  Overall: 7.8/10 (B)  ← above threshold ✓
  Network Topology Realism          9/10 (A+)
  Properties & Vulnerabilities      7/10 (B)
  Scenario Difficulty               7/10 (B)
  Firewall Rules Realism            8/10 (A)
  General Realism                   8/10 (A)

✓ All thresholds passed. Generating Phase 1 report...

╔══════════════════════════════════════════════════════════════════╗
  PHASE 1 GENERATION REPORT
  Scenario : enterprise_ad   Iterations: 2   Final Score: 7.8/10
╚══════════════════════════════════════════════════════════════════╝
...
VERDICT: PHASE 1 COMPLETE ✓
```

---

## Arguments

$ARGUMENTS
