# Critique Prompt Template

This document describes the structure of the critique prompt that is injected between generation iterations in the automated Phase 1 pipeline. It is used internally by the `build_critique_prompt` MCP tool.

---

## Purpose

After each generation attempt, the pipeline:

1. Validates the YAML structurally (`validate_config`)
2. Evaluates realism quality (`evaluate_scenario_quality`)
3. Calls `build_critique_prompt` to produce a structured feedback message
4. Feeds that message back to the LLM with the original prompt package as the basis for the next iteration

The critique is designed to be **prescriptive** — it tells the LLM exactly what to fix, not just what is wrong.

---

## Critique Structure

```
# GENERATION CRITIQUE — Iteration N/Max

You previously generated a domain configuration YAML. It has been evaluated
and found to have issues that must be fixed before this iteration is complete.
Study the findings below carefully, then regenerate the COMPLETE YAML with all
issues resolved. Do NOT just patch individual fields — rewrite the full config.

══════════════════════════════════════════════════════════════════
  SCENARIO REQUEST (unchanged): <original description>
  Generated file:  data/<name>_v<N>.yaml
  Overall quality: <score>/10  Grade: <grade>
══════════════════════════════════════════════════════════════════

## STRUCTURAL ERRORS (parser will fail — fix ALL of these first)

  1. <error text>
  → Hint: AP-00X: <anti-pattern description>

## STRUCTURAL WARNINGS

  ⚠ <warning text>

## QUALITY DIMENSION SCORES (target: every dimension ≥ 7/10)

  ✓✓ Network Topology Realism             9/10  (A+)
  ✗  Properties & Vulnerabilities Realism  5/10  (D)
  ~  Scenario Difficulty                   7/10  (B)
  ✗  Firewall Rules Realism               4/10  (F)
  ~  General Realism                       7/10  (B)

## CRITICAL & FAIL FINDINGS — must resolve in next iteration

  ✗ [Firewall Rules Realism] Multi-domain config has no inter_domain_constraints  [→ AP-017]
  ✗ [Properties & Vulnerabilities Realism] No REMOTE-type vulnerabilities

## WARNINGS — address where possible

  ⚠ [Scenario Difficulty] min_total_nodes=8 — too few nodes for meaningful RL training

## REGENERATION INSTRUCTIONS

1. Fix ALL structural errors above.
2. For each CRITICAL/FAIL quality finding, make the specific change described.
3. Re-read the MASTER DIRECTIVES from the system prompt — especially:
   - Strict network segmentation (no InternetEdge→ServerFarm direct connections — must pass through HQ Edge)
   - Attacker on public internet (start_node.subnet = 0.0.0.0/0)
   - Probabilistic exploits (success_rate 0.40–0.80)
   - match_properties specific to OS and role
   - All rewards are descriptive strings
4. Generate the COMPLETE YAML from scratch.
5. Save to: data/<name>_v<N+1>.yaml

Iteration N+1/Max. <N> iteration(s) remaining after this.

## ANTI-PATTERNS REFERENCE (review before regenerating)

<contents of anti_patterns.md>
```

---

## Scoring Icons

| Icon | Grade | Meaning |
|------|-------|---------|
| ✓✓   | A+    | Excellent — no changes needed for this dimension |
| ✓    | A     | Good — minor improvements welcome |
| ~    | B     | Above average — a few issues to address |
| ✗    | C/D   | Below threshold — specific fixes required |
| ✗✗✗  | F     | Critical failures — this dimension must be rebuilt |

---

## Decision Threshold

After each iteration, the pipeline decides whether to continue based on:

| Condition | Action |
|-----------|--------|
| `validation.passed == True` AND `quality.overall_score >= 7.0` | **STOP** — Phase 1 complete |
| `validation.passed == False` OR `quality.overall_score < 7.0` | **CONTINUE** — iterate |
| `iteration >= max_iterations` | **STOP** — generate Phase 1 report regardless |

The default `max_iterations` is **3**. This is configurable via the `/auto-generate` command arguments.

---

## What the LLM Should Do With the Critique

When the LLM receives a critique prompt, it must:

1. **Read all structural errors first** — these are parser failures, not realism issues. Fix them unconditionally.
2. **Address every CRITICAL and FAIL finding** — these caused significant point deductions.
3. **Address as many WARNINGS as possible** — each warning is a deduction that lowers the overall score.
4. **Do not introduce new issues** — re-read the anti-patterns and validation checklist before writing.
5. **Write a complete YAML** — do not produce a diff or partial config. The evaluator needs the full document.
6. **Verify the output mentally** using the 10-point checklist from `prompts/tools/validation_checklist.md`.
