---
name: project-decisions-state
description: Implementation status of DECISIONS.md Track A and Track B — what is done vs remaining
metadata:
  type: project
---

All decisions from `design/DECISIONS.md` have been implemented as of 2026-05-16.

## Track B — Pipeline code changes: COMPLETE

All 8 decisions implemented across two sessions:

- **D-P5** — `pipeline/constants.py` created; all callers import from it
- **D-P6** — `_04_quality_evaluator.py` + `_05_apply_critic_fixes.py` moved from `phase1/` to `phase2/`; shims in `pipeline/quality_evaluator.py` and `pipeline/phase1/quality_evaluator.py`; `CLAUDE.md` updated
- **D-P7** — `run.py` steps renumbered: step3/4/5/6 (was 4/5/6/7); STEP 8 → STEP 7
- **D-A5** — `check_agent_category_allowlist()` in `02_config_checker.py`; imports `AGENT_CATEGORY_ALLOWLIST` from `constants.py`
- **D-P2** — Post-repair Phase 1 validation in `_05_apply_critic_fixes.py` (runs `02_config_checker.py --strict` + `03_validate_zone_coverage.py`)
- **D-P1** — `--agent-type` + `--config` flags in `02_test_env_integration.py`; `BFSPlannerAgent` filters by `allowed_vuln_names`; `run.py` passes `metadata.agent`
- **D-P3** — `template_alignment` removed from LLM prompt; `_compute_template_alignment_score(cfg)` added with 10 structural rule assertions; injected post-LLM-parse
- **D-P4** — Diameter penalty in `_05_apply_critic_fixes.py`: fires when `diameter < MIN_DIAMETER_TARGET`, mandates `min_domains: 2`, rejects SR-only fixes

## Track A — Agent spec updates: MOSTLY COMPLETE

- **D-A3** — CBS mechanic split documented in `README.md`, `meta_agent.md`, `s_lateral.md`; meta routing "stale creds → S_Lateral" corrected
- **D-A1** — S_Lateral `credential_leak LOCAL ✅` in action table; extraction techniques section added; `s_windows.md` rationale updated
- **D-A2** — Standalone flow in `s_lateral.md`; 4 slat task files updated (no pre-seeded creds)
- **D-A4** — Swing techniques duplicated in `vulnerability_catalog.md`; ADCS_ESC6 added to both sections; ownership notes per entry

## Remaining

Nothing. All decisions fully implemented as of 2026-05-16.

- **D-A6** — DONE: `CloudIAM_LDAP_Write` confirmed in `vulnerability_catalog.md`; `CloudFederated` added to `allowed_properties.md` section 4.5
- **`system_prompt.md`** — DONE: AGENT-CATEGORY SOLVABILITY ALLOWLIST section added; `solvability_vulnerabilities` rule updated to reference allowlist instead of hardcoded 4-key list
