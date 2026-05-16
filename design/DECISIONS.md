# Design Decisions — GLOBALTECH DRL Pipeline

**Date:** 2026-05-16  
**Source:** Grill session (`GRILL_QUESTIONS.md` → `GRILL_ANSWERS.md` → `GRILL_FOLLOWUP.md` → `GRILL_FOLLOWUP_ANSWERS_GEMINI.md`)  
**Status:** All decisions final — implementation pending

---

## Legend

- **SUPERSEDED** — an earlier decision overridden by a later follow-up  
- **PENDING** — implementation not yet done  
- **VERIFIED** — needs a manual check before implementing

---

## Part 1 — Agent Architecture

---

### D-A1 — S_Lateral owns the full credential lifecycle (extraction + relay)

**Decision:** S_Lateral's action space is expanded to two sub-roles:

| Sub-role | CBS category | type | Examples |
|----------|-------------|------|---------|
| Extraction | `credential_leak` | LOCAL | `Mimikatz_LSASS`, `LAPS_Password_Read`, `GPP_Password_Decryption`, `WinRM_Credential_Cache` |
| Relay | `lateral_movement` | REMOTE / LOCAL | `NTLM_Relay_SMB`, `WinRM_Exec_Hash`, `ADCS_ESC1` (lateral role), `ShadowCredentials` (lateral role) |

**Rationale:** Credential chains often cross OS families (AWS IAM → on-prem NTLM relay). A single "Credential Specialist" handles this cross-surface logic more cleanly than multiple surface specialists passing the baton. Keeps S_Windows and S_Linux focused on exploitation only.

**Impact:**
- `specialist_agent_spec.md` — S_Lateral action table: add `credential_leak LOCAL ✅`
- `s_lateral.md` — add extraction section with technique list above
- `s_windows.md` — confirm `credential_leak ❌ No` (now explicitly owned by S_Lateral)
- `s_linux.md` — cloud-specific credential_leak entries (Container_EnvVars, AWS_CredFile, etc.) stay with S_Linux; Windows post-exploitation extraction moves to S_Lateral — no overlap

**Status:** DONE — `s_lateral.md` action table updated (`credential_leak LOCAL ✅`); extraction section added (Mimikatz_LSASS, LAPS_Password_Read, GPP_Password_Decryption, WinRM_Credential_Cache); `s_windows.md` rationale clarified; `README.md` action matrix updated; S_Linux cloud creds confirmed in place.

---

### D-A2 — S_Lateral standalone training does not need a seeded breach

**Decision:** The "synthetically seeded breach" design from the earlier Q4 answer is superseded. Under D-A1, S_Lateral can run `Mimikatz_LSASS` (or equivalent) as step 1 on its breach node, populating the credential store itself. No SR 1.0 dummy `credential_leak` entry is needed.

**Standalone episode flow:**
1. S_Lateral owns breach node (SR 1.0 probe, `breach_node` property)
2. Step 1: fires LOCAL `credential_leak` (e.g., `Mimikatz_LSASS`) → credentials enter store
3. Steps 2–N: fires `lateral_movement` techniques using those credentials → terminal goal

**Impact:**
- `s_lateral.md` standalone training section — replace seeded-breach description with the above flow
- Scenario task files `slat_*.md` — remove "credential store contains NTLM hash" from breach node description

**Status:** DONE — `s_lateral.md` standalone episode flow added; `slat_ntlm_relay_v1.md`, `slat_winrm_creds_v1.md`, `slat_adcs_cert_v1.md`, `slat_cloud_to_corp_v1.md` updated to remove pre-seeded credential language.  
**Supersedes:** Q4 answer in `GRILL_ANSWERS.md`

---

### D-A3 — Cross-zone credential propagation: LEAK_KNOWN_CREDENTIALS is passive; extraction is active

**Decision:** Clarify the CBS mechanic split in all specs:

| Mechanic | Who acts | How |
|----------|----------|-----|
| `credential_leak` solvability entry | S_Lateral (Windows nodes), S_Linux (cloud nodes) | Agent chooses to run a LOCAL loot action on an owned node → cred enters store |
| `LEAK_KNOWN_CREDENTIALS` constraint | CBS engine | Fires automatically when a node holding the constraint is owned — no agent action needed |

The meta-agent routing trigger "credential store stale → call S_Recon" becomes "credential store stale → call S_Lateral." S_Lateral runs extraction on the stalled node; the LEAK constraint fires passively.

**Impact:**
- `specialist_agent_spec.md` — meta-agent routing table: replace S_Recon stagnation trigger with S_Lateral
- `SCENARIO_CATALOG.md` — all steps labeled "S_Recon: Mimikatz_LSASS / BloodHound_Recon" reassigned to S_Lateral

**Status:** DONE — `README.md` (agents) action matrix updated with CBS mechanic note; `meta_agent.md` routing trigger "credential store stale → S_Lateral" corrected; `s_lateral.md` scope updated with mechanic split box.

---

### D-A4 — S_Identity / S_Lateral technique partition: category is the key, not technique name

**Decision:** Techniques that can serve both a lateral role and a goal-access role (ADCS_ESC1, ADCS_ESC6, ShadowCredentials, NTLM_Relay_LDAP, PassTheHash) appear **twice** in `vulnerability_catalog.md` under different category sections:

- Under `## Category: lateral_movement` → owned by S_Lateral (crossing a zone boundary or pivoting to a new node)
- Under `## Category: goal_access` → owned by S_Identity (achieving domain compromise on an already-reachable DC)

The `(category, technique_name)` pair is the canonical key. Technique name alone is not sufficient.

**Impact:**
- `vulnerability_catalog.md` — duplicate swing techniques into `## Category: lateral_movement` section; add ownership note per entry
- `02_config_checker.py` — validator must parse catalog section for each entry, not just check name existence

**Status:** DONE — swing techniques (NTLM_Relay_LDAP, PassTheHash, ShadowCredentials) duplicated into `goal_access` section with S_Identity ownership notes; ADCS_ESC1/ESC6/ESC8 now appear in both sections; ownership notes added in `lateral_movement`; `(category, technique_name)` canonical key documented. Note: `02_config_checker.py` catalog-section parsing not yet implemented (validator currently checks allowlist by category, not catalog section).

---

### D-A5 — S_Identity / S_Lateral partition enforced by config_checker allowlist

**Decision:** Extend `02_config_checker.py` (not a new step) with an agent-category allowlist. Any solvability entry whose category is not in the agent's allowlist → hard validation error.

**Allowlist:**

| Agent | Permitted solvability categories |
|-------|----------------------------------|
| S_Network | `remote_access`, `credential_leak` |
| S_Linux | `remote_access`, `credential_leak` |
| S_Windows | `remote_access` |
| S_Identity | `remote_access`, `goal_access` |
| S_Lateral | `lateral_movement`, `credential_leak` |
| Meta | all categories |

**Impact:**
- `02_config_checker.py` — add allowlist dict + validation loop over all solvability entries
- `system_prompt.md` — update generation instructions to match allowlist exactly

**Status:** DONE — `check_agent_category_allowlist()` added to `pipeline/phase1/02_config_checker.py`; `AGENT_CATEGORY_ALLOWLIST` imported from `constants.py`; agent-aware `required_categories` in `check_vulnerability_coverage()`. `system_prompt.md` update still PENDING (Track A).

---

### D-A6 — CloudIAM_LDAP_Write: valid abstraction, properties must be verified

**Decision:** `Solvability.CloudIAM_LDAP_Write` is an accepted CBS simplification of the IAM → SAML → Kerberos chain. Modeled as `type: LOCAL` on a Z6 node, targeting a Z1 node. Valid only when target has `CloudFederated` property.

**Action before implementing S-LAT-02:** Verify both of the following exist:
- `Solvability.CloudIAM_LDAP_Write` in `vulnerability_catalog.md` (cited as line 615 — needs manual confirmation)
- `CloudFederated` token in `prompts/reference/allowed_properties.md`

**Status:** VERIFIED (manual check required before S-LAT-02 config generation)

---

## Part 2 — Pipeline

---

### D-P1 — BFS evaluator must enforce agent action-space restrictions

**Decision:** `02_test_env_integration.py` must accept an `--agent-type` flag. When set, the internal BFS planner filters its solvability graph to only the categories permitted for that agent (per the allowlist in D-A5). A scenario that BFS solves with the full graph but fails with the restricted graph is flagged as "BFS-solvable, specialist-unsolvable" — a validation error.

**Impact:**
- `pipeline/phase2/02_test_env_integration.py` — add `--agent-type` argument + solvability filter
- `pipeline/run.py` — pass `metadata.agent` from config to `02_test_env_integration.py`

**Status:** DONE — `--agent-type` and `--config` args added; `BFSPlannerAgent.__init__` accepts `allowed_vuln_names`; `_replan()` skips disallowed vulns; `run.py` passes args from `metadata.agent` in both BFS eval and replacement re-check calls.

---

### D-P2 — Phase 1 validators must re-run after every actor repair

**Decision:** After `_05_apply_critic_fixes.py` produces a fixed config, run the following before accepting it:

```python
subprocess.run([python, "pipeline/phase1/02_config_checker.py", fixed_path, "--strict"])
subprocess.run([python, "pipeline/phase1/03_validate_zone_coverage.py", fixed_path])
```

If either fails: abort the repair round, re-prompt the actor with the checker errors, do not advance the config.

**Impact:**
- `pipeline/phase1/_05_apply_critic_fixes.py` — add post-repair validation hook

**Status:** DONE — post-repair hook added to `pipeline/phase2/_05_apply_critic_fixes.py`; runs `02_config_checker.py --strict` and `03_validate_zone_coverage.py`; aborts and returns `None` on failure.

---

### D-P3 — `template_alignment` score replaced by quantitative rule count

**Decision:** Remove the LLM-graded `template_alignment` dimension (circular — LLM grades its own output). Replace with a score derived from the number of hard-coded architectural assertions passed in `02_config_checker.py` (e.g., "Z4 must have firewall rule to Z2", "Z1 must have DomainController", "no HTTP/ALL on internal constraints").

**Impact:**
- `pipeline/phase1/_04_quality_evaluator.py` — remove `template_alignment` LLM prompt; replace with rule-pass-count score
- `02_config_checker.py` — add architectural assertion list that returns a pass/fail count

**Status:** DONE — `template_alignment` removed from `DIMENSION_NAMES` and LLM prompt; `_compute_template_alignment_score(cfg)` added with 10 structural assertions (metadata, services, goals, attack_flow depth, domain count, solvability categories, no-ALL-protocol, IDC for multi-domain, start_node); injected into result after LLM parse in both `evaluate_with_llm()` and `_fallback_result()`.

---

### D-P4 — Actor repair prompt must penalize low diameter more heavily

**Decision:** The Critic prompt already instructs domain fragmentation as the fix for low `scenario_difficulty`. Add an explicit structural assertion: if `mean_diameter < 3`, the repair prompt must include `min_domains: 2` as a hard constraint and forbid SR-tweak-only fixes.

**Impact:**
- `pipeline/phase1/_05_apply_critic_fixes.py` — add diameter-conditional instruction block to repair prompt

**Status:** DONE — diameter check in `_runtime_repair_rules()` now fires when `diameter < MIN_DIAMETER_TARGET` (not just ≤ FLAT_TOPOLOGY_DIAMETER); mandates `min_domains: 2`, IDC choke points, and explicitly rejects SR-only fixes.

---

### D-P5 — All magic numbers extracted to a constants module

**Decision:** Create `pipeline/constants.py` with every hardcoded threshold, with a description for each.

```python
SOLVE_RATE_DESIGN_THRESHOLD = 0.40   # below this → YAML is broken, invoke LLM repair
MIN_SOLVE_RATE              = 0.75   # minimum acceptable solve rate for a passing config
MAX_BFS_ROUNDS              = 2      # max actor-critic repair iterations
TARGET_SCORE                = 8.0    # default LLM quality score threshold
MIN_DIAMETER_TARGET         = 3      # below this → low difficulty; trigger fragmentation fix
BFS_STEPS                   = 5000   # steps per BFS evaluation episode
BFS_NUM_AGENTS              = 3      # parallel BFS agents per scenario
BFS_EPISODES                = 3      # episodes per scenario
REPLACEMENT_MAX_ATTEMPTS    = 3      # max seed-replacement attempts before giving up
```

**Impact:**
- `pipeline/constants.py` — create file
- `pipeline/run.py`, `pipeline/phase2/02_test_env_integration.py`, `pipeline/phase1/_05_apply_critic_fixes.py` — import from constants instead of inline values

**Status:** DONE — `pipeline/constants.py` created; all callers import from it.

---

### D-P6 — Phase 1 / Phase 2 boundary clarified; actor-critic files moved

**Decision:**
- **Phase 1** = static soundness (schema, CVE catalog, zone coverage, agent-category allowlist)
- **Phase 2** = dynamic quality (BFS solvability, LLM critic score, actor repair)

`_04_quality_evaluator.py` and `_05_apply_critic_fixes.py` move from `pipeline/phase1/` to `pipeline/phase2/`. Update `CLAUDE.md` accordingly.

**Impact:**
- Move files; update all imports in `run.py`
- Update `CLAUDE.md` phase description

**Status:** DONE — both files moved to `pipeline/phase2/`; `pipeline/quality_evaluator.py` shim created; `pipeline/phase1/quality_evaluator.py` re-pointed; `run.py` `_repair()` updated; `CLAUDE.md` updated.

---

### D-P7 — Pipeline step numbers renumbered sequentially

**Decision:** The gap `2 → 4` in `run.py` is a vestigial artifact. Renumber all steps sequentially: 1, 1b, 2, 3, 4, 5, 6, 7 → 1, 2, 3, 4, 5, 6, 7. Update docstring and log headers.

**Impact:**
- `pipeline/run.py` — renumber step methods and docstring

**Status:** DONE — `step4/5/6/7` → `step3/4/5/6`; `_header` calls updated; `STEP 8` → `STEP 7`; `--skip-exec-report` help updated.

---

## Implementation Order

Work can proceed in two parallel tracks:

**Track A — Agent spec updates (no code)** ⏳ PENDING

| Order | Decision | Status | Files |
|-------|----------|--------|-------|
| 1 | D-A3 (clarify CBS mechanics in all specs) | ✅ Done | `README.md` (agents), `meta_agent.md` |
| 2 | D-A1 (S_Lateral action table update) | ✅ Done | `README.md` (agents), `s_lateral.md`, `s_windows.md` |
| 3 | D-A2 (standalone training flow update) | ✅ Done | `s_lateral.md`, `slat_ntlm_relay_v1.md`, `slat_winrm_creds_v1.md`, `slat_adcs_cert_v1.md`, `slat_cloud_to_corp_v1.md` |
| 4 | D-A4 (duplicate swing techniques in catalog) | ✅ Done | `vulnerability_catalog.md` |
| 5 | D-A6 (verify CloudIAM_LDAP_Write + CloudFederated) | ⏳ Pending | manual check only |

**Track B — Pipeline code changes** ✅ COMPLETE

| Order | Decision | Status | Files |
|-------|----------|--------|-------|
| 1 | D-P5 (constants.py) | ✅ Done | `pipeline/constants.py` + callers |
| 2 | D-P6 (move _04/_05 to phase2/) | ✅ Done | file move + shims + `run.py` + `CLAUDE.md` |
| 3 | D-P7 (renumber steps) | ✅ Done | `pipeline/run.py` |
| 4 | D-A5 (allowlist in config_checker) | ✅ Done | `pipeline/phase1/02_config_checker.py` |
| 5 | D-P2 (re-validate after repair) | ✅ Done | `pipeline/phase2/_05_apply_critic_fixes.py` |
| 6 | D-P1 (agent-type filter in BFS evaluator) | ✅ Done | `pipeline/phase2/02_test_env_integration.py`, `pipeline/run.py` |
| 7 | D-P3 (template_alignment → rule count) | ✅ Done | `pipeline/phase2/_04_quality_evaluator.py` |
| 8 | D-P4 (diameter penalty in repair prompt) | ✅ Done | `pipeline/phase2/_05_apply_critic_fixes.py` |
