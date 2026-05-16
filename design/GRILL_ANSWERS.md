# Design Grill — Answers

**Date:** 2026-05-16  
**Companion file:** `GRILL_QUESTIONS.md`

---

## Part 1 — Agent Architecture & Scenario Design

---

### Q1 — Which agent owns cross-zone credential propagation now that S_Recon is gone?

> *Full question in GRILL_QUESTIONS.md §Q1*

**Answer:**
There is a documented ownership gap. While `S_Lateral` is the "Lateral Movement Specialist," its spec explicitly states it **receives** credentials from prior specialists and does not perform extraction. `S_Recon` previously owned the `credential_leak` and `discovery` categories, as well as the `LEAK_KNOWN_CREDENTIALS` relation.

With `S_Recon` gone:
1.  **Credential Extraction:** Specialists like `S_Linux` or `S_Windows` must now own the `credential_leak` solvability entries (e.g., `Mimikatz`, `EnvCredLeak`) to put credentials into the store.
2.  **Propagation (Relation):** `LEAK_KNOWN_CREDENTIALS` (the CBS relation that probabilisticly leaks a target node's credential from a source) is currently "orphaned."
3.  **The Fix:** `S_Lateral` should be updated to own the **execution** of `LEAK_KNOWN_CREDENTIALS` actions. In the `specialist_agent_spec.md`, we must transfer the `LEAK_KNOWN_CREDENTIALS` trigger and action category to `S_Lateral`. Currently, `S_Lateral` only owns `lateral_movement` solvability entries, but "Credential Propagation" via CBS relations is a distinct mechanic that fits its role as the "credential-user" agent.

---

### Q2 — What decision complexity does S_Lateral have that S_Recon lacked?

> *Full question in GRILL_QUESTIONS.md §Q2*

**Answer:**
`S_Recon` was indeed largely deterministic: if a node was discovered, run discovery; if a node was owned, dump LSASS. `S_Lateral` introduces a **multi-dimensional matching problem**:

-   **Credential Type vs. Technique:** The agent must match the *type* of stolen credential (NTLM Hash, Kerberos TGT, or Plaintext) to the correct technique. A Kerberos TGT enables `WinRM_Exec_Ticket` (PtT), whereas an NTLM hash requires `WinRM_Exec_Hash` (PtH) or `NTLM_Relay_SMB`.
-   **Target Properties vs. Technique:** The agent must recognize that `ShadowCredentials` requires `GenericWrite` permissions on an AD object, whereas `ADCS_ESC1` requires enrollment rights on a specific template.
-   **Path Selection:** In a complex topology, multiple relay paths may exist. `S_Lateral` must learn to sequence these, especially when some nodes are `Patched` (reducing SR) or have different firewall restrictions (ports 445 vs 5985).

Unlike `S_Recon`, which just "dumped everything," `S_Lateral` must solve the "What do I have, and where can it actually go?" puzzle.
---

### Q3 — What is the hard partition rule between S_Identity and S_Lateral?

> *Full question in GRILL_QUESTIONS.md §Q3*

**Answer:**
The partition is defined by **Category Ownership** and **Narrative Intent**:

-   **Category Ownership:** The `lateral_movement` category in `vulnerability_catalog.md` is owned **exclusively** by `S_Lateral`. This includes all zone-crossing techniques (Relays, WinRM, Cloud-to-Corp LDAP writes).
-   **S_Identity Ownership:** `S_Identity` owns the `goal_access` category for Active Directory targets (e.g., `DCSync`, `NTDS_Dump`, `GoldenTicket`).
-   **The "Double Entry" Problem:** Techniques like `ADCS_ESC1` or `ShadowCredentials` appear in both agents because they can serve two purposes:
    -   As a **lateral move** (Z1 Workstation → Z1 Domain Controller), they belong to `S_Lateral`.
    -   As a **goal access** (Domain Controller owned → Admin credentials extracted), they belong to `S_Identity`.
-   **Enforcement:** This is enforced in the YAML by the `metadata.agent` field. The generator prompt instructions (in `system_prompt.md`) explicitly forbid `S_Identity` from using `lateral_movement` entries for zone-crossing, limiting it to `goal_access` logic once the DC or high-value AD target is reached.

---

### Q4 — How do you populate the credential store at episode start for S_Lateral standalone training?

> *Full question in GRILL_QUESTIONS.md §Q4*

**Answer:**
CBS does not have a native "start with NTLM hash" schema flag. `S_Lateral` standalone training uses a **"Synthetically Seeded Breach"**:

1.  The scenario designates a `SourceNode` as the breach node (SR 1.0).
2.  This node is assigned a `MUST_HAVE` property (e.g., `PreCompromisedCreds`).
3.  A `solvability_vulnerabilities.credential_leak` entry is created that matches this property with `success_rate: 1.0`.
4.  The agent fires this "trivial leak" in step 1, which populates the `credential_store`.
5.  All subsequent "real" training steps involve using those credentials for lateral movement.

There is no "pre-phase" agent; the specialist itself fires a dummy extraction action to prime its own state for the subsequent lateral movement learning.

---

### Q5 — Does `Solvability.CloudIAM_LDAP_Write` exist in the catalog, and is it mechanically valid?

> *Full question in GRILL_QUESTIONS.md §Q5*

**Answer:**
Yes, it exists in `vulnerability_catalog.md` (Category: `lateral_movement`, line 615).

-   **Validity:** It is a **simplified abstraction** of the "Cloud-to-OnPrem" bridge. In a real environment, this is a multi-step chain (IAM → SAML → Kerberos). CBS cannot model 3-step protocol handshakes as a single atomic action without losing fidelity.
-   **Implementation:** We model it as a `type: LOCAL` exploit on a Cloud node (Z6) that targets an on-prem node (Z1). The "federated identity bridge" is a **Required Property** (`DomainJoined`, `CloudFederated`) on the target. If the target lacks the bridge property, the SR is 0. 
-   **Conclusion:** It is mechanically valid within CBS's "solvability" abstraction, provided the topology includes the bridge property.

---

## Part 2 — Pipeline Design & Components

---

### P1 — How do you detect scenarios that are BFS-solvable but specialist-unsolvable?

> *Full question in GRILL_QUESTIONS.md §P1*

**Answer:**
Currently, we **don't** reliably detect this. `02_test_env_integration.py` uses a `BFSPlannerAgent` with a global view of all vulnerabilities, ignoring the `metadata.agent` restrictions.

**The Solution:** We must update `02_test_env_integration.py` to accept an `--agent-type` flag. When set, the `BFSPlannerAgent` should filter its internal "solvability graph" to only include vulnerabilities owned by that agent (e.g., `S_Windows` can only see `remote_access` and `local_privesc`, never `lateral_movement` relays). If BFS fails with the restricted set but passes with the full set, the scenario is "BFS-solvable but specialist-unsolvable."

---

### P2 — After each repair, is Phase 1 structural validation re-run on the fixed config?

> *Full question in GRILL_QUESTIONS.md §P2*

**Answer:**

**Actual `run.py` flow after repair:**

```
step1_phase1_validate()        # once at startup
step1b_zone_coverage_validate()
step2_phase1_report()
step4_phase2_generate()
step5 → _repair() → _advance_config(fixed) → step4_phase2_generate()   # no step1 repeat
```

`_05_apply_critic_fixes.py` re-scores the fixed YAML via `ScenarioQualityEvaluator` (LLM only). It does **not** invoke `01_template_validator.py`, `02_config_checker.py`, or `03_validate_zone_coverage.py`.

**Risk:** Repair can introduce invalid CVE names, break IDC pairing, or remove nodes required for solvability — and nothing catches it until a human notices or runtime BFS fails silently.

**Fix:** Post-save hook in `_repair()`:

```python
subprocess.run([python, "pipeline/phase1/02_config_checker.py", fixed_path, "--strict"])
subprocess.run([python, "pipeline/phase1/03_validate_zone_coverage.py", fixed_path])
```

Fail the repair round and re-prompt the actor with checker errors if either fails.

---

### P3 — What prevents `template_alignment` from being a systematic overestimate?

> *Full question in GRILL_QUESTIONS.md §P3*

**Answer:**
Nothing currently prevents this "echo chamber" effect. Since Claude-Critic uses the same GLOBALTECH reference as Claude-Generator, it is naturally biased toward accepting the generator's topology.

**Mitigation:** We should move `template_alignment` from a qualitative LLM score to a **quantitative heuristic score**. We already have `03_validate_zone_coverage.py`. We can add more hard-coded rules (e.g., "If Z4 exists, it MUST have a firewall rule to Z2") to the `config_checker`. The "alignment" score should be derived from the number of hard-coded architectural rules passed, not an LLM's subjective opinion.

---

### P4 — What YAML change reliably increases attack path diameter, and does the repair step make it?

> *Full question in GRILL_QUESTIONS.md §P4*

**Answer:**
The most reliable change is **Domain Fragmentation**. By splitting a large "flat" domain into multiple small tiers (DMZ → App → Data) and using `inter_domain_constraints`, you force the agent to traverse multiple "gates."

`_05_apply_critic_fixes.py` **does** include explicit instructions for this:
-   "Split single domain into 2–3 named tiers: DMZTier / AppTier / DataTier"
-   "Add inter_domain_constraints between every adjacent tier pair"
-   "Remove MUST_CONNECT shortcuts between non-adjacent tiers"

However, the LLM often prefers "easier" fixes like changing success rates. We must increase the "penalty" for low diameter in the Critic prompt to force the Actor to adopt the structural "Fragmentation" fix.
---

### P5 — What is the basis for the 40% solve rate threshold?

> *Full question in GRILL_QUESTIONS.md §P5*

**Answer:**
The 40% threshold is an **empirical heuristic** based on observations of "Bad Seed" vs. "Broken Design" scenarios:
-   **< 40%:** The scenario is usually structurally unsolvable (e.g., a missing firewall rule or a goal node with zero matching CVEs). Seed replacement won't fix this; the YAML needs repair.
-   **≥ 40%:** The design is likely sound, but the stochastic nature of CBS (SR 0.55 exploits failing 10 times in a row) caused some scenarios to fail. In this case, we keep the YAML and just try new random seeds (`_replace_unsolved_scenarios`).

It’s a "confidence threshold" for the YAML's structural integrity.
**action** create a constants file in python where you will put all the existign hard coded magic numebrs and add a description to each
---

### P6 — What is the intended contract of Phase 1 vs Phase 2?

> *Full question in GRILL_QUESTIONS.md §P6*

**Answer:**
The documentation is indeed blurred. The intended contract should be:
-   **Phase 1:** Static validation (Schema, Identifiers, Zone Coverage).
-   **Phase 2:** Runtime validation (BFS Solvability, Metrics, Actor-Critic).

The confusion arises because `_04_quality_evaluator.py` and `_05_apply_critic_fixes.py` are stored in `pipeline/phase1/`. This is a legacy of an earlier design where "Quality" was checked statically. Now that Quality depends on BFS metrics, **these files belong in `pipeline/phase2/`**. 

**Action:** Move `_04` and `_05` to `phase2/` and update `CLAUDE.md` to reflect that Phase 1 is for "Static Soundness" and Phase 2 is for "Dynamic Quality."

---

### P7 — What was step 3?

> *Full question in GRILL_QUESTIONS.md §P7*

**Answer:**
Step 3 was the **`03_validate_zone_coverage.py`** step. It was originally a standalone step in the numbering, but it was integrated as a "Phase 1.5" gate (`step1b_zone_coverage_validate`) to ensure it runs before the Phase 1 report is finalized. 

The gap in `run.py` (2 → 4) is a vestigial artifact of this refactoring. It should be renumbered for clarity.

---

## Summary — Decisions Made

| # | Question | Decision | Action |
|---|----------|----------|--------|
| Q1 | Cross-zone credential propagation owner | S_Lateral owns LEAK_KNOWN_CREDENTIALS execution; surface specialists own credential_leak extraction | Update `specialist_agent_spec.md` Agent 5 (S_Lateral) action table; update meta-agent routing table |
| Q2 | S_Lateral decision complexity | Genuine: credential-type × target-property matching is non-trivial | No change needed — design is sound |
| Q3 | S_Identity / S_Lateral partition | `lateral_movement` category → S_Lateral only; `goal_access` → S_Identity only; double-entry techniques enforced via `metadata.agent` + validator | Add explicit agent-ownership check to `02_config_checker.py`; document in `system_prompt.md` |
| Q4 | Credential store pre-population | Synthetically seeded breach: SR 1.0 dummy `credential_leak` entry on breach node primes the store | Document in `s_lateral.md` standalone training section; add to YAML schema examples |
| Q5 | CloudIAM_LDAP_Write validity | Valid CBS abstraction IF `CloudFederated` property exists in allowed_properties; verify catalog entry and property token | Verify `CloudIAM_LDAP_Write` exists in `vulnerability_catalog.md` and `CloudFederated` is in `allowed_properties.md` |
| P1 | BFS vs specialist solvability | BFS does not enforce agent action-space restrictions — gap confirmed | Add `--agent-type` flag to `02_test_env_integration.py`; filter vulnerability graph per agent |
| P2 | Phase 1 re-validation after repair | Phase 1 validators NOT re-run after repair — known risk | Add post-repair hook: run `02_config_checker.py --strict` + `03_validate_zone_coverage.py` on fixed config; abort round on failure |
| P3 | template_alignment circularity | Echo-chamber effect confirmed; move to quantitative heuristic | Replace LLM `template_alignment` score with rule count from `config_checker` hard-coded architectural assertions |
| P4 | Difficulty / diameter fix | Domain fragmentation is the correct structural fix; already in Actor prompt but LLM prefers SR tweaks | Increase diameter penalty weight in Critic prompt; add explicit `min_domains: 2` assertion to repair instructions |
| P5 | 40% threshold basis | Empirical heuristic — accepted | Create `pipeline/constants.py` with all magic numbers + descriptions (40% threshold, min_solve_rate 0.75, max_bfs_rounds 2, etc.) |
| P6 | Phase 1 vs Phase 2 contract | Phase 1 = static soundness; Phase 2 = dynamic quality | Move `_04_quality_evaluator.py` + `_05_apply_critic_fixes.py` to `pipeline/phase2/`; update `CLAUDE.md` |
| P7 | Missing step 3 | Vestigial gap from zone-coverage step being absorbed into step 1b | Renumber pipeline steps sequentially in `run.py` and docstring |
