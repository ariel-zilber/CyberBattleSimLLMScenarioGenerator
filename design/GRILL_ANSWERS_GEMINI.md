# Design Grill — Answers (Gemini Edition)

**Date:** 2026-05-16  
**Agent:** Gemini CLI  
**Scope:** Agent architecture, scenario design, and pipeline components  
**Companion file:** `GRILL_QUESTIONS.md`

---

## Part 1 — Agent Architecture & Scenario Design

---

### Q1 — Which agent owns cross-zone credential propagation now that S_Recon is gone?

**Answer:**
There is a documented ownership gap. While `S_Lateral` is the "Lateral Movement Specialist," its spec explicitly states it **receives** credentials from prior specialists and does not perform extraction. `S_Recon` previously owned the `credential_leak` and `discovery` categories, as well as the `LEAK_KNOWN_CREDENTIALS` relation.

With `S_Recon` gone:
1.  **Credential Extraction:** Specialists like `S_Linux` or `S_Windows` must now own the `credential_leak` solvability entries (e.g., `Mimikatz`, `EnvCredLeak`) to put credentials into the store.
2.  **Propagation (Relation):** `LEAK_KNOWN_CREDENTIALS` (the CBS relation that probabilisticly leaks a target node's credential from a source) is currently "orphaned."
3.  **The Fix:** `S_Lateral` should be updated to own the **execution** of `LEAK_KNOWN_CREDENTIALS` actions. In the `specialist_agent_spec.md`, we must transfer the `LEAK_KNOWN_CREDENTIALS` trigger and action category to `S_Lateral`. Currently, `S_Lateral` only owns `lateral_movement` solvability entries, but "Credential Propagation" via CBS relations is a distinct mechanic that fits its role as the "credential-user" agent.

---

### Q2 — What decision complexity does S_Lateral have that S_Recon lacked?

**Answer:**
`S_Recon` was indeed largely deterministic: if a node was discovered, run discovery; if a node was owned, dump LSASS. `S_Lateral` introduces a **multi-dimensional matching problem**:

-   **Credential Type vs. Technique:** The agent must match the *type* of stolen credential (NTLM Hash, Kerberos TGT, or Plaintext) to the correct technique. A Kerberos TGT enables `WinRM_Exec_Ticket` (PtT), whereas an NTLM hash requires `WinRM_Exec_Hash` (PtH) or `NTLM_Relay_SMB`.
-   **Target Properties vs. Technique:** The agent must recognize that `ShadowCredentials` requires `GenericWrite` permissions on an AD object, whereas `ADCS_ESC1` requires enrollment rights on a specific template.
-   **Path Selection:** In a complex topology, multiple relay paths may exist. `S_Lateral` must learn to sequence these, especially when some nodes are `Patched` (reducing SR) or have different firewall restrictions (ports 445 vs 5985).

Unlike `S_Recon`, which just "dumped everything," `S_Lateral` must solve the "What do I have, and where can it actually go?" puzzle.

---

### Q3 — What is the hard partition rule between S_Identity and S_Lateral?

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

**Answer:**
Yes, it exists in `vulnerability_catalog.md` (Category: `lateral_movement`, line 615).

-   **Validity:** It is a **simplified abstraction** of the "Cloud-to-OnPrem" bridge. In a real environment, this is a multi-step chain (IAM → SAML → Kerberos). CBS cannot model 3-step protocol handshakes as a single atomic action without losing fidelity.
-   **Implementation:** We model it as a `type: LOCAL` exploit on a Cloud node (Z6) that targets an on-prem node (Z1). The "federated identity bridge" is a **Required Property** (`DomainJoined`, `CloudFederated`) on the target. If the target lacks the bridge property, the SR is 0. 
-   **Conclusion:** It is mechanically valid within CBS's "solvability" abstraction, provided the topology includes the bridge property.

---

## Part 2 — Pipeline Design & Components

---

### P1 — How do you detect scenarios that are BFS-solvable but specialist-unsolvable?

**Answer:**
Currently, we **don't** reliably detect this. `02_test_env_integration.py` uses a `BFSPlannerAgent` with a global view of all vulnerabilities, ignoring the `metadata.agent` restrictions.

**The Solution:** We must update `02_test_env_integration.py` to accept an `--agent-type` flag. When set, the `BFSPlannerAgent` should filter its internal "solvability graph" to only include vulnerabilities owned by that agent (e.g., `S_Windows` can only see `remote_access` and `local_privesc`, never `lateral_movement` relays). If BFS fails with the restricted set but passes with the full set, the scenario is "BFS-solvable but specialist-unsolvable."

---

### P2 — After each repair, is Phase 1 structural validation re-run on the fixed config?

**Answer:**
**No.** `run.py` only runs `step1_phase1_validate()` once at the start of the script. The actor-critic loop in `step5_phase2_evaluate()` advances the config and loops back to `step4_phase2_generate()`.

This is a critical flaw. If the repair LLM introduces a schema violation or an invalid property token, the pipeline will crash in Phase 2 or produce garbage results. We must refactor `run.py` to move the Phase 1 validation block **inside** the retry loop.

---

### P3 — What prevents `template_alignment` from being a systematic overestimate?

**Answer:**
Nothing currently prevents this "echo chamber" effect. Since Claude-Critic uses the same GLOBALTECH reference as Claude-Generator, it is naturally biased toward accepting the generator's topology.

**Mitigation:** We should move `template_alignment` from a qualitative LLM score to a **quantitative heuristic score**. We already have `03_validate_zone_coverage.py`. We can add more hard-coded rules (e.g., "If Z4 exists, it MUST have a firewall rule to Z2") to the `config_checker`. The "alignment" score should be derived from the number of hard-coded architectural rules passed, not an LLM's subjective opinion.

---

### P4 — What YAML change reliably increases attack path diameter, and does the repair step make it?

**Answer:**
The most reliable change is **Domain Fragmentation**. By splitting a large "flat" domain into multiple small tiers (DMZ → App → Data) and using `inter_domain_constraints`, you force the agent to traverse multiple "gates."

`_05_apply_critic_fixes.py` **does** include explicit instructions for this:
-   "Split single domain into 2–3 named tiers: DMZTier / AppTier / DataTier"
-   "Add inter_domain_constraints between every adjacent tier pair"
-   "Remove MUST_CONNECT shortcuts between non-adjacent tiers"

However, the LLM often prefers "easier" fixes like changing success rates. We must increase the "penalty" for low diameter in the Critic prompt to force the Actor to adopt the structural "Fragmentation" fix.

---

### P5 — What is the basis for the 40% solve rate threshold?

**Answer:**
The 40% threshold is an **empirical heuristic** based on observations of "Bad Seed" vs. "Broken Design" scenarios:
-   **< 40%:** The scenario is usually structurally unsolvable (e.g., a missing firewall rule or a goal node with zero matching CVEs). Seed replacement won't fix this; the YAML needs repair.
-   **≥ 40%:** The design is likely sound, but the stochastic nature of CBS (SR 0.55 exploits failing 10 times in a row) caused some scenarios to fail. In this case, we keep the YAML and just try new random seeds (`_replace_unsolved_scenarios`).

It’s a "confidence threshold" for the YAML's structural integrity.

---

### P6 — What is the intended contract of Phase 1 vs Phase 2?

**Answer:**
The documentation is indeed blurred. The intended contract should be:
-   **Phase 1:** Static validation (Schema, Identifiers, Zone Coverage).
-   **Phase 2:** Runtime validation (BFS Solvability, Metrics, Actor-Critic).

The confusion arises because `_04_quality_evaluator.py` and `_05_apply_critic_fixes.py` are stored in `pipeline/phase1/`. This is a legacy of an earlier design where "Quality" was checked statically. Now that Quality depends on BFS metrics, **these files belong in `pipeline/phase2/`**. 

**Action:** Move `_04` and `_05` to `phase2/` and update `CLAUDE.md` to reflect that Phase 1 is for "Static Soundness" and Phase 2 is for "Dynamic Quality."

---

### P7 — What was step 3?

**Answer:**
Step 3 was the **`03_validate_zone_coverage.py`** step. It was originally a standalone step in the numbering, but it was integrated as a "Phase 1.5" gate (`step1b_zone_coverage_validate`) to ensure it runs before the Phase 1 report is finalized. 

The gap in `run.py` (2 → 4) is a vestigial artifact of this refactoring. It should be renumbered for clarity.

---

## Summary — Decisions Made

| # | Question | Decision | Action |
|---|----------|----------|--------|
| Q1 | Credential propagation owner | Assign to `S_Lateral` | Update `specialist_agent_spec.md` |
| Q2 | S_Lateral decision complexity | Confirmed non-trivial matching | None (documentation only) |
| Q3 | S_Identity / S_Lateral partition | Exclusive `lateral_movement` category | Audit catalog for category overlap |
| Q4 | Credential store pre-population | Use "Synthetic Breach" action | Add example to `S_Lateral` golden YAML |
| Q5 | CloudIAM_LDAP_Write validity | Valid as simplified abstraction | Ensure `CloudFederated` property is in dictionary |
| P1 | BFS vs specialist solvability | Add `--agent-type` to BFS agent | Update `02_test_env_integration.py` |
| P2 | Phase 1 re-validation after repair | Re-validate after every edit | Refactor `run.py` loop |
| P3 | template_alignment circularity | Move to heuristic-based scoring | Update `config_checker.py` with arch rules |
| P4 | Difficulty / diameter fix | Force "Domain Fragmentation" | Update Actor prompt with higher diameter priority |
| P5 | 40% threshold basis | Keep as empirical heuristic | None |
| P6 | Phase 1 vs Phase 2 contract | Phase 1=Static, Phase 2=Dynamic | Move `_04` and `_05` to `phase2/` |
| P7 | Missing step 3 | Renumber steps sequentially | Update `run.py` step labels |
