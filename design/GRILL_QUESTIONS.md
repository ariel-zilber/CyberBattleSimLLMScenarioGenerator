# Design Grill — Questions

**Date:** 2026-05-16  
**Scope:** Agent architecture, scenario design, and pipeline components  
**Companion file:** `GRILL_ANSWERS.md`

---

## Part 1 — Agent Architecture & Scenario Design

---

### Q1 — The orphaned credential propagation problem

The meta-agent routing table lists this trigger:

> "Credential store stale (no new creds in N steps) → Call S_Recon"

S_Recon is gone. S_Lateral is not a substitute — S_Lateral does *relay and exec*, not credential *extraction and propagation*. Concretely:

- In M-ST1-01, after S_Network extracts `SNMP_CommunityDump` creds from Z4, something must propagate those creds to bridge into Z2 and then into Z1. Who does that now?
- In M-ST3-01, step 7 is `Mimikatz_LSASS + BloodHound_Recon`. Whose action is that?
- In M-ST2-02, `Cloud_CredFile` LEAK propagates from `AWSAppServer` to `AdminWorkstation`. Whose action is that?

Every one of these is still labeled **S_Recon** in `specialist_agent_spec.md`. No other specialist currently holds `LEAK_KNOWN_CREDENTIALS`.

**Which agent owns cross-zone credential propagation now that S_Recon is gone, and where in the spec is that defined?**

---

### Q2 — S_Lateral's policy may still be deterministic

The thesis for killing S_Recon was that its policy was deterministic once credentials exist — you run LSASS and DNS zone transfer on every reachable node. S_Lateral was supposed to fix this.

But in S-LAT-01:
- Agent has NTLM hash from breach node
- Tries `NTLM_Relay_SMB` (SR 0.72) and `WinRM_Exec_Hash` (SR 0.75) on each target
- 40% of Z1 targets are patched → agent skips them

That reduces to: sort unpatched targets by SR, try highest first. The only genuine decision is *which targets* to attempt when steps are limited — but that's driven entirely by the observable `patched` property flag.

**What decision complexity does S_Lateral have that S_Recon lacked? Give one concrete example where two agents would make different choices on the same game state and explain why one choice is better.**

---

### Q3 — S_Identity and S_Lateral share the same techniques

Both agents currently own overlapping techniques:

| Technique | S_Identity | S_Lateral |
|-----------|-----------|-----------|
| NTLM relay to LDAP | `NTLM_Relay_LDAP` | `ldap` category |
| Shadow Credentials | `ShadowCredentials` | `ShadowCredentials` |
| ADCS ESC1 | `ADCS_ESC1` | `ADCS_ESC1` |
| ADCS ESC6 | `ADCS_ESC6` | `ADCS_ESC6` |
| Pass-the-Hash | `PassTheHash` | `credential` category |

In the meta-agent, both S_Identity and S_Lateral would be valid choices when the observation shows "Z1 owned node + NTLM hash in credential store." The meta-agent has no signal to distinguish which to call.

**What is the hard partition rule between these two agents? How is it enforced in the CBS YAML so the same CVE anchor cannot appear in both agents' configs?**

---

### Q4 — S_Lateral standalone training requires a pre-populated credential store

S-LAT-01 says the breach node is `CiscoEdgeRouter (Z2, pre-owned)` and "credential store contains NTLM hash + Kerberos ticket."

In CBS YAML, a breach node is a node with a SR 1.0 trivial probe. The credential store starts empty. There is no schema mechanism to pre-populate it with hashes before episode start. S_Recon's `LSASS dump` or `WinRM_Credential_Cache` actions were what put hashes into the store — but S_Recon is gone and S_Lateral can't extract credentials, only use them.

**How do you populate the credential store at episode start for S_Lateral standalone training? Is there a CBS schema mechanism for that, or does S_Lateral standalone training require a pre-phase where another agent runs first?**

---

### Q5 — S-LAT-02 uses a technique that likely does not exist in the catalog

S-LAT-02 (`slat_cloud_to_corp_v1`) task spec says:

> "Verify techniques present: `Solvability.CloudIAM_LDAP_Write` (SR 0.65)"

An AWS IAM token cannot directly write LDAP attributes to on-prem Active Directory without:
1. IAM → SAML assertion
2. SAML → Kerberos TGT (Seamless SSO)
3. TGT → LDAP bind with write permission

That is a three-step protocol chain that CBS cannot model as a single solvability entry. And `CloudIAM_LDAP_Write` does not appear to exist in `vulnerability_catalog.md`.

**Does `Solvability.CloudIAM_LDAP_Write` exist in `vulnerability_catalog.md`? If not, the pipeline validator will reject any config using it. And even if it does exist as a catalog entry, how is a single AWS IAM credential a valid authenticator for on-prem LDAP without a federated identity bridge?**

---

## Part 2 — Pipeline Design & Components

---

### P1 — BFS solvability is not the same as DRL solvability

Phase 2 uses `02_test_env_integration.py` — a heuristic BFS agent — to validate scenario solvability. The BFS agent tries **every vulnerability on every reachable node** with no action space restriction.

Your actual DRL specialists have restricted action spaces:
- S_Network only fires network CVEs
- S_Linux only fires Bitnami CVEs
- S_Lateral only fires `lateral_movement` solvability entries

A scenario where BFS solves in 50 steps by freely chaining `BlueKeep → DCSync → LSASS` will show 100% solve rate — but when S_Windows runs with only OS-level RCEs and no credential propagation, the same scenario may be completely unsolvable.

**You're validating reachability of the goal node, not solvability by the intended agent. How do you detect scenarios that are BFS-solvable but specialist-unsolvable?**

---

### P2 — The actor repair loop can break Phase 1 constraints without re-checking them

The flow in `run.py`:

```
step1_phase1_validate()      ← checks schema, CVE anchors, BFS
step1b_zone_coverage_validate()
step2_phase1_report()
step4_phase2_generate()
step5_phase2_evaluate()      ← actor-critic loop starts here
    → _llm_evaluate()
    → _repair()              ← LLM edits the YAML
    → _advance_config(fixed)
    → step4_phase2_generate(next round)
    # ← Phase 1 is NOT re-run after repair
```

If the repair LLM introduces a new CVE anchor that does not exist in `vulnerability_catalog.md`, or removes a node required for BFS solvability, the schema and catalog validators in Phase 1 will never catch it — Phase 1 only runs once at startup.

**After each repair, is Phase 1 structural validation re-run on the fixed config? If not, what prevents the repaired config from violating constraints that were checked initially?**

---

### P3 — The quality evaluator grades LLM output using LLM-derived criteria

The 7th quality dimension is `template_alignment` — GLOBALTECH Template Alignment. The evaluator injects `_GLOBALTECH_ZONE_CONTEXT` into the LLM prompt and asks Claude to assess whether the YAML aligns with GLOBALTECH architecture.

The YAML being evaluated was itself generated by Claude using the same GLOBALTECH spec. The evaluator is asking Claude to assess whether Claude's output matches Claude's own reference material. There is no independent ground truth. The LLM will systematically overrate configs it generated because its internal representation of "correct GLOBALTECH topology" is the same one it used to generate the YAML.

**What prevents `template_alignment` from being a systematic overestimate? Is there any component of the quality score that is NOT derived from LLM self-assessment?**

---

### P4 — `scenario_difficulty` consistently scores 3–6/10 and the actor-critic loop cannot structurally fix it

The pipeline report explicitly states:

> "Consistent weakness: `scenario_difficulty` is low across all configs (3–6/10). All scenarios produce shallow attack graphs (diameter 2–3)."

The actor-critic repair loop calls the LLM with current quality scores and asks it to produce YAML edits. But graph diameter is determined by how many domains exist and how inter-domain constraints chain them — not by individual node or vulnerability settings. Adding a third domain changes the agent scope (S_Network becomes required where it wasn't). The quality evaluator does not detect scope changes.

**What change to the YAML actually increases attack path diameter in a reliable, predictable way — and does the current repair prompt instruct the LLM to make that specific change?**

---

### P5 — The 40% solve rate threshold is a magic number

In `step5_phase2_evaluate`:

```python
if loop_mode and 0.40 <= _sr_quick < self.min_solve_rate:
    # Assume YAML is sound — replace unsolved scenarios (bad seeds)
else:
    # Assume YAML is broken — invoke LLM repair
```

Below 40%, the pipeline assumes the YAML is broken and calls the LLM to repair. At ≥40%, it assumes the problem is random seed variance and replaces unsolved scenarios. But:

- A config with 38% solve rate might be structurally valid but genuinely hard
- A config with 55% solve rate might have a reachability gap that seed replacement will never fix

The distinction between "broken YAML" and "hard scenario with bad seeds" is not captured by solve rate alone.

**What is the basis for the 40% threshold? How does the pipeline distinguish a hard-but-valid scenario from a scenario with a structural reachability gap?**

---

### P6 — Phase 1 and Phase 2 have blurred responsibility boundaries

Directory structure:

```
pipeline/phase1/
  01_template_validator.py
  02_config_checker.py
  03_validate_zone_coverage.py
  _04_quality_evaluator.py      ← called from Phase 2 loop
  _05_apply_critic_fixes.py     ← called from Phase 2 loop
```

`_04` and `_05` live in `phase1/` but are invoked during Phase 2 by `run.py`. The quality evaluator consumes BFS runtime metrics — a Phase 2 artifact. The repair step uses those metrics to edit the YAML.

`run.py` documents Phase 1 as "format validation only." `CLAUDE.md` documents Phase 1 as "validation + actor-critic loop." These are contradictory.

**What is the intended contract of Phase 1 vs Phase 2? Is Phase 1 "format validation only" or "validation + actor-critic"? Why do the actor and critic live in `phase1/` if they operate on Phase 2 runtime data?**

---

### P7 — Step 3 is missing from the pipeline

`run.py` main `run()` sequences: step 1 → step 1b → step 2 → step 4 → step 5 → step 6 → step 7.

Step 3 does not exist. The step numbering skips directly from 2 to 4.

**What was step 3? Is its absence intentional, or is there a preprocessing step that should exist between the Phase 1 report and Phase 2 scenario generation?**

---

*Total: 5 agent/scenario questions (Q1–Q5) + 7 pipeline questions (P1–P7) = 12 questions*
