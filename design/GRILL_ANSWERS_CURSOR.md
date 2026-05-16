# Design Grill — Answers (Cursor Edition)

**Date:** 2026-05-16  
**Agent:** Cursor (codebase-grounded)  
**Scope:** Agent architecture, scenario design, pipeline mechanics  
**Companion file:** `GRILL_QUESTIONS.md`

---

## Part 1 — Agent Architecture & Scenario Design

---

### Q1 — Which agent owns cross-zone credential propagation now that S_Recon is gone?

**Answer: Nobody — this is an undocumented ownership gap.**

**Current state in this repo**

| Mechanism | What it does | Who the specs say owns it |
|-----------|--------------|---------------------------|
| `credential_leak` solvability | Puts credentials into the CBS credential store from an owned node | Was **S_Recon**; still referenced as forbidden for S_Network/S_Linux (`prompts/reference/agents/s_network.md`, `s_linux.md`) |
| `LEAK_KNOWN_CREDENTIALS` / `CLIENT_OF` constraints | Probabilistic cross-node credential bridge when source is owned | Was **S_Recon**; **not assigned** to any surviving specialist |
| `KNOWS` constraints | Discovers target node IDs | Was **S_Recon**; orphaned |

`S_Lateral` explicitly disclaims both extraction and propagation:

```7:8:prompts/reference/agents/s_lateral.md
**Scope:** S_Lateral specializes in **authenticated lateral movement after credential theft**. Given a compromised node with credentials in cache, it selects the correct relay or remote-execution technique to cross a zone boundary. It does not exploit OS memory corruption bugs, does not probe services, and does not perform credential extraction — it receives credentials from prior specialists and decides how to use them.
```

The meta-agent spec still routes stale-credential and stagnation events to **S_Recon**:

```20:21:prompts/reference/agents/meta_agent.md
| Credential store monitoring | Credential store stale (no new creds in N steps) | Call S_Recon |
| Stagnation recovery | Specialist fails K consecutive actions | Call S_Recon |
```

CBS still processes `LEAK_KNOWN_CREDENTIALS` in `cbsim/components/constraint_engine.py`, and golden YAMLs / `srec_recon_standalone_v1.yaml` still define those edges — but no agent prompt says "you generate this."

**Concrete grill examples (today)**

| Scenario step | CBS mechanism | Who should own it (today) |
|---------------|---------------|---------------------------|
| M-ST1-01: SNMP creds Z4 → Z2 → Z1 | `credential_leak` on Z4 device + `LEAK_KNOWN_CREDENTIALS` IDC edges | **Gap** — S_Network extracts SNMP; nothing owns propagation |
| M-ST3-01 step 7: Mimikatz + BloodHound | `credential_leak` + `discovery` | **Gap** — was S_Recon |
| M-ST2-02: `Cloud_CredFile` AWS → AdminWorkstation | S_Linux `credential_leak` + `LEAK_KNOWN_CREDENTIALS` | **Split** — extraction = S_Linux (`s_linux.md` boundary rule); propagation = **orphaned** |

**Recommended resolution (two-layer model)**

1. **Extraction** (`credential_leak`, LSASS, env creds, SNMP walk): assign to the **surface specialist that owns the source zone** — S_Network (Z4/Z2), S_Linux (Z6), S_Windows (Z1 VLAN foothold).
2. **Propagation** (`LEAK_KNOWN_CREDENTIALS`, `KNOWS`): assign to **Meta configs only** for full-chain training, *or* document as **YAML topology mechanics** (not a specialist DRL action) that fire automatically when the source node is owned.
3. **Meta routing**: replace `Call S_Recon` with `Call S_Lateral` when creds exist but no new zone progress, *or* call the surface agent that owns the frontier zone — and add an explicit observation flag (`credential_store_stale: bool`).

**Where to define it:** update `prompts/reference/agents/s_lateral.md`, `meta_agent.md`, and the external `specialist_agent_spec.md` (still lists S_Recon). This repo's `CLAUDE.md` already notes IDC is "required for S_Lateral, S_Identity" but does not say which agent *authors* those constraints.

---

### Q2 — What decision complexity does S_Lateral have that S_Recon lacked?

**Answer: Credential-type × technique × target matching under port/firewall constraints — not "run every dump on every node."**

S_Recon's effective policy was: if node owned → run all `credential_leak` + `discovery` templates matching that node. That is largely **coverage expansion**, not conditional technique selection.

S_Lateral must solve a **constrained assignment problem**:

| Dimension | S_Recon | S_Lateral |
|-----------|---------|-----------|
| Action filter | All leak/discovery templates on owned nodes | Only `lateral_movement` (+ `goal_access` for zone entry) |
| Credential gating | Dump everything | Each technique requires a specific cred type (NTLM hash vs Kerberos TGT vs cert) |
| Target gating | N/A (local dumps) | Target must expose the right service/port (445 SMB, 5985 WinRM, 389 LDAP) and not be blocked |
| Patch awareness | Minimal | `match_properties` like `Unpatched`, `PrintSpooler` — patched targets are dead ends |

**Concrete diverging-choice example**

**Game state:** Own `CiscoEdgeRouter` (Z2). Credential cache: `{NTLM_Hash: edge-admin, Kerberos_TGT: none}`. Discovered-not-owned: `SalesWorkstation` (WinRM 5985 open, unpatched), `FileServer` (`Patched`, SMB signing enforced), `PrintServer` (`PrintSpooler`, unpatched).

| Agent | Likely next action | Why |
|-------|-------------------|-----|
| S_Recon (old) | `Mimikatz_LSASS` on `CiscoEdgeRouter` again, then `BloodHound_Recon` on every owned Z1 node when reached | No technique–credential matching; maximizes store size |
| S_Lateral | `Solvability.NTLM_Relay_SMB` or `WinRM_Exec_Hash` toward `SalesWorkstation`; **skip** `FileServer` | PtH/relay requires NTLM hash + reachable SMB/WinRM; patched/signing blocks relay to FileServer |

**Why S_Lateral's choice is better:** With a 500-step budget, re-dumping LSASS on an already-owned router wastes steps; relaying the *existing* hash to an unpatched workstation is the shortest path to Z1 foothold. S_Recon would eventually succeed but with lower sample efficiency — exactly why S_Recon was removed as a specialist.

**Caveat:** If the only observable difference is a binary `patched` flag and targets are sorted by SR, the policy can still collapse to a greedy heuristic (as S-LAT-01 warns). True DRL value appears when **multiple cred types** and **competing paths** (relay vs WinRM vs ADCS cert) exist with different costs and firewall blocks.

---

### Q3 — What is the hard partition rule between S_Identity and S_Lateral?

**Answer: Partition by solvability category and episode intent, not by CVE string alone.**

**Hard rules (from `vulnerability_catalog.md`)**

```626:628:prompts/reference/vulnerability_catalog.md
> **Agent ownership:** All `lateral_movement` solvability entries are exclusively owned by **S_Lateral**.
> S_Windows may not reference these. S_Identity may share `ADCS_ESC1` / `ADCS_ESC8` for goal_access
> only — not for zone-crossing lateral movement.
```

| Namespace | Category | Agent | Changes game state by |
|-----------|----------|-------|------------------------|
| Lateral movement | `lateral_movement` | **S_Lateral only** | Owning a *new* node / crossing a zone |
| AD goal abuse | `goal_access` | **S_Identity only** | Privilege or credential store on nodes already in scope (DCSync, Golden Ticket) |
| OS RCE | `remote_access` (non-AD) | **S_Windows** | Initial Z1 foothold |

**Overlapping names (ShadowCredentials, NTLM_Relay_LDAP, ADCS_ESC1, PassTheHash)**

The same *technique name* may appear in both agents' catalogs, but they must land in **different YAML categories**:

- In `slat_*.yaml`: under `solvability_vulnerabilities.lateral_movement` → zone crossing / new node ownership.
- In `sid_*.yaml`: under `goal_access` or `remote_access` → privilege escalation or DC compromise on the AD layer.

Use `goal_category` on `goal_access` entries (`dump`, `privesc`, `persistence`) to signal Identity intent:

```250:250:prompts/schema/definition.md
| `goal_category` | String | Optional | For `goal_access` vulns: `dump`, `privesc`, `ransomware`, or `persistence` |
```

**YAML enforcement today**

- `02_config_checker.py` validates catalog names, attack_flow depth, and IDC pairing — it does **not** reject the same solvability name in two configs.
- Enforcement is by **convention**: one config file per `metadata.agent`, and the generator only emits vulnerabilities listed in that agent's config.
- **Gap:** the meta-agent has no routing signal when both agents could apply (Z1 owned + NTLM hash in store). Needs an explicit observation such as `domain_foothold`, `frontier_zone`, or `goal_distance_to_dc`.

---

### Q4 — How do you populate the credential store at episode start for S_Lateral standalone training?

**Answer: There is no CBS schema field to pre-seed the credential store. Standalone S_Lateral configs must bootstrap creds via a step-0/1 solvability action on the breach node.**

**What exists today**

- `breach_node` in `identifiers.base_properties` marks the start node (`memory/project_cbs_architecture.md`).
- `Solvability.BreachNode_Entry` (SR 1.0) **owns** the node but does **not** fill the credential cache — see `sid_ad_standalone_v1.yaml` / `swin_serverfarm_standalone_v1.yaml`.
- The credential store is populated only when a `credential_leak` outcome or `LEAK_KNOWN_CREDENTIALS` constraint fires during the episode.

**S_Lateral's spec forbids `credential_leak`**, so a pure `slat_*.yaml` cannot use the same bootstrap pattern as S_Identity/S_Windows standalones unless the catalog is extended.

**Viable patterns**

| Pattern | How | Trade-off |
|---------|-----|-----------|
| **A. Synthetic bootstrap vuln** | Add `Solvability.Bootstrap_CachedCreds` under `lateral_movement`, type LOCAL, SR 1.0, `match_properties: [breach_node]` — models "cred cache already populated from prior op" | Cleanest for S_Lateral-only training; **not in catalog yet** |
| **B. Handoff config** | Don't train S_Lateral standalone — use `metadata.agent: Meta` or a joint config where S_Windows runs first | Matches real kill chain; not isolated curriculum |
| **C. IDC-only bridge** | `LEAK_KNOWN_CREDENTIALS` from breach group to targets — populates cross-node creds when breach is owned, but may not fill the global cache the way `credential_leak` does | Depends on CBS cred-bank wiring; brittle for standalone |

**Recommendation:** Pattern A — one catalog entry + golden `slat_ntlm_relay_v1.yaml` example showing breach node + bootstrap leak before any relay technique. S-LAT-01's "credential store contains NTLM hash" is a **training narrative**, not something the current schema expresses without a bootstrap action.

**Does standalone require another agent first?** Not if Pattern A is added. With the catalog as-is, yes — either run a surface agent phase or temporarily allow a single `credential_leak` bootstrap on the breach node (violates current `s_lateral.md`).

---

### Q5 — Does `Solvability.CloudIAM_LDAP_Write` exist in the catalog, and is it mechanically valid?

**Answer: Yes, it exists. Mechanical validity is conditional on federated-bridge properties and IDC edges — it is an intentional abstraction, not a literal three-protocol simulation.**

**Catalog entry** (`prompts/reference/vulnerability_catalog.md`, line 615):

| Field | Value |
|-------|-------|
| Name | `Solvability.CloudIAM_LDAP_Write` |
| Description | Cloud IAM token → AD Seamless SSO LDAP write |
| Properties | `Windows`, `DomainController`, `DomainJoined` |
| SR | 0.65 |
| Category | `lateral_movement` (S_Lateral exclusive) |

The pipeline **will not reject** this name — `02_config_checker.py` validates against the catalog.

**Federated-bridge validity in CBS**

CBS does not model SAML → Kerberos → LDAP as three edges. The single solvability entry is a **composite abstraction** of that chain, acceptable if the YAML also provides:

1. **`MUST_CONNECT`** (or `MUST_REACH`) from the Z6 cloud domain to Z1 on LDAP/Kerberos-relevant protocols in `inter_domain_constraints`.
2. **Properties** on the DC or federation hop (e.g. `CloudFederated`, `SeamlessSSO` — must exist in `allowed_properties.md` if used).
3. A **`credential_leak`** on the AWS side that puts an IAM/cloud token into the store before the lateral_movement action is available.

Without (1), `GreedyExplorationAgent` in `02_test_env_integration.py` may find the vuln in the abstract graph while `ImprovedCyberBattleEnv` blocks the network path — classic "solvable in metrics, unreachable in sim."

**S-LAT-02 task spec** is valid to reference this CVE name; the config author must wire the cloud→corp IDC chain, not only the solvability line.

---

## Part 2 — Pipeline Design & Components

---

### P1 — How do you detect scenarios that are BFS-solvable but specialist-unsolvable?

**Answer: This is not implemented. Phase 2 only runs an unrestricted greedy solver over the full vulnerability set.**

`pipeline/phase2/02_test_env_integration.py` uses `GreedyExplorationAgent`, which tries every local/remote/port action on owned/discovered nodes with no filter by `metadata.agent` or solvability category:

```50:66:pipeline/phase2/02_test_env_integration.py
class GreedyExplorationAgent:
    """
    Learnability-proxy solver.
    ...
    If this agent solves the scenario, a DRL agent with proper exploration can learn
    the same policy.
    """
```

`pipeline/phase2/03_evaluator.py` computes **structural** attack-graph metrics from generated node YAML — not specialist-restricted reachability.

**What would be needed**

1. **Agent action mask** derived from `metadata.agent` + `vulnerability_catalog.md` ownership tables (e.g. S_Lateral → only `lateral_movement` names).
2. **Second solver pass** with that mask on the same scenarios.
3. **Metric:** `solvability_gap = full_solve_rate − restricted_solve_rate`; flag if gap > threshold (e.g. 0.5) for the config's declared agent.

Until that exists, a scenario marked 100% solved may still be impossible for `swin_serverfarm_standalone_v1.yaml` (no credential propagation) or `slat_*` (no bootstrap creds).

---

### P2 — After each repair, is Phase 1 structural validation re-run on the fixed config?

**Answer: No. This is a real gap.**

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

**Answer: Nothing in the quality scorer itself — the LLM is the sole judge for all seven dimensions.**

```7:8:pipeline/phase1/_04_quality_evaluator.py
Evaluates 7 dimensions by sending the YAML + optional runtime agent metrics to
Claude. No static rule scoring — the LLM is the sole quality judge.
```

`template_alignment` injects the same `_GLOBALTECH_ZONE_CONTEXT` the generator already used — classic self-assessment circularity.

**Independent (non-LLM) ground truth that already exists**

| Component | What it checks |
|-----------|----------------|
| `01_template_validator.py` | Schema shape, required blocks |
| `02_config_checker.py` | Properties, attack_flow depth, IDC/MUST_CONNECT pairing, CVE catalog names |
| `03_validate_zone_coverage.py` | Domain count, zone groups, forbidden IDC shortcuts vs `data/zone_manifest.yaml` |

These run in Phase 1 but **do not feed** the 7-dimension score.

**Mitigation options**

1. **Demote** `template_alignment` to advisory text; drive the gate from `03_validate_zone_coverage.py` pass/fail counts.
2. **Quantify alignment** as `passed_rules / total_rules` from an expanded manifest (forbidden edges, required device properties per zone) — same pattern as zone coverage.
3. **Keep LLM dimension** but cap its weight when static checks fail (e.g. max 5/10 if any hard gate fails).

**Components of the quality score that are NOT LLM-derived today:** only ancillary telemetry (`cve_metrics` extraction, BFS runtime metrics *fed into* the prompt). The score itself is 100% LLM.

---

### P4 — What YAML change reliably increases attack path diameter, and does the repair step make it?

**Answer: Insert intermediate domains/groups into the attack_flow and IDC chain; remove shortcut `MUST_CONNECT` edges. The repair prompt does instruct this; LLM compliance is not guaranteed.**

**Reliable structural changes** (validated by `02_config_checker.py` attack-flow BFS — depth < 2 is an error):

1. **Break direct shortcuts:** remove `MUST_CONNECT` from tier A → tier C; add A → B → C with distinct groups and protocols.
2. **Enforce attack_flow depth ≥ 3:** entry service → intermediate service(s) → goal service (see `memory/project_cbs_architecture.md`).
3. **Reduce credential graph density** — high `LEAK_KNOWN_CREDENTIALS` coverage creates de facto diameter-1 cred jumps; lowering `node_probability` / `target_coverage` forces more hops.

**Repair tooling** (`_05_apply_critic_fixes.py`, `_build_runtime_repair_rules`) **does** emit mandatory diameter fixes when `mean_diameter ≤ 2`:

- Remove non-adjacent-tier shortcuts.
- Add tier-separating constraints (DMZ → App → Core pattern).
- Tie density reduction to diameter increase.

So the **prompt instructs the right edit**; the actor-critic loop does not *structurally guarantee* it because the LLM may patch node-level SR values instead of topology.

**Known blind spot:** adding a third domain can change which specialists are required (scope creep); the quality evaluator does not detect agent-scope changes.

---

### P5 — What is the basis for the 40% solve rate threshold?

**Answer: It is an engineering heuristic, not a derived statistical bound. The pipeline cannot reliably separate "hard but valid" from "structurally broken."**

```741:744:pipeline/run.py
            if loop_mode and 0.40 <= _sr_quick < self.min_solve_rate:
                self._log(
                    f"\n  Solve rate {_sr_quick:.0%} ≥ 40% — YAML design is sound. "
                    f"Replacing unsolved scenarios instead of LLM repair ..."
```

| Solve rate | Pipeline assumption | Action |
|------------|---------------------|--------|
| ≥ `min_solve_rate` (default 75%) | Converged | Stop or continue on quality score |
| 40% – 75% | YAML OK, bad seeds | `_replace_unsolved_scenarios()` |
| < 40% | YAML broken | LLM repair via `_05_apply_critic_fixes.py` |

**Problems**

- 38% solve rate might be a **hard but valid** scenario (low SR chain).
- 55% might still have a **reachability gap** seed replacement will never fix.
- No check of **variance across seeds**, **stratum**, or **credential-bootstrap failures**.

**Better discrimination (not implemented)**

- Compare solve rate across strata; high variance → seed issue, consistently zero → structural.
- Run specialist-restricted solver (P1) alongside full solver.
- Require minimum cred-discovery rate in `run_metrics.json` before blaming seeds.

The 40% cutoff is a **pragmatic default** to avoid expensive LLM repair when some scenarios already solve — not a 3-sigma stochastic bound.

---

### P6 — What is the intended contract of Phase 1 vs Phase 2?

**Answer: `run.py` is authoritative — Phase 1 is static validation; Phase 2 is generation + runtime evaluation + actor-critic. `_04`/`_05` are misplaced legacy paths.**

**`run.py` docstring (intended contract):**

```8:18:pipeline/run.py
Phase 1 — format validation only
  1  Config structural check (schema, identifiers, BFS reachability)
  2  Generate phase1_report.txt

Phase 2 — runtime actor-critic loop
  3  Generate stratified scenarios
  4  BFS heuristic-agent evaluation
  5  LLM quality evaluation (YAML + runtime metrics → 6-dimension score)
     Actor: apply_critic_fixes.repair_config()
     Critic: ScenarioQualityEvaluator.evaluate_with_llm(runtime_metrics)
```

**Actual step numbers in `run()`:** 1 → 1b → 2 → **4** → 5 → 6 → 7 (no step 3).

| Phase | Folder | Responsibility |
|-------|--------|----------------|
| **Phase 1** | `pipeline/phase1/` (steps 1, 1b, 2) | Schema, config checker, zone manifest, phase1 report — **no LLM quality loop** |
| **Phase 2** | `pipeline/phase2/` + misplaced `_04`/`_05` | Scenario generation, `02_test_env_integration.py`, LLM critic, YAML repair |

**Contradiction:** `CLAUDE.md` still describes actor-critic under Phase 1. **`run.py` wins.**

**Why `_04`/`_05` live in `phase1/`:** historical — they were written before Phase 2 was split in `run.py`. They consume Phase 2 artifacts (`run_metrics.json`, `bfs_metrics.json`) and should move to `pipeline/phase2/` for clarity.

---

### P7 — What was step 3?

**Answer: Stale step numbering — not a missing preprocessing stage.**

The `run.py` header comment still labels "Generate stratified scenarios" as **step 3**, but `run()` calls it as **`step4_phase2_generate()`**. Step 3 was dropped when the pipeline was restructured to:

- Run Phase 1 validation and reporting first (steps 1–2).
- Defer scenario generation until after a clean static pass (step 4).

There is **no** intended preprocessing step between `phase1_report.txt` and Phase 2 generation. Optional work that might have been "step 3" in older designs (architecture mapping, config enrichment) is either merged into `01_template_validator.py` / `phase1/pipeline.py` or lives in the separate `data_preprocessing/` one-time flow.

**Action:** Renumber comments and headers to 1 → 1b → 2 → 3 (generate) → 4 (BFS) → 5 (critic loop) → 6 → 7, or update the docstring to match the current 4–7 labels.

---

## Summary — Decisions Made

| # | Question | Decision | Action |
|---|----------|----------|--------|
| Q1 | Credential propagation owner | **Gap** — assign extraction to surface agents; propagation to Meta YAML / IDC spec; update meta routing off S_Recon | Edit `s_lateral.md`, `meta_agent.md`, `specialist_agent_spec.md` |
| Q2 | S_Lateral decision complexity | Cred×technique×target matching under patch/port constraints | Document in S_Lateral curriculum; add multi-path configs beyond patched-flag greedy |
| Q3 | Identity vs Lateral split | `lateral_movement` vs `goal_access` category + `goal_category`; not CVE string alone | Enforce in config review; add meta routing signals |
| Q4 | Credential store bootstrap | No schema pre-seed; add `Bootstrap_CachedCreds` lateral_movement entry | Extend catalog + `slat_ntlm_relay_v1.yaml` golden |
| Q5 | CloudIAM_LDAP_Write | Exists; valid as abstraction with IDC + federated properties | Wire S-LAT-02 with cloud→corp `MUST_CONNECT` |
| P1 | Specialist solvability gap | **Not built** | Add masked solver pass in Phase 2 |
| P2 | Re-validate after repair | **Not done** | Post-repair `config_checker` + zone coverage hook |
| P3 | template_alignment bias | LLM-only today | Score from `03_validate_zone_coverage` pass rate |
| P4 | Increase diameter | Break shortcuts, deepen attack_flow; repair prompt OK | Track whether actor edits topology vs SR tweaks |
| P5 | 40% threshold | Heuristic only | Add stratum variance + specialist pass before repair |
| P6 | Phase contract | Phase 1 = static; Phase 2 = runtime + critic | Move `_04`/`_05` to `phase2/`; fix `CLAUDE.md` |
| P7 | Missing step 3 | Renumbering artifact | Align `run.py` comments with `step4–7` |
