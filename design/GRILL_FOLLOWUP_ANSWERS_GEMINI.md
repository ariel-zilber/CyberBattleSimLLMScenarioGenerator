# Design Grill — Follow-Up Answers (Gemini Edition)

**Date:** 2026-05-16  
**Agent:** Gemini CLI  
**Source:** Resolving FU-01 and FU-02 from `GRILL_FOLLOWUP.md`

---

## FU-01 — Q1 Revisited: LEAK_KNOWN_CREDENTIALS vs. Active Extraction

### Decision: Option B — S_Lateral gains a pre-relay credential extraction sub-role

**Rationale:**
Consolidating both **LOCAL extraction** (`credential_leak` solvability entries) and **REMOTE/LOCAL relay** (`lateral_movement`) into `S_Lateral` is the most architecturally scalable choice. 

1.  **Policy Coherence:** The "Credential Chain" is a distinct mental model from the "RCE/Memory Corruption" model. By giving `S_Lateral` the extraction role, we create a specialist that deeply understands the full lifecycle of a credential: **Identify (Loot) → Match (Technique) → Execute (Move).**
2.  **Protecting Surface Focus:** If we add extraction to `S_Windows` and `S_Linux` (Option A/C), we force those agents to learn OS-specific post-exploitation logic that is largely disconnected from their primary goal of achieving the initial breach.
3.  **Cross-Platform Chains:** Credential chains often jump between OS types (e.g., extracting AWS keys from a Linux container to use against an on-prem Windows domain). A single "Credential Specialist" can handle this cross-surface logic more efficiently than multiple surface specialists passing the baton.

**Impact on `specialist_agent_spec.md`:**
Yes, the action table for `S_Lateral` must be updated to allow `credential_leak` solvability:

| CBS Action Category | type | Allowed? | Rationale |
|--------------------|------|----------|-----------|
| `credential_leak` solvability | LOCAL | ✅ **Yes** | **Extraction:** S_Lateral now owns post-exploitation looting (Mimikatz, etc.) |
| `lateral_movement` solvability | REMOTE/LOCAL | ✅ Yes | **Relay:** Use stolen creds to cross boundaries |

---

## FU-02 — Q3 Revisited: Enforcement and Catalog Structure

### 1. Enforcement Strategy
**Decision:** Extend `02_config_checker.py` with an agent-category allowlist.

**Rationale:**
Static semantic validation should happen as early as possible. `02_config_checker.py` is already responsible for verifying that CVE names exist; it is the natural "Compiler" gate for verifying that those CVEs belong to the agent's assigned scope. Adding a separate `04_validate_agent_scope.py` adds unnecessary turn-overhead to the pipeline.

### 2. Double-Entry Techniques
**Decision:** Techniques should appear **twice** under different category sections in `vulnerability_catalog.md`.

**Rationale:**
From a validation logic perspective, `(AgentType, Category)` is a cleaner primary key than `(AgentType, TechniqueName)`. 

-   If `ADCS_ESC1` appears in the `## Category: lateral_movement` section, it is a "Move" action owned by `S_Lateral`.
-   If `ADCS_ESC1` appears in the `## Category: goal_access` section, it is a "Win" action owned by `S_Identity`.
-   **Clarity for Generator:** This forces the LLM generator to explicitly decide the **role** of the technique in the scenario by placing it in the correct YAML block. It prevents "Lazy Generation" where an agent uses a goal-level technique as a routine movement.

---

## Updated Resolution Checklist (Gemini)

- [x] Update `specialist_agent_spec.md` — S_Lateral now owns `credential_leak` (LOCAL).
- [x] Update `s_lateral.md` — Include Mimikatz/Extraction techniques.
- [x] Extend `02_config_checker.py` — Add the Agent-Category allowlist.
- [x] Update `vulnerability_catalog.md` — Explicitly duplicate "swing" techniques into both Lateral and Goal sections.
