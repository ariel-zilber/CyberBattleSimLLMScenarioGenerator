# Design Grill — Follow-Up

**Date:** 2026-05-16  
**Source:** Pushbacks on `GRILL_ANSWERS.md` Q1 and Q3  
**Status:** Needs resolution before spec writing begins

---

## FU-01 — Q1 Revisited: LEAK_KNOWN_CREDENTIALS is passive; who deposits credentials post-exploitation?

### The Confusion

The Q1 answer said S_Lateral should own "execution of LEAK_KNOWN_CREDENTIALS." This conflates two distinct CBS mechanics:

| Mechanic | Type | Who triggers it |
|----------|------|----------------|
| `LEAK_KNOWN_CREDENTIALS` | Passive topology constraint | CBS engine — fires automatically when a node that holds the constraint is owned |
| `credential_leak` solvability entry | Active agent action | An agent that owns the node and chooses to run a LOCAL leak exploit (e.g., `Mimikatz_LSASS`, `WinRM_Credential_Cache`) |

S_Recon's real role was the **second** mechanic — it chose to apply LOCAL `credential_leak` solvability entries, depositing credentials into the CBS store. The passive LEAK constraint then propagated those credentials automatically across node boundaries. No agent "executes" the constraint; it just fires.

### The Actual Gap

With S_Recon gone, nobody decides to run `Mimikatz_LSASS` on an owned DC, or `WinRM_Credential_Cache` on an AdminWorkstation. Both S_Windows and S_Identity explicitly disclaim `credential_leak` ownership. S_Lateral states it only relays credentials already in the store.

In M-ST3-01 step 7 (`Mimikatz_LSASS + BloodHound_Recon` on the DC), no specialist is currently assigned this action.

### The Two Options

**Option A — S_Windows gains LOCAL credential_leak entries**

S_Windows already owns the DC (via OS RCE). It is natural for it to also dump LSASS post-exploitation. `Mimikatz_LSASS`, `LAPS_Password_Read`, `GPP_Password_Decryption`, `WinRM_Credential_Cache` become LOCAL actions in S_Windows' spec, conditional on owning the source node.

- Pro: No new agent needed; fits the "OS exploitation → OS credential extraction" narrative
- Con: S_Windows' policy now has two phases (exploit → extract), which may dilute its feature space. The agent must also learn *which* extraction to run, not just which exploit

**Option B — S_Lateral gains a pre-relay credential extraction sub-role**

S_Lateral owns both extraction (LOCAL `credential_leak` on owned nodes) and relay (lateral_movement on target nodes). It becomes the "post-exploitation credential chain" specialist end-to-end.

- Pro: Clean narrative — one agent owns the full credential pipeline after initial exploitation
- Con: S_Lateral's policy now spans two very different action types (dump vs relay), complicating the feature space in the opposite direction from Option A

**Option C — Add a minimal extraction phase to the breach node setup (standalone only)**

For standalone training, seed credentials via the SR 1.0 dummy leak (already in Q4 answer). For meta-agent training, explicitly make `credential_leak` entries available to whichever specialist owns the node at that step — i.e., S_Windows extracts from Z1 nodes it owns via OS RCE; S_Linux extracts from Z6 nodes it owns; extraction is a *secondary* action that each surface specialist can perform on their owned nodes.

- Pro: Keeps each specialist's scope coherent (you extract from what you compromised)
- Con: Requires adding credential_leak entries to S_Windows and S_Linux specs, which were previously S_Recon's territory

### Question

**Which option? And does your answer change the specialist_agent_spec.md action table for S_Windows, S_Linux, or S_Lateral?**

**Answer:**

---

## FU-02 — Q3 Revisited: `metadata.agent` is a documentation tag, not a validator input

### The Confusion

The Q3 answer said the S_Identity / S_Lateral technique partition is "enforced via `metadata.agent` field and `system_prompt.md` instructions." But:

- `metadata.agent` is a free-text YAML header field. `02_config_checker.py` validates CVE names against `vulnerability_catalog.md` but does not cross-reference the agent field against which solvability categories are present.
- `system_prompt.md` generation instructions are a prompt constraint, not a runtime check. A generated config that violates the partition would pass Phase 1 validation silently.

Concretely: a generated `slat_perimeter_to_hq_v1.yaml` with `metadata.agent: S_Lateral` that contains a `goal_access` block with `ADCS_ESC1` would pass `02_config_checker.py` today.

### What Enforcement Actually Requires

The config checker needs an **agent-category allowlist**: given `metadata.agent`, which solvability categories are permitted?

```
S_Network:   remote_access, credential_leak
S_Linux:     remote_access, credential_leak
S_Windows:   remote_access, credential_leak (TBD per FU-01)
S_Identity:  remote_access, goal_access
S_Lateral:   lateral_movement, credential_leak (if Option B/C in FU-01)
Meta:        all categories permitted
```

Any solvability entry whose category is not in the agent's allowlist → validation error.

Additionally, the double-entry techniques (ADCS_ESC1, ShadowCredentials, PassTheHash) need a second enforcement layer: **which catalog section they appear under determines ownership, not the technique name alone.** If `ADCS_ESC1` appears under `## Category: goal_access` in `vulnerability_catalog.md`, it is an S_Identity entry. If it appears under `## Category: lateral_movement`, it is an S_Lateral entry. The config_checker must verify the category matches the catalog section, not just that the name exists.

### Questions

1. **Should `02_config_checker.py` be extended with an agent-category allowlist, or should this be a separate validation step (`04_validate_agent_scope.py`)?**

2. **For the double-entry techniques (ADCS_ESC1, ShadowCredentials, NTLM_Relay_LDAP): should they appear once in the catalog under one canonical category, with the other agent referencing them via a cross-reference tag — or should they appear twice under different category sections?**

**Answer:**

---

## Resolution Checklist

Once both follow-ups are answered, these specs need to be written:

- [ ] Update `specialist_agent_spec.md` — Agent action table for S_Windows and/or S_Lateral reflecting FU-01 decision
- [ ] Update `s_lateral.md` and `s_windows.md` agent specs with resolved credential_leak ownership
- [ ] Extend `02_config_checker.py` (or new `04_validate_agent_scope.py`) with agent-category allowlist per FU-02
- [ ] Update `vulnerability_catalog.md` to resolve double-entry techniques into single canonical category per FU-02
- [ ] Update `system_prompt.md` generation instructions to match resolved partition
