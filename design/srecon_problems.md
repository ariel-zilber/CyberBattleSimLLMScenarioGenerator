# S_Recon — Design Problems

Identified during explore-mode analysis of `s_recon.md` and `agents/README.md`.

---

## Problem 1: Direct Contradiction in the Spec

`s_recon.md` line 21:
```
goal_access solvability  —  ❌ No  —  Never terminates an episode
```

`s_recon.md` line 103:
```yaml
AdminWorkstation:  value: 10000  is_goal: true    # TERMINAL GOAL
```

One says S_Recon never terminates an episode. The other marks a node as `is_goal: true` — which **does** terminate an episode in CBS. These cannot both be true simultaneously.

**Decision needed:** Does S_Recon terminate episodes or not?

---

## Problem 2: Standalone Role vs. Bridge Role

S_Recon is described as "the bridge between surface specialists and AD specialists." But the dataset requires 11 standalone S_Recon training configs. A bridge trained in isolation — without the surface specialist that is supposed to hand it a foothold — is not practicing its bridge role.

```
Standalone S_Recon training:
  ISPRouter (pre-owned, SR=1.0) ──► credential chain ──► AdminWorkstation
  S_Recon handles its own initial foothold

Meta S_Recon role:
  S_Network already owns Z4/Z2 ──► S_Recon receives that foothold
  S_Recon's task: propagate credentials from Z2 into Z1
```

These are different problems. Training on the standalone version may not teach the meta-role at all — the agent learns to bootstrap from a trivial breach node, not to exploit an already-compromised zone boundary.

**Decision needed:** Should standalone S_Recon configs simulate the handoff (pre-own Z2 nodes) to match the meta context? Or is standalone training intentionally decoupled from the bridge role?

---

## Problem 3: Terminology Collision — Two Definitions of "REMOTE"

The `agents/README.md` action space matrix says:

| Agent | REMOTE Exploit |
|-------|:---:|
| S_Recon | ❌ |

But `s_recon.md` explicitly lists vulnerabilities with `type: REMOTE`:

| Name | Type |
|------|------|
| `Solvability.LDAP_AnonymousBind` | REMOTE |
| `Solvability.SMB_NullSession` | REMOTE |
| `Solvability.SNMP_CommunityDump` | REMOTE |
| `Solvability.DNS_ZoneTransfer` | REMOTE |
| `Solvability.AWS_IMDSv1` | REMOTE |
| `Solvability.Nmap_Internal` | REMOTE |

The README uses "REMOTE Exploit" to mean `remote_access` RCE only.  
The spec uses `type: REMOTE` in the CBS sense: *executable without owning the target node first*.

**RESOLVED — CBS definition is authoritative:**

> `type: REMOTE` = the vulnerability can be executed without first owning the target node.  
> `type: LOCAL` = the vulnerability requires owning the source/target node first.

This is the CBS data model definition and must be used consistently across all agent specs, the README matrix, BFS filtering logic, and generated YAML configs. The README column "REMOTE Exploit" is a misnomer — it should be read as "has `type: REMOTE` vulnerabilities of the `remote_access` solvability category."

**Consequence for the README action space matrix:** The column heading "REMOTE Exploit" must be renamed to something that does not conflict with the CBS `type: REMOTE` field. Proposed rename: **"RCE (remote\_access)"** to make clear it refers specifically to `remote_access` solvability entries, not all `type: REMOTE` entries.

**Consequence for BFS filtering:** When filtering BFS actions by agent, the filter must use the vulnerability's solvability category (`remote_access` / `credential_leak` / `discovery`), not the CBS `type` field. The `type` field alone cannot distinguish an RCE from an LDAP anon bind — both are `type: REMOTE`.

---

## Problem 4: Reward Structure Anomaly
~~Every other specialist earns reward by capturing nodes. S_Recon used event-triggered shaped rewards (+150/node, +300/cred, +1200/zone, +10000/goal) which caused high variance and required a special rollout buffer recommendation.~~

**RESOLVED — New reward structure:**

| Outcome | Reward |
|---------|--------|
| Any successful action with a positive result | +1 |
| Failed or no-op action | 0 |
| Terminal goal reached | +1000 |

This eliminates the event-triggered complexity. S_Recon now uses a binary step signal (+1 / 0) plus a large terminal bonus (+1000), removing the distinction between "revealed a node," "found a credential," and "crossed a zone boundary" — all positive outcomes are equal weight.

**Remaining open question:** What exactly counts as a "positive result" in CBS action terms? Candidates:
- Any action that returns a non-empty `new_credentials` or `new_nodes` in the outcome object
- Any action with `reward > 0` from the CBS environment itself
- Any action that changes the owned/discovered/credential state

The definition matters because CBS may return different outcome objects for credential_leak vs. discovery vs. connect actions. Needs to be pinned down in the implementation so the +1 signal is consistent across all S_Recon action types.

---

## Root Tension

All four problems point to the same underlying issue:

> **Is S_Recon a specialist that learns a skill, or is it a coordination mechanism dressed up as a specialist?**

Every other specialist has a clean learning objective:
- S_Network learns: perimeter appliance exploitation
- S_Linux learns: container breakout chains
- S_Windows learns: Windows OS RCE escalation
- S_Identity learns: AD protocol abuse

What does S_Recon *learn*? Credential propagation is not a skill in the same sense — it is a consequence of executing the right sequence of discovery and leak actions in the right order. The scenario topology shapes the path more than the agent's policy does.

If S_Recon's real function is to act as a credential bridge in meta-training, it may not need to be a standalone specialist at all — it could instead be a **fixed heuristic module** that the meta-agent calls when a zone boundary is reached and no RCE path exists.

---

## Open Questions

1. If the standalone role is kept, how should the 11 standalone configs simulate the meta handoff context?
2. If S_Recon is redesigned as a heuristic module rather than a learned specialist, what happens to the 11 planned configs and the 39 train scenarios?
3. Should the terminology fix (Problem 3) be resolved in the README, in the CBS vulnerability entries, or in the BFS filtering code?
