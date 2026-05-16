# Meta-Agent: Full Specification

**Role:** Routing policy — selects which specialist to invoke at each CBS episode step  
**Algorithm:** PPO with recurrent LSTM encoder  
**Action space:** Discrete(5) — one specialist per option  
**Terminal goal:** `CyberArkPAM` (Z8, value 10000, is_goal: true)

The meta-agent does not execute CBS actions directly. It selects a specialist; that specialist executes one action; the resulting game state is returned for the next routing decision.

---

## What the Meta-Agent Learns

| Skill | Trigger condition | Routing decision |
|-------|-----------------|-----------------|
| Zone recognition | Frontier ∩ Z4/Z2 network device nodes | Call S_Network |
| Zone recognition | Frontier ∩ Z6 Linux container nodes | Call S_Linux |
| Zone recognition | Frontier ∩ Z1 Windows nodes, no domain foothold | Call S_Windows |
| Protocol recognition | Z1 domain foothold exists, AD protocols exposed | Call S_Identity |
| Credential store monitoring | Credential store stale (no new creds in N steps) | Call S_Recon |
| Stagnation recovery | Specialist fails K consecutive actions | Call S_Recon |
| Prerequisite enforcement | DomainController not owned → S_Mgmt unavailable | Avoid S_Mgmt routing |
| Goal priority | DomainController owned, Z8 reachable | Call S_Identity (DSRM) then pivot to Z8 |

---

## Training Scenarios (Curriculum Stages)

### Stage 1 — Two-Zone Transitions

| Config | Zones | Specialists | Transitions |
|--------|-------|------------|------------|
| `meta_perimeter_ad_v1` | Z4 + Z2 + Z1 | S_Network → S_Recon → S_Windows → S_Identity | 3 |
| `globaltech_z6_to_z1_v1` | Z6 + Z1 | S_Linux → S_Recon → S_Windows → S_Identity | 3 |
| `globaltech_z2_perimeter_v1` | Z4 + Z2 | S_Network → S_Recon | 1 |

**Purpose:** Teach the basic surface-specialist → S_Recon bridge → next-specialist pattern.

### Stage 2 — Three-Zone Transitions

| Config | Zones | Specialists | Goal |
|--------|-------|------------|------|
| `meta_perimeter_ad_v1` | Z4 + Z2 + Z1 | S_Network → S_Recon → S_Windows → S_Identity | DC (value 10000) |
| `meta_cloud_ad_v1` | Z6 + Z1 | S_Linux → S_Recon → S_Identity | DC (value 10000) |
| `globaltech_branch_hq_v1` | Z5 + Z2 + Z1 | S_Network → S_Recon → S_Identity | DC (value 10000) |

**Purpose:** Introduce prerequisite enforcement. Meta-agent learns to call S_Windows before S_Identity on new Z1 nodes.

### Stage 3 — Full Enterprise Kill Chain

| Config | Zones | All specialists? | Terminal goal |
|--------|-------|-----------------|--------------|
| `meta_full_enterprise_v1` | Z4+Z2+Z1+Z8 | Yes | CyberArkPAM (value 10000) |
| `globaltech_full_cloud_corp_v1` | Z6+Z1+Z8 | S_Linux, S_Recon, S_Identity | CyberArkPAM (value 10000) |

**Purpose:** Full multi-zone chain. Meta-agent must learn that DomainController (value 6000, not terminal) is an intermediate, and continuing to Z8 yields the highest cumulative reward.

### Stage 4 — Adversarial / Stress

| Config | Challenge | What meta-agent learns |
|--------|-----------|----------------------|
| `globaltech_stagnation_v1` | Z4 has 90% patched devices | Recovery: switch to S_Recon after 3 S_Network failures |
| `globaltech_dual_path_v1` | Both Z4 and Z6 paths reach Z1 | Path selection: which route is faster |
| `globaltech_decoy_v1` | High-value decoy node in Z4 (value 3000) | Goal priority: ignore intermediate bait; pursue terminal goal |

---

## Goal Definition

```yaml
# All meta-agent training configs:
goal_config:
  num_goals: 1
  selection_strategy: diverse
# Terminal goal: CyberArkPAM — value 10000, is_goal: true
# DomainController: value 6000, is_goal: false
```

Episode terminates when CyberArkPAM is owned. The meta-agent receives cumulative reward from all intermediate nodes across all specialists throughout the episode.

---

## Reward Structure

| Reward event | Value | Source |
|-------------|-------|--------|
| Surface specialist compromises intermediate node | Node `value` field | CBS environment |
| S_Recon discovers new credential | +300 (shaped) | Reward shaping |
| S_Recon reveals new node via KNOWS | +150 (shaped) | Reward shaping |
| S_Recon crosses new zone boundary | +1200 (shaped) | Reward shaping |
| Meta-agent routes to stagnated specialist (>K fails) | −10 penalty | Reward shaping |
| CyberArkPAM owned — episode terminates | 10000 | CBS environment |
| Episode timeout (max steps exceeded) | 0 | — |

---

## DRL Architecture

**Algorithm:** PPO with recurrent LSTM encoder  
**Action space:** Discrete(5) — one specialist per option  
**Observation:** CBS global game state — discovered nodes + properties, owned nodes, credential store, per-specialist fail counts, episode step, `domain_foothold: bool` (true when S_Windows has compromised at least one Z1 node; exposes the S_Windows → S_Identity prerequisite as an explicit signal so the LSTM does not have to infer it from ownership history alone)  
**Entropy regularization:** β = 0.01 applied to PPO policy loss to prevent premature convergence to a fixed specialist sequence  
**LSTM rationale:** Prerequisite ordering (call S_Windows before S_Identity, DomainController before Z8) requires memory of earlier episode events — a memoryless policy cannot learn this.

---

## Training Curriculum

```
Stage 0: Train each specialist independently on single-zone configs
          Freeze specialist weights before Stage 1.

Stage 1: Meta-agent on Stage 1 configs (two-zone, 3 specialist transitions)
          Target: meta-agent learns zone-trigger routing

Stage 2: Meta-agent on Stage 2 configs (three-zone, prerequisite chains)
          Target: meta-agent learns S_Windows → S_Identity ordering

Stage 3: Meta-agent on Stage 3 configs (full enterprise chain)
          Target: meta-agent learns to not terminate at DomainController

Stage 4: Meta-agent on Stage 4 configs (adversarial)
          Target: stagnation recovery and decoy resistance
```

**Critical constraint:** Specialist weights are **frozen** in all meta-agent training stages. The meta-agent learns routing; specialists do not change. Allowing co-training confounds the routing signal with simultaneous policy drift.

---

## Pros and Cons

| Pros | Cons |
|------|------|
| Zone-trigger routing is directly observable in CBS game state | Meta-agent action space (5 options) may converge to a fixed sequence rather than a dynamic policy |
| Shared global observation eliminates state-translation overhead | Frozen specialist assumption fails if any specialist has a weak policy — meta-agent cannot compensate |
| S_Recon dense reward prevents gradient starvation | LSTM training instability under PPO — requires careful sequence-length and gradient-clip tuning |
| Curriculum prevents cold-start | Strict curriculum ordering means Stage 4 cannot begin until Stages 0–3 are fully converged |
| LSTM captures prerequisite ordering across steps | `domain_foothold` flag makes S_Windows → S_Identity dependency explicit, but all other inter-specialist prerequisites still require implicit learning from history |
