# Design Grill — Open Questions

Sourced from explore-mode analysis of the pipeline codebase and agent architecture.  
Each question targets a specific gap or assumption in the current design.

---

## Q1 — S_Recon BFS Filtering: Category vs. Type

S_Recon has no `remote_access` RCE exploits but it **does** have `type: REMOTE` vulnerabilities — specifically `credential_leak` and `discovery` entries (LDAP anon bind, SMB null session, SNMP walk, DNS zone transfer, AWS IMDS, etc.).

The `BFSPlannerAgent` expands its frontier using:

```python
has_remote = any(vd.type == VulnerabilityType.REMOTE ...)
```

This checks `VulnerabilityType.REMOTE` — which is true for both `remote_access` RCEs **and** S_Recon's `credential_leak`/`discovery` entries. In CBS, both appear as the same enum value.

**Q1a.** In the CBS data model, is there a separate field (e.g., a `category` or `solvability_type` field) that distinguishes a `remote_access` RCE from a `credential_leak` REMOTE or a `discovery` REMOTE? Or are they all just `VulnerabilityType.REMOTE` with no further sub-classification in the environment object?

**Q1b.** If there is no sub-category field, then BFS filtering for S_Recon cannot be done by checking `VulnerabilityType` alone — you would need to filter by vulnerability **name** (e.g., only allow vulnerabilities whose name starts with `Solvability.`). Is that the intended filtering mechanism? If so, where is the naming convention enforced — in the CVE databases, in the generator, or only in documentation?

**Q1c.** S_Recon's `KNOWS` constraint is listed as a separate CBS mechanic (not a standard vulnerability entry). Does KNOWS appear in the environment's vulnerability dictionary at all, or is it a CBS graph-level constraint that the BFS never touches? If the BFS cannot see KNOWS edges, is that a gap — or does the credential-chain path make KNOWS redundant for BFS purposes?

---

## Q2 — Action Space Overlap: S_Windows vs S_Identity

Both agents draw from `windows_cves.json`. The split is described as:
- S_Windows → "Windows OS RCEs"
- S_Identity → "AD techniques (Kerberos, DCSync)"

But the existing `sid_ad_standalone_v1.yaml` uses **PrintNightmare** and **SpoolSample** as intermediate steps in an NTLM coercion chain — which are also Windows OS RCEs (they exploit the Windows Print Spooler service).

**Q2a.** Where is the exact partition between S_Windows and S_Identity actions defined? Is it in a file, a naming convention, or only in human documentation?

**Q2b.** Is PrintNightmare/SpoolSample classified as an S_Windows action or an S_Identity action? What is the decision rule — exploit outcome (NTLM hash = S_Identity), target node property (DomainJoined = S_Identity territory), or CVE tag in the database?

**Q2c.** Can an S_Identity config validly contain Windows OS RCEs as intermediate steps, or should all Windows RCEs in an S_Identity scenario be in pre-owned nodes (handed off from S_Windows)?

**Q2d.** When the BFS filtering for S_Identity is implemented, will it use a list of allowed vulnerability names, a node-property predicate, or something else? Who maintains that list?

---

## Q3 — Meta Stage 4 BFS Validity

The three Stage 4 adversarial configs are:

| Config | Adversarial Property |
|--------|----------------------|
| `meta_stagnation_v1` | 90% patched Z4 devices — meta must switch to S_Recon after N failures |
| `meta_dual_path_v1` | Two paths to Z1 — meta must pick the faster one |
| `meta_decoy_v1` | High-value decoy node (3000) in Z4 — meta must ignore it and reach true goal (10000) |

`BFSPlannerAgent` has **global knowledge** — it sees all nodes, all values, all paths simultaneously. It will:
- Never be tricked by the decoy (it knows the true goal value)
- Route around patched devices trivially (it sees all unpatched paths)
- Always pick the shorter of two paths (it computes BFS hop distance)

**Q3a.** What does BFS solvability actually validate for Stage 4 configs? If BFS trivially solves all three adversarial scenarios, does that mean they're "valid" in any meaningful sense for training the meta-agent?

**Q3b.** Should Stage 4 configs use `GreedyExplorationAgent` (which has only local visibility) as the solvability test instead of BFS? The greedy agent can actually be trapped by the decoy or stalled by patched devices.

**Q3c.** For `meta_stagnation_v1` specifically: if BFS sees the 10% unpatched devices and solves in one try, but the intended training challenge is the meta learning to detect stagnation after 3 consecutive failures — is BFS solvability the wrong success criterion entirely? What should the solvability criterion be for Stage 4?

**Q3d.** Is there a risk that Stage 4 configs that are designed to be "adversarial" will be rejected by the BFS solvability gate if the adversarial property makes the scenario genuinely harder to solve? For example, a decoy that happens to be on a choke-point node could make BFS take longer or fail.

---

## Q4 — Small Config Technique Isolation

S_Identity's 5 small configs each isolate one AD attack technique:

```
sid_kerberoast_v1    — Kerberoasting
sid_asrep_roast_v1   — AS-REP Roasting
sid_ntlm_relay_v1    — NTLM Relay
sid_delegation_v1    — Delegation abuse
sid_zerologon_v1     — Zerologon
```

In a real AD attack chain, these techniques are **composable** — Kerberoasting harvests a hash, NTLM relay pivots to ADCS, DCSync completes the takeover. Isolating them means each small config trains the agent on a single technique with no context of when to prefer one over another.

**Q4a.** Is the intent that small configs train individual sub-skills (technique isolation as curriculum), or are they meant to be independently complete scenarios that just happen to emphasize different techniques?

**Q4b.** If the agent trained on `sid_kerberoast_v1` has only ever seen Kerberoasting as the path to DomainController, will it transfer to a medium config that requires choosing between Kerberoasting and NTLM relay? Is there a risk of technique overfitting on small configs?

**Q4c.** The same pattern applies to S_Recon's 5 small configs (aws_imds, redis_noauth, smb_null, dns_zone, laps_extract) — each isolates one credential-extraction mechanic. Is this intentional curriculum design, or a side effect of naming them by technique?

**Q4d.** For S_Network's 5 small configs (soho, branch, dmz_edge, vpn_gateway, single_fw) — these are differentiated by **network topology shape**, not by CVE technique. Is that a deliberate difference in how small configs are designed for network vs. identity specialists? If so, why?

---

## Q5 — The `maximum_node_count=100` Hardcoded Cap

In `test_dynamic_solve()` (line 1041–1049 of `02_test_env_integration.py`):

```python
env = ImprovedCyberBattleEnv(
    ...
    maximum_node_count=100,
    ...
)
```

XL configs are specified as 500–1200 nodes. The environment is initialized with a cap of 100 nodes.

**Q5a.** What does `maximum_node_count=100` actually control in `ImprovedCyberBattleEnv`? Does it cap the observation space (agent can only see 100 nodes at once), truncate the actual node count (only 100 nodes are loaded), or something else?

**Q5b.** If XL scenarios have 800–1200 nodes but the env is capped at 100, does BFS still run over all nodes (via `env.get_nodes()` which may bypass the cap), or does BFS also only see 100 nodes?

**Q5c.** If this cap affects the observation space only (not the actual node set), is it set correctly for the actual DRL training runs? Or is the Phase 2 evaluation running BFS in a different observation window than the DRL agent will see during training?

---

## Q6 — Scoring Semantics

The completed configs in `tasks/README.md` show scores:

```
snet_perimeter_standalone_v1  →  8.3
slin_cloud_standalone_v1      →  8.5
swin_serverfarm_standalone_v1 →  8.5
srec_recon_standalone_v1      →  9.0
```

The pipeline has two separate scoring systems:
- Phase 1 `_04_quality_evaluator.py` — LLM critic score (structural quality)
- Phase 2 `calculate_difficulty_score()` — runtime difficulty score (0–10, based on BFS telemetry)

**Q6a.** Which score do the task README numbers represent — LLM critic quality, BFS difficulty, or a combination?

**Q6b.** Should a high difficulty score (e.g., 9.0 for `srec_recon_standalone_v1`) be considered good or bad? If the DRL agent cannot learn from an extremely difficult scenario (reward too sparse), a high difficulty score is a problem, not a success marker.

**Q6c.** Is there a target difficulty range for each tier? For example: small configs should score 2–4 (EASY), medium 4–6 (MODERATE), large 6–8 (HARD), XL 8+ (EXTREME)? Or is difficulty not expected to correlate with tier?
