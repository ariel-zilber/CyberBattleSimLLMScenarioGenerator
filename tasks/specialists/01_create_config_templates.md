# Task 01 - Create Specialist-Style Meta Config Templates

## Goal

Create 20 new source YAML configs under:

```text
data/scenarios/specialists/
```

These configs should replace the old `data/scenarios/specialist_meta/` configs for the final experiment dataset.

## Config Matrix

Create 5 meta scenario families, each with 4 size variants:

| Family | Small | Medium | Large | X-Large |
|---|---|---|---|---|
| Perimeter to domain escalation | `*_small_v1.yaml` | `*_medium_v1.yaml` | `*_large_v1.yaml` | `*_xlarge_v1.yaml` |
| Cloud to corp identity pivot | `*_small_v1.yaml` | `*_medium_v1.yaml` | `*_large_v1.yaml` | `*_xlarge_v1.yaml` |
| Branch to HQ lateral movement | `*_small_v1.yaml` | `*_medium_v1.yaml` | `*_large_v1.yaml` | `*_xlarge_v1.yaml` |
| CI/CD to production compromise | `*_small_v1.yaml` | `*_medium_v1.yaml` | `*_large_v1.yaml` | `*_xlarge_v1.yaml` |
| Hybrid enterprise crown jewels | `*_small_v1.yaml` | `*_medium_v1.yaml` | `*_large_v1.yaml` | `*_xlarge_v1.yaml` |

Recommended filenames:

```text
specialist_perimeter_to_domain_escalation_small_v1.yaml
specialist_perimeter_to_domain_escalation_medium_v1.yaml
specialist_perimeter_to_domain_escalation_large_v1.yaml
specialist_perimeter_to_domain_escalation_xlarge_v1.yaml
specialist_cloud_to_corp_identity_pivot_small_v1.yaml
specialist_cloud_to_corp_identity_pivot_medium_v1.yaml
specialist_cloud_to_corp_identity_pivot_large_v1.yaml
specialist_cloud_to_corp_identity_pivot_xlarge_v1.yaml
specialist_branch_to_hq_lateral_movement_small_v1.yaml
specialist_branch_to_hq_lateral_movement_medium_v1.yaml
specialist_branch_to_hq_lateral_movement_large_v1.yaml
specialist_branch_to_hq_lateral_movement_xlarge_v1.yaml
specialist_cicd_to_production_compromise_small_v1.yaml
specialist_cicd_to_production_compromise_medium_v1.yaml
specialist_cicd_to_production_compromise_large_v1.yaml
specialist_cicd_to_production_compromise_xlarge_v1.yaml
specialist_hybrid_enterprise_crown_jewels_small_v1.yaml
specialist_hybrid_enterprise_crown_jewels_medium_v1.yaml
specialist_hybrid_enterprise_crown_jewels_large_v1.yaml
specialist_hybrid_enterprise_crown_jewels_xlarge_v1.yaml
```

## Size Rules

| Variant | Node range | Goals |
|---|---:|---:|
| Small | `35-50` | 3 |
| Medium | `100-180` | 4 |
| Large | `300-450` | 6 |
| X-Large | `700-950` | 8 |

These ranges intentionally mirror the existing `specialist_meta` configs while keeping the final distribution compatible with the proposal.

## Vocabulary Rules

Use only the collections in:

```text
prompts/reference/agents/s_network.md
prompts/reference/agents/s_linux.md
prompts/reference/agents/s_windows.md
prompts/reference/agents/s_identity.md
prompts/reference/agents/s_lateral.md
```

Hard forbidden identifiers:

```text
Remote.Probe.*
External.*
Local.*
Solvability.ARP_Table_Dump
Solvability.Nmap_Internal
Solvability.CDP_Neighbors
BranchRouter
BranchSDWAN
BGP
Redis as a port
S_Recon
```

## Done Criteria

- [x] 20 YAML configs exist under `data/scenarios/specialists/`.
- [x] Each config has `metadata.agent: Meta` or equivalent meta-style marker.
- [x] Each config has multiple goals via `config.goal_config.num_goals`.
- [x] Each config uses only global vocabulary identifiers.
- [x] Each config includes at least two specialist surfaces, preferably three or more.
- [x] No config uses old off-vocabulary probe, external, or local pseudo-actions.

## Completion Notes

Completed on 2026-06-13.

Created from the old `data/scenarios/specialist_meta/meta_*_v1.yaml` templates and written to the new final folder:

```text
data/scenarios/specialists/
```

The generated config set contains exactly:

```text
5 scenario families x 4 size variants = 20 configs
```

The transformation preserved the old specialist-meta family/size shape but replaced legacy identifiers with the current fixed vocabulary from:

```text
/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml
```

Important replacements:

- Removed old `Remote.Probe.*`, `External.*`, and `Local.*` helper vulnerability names.
- Replaced removed ports such as `BGP`, `REST`, and `Redis` as a port.
- Replaced removed services such as `BranchRouter`, `BranchSDWAN`, and accidental `AWSHTTP`.
- Kept `breach_node` as a pipeline-required synthetic start marker.
- Kept port labels valid in property slots because the generator schema treats `standard_ports` as valid node labels for connect/firewall semantics.

Validation performed:

```bash
python tools/validate_specialist_vocabulary.py data/scenarios/specialists/*.yaml
```

Result:

```text
Specialist vocabulary validation passed: 20 file(s)
```
