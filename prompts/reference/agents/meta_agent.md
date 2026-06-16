# Meta-Agent Scenario Composition Reference

The current dataset generation target is specialist-style meta scenarios with multiple goals. The meta scenario may contain all five specialist surfaces, but the primitive actions must still come from the five specialist collections:

- `s_network.md`
- `s_linux.md`
- `s_windows.md`
- `s_identity.md`
- `s_lateral.md`

There is no S_Recon collection in the new dataset. Discovery, credential leakage, and lateral expansion must be represented through one of the five specialist vocabularies, especially `s_lateral` for credential reuse and cross-zone movement.

## Dataset Shape

| Size group | Node range | Scenarios |
|---|---:|---:|
| Small | <= 50 | 250 |
| Medium | 51-200 | 250 |
| Large | 201-500 | 250 |
| X-Large | 501-1000 | 250 |

Total: 1000 scenarios, split into 800 train and 200 test.

## Meta Scenario Requirements

- Use only identifiers from `/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml`.
- Use multiple goals per scenario; goal count may scale by size.
- Include enough valid fixed source-target pairs for each relevant specialist.
- Include credentials that support connect actions through one of the 20 global ports.
- Keep service and property names inside the global service/property vocabularies.
- Do not emit legacy `Remote.Probe.*`, `External.*`, or `Local.*` identifiers.
- Do not use off-vocabulary service names such as `BranchRouter` or `BranchSDWAN`; map them to vocabulary service IDs such as `CiscoEdgeRouter`, `ISPRouter`, `MikroTikRouter`, `OpenWRTRouter`, or `CiscoNXOS`.
- Do not use off-vocabulary ports such as `BGP` or `Redis`; express those concepts as service/property context if needed.

## Specialist Routing Intent

A meta scenario should combine several of these surfaces:

| Surface | Specialist |
|---|---|
| Network perimeter, VPN, routers, firewalls | `s_network` |
| Linux, cloud, containers, CI/CD | `s_linux` |
| Windows RCE and local privilege escalation | `s_windows` |
| AD, Kerberos, LDAP, ADCS, domain compromise | `s_identity` |
| Credential reuse, relay, WinRM/SMB/LDAP movement | `s_lateral` |

The generated scenario should remain solvable without adding actions outside these five collections.
