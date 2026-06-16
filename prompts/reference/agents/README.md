# Specialist Agent Vocabulary Reference

These files define the vocabulary-controlled specialist collections used by the scenario generator.
They are aligned to `/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml` and to the specialist action maps in `CyberBattleSim/cyberbattle/specialists/specialist_definitions.py`.

## Global Counts

| Vocabulary | Count |
|---|---:|
| Local vulnerabilities | 98 |
| Remote vulnerabilities | 72 |
| Connect ports | 20 |
| Service IDs | 93 |
| Property IDs | 110 |

## Specialist Counts

| Specialist | Local | Remote | Connect | Actions | Services | Properties |
|---|---:|---:|---:|---:|---:|---:|
| `s_network` | 18 | 14 | 18 | 50 | 23 | 41 |
| `s_linux` | 19 | 17 | 14 | 50 | 30 | 52 |
| `s_windows` | 12 | 21 | 17 | 50 | 27 | 44 |
| `s_identity` | 15 | 16 | 19 | 50 | 29 | 48 |
| `s_lateral` | 34 | 4 | 12 | 50 | 28 | 72 |

## Files

| File | Purpose |
|---|---|
| `s_network.md` | Network device and perimeter appliance collection. |
| `s_linux.md` | Linux, cloud, container, and CI/CD collection. |
| `s_windows.md` | Windows OS and application exploitation collection. |
| `s_identity.md` | Active Directory, Kerberos, LDAP, ADCS, and identity collection. |
| `s_lateral.md` | Credential reuse, relay, WinRM/SMB/LDAP, and cross-zone movement collection. |
| `meta_agent.md` | Meta scenario composition rules using the five specialists. |

## Hard Generation Rules

- Generate only specialist-style scenarios for the new dataset.
- Use the 20 `specialist_meta` source configs as the shape reference, but update identifiers to this vocabulary.
- Do not use legacy identifiers such as `Remote.Probe.*`, `External.*`, `Local.*`, `Solvability.ARP_Table_Dump`, `Solvability.Nmap_Internal`, or other IDs not present in `global_vocabulary.yaml`.
- Do not introduce S_Recon or other removed specialists.
- Multiple goals are allowed and expected in meta-style scenarios.
- The final dataset target is evenly distributed by size: 250 small, 250 medium, 250 large, and 250 xlarge scenarios, split 800 train and 200 test.
