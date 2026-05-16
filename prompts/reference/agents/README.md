# Specialist Agent Architecture
## GLOBALTECH Multi-Agent DRL — Overview, Action Space, Reward Summary

**Basis:** GLOBALTECH Enterprise Network (8 zones, Z1–Z8), 5 specialist + 1 meta agent  
**Authoritative spec:** `/home/ariel/Documents/thesis/CyberBattleSimDomainGenerator/prompts/docs/reference/specialist_agent_spec.md`  
**Per-agent deep specs:** `s_network.md`, `s_linux.md`, `s_windows.md`, `s_identity.md`, `s_lateral.md`, `meta_agent.md`

---

## Design Principles

Agents are partitioned by **attack surface**, not by MITRE tactic phase. Each agent owns a distinct zone subset and a distinct CVE family:

1. **Skill specialization is real:** A network device exploit (PAN-OS) requires completely different knowledge than an AD Kerberos attack. Mixed-surface agents underfit both.
2. **CVE family alignment:** The three CVE databases map cleanly to three attack surfaces. No agent trains on CVEs it will never encounter.
3. **Composability for meta-agent:** When each specialist has a clean zone boundary, meta-agent routing reduces to zone-transition timing — a tractable coordination problem.

---

## Agent Summary Table

| Agent | Codename | GLOBALTECH Zones | CVE Family | Entry | Terminal Goal |
|-------|----------|-----------------|-----------|-------|--------------|
| 1 | `S_Network` | Z4, Z2 | Network devices (PAN-OS, IOS, FortiOS) | Internet (Z3) | CiscoEdgeRouter (Z2) |
| 2 | `S_Linux` | Z6 | Bitnami / Linux containers | Z6 WebTier | AWSRedis (standalone) / AWSPostgreSQL (meta) |
| 3 | `S_Windows` | Z1 VLANs + Server Farm | Windows OS RCEs | Z1 VLANs entry | DomainController (Z1) |
| 4 | `S_Identity` | Z1 Server Farm | AD techniques (Kerberos, DCSync) | Z1 domain foothold | DomainController (Z1) |
| 5 | `S_Lateral` | All zones (post-exploitation) | `windows_cves.json` (lateral movement subset) | Any compromised node with credentials | First node in target zone |
| Meta | `Meta` | Full topology | Routing policy | Z4 or Z6 | CyberArkPAM (Z8) |

---

## Architecture at a Glance

```text
Internet (Z3)
     │
     ▼  [S_Network] (Firmware/Appliance)
Internet Edge Z4 (10.0.1.0/24) ──► HQ Edge Z2 (10.0.2.0/24)
                                          │
                             [S_Lateral]  │  (NTLM relay / WinRM with stolen creds)
                                          ▼
                              HQ VLANs Z1 (10.1.0.0/24–10.1.4.0/24)
                                          │
                             [S_Windows]  │  (OS RCEs)
                                          ▼
                              Server Farm Z1 (10.1.10.0/24)
                                          │
                             [S_Identity] │  (AD Protocol / DCSync)
                                          ▼
                                Domain Controller

Parallel cloud path:
Internet (Z3) ──► [S_Linux] ──► AWS Z6 (10.3.0.0/24) ──► [S_Lateral] ──► Z1
                                                           (LDAP attr write via cloud IAM)
```

**Technology → Agent Mapping:**

| Technology Stack | Agent | CVE Database Source |
|-----------------|-------|---------------------|
| Firmware / Appliances (PAN-OS, IOS, FortiOS, F5) | **S_Network** | `network_devices_cves.json` |
| Linux / Containers / Bitnami | **S_Linux** | `bitnami_cves.json` |
| Windows OS (memory corruption, logic flaws) | **S_Windows** | `windows_cves.json` (RCE subset) |
| Active Directory / Kerberos (identity abuse) | **S_Identity** | `windows_cves.json` (AD techniques subset) |
| Post-exploitation lateral movement (relay, WinRM, ADCS) | **S_Lateral** | `windows_cves.json` (lateral movement subset) |

---

## Action Space Matrix

| Agent | Probe (OS ID) | REMOTE Exploit | LOCAL Exploit | Loot (Creds/Goals) | Scout (Graph) |
|-------|:---:|:---:|:---:|:---:|:---:|
| **S_Network** | ✅ Network devices | ✅ Network CVEs | ✅ Config extraction | ✅ Own device creds | ❌ |
| **S_Linux** | ✅ Linux only | ✅ Bitnami CVEs | ✅ Container internals | ❌ (→ S_Recon) | ❌ |
| **S_Windows** | ✅ Windows only | ✅ OS-level RCEs | ✅ Local PrivEsc | ❌ (→ S_Identity) | ❌ |
| **S_Identity** | ❌ | ✅ AD protocol attacks | ✅ DCSync / NTDS | ✅ Domain compromise | ❌ |
| **S_Lateral** | ❌ | ❌ | ✅ PtH / PtT / relay | ✅ Cross-zone credential exec | ❌ |

**Key:** REMOTE = type: REMOTE in CBS YAML (exploitable from network without prior node access). LOCAL = type: LOCAL (requires owning the node first).

---

## Normalized Reward Summary

All five specialists use **identical reward parameters** in standalone training configs:

| Agent | Entry node value | Mid node value | Near-goal value | Terminal goal value | num_goals |
|-------|-----------------|----------------|----------------|--------------------| ----------|
| S_Network | 1000 | 3500 | 6500 | 10000 | 1 |
| S_Linux | 1000 | 3500 | 6500 | 10000 | 1 |
| S_Windows | 1000 | 3500 | 6500 | 10000 | 1 |
| S_Identity | 1000 | 3500 | 6500 | 10000 | 1 |
| S_Lateral | — | — | — | 10000 | 1 |

**Meta-agent training configs (differentiated to enforce ordering):**

| Node | Value | is_goal |
|------|-------|---------|
| All Z4/Z2 intermediate nodes | 500–2500 | false |
| All Z6 intermediate nodes | 500–3000 | false |
| All Z1 intermediate nodes (excl. DC) | 500–3000 | false |
| DomainController | 6000 | **false** |
| CyberArkPAM / highest Z8 target | 10000 | **true** |

DomainController is `is_goal: false` in meta configs — the episode does not terminate there. The meta-agent must learn to continue to the highest-value Z8 node.

---

## Meta-Agent Composition

```
Internet (Z3)
    │  [S_Network exploits Z4+Z2 perimeter]
    ▼
Internet Edge (Z4) → HQ Edge (Z2)
    │  [S_Lateral relays Z2 credentials into Z1 via NTLM relay / WinRM]
    ▼
HQ VLANs (Z1)
    │  [S_Windows compromises Server Farm nodes via OS RCEs]
    ▼
Server Farm (Z1)
    │  [S_Identity DCSync → domain admin]
    ▼
DomainController (Z1) — value 6000, is_goal: false
    │  [S_Lateral ADCS cert / MSSQL xp_cmdshell pivot into Z8]
    ▼
Key Management (Z8) → CyberArkPAM [GOAL — value 10000]

Parallel path:
Internet (Z3) → Z6 WebTier  [S_Linux exploits Bitnami stack]
    │  [S_Lateral reuses cloud IAM creds via LDAP attribute write into Z1]
    ▼
Z6 DataTier → credential relay → Z1
```

Transition triggers for the meta-agent:
- Switch to `S_Lateral` when a zone boundary node has been reached but not the target zone
- Switch to `S_Windows` when Z1 VLAN workstation is compromised
- Switch to `S_Identity` when Z1 domain foothold exists
- Switch to `S_Linux` when AWS WebTier is the entry point
- Fall back to `S_Network` if Z2 is reachable but not yet breached

---

## Domain Config Inventory Required

Tier → train count: small ≤50 nodes → 5 · medium 50–200 → 3 · large 200–500 → 2 · xl 500–1000 → 1

| Agent | Configs (S+M+L+XL) | Train scenarios | Test scenarios (×2) |
|-------|:-----------------:|:---------------:|:-------------------:|
| S_Network | 5+3+2+1 = 11 | 5×5+3×3+2×2+1×1 = 39 | 22 |
| S_Linux | 5+3+2+1 = 11 | 39 | 22 |
| S_Windows | 5+3+2+1 = 11 | 39 | 22 |
| S_Identity | 5+3+2+1 = 11 | 39 | 22 |
| S_Lateral | 5+3+2+1 = 11 | 39 | 22 |
| Meta (4 curriculum stages) | 3+3+2+3 = 11 | 33 | 22 |
| **Total** | **66 configs** | **228 train** | **132 test** |
