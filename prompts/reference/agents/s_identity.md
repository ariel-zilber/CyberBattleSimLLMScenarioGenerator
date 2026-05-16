# Agent 4: S_Identity — Active Directory Specialist

**Zones:** Z1 Server Farm (AD protocol layer)  
**CVE source:** `windows_cves.json` (AD techniques subset)  
**Terminal goal (standalone):** `DomainController` (value 10000, is_goal: true)

**Scope:** AD protocol abuse requires recognizing `(DomainJoined, ADCS_present, SPN_count, delegation_type)` — completely different input features from the memory-address/OS-version features that drive S_Windows RCE selection. S_Identity does not probe OS versions or use memory exploits.

---

## Action Types

| CBS Action Category | type | Allowed? | Rationale |
|--------------------|------|----------|-----------|
| `probe` vulnerabilities | — | ❌ No | Rely on S_Windows / S_Recon to establish OS and domain context |
| `remote_access` solvability | REMOTE | ✅ Yes | AS-REP Roasting (no creds needed), Kerberoasting (domain creds), coercion attacks |
| `remote_access` solvability | LOCAL | ✅ Yes | NTLM relay, pass-the-hash, token impersonation (require foothold) |
| `credential_leak` solvability | — | ❌ No | S_Recon |
| `discovery` solvability | — | ❌ No | S_Recon |
| `goal_access` solvability | LOCAL | ✅ Yes | DCSync, NTDS dump, Golden Ticket — require domain-admin or DC access |

---

## Vulnerabilities

### Remote Access Vulnerabilities (type: REMOTE — usable from network without prior local access)
| Name | Technique / CVE | SR | Service | Attack |
|------|----------------|----|---------|-|
| `Solvability.ASREPRoasting` | AD technique | 0.55 | DomainController | Pre-auth disabled accounts — TGT request without creds |
| `Solvability.Kerberoasting` | AD technique | 0.60 | DomainController | SPN enumeration + TGS request → offline crack |
| `Solvability.PrinterBug_Coercion` | AD technique | 0.85 | PrintServer | MS-RPRN coerce machine auth → relay |
| `Solvability.PetitPotam` | AD technique | 0.75 | DomainController | MS-EFSRPC coerce machine auth → relay |
| `Solvability.UnconstrainedDelegation` | AD technique | 0.65 | DomainController | Abuse TGT cached in memory of delegated server |
| `Solvability.ShadowCredentials` | AD technique | 0.60 | DomainController | msDS-KeyCredentialLink → PKINIT auth |

### Local Access Vulnerabilities (type: LOCAL — require domain foothold)
| Name | Technique / CVE | SR | Service | Attack |
|------|----------------|----|---------|-|
| `Solvability.PassTheHash` | AD technique | 0.65 | All Windows nodes | NTLM hash reuse without cracking |
| `Solvability.NTLM_Relay_LDAP` | AD technique | 0.58 | FileServer, MSSQLServer | Relay NTLM auth to LDAP → write AD attributes |
| `Solvability.ZeroLogon` | CVE-2020-1472 | 0.70 | DomainController | Netlogon machine account password reset |
| `Solvability.ConstrainedDelegation_S4U` | AD technique | 0.60 | IISServer | S4U2Self/S4U2Proxy impersonation |
| `Solvability.RBCD_Attack` | AD technique | 0.55 | All Windows nodes | Resource-based constrained delegation write → impersonation |
| `Solvability.SilverTicket` | AD technique | 0.70 | MSSQLServer, FileServer | Forged service ticket → local access without DC |
| `Solvability.TokenImpersonation` | AD technique | 0.52 | All Windows nodes | SeImpersonatePrivilege → token theft |

### Goal Access Vulnerabilities (type: LOCAL — require domain-admin or DC-level access)
| Name | Technique / CVE | SR | Service | What it achieves |
|------|----------------|----|---------|-|
| `Solvability.DCSync` | AD technique | 0.60 | DomainController | Mimic DC replication → dump all NTLM hashes |
| `Solvability.NTDS_Dump` | AD technique | 0.60 | DomainController | VSS shadow copy → ntds.dit + SYSTEM hive |
| `Solvability.GoldenTicket` | AD technique | 0.55 | DomainController | KRBTGT hash → forged TGT; valid 10 years |
| `Solvability.ADCS_ESC1` | CVE-2022-26923 | 0.60 | ADCS_Server | Misconfigured cert template → domain admin cert |
| `Solvability.ADCS_ESC6` | AD technique | 0.60 | ADCS_Server | EDITF_ATTRIBUTESUBJECTALTNAME2 → arbitrary SAN |
| `Solvability.DCShadow` | AD technique | 0.60 | DomainController | Rogue DC replication → inject AD objects |
| `Solvability.DSRM_Abuse` | AD technique | 0.70 | DomainController | DSRM password sync → persistent local admin |

---

## Services and Ports

| Service | Primary Ports | Protocol | OS | GLOBALTECH Zone |
|---------|--------------|----------|----|----------------|
| `DomainController` | 88, 389, 636, 445, 3268, 53 | Kerberos, LDAP, LDAPS, SMB, GC, DNS | Win Server 2019/2022 | Z1 Server Farm |
| `ADCS_Server` | 443, 80, 135 | HTTPS, HTTP, RPC (enrollment) | Win Server 2019 | Z1 Server Farm |
| `MSSQLServer` | 1433, 445 | MSSQL, SMB | Win Server 2019 | Z1 Server Farm |
| `FileServer` | 445, 139 | SMB, NetBIOS | Win Server | Z1 Server Farm |
| `IISServer` | 80, 443 | HTTP, HTTPS | Win Server | Z1 Server Farm |
| `PrintServer` | 445 | SMB (MS-RPRN) | Win Server | Z1 Server Farm |

---

## Goal Specification (Standalone)

```yaml
goal_config:
  num_goals: 1
  selection_strategy: diverse

SalesWorkstation:  value: 1000   is_goal: false   # Entry handoff from S_Windows
MSSQLServer:       value: 3500   is_goal: false   # Mid tier (SilverTicket target)
ADCS_Server:       value: 6500   is_goal: false   # Near-goal (ESC1 chain reward)
DomainController:  value: 10000  is_goal: true    # TERMINAL GOAL (DCSync)
```
