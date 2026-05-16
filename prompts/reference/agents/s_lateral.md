# Agent 5: S_Lateral — Post-Exploitation Lateral Movement Specialist

**Zones:** All zones — wherever stolen credentials exist  
**CVE source:** `windows_cves.json` (lateral movement subset — exclusive ownership)  
**Terminal goal (standalone):** First owned node in the target zone (value 10000, is_goal: true)

**Scope:** S_Lateral specializes in the full **credential lifecycle**: extraction, then relay. It fires LOCAL `credential_leak` techniques (Mimikatz_LSASS, LAPS_Password_Read, etc.) on owned nodes to populate the credential store, then selects the correct relay or remote-execution technique to cross a zone boundary. It does not exploit OS memory corruption bugs and does not probe services — those belong to surface specialists. Cloud-specific credential extraction (Container_EnvVars, AWS_CredFile) stays with S_Linux.

**CBS mechanic split (D-A3):**
- `credential_leak` solvability entry → **active**: S_Lateral chooses to fire the LOCAL loot action on an owned node → credential enters the store.
- `LEAK_KNOWN_CREDENTIALS` constraint → **passive**: CBS engine fires automatically when the node holding the constraint is owned — no agent action required.

---

## Action Types

| CBS Action Category | type | Allowed? | Rationale |
|--------------------|------|----------|-----------|
| `probe` vulnerabilities | — | ❌ No | S_Windows / S_Network own OS fingerprinting |
| `remote_access` solvability | — | ❌ No | OS RCEs belong to S_Windows / S_Network / S_Linux |
| `credential_leak` solvability | LOCAL | ✅ Yes | Extraction: Mimikatz_LSASS, LAPS_Password_Read, GPP_Password_Decryption, WinRM_Credential_Cache — populates store for relay (D-A1) |
| `discovery` solvability | — | ❌ No | Not S_Lateral's role |
| `lateral_movement` solvability | REMOTE | ✅ Yes | NTLM relay, WinRM remote exec — no RCE needed, creds suffice |
| `lateral_movement` solvability | LOCAL | ✅ Yes | MSSQL xp_cmdshell, Exchange NTLM relay — requires owning source node |
| `goal_access` solvability | LOCAL | ✅ Yes | First node in target zone reached via credential use |

---

## What S_Lateral Learns

Given credential cache + discovered target nodes, the agent must choose:
- **Which credential type to use** — NTLM hash · Kerberos ticket · plaintext password
- **Which technique matches that credential** — PtH · PtT · NTLM relay · WinRM exec · MSSQL xp_cmdshell · ADCS cert auth
- **Which target node is reachable** with the available technique and port access
- **Execution order** when multiple relay paths exist and some are patched

This is a non-trivial matching and sequencing problem. The optimal policy depends on what is patched, which ports are open, and which credential type was collected. A DRL agent must learn the credential-type × technique × target mapping.

---

## Standalone Episode Flow (D-A2)

No seeded breach — S_Lateral bootstraps credentials itself:

1. **Step 1 — Extraction (LOCAL `credential_leak`):** S_Lateral fires a LOCAL extraction technique on the breach node (e.g., `Solvability.Mimikatz_LSASS`). Credential enters the store.
2. **Steps 2–N — Relay / Exec (`lateral_movement`):** S_Lateral uses the extracted credential to cross zone boundaries via relay, WinRM exec, MSSQL xp_cmdshell, ADCS cert auth, etc.
3. **Terminal:** First node in the target zone owned → episode ends.

The breach node is pre-owned (SR 1.0, `breach_node` property) but **credential store starts empty**. There is no dummy `credential_leak` seed entry needed.

---

## Extraction Techniques (`credential_leak` — type: LOCAL)

| Name | Technique | Required Properties | SR |
|------|-----------|---------------------|----|
| `Solvability.Mimikatz_LSASS` | LSASS memory dump → NTLM hashes + Kerberos tickets | `Windows`, `DomainJoined` | 0.85 |
| `Solvability.LAPS_Password_Read` | Read LAPS local admin password from AD attribute | `Windows`, `DomainJoined`, `DomainController` | 0.75 |
| `Solvability.GPP_Password_Decryption` | Decrypt Group Policy Preferences cpassword | `Windows`, `DomainJoined` | 0.70 |
| `Solvability.WinRM_Credential_Cache` | Extract WinRM credential cache from DPAPI | `Windows`, `DomainJoined`, `WinRM` | 0.65 |

These are the LOCAL loot actions that populate the credential store. Only S_Lateral may use `credential_leak` solvability entries (S_Windows may not).

---

## CVE Categories (Exclusive to S_Lateral)

| Category | CVEs | Description |
|----------|:----:|-------------|
| `ntlm_relay` | 8 | NTLM hash relay via Responder/ntlmrelayx — requires network position |
| `winrm` | 3 | WinRM remote exec with stolen credentials |
| `credential` | 5 | Credential reuse techniques (PtH, PtT, pass-the-ticket) |
| `print_spooler` | 11 | PrintNightmare / SpoolSample NTLM coercion → hash relay |
| `exchange` | 29 | Exchange NTLM relay, PrivExchange, ProxyNotShell (credential-required) |
| `mssql` | 16 | MSSQL xp_cmdshell with DA/SA creds, linked server traversal |
| `ldap` | 8 | LDAP attribute writes (Shadow Credentials, Resource-Based Constrained Delegation) |
| `adcs` | 7 | ADCS certificate request → Kerberos auth → PAM API |
| **Total** | **87** | |

These 8 categories transfer exclusively from `windows_cves.json` and are not available to S_Windows.

---

## Vulnerabilities

### NTLM Relay / WinRM (type: REMOTE — requires credential, not RCE)
| Name | Category | SR | Source Node | Target Technique |
|------|----------|----|------------|-----------------|
| `Solvability.NTLM_Relay_SMB` | ntlm_relay | 0.72 | Any domain-joined | SMB NTLM relay → captured machine hash |
| `Solvability.NTLM_Relay_LDAP` | ntlm_relay | 0.68 | Any domain-joined | NTLM relay → LDAP attribute write (RBCD) |
| `Solvability.WinRM_Exec_Hash` | winrm | 0.75 | AdminWorkstation | WinRM remote exec using NTLM hash |
| `Solvability.WinRM_Exec_Ticket` | winrm | 0.70 | AdminWorkstation | WinRM remote exec using Kerberos TGT |

### Print Spooler Coercion (type: LOCAL — requires owning source)
| Name | CVE | SR | Source Node | Target Technique |
|------|-----|----|------------|-----------------|
| `Solvability.PrintNightmare_LocalPrivEsc` | CVE-2021-1675 | 0.88 | PrintServer, FileServer | Print Spooler LOCAL privilege escalation → SYSTEM |
| `Solvability.PrintNightmare` | CVE-2021-34527 | 0.88 | PrintServer | Print Spooler REMOTE RCE via credential coercion |
| `Solvability.SpoolSample_Coerce` | print_spooler | 0.75 | Any PrintServer | SpoolSample NTLM coercion → hash relay to DC |

### Exchange / MSSQL Remote Execution (type: LOCAL)
| Name | Category | SR | Source Node | Target Technique |
|------|----------|----|------------|-----------------|
| `Solvability.Exchange_NTLM_Relay` | exchange | 0.78 | ExchangeServer | Exchange NTLM relay → domain machine account |
| `Solvability.PrivExchange` | exchange | 0.72 | ExchangeServer | PrivExchange DA → relay Exchange machine account |
| `Solvability.MSSQL_xpCmdshell` | mssql | 0.80 | MSSQLServer | xp_cmdshell OS exec with SA/DA credentials |
| `Solvability.MSSQL_LinkedServer` | mssql | 0.65 | MSSQLServer | Linked server traversal across database network |

### LDAP / ADCS Certificate Chain (type: LOCAL)
| Name | Category | SR | Source Node | Target Technique |
|------|----------|----|------------|-----------------|
| `Solvability.ShadowCredentials` | ldap | 0.70 | DomainController | LDAP msDS-KeyCredentialLink write → PKINIT auth |
| `Solvability.RBCD_Write` | ldap | 0.68 | DomainController | Resource-Based Constrained Delegation via LDAP write |
| `Solvability.ADCS_ESC1` | adcs | 0.75 | ADCS_Server | ESC1 template → certificate request → PAM API auth |
| `Solvability.ADCS_ESC8` | adcs | 0.72 | ADCS_Server | ESC8 Web Enrollment NTLM relay → domain cert |

---

## Zone Crossings Owned by S_Lateral

| Crossing | Source | Target | Technique | CVE Category |
|----------|--------|--------|-----------|-------------|
| Perimeter → HQ | Z2 (HQ Edge) | Z1 (HQ VLANs) | NTLM relay from network device creds → Z1 workstation | `ntlm_relay` |
| Perimeter → HQ | Z2 (HQ Edge) | Z1 (HQ VLANs) | WinRM remote exec with stolen creds | `winrm` |
| Cloud → Corp | Z6 (AWS DataTier) | Z1 (HQ VLANs) | LDAP attribute write via cloud IAM → AD Seamless SSO | `ldap` |
| DC → PAM | Z1 (DomainController) | Z8 (CyberArkPAM) | ADCS certificate → PAM API authentication | `adcs` |
| DC → PAM | Z1 (DomainController) | Z8 (PAM DB node) | MSSQL xp_cmdshell on Z8 database node | `mssql` |

---

## Services and Ports

| Service | Primary Ports | Protocol | GLOBALTECH Zone |
|---------|--------------|----------|----------------|
| `DomainController` | 88, 389, 445, 636, 3268 | Kerberos, LDAP, SMB | Z1 Server Farm |
| `ExchangeServer` | 443, 80, 135 | HTTPS, SMTP, RPC | Z1 Server Farm |
| `MSSQLServer` | 1433, 445 | MSSQL, SMB | Z1 Server Farm / Z8 |
| `PrintServer` | 445, 9100 | SMB, RAW | Z1 Server Farm |
| `ADCS_Server` | 80, 443, 135 | HTTP, HTTPS, RPC | Z1 Server Farm |
| `AdminWorkstation` | 5985, 5986, 3389 | WinRM, RDP | Z1 HQ VLANs |
| `CyberArkPAM` | 443, 8080 | HTTPS | Z8 PAM |
| Any domain-joined node | 445, 5985 | SMB, WinRM | All zones |

---

## Goal Specification (Standalone)

```yaml
goal_config:
  num_goals: 1
  selection_strategy: diverse

# S_Lateral entry: any pre-owned source node with credentials in cache
# S_Lateral goal: first node in the target zone reached via credential technique

SourceNode:   value: 0      is_goal: false   # Pre-owned by upstream specialist (not scored)
MidNode:      value: 3500   is_goal: false   # Intermediate lateral move
TargetEntry:  value: 10000  is_goal: true    # TERMINAL GOAL — first node in target zone
```

**Small config technique isolation:** each small config isolates one lateral movement technique:

| Config | Technique isolated | CVE category |
|--------|--------------------|-------------|
| `slat_ntlm_relay_v1` | NTLM relay only | `ntlm_relay` |
| `slat_winrm_creds_v1` | WinRM with hash | `winrm` |
| `slat_mssql_lateral_v1` | xp_cmdshell with SA creds | `mssql` |
| `slat_exchange_relay_v1` | Exchange NTLM coercion | `exchange` |
| `slat_adcs_cert_v1` | ADCS ESC1 → PAM auth | `adcs` |

---

## Reward Structure

| Outcome | Reward |
|---------|--------|
| Any successful credential relay / remote exec (positive CBS result) | +1 |
| Failed or blocked action | 0 |
| Terminal goal reached | +1000 |

Binary step signal (+1 / 0) plus large terminal bonus. All positive outcomes are equal weight regardless of credential type or technique.
