# S_Recon Replacement — Options

S_Recon is being scrapped. This document maps what it provided, what it leaves uncovered, and the candidate replacements.

---

## What S_Recon Owned

### In the meta attack path

| Crossing | From | To | Mechanism |
|----------|------|----|-----------|
| Perimeter → HQ | Z2 (HQ Edge) | Z1 (HQ VLANs) | Credential-based connect |
| Cloud → Corp | Z6 (AWS DataTier) | Z1 (HQ VLANs) | Cloud IAM creds reused against AD |
| Domain → PAM | Z1 (DomainController) | Z8 (CyberArkPAM) | DSRM / Golden Ticket / PAM API |

### In standalone training

11 configs across 4 tiers covering credential-extraction mechanics:
- SNMP walk, AWS IMDS, LDAP anon bind, SMB null session, DNS zone transfer
- LSASS dump, LAPS read, BloodHound, Redis noauth, cloud credential files

### Slot in the dataset

1 of 6 agents · 11 configs · 39 train scenarios · 22 test scenarios

Whatever replaces S_Recon must fill this slot exactly — 11 configs, same tier distribution (5+3+2+1).

---

## Coverage Gap Analysis

Without S_Recon, the four remaining specialists cover:

```
Z4 / Z2  ──  S_Network   (firmware / appliance RCEs)
Z6       ──  S_Linux     (Bitnami / container RCEs)
Z1 VLANs ──  S_Windows   (Windows OS RCEs)
Z1 Farm  ──  S_Identity  (AD protocol attacks)
Z8       ──  ??? nobody  (PAM / key management endgame)
```

Three crossings and an entire zone (Z8) are unowned.

**Hard constraint:** the meta-agent's action space is calling lower-level specialists on (source, target) node pairs only. It cannot execute CBS actions directly. All zone crossings must be owned by a specialist.

---

## CVE Database Analysis

The three existing databases and what each covers:

```
network_devices_cves.json  — 240 CVEs, 17 categories
  Cisco (ASA · IOS · Firepower · NX-OS), Palo Alto (PAN-OS · GP),
  Fortinet (FortiGate · SSL VPN), Juniper, Citrix, Checkpoint,
  MikroTik, Netgear, OpenWRT, BGP, OSPF, default_creds

windows_cves.json  — 268 CVEs, 19 categories
  OS layer:     smb · rdp · rpc_dcom · tcp_ip · kernel · iis · hyper_v · dns · bluetooth
  Post-exploit: ntlm_relay · winrm · credential · print_spooler · exchange · mssql · ldap · adcs
  Identity:     active_directory

bitnami_cves.json  — 163 CVEs, 94 services
  Web apps:   wordpress · drupal · moodle · ghost · discourse · mastodon
  DevOps/CI:  jenkins · argo-cd · concourse · gitlab-runner
  Data:       kafka · cassandra · mongodb · postgresql-ha · elasticsearch · grafana
  Identity:   keycloak · oauth2-proxy
  K8s:        cert-manager · nginx-ingress · metallb
  ML/AI:      airflow · mlflow · deepspeed · pytorch · kuberay
```

### Key finding: the Windows CVE database contains two distinct attack surfaces

```
Surface A — OS exploitation (S_Windows owns today)
  smb (initial RCE) · rdp · rpc_dcom · tcp_ip · kernel
  iis · hyper_v · dns · bluetooth

Surface B — Post-exploitation lateral movement (currently unowned)
  ntlm_relay · winrm · credential · print_spooler
  exchange · mssql · ldap · adcs
```

Surface B is not OS exploitation. It is **authenticated lateral movement**:
- NTLM relay requires a network position to intercept credentials — not a code execution exploit
- WinRM remote exec requires credentials, not an RCE
- Exchange NTLM relay, LDAP attribute writes, MSSQL xp_cmdshell all require prior credential access

This is precisely the zone-crossing mechanic S_Recon was providing — and it already exists in `windows_cves.json`.

---

## Eliminated Options

### ~~Option B — Absorb into the Meta-agent~~
**ELIMINATED.** The meta-agent can only call specialists on (source, target) node pairs. It cannot execute CBS actions directly.

### ~~Option A — S_Pivot (generic lateral movement)~~
**ELIMINATED.** Shares the same root flaw as S_Recon: no genuine learnable policy. Once credentials exist the path is deterministic — try all credentials against all reachable nodes. No non-trivial choice for the agent to learn.

---

## Recommended Replacement — S_Lateral

**S_Lateral: Post-Exploitation Lateral Movement**

| Field | Value |
|-------|-------|
| **CVE source** | `windows_cves.json` — lateral movement subset |
| **CVE categories** | `ntlm_relay` · `winrm` · `credential` · `print_spooler` · `exchange` · `mssql` · `ldap` · `adcs` |
| **Zone scope** | All zones — wherever credentials exist |
| **Entry** | Any compromised node with credentials in cache |
| **Terminal goal (standalone)** | First owned node in the target zone |
| **Terminal goal (meta)** | Depends on crossing: Z1 first VLAN node / Z8 first key-mgmt node |

### What S_Lateral learns

Given a credential cache + a set of discovered target nodes, the agent must choose:
- Which credential type to use (NTLM hash · Kerberos ticket · plaintext)
- Which technique matches that credential type (PtH · PtT · NTLM relay · WinRM exec · MSSQL xp_cmdshell)
- Which target node is reachable with the available technique
- In what order to attempt relays when multiple paths exist

This is a non-trivial matching and sequencing problem. The optimal policy depends on what is patched, what ports are open, and which credential type was collected — not just "try everything." A DRL agent must learn the mapping.

### How S_Lateral covers the zone crossings

| Crossing | Technique | CVE category |
|----------|-----------|-------------|
| Z2 → Z1 | NTLM relay from network device creds → Z1 workstation | `ntlm_relay` |
| Z2 → Z1 | WinRM remote exec with stolen creds | `winrm` |
| Z6 → Z1 | LDAP attribute write via cloud IAM → AD Seamless SSO | `ldap` |
| DC → Z8 | ADCS certificate → PAM API auth | `adcs` |
| DC → Z8 | MSSQL xp_cmdshell on Z8 database node | `mssql` |

### CVE source and partition with S_Windows

**Constraint: no agent's vulnerability count may be reduced. Substitution is allowed.**

The 8 lateral movement categories transfer from S_Windows to S_Lateral exclusively. S_Windows substitutes them with expanded OS-level CVEs from `windows_cves.json` (deeper coverage of existing categories: `smb`, `rdp`, `kernel`, `rpc_dcom`, `iis`, `hyper_v`) to maintain or exceed its current count of 268 CVEs.

**Categories transferring out of S_Windows to S_Lateral (87 CVEs):**

| Category | CVEs out |
|----------|:--------:|
| `ntlm_relay` | 8 |
| `ldap` | 8 |
| `adcs` | 7 |
| `credential` | 5 |
| `print_spooler` | 11 |
| `mssql` | 16 |
| `exchange` | 29 |
| `winrm` | 3 |
| **Total** | **87** |

**S_Windows substitution — 4 new categories + expanded kernel:**

Adding new categories is preferred over deepening existing ones. New categories expand S_Windows's attack surface breadth, forcing the agent to learn *when to choose* between techniques — a richer policy problem than having more CVEs within the same technique.

| Category | Type | CVEs (est.) | Why |
|----------|------|:-----------:|-----|
| `office` | NEW | ~15 | Follina · MSHTML injection — most common real-world initial access; not covered anywhere in the pipeline |
| `netlogon` | NEW | ~10 | Zerologon (CVE-2020-1472) — OS-level auth bypass exploitable without credentials |
| `task_scheduler` | NEW | ~12 | SYSTEM privesc via task scheduler DLL hijacking — pure OS, common post-foothold escalation |
| `wmi` | NEW | ~10 | WMI provider host RCE — OS execution engine exploit, distinct from WMI lateral movement |
| `kernel` (expand) | EXPAND | +40 | 45 CVEs available in scraper; go from 3 selected → full pool to fill remaining gap |

**Resulting S_Windows partition:**

| CVE categories | S_Windows | S_Lateral |
|---------------|:---------:|:---------:|
| `smb` · `rdp` · `rpc_dcom` · `tcpip` · `iis` · `hyper_v` · `dns` · `bluetooth` · `workstation` · `active_directory` | ✅ | ❌ |
| `kernel` (expanded to full pool) | ✅ | ❌ |
| `office` · `netlogon` · `task_scheduler` · `wmi` (new) | ✅ | ❌ |
| `ntlm_relay` · `winrm` · `credential` · `print_spooler` · `exchange` · `mssql` · `ldap` · `adcs` | ❌ | ✅ |

**Result:** clean partition — no overlap, count maintained or exceeded. S_Windows owns OS exploitation and initial access. S_Lateral owns post-exploitation lateral movement.

```
S_Windows:  entry = network-accessible node, no credentials
            learns = which OS RCE / initial-access technique gains first foothold

S_Lateral:  entry = already-compromised node WITH credentials in cache
            learns = which relay / exec technique crosses the zone boundary
```

### Reward structure

Follows the simplified structure decided for S_Recon:

| Outcome | Reward |
|---------|--------|
| Any successful credential relay / remote exec (positive result) | +1 |
| Failed or blocked action | 0 |
| Terminal goal reached | +1000 |

---

## Downstream Impact

| Item | Change required |
|------|----------------|
| `data/vulnerability_db/windows_cves.json` | Scrape and add 4 new categories: `office` · `netlogon` · `task_scheduler` · `wmi`; expand `kernel` to full pool |
| `agents/README.md` action space matrix | Add S_Lateral row; update S_Windows row (new categories, removed lateral movement) |
| `prompts/reference/agents/s_windows.md` | Replace lateral movement categories with `office` · `netlogon` · `task_scheduler` · `wmi` · expanded `kernel` |
| `prompts/reference/agents/s_recon.md` | Delete — replaced by `s_lateral.md` |
| `prompts/reference/agents/s_lateral.md` | Create new spec |
| `tasks/srec/` directory | Delete all 10 pending task files + README entry |
| `tasks/slat/` directory | Create 10 new task files (5+3+2+1 tier distribution) |
| `tasks/swin/` | Review 5 small task files — `swin_printserver_v1` and `swin_mssql_entry_v1` used categories now owned by S_Lateral; replace with `office` and `netlogon` focused scenarios |
| `tasks/README.md` | Replace S_Recon section with S_Lateral |
| Meta-agent configs | Update transition triggers: replace `S_Recon` with `S_Lateral` |
| `CLAUDE.md` | Update agent table |

---

## Open Questions

1. For S_Lateral small configs (≤50 nodes): each small config should isolate one lateral movement technique (e.g., `slat_ntlm_relay_v1`, `slat_winrm_v1`, `slat_mssql_v1`). Is technique-isolation appropriate here, or should small configs chain two techniques?
2. Does Z8 remain unowned after this change? S_Lateral covers DC→Z8 via ADCS and MSSQL, but is that sufficient or does Z8 need its own specialist?
3. Should `print_spooler` stay in S_Lateral or move back to S_Windows? PrintNightmare triggers NTLM coercion (lateral movement) but exploits the Windows Print Spooler service (OS).
