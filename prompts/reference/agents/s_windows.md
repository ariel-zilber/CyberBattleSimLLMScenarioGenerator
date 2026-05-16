# Agent 3: S_Windows — OS Exploitation Specialist

**Zones:** Z1 HQ VLANs + Z1 Server Farm  
**CVE source:** `windows_cves.json` (OS exploitation + initial access subset)  
**Terminal goal (standalone):** `DomainController` (value 10000, is_goal: true)

**Scope:** S_Windows specializes strictly in **OS-level and application-level memory/logic flaws**. Its policy maps `(Windows version, service) → specific RCE exploit`. It does not touch Kerberos, NTLM relay, or any AD protocol — those belong to S_Identity.

---

## Action Types

| CBS Action Category | type | Allowed? | Rationale |
|--------------------|------|----------|-----------|
| `probe` vulnerabilities | REMOTE | ✅ Yes | Windows version fingerprinting before CVE selection |
| `remote_access` solvability | REMOTE | ✅ Yes | OS/application RCEs: EternalBlue, BlueKeep, ProxyLogon |
| `remote_access` solvability | LOCAL | ✅ Yes | Local privilege escalation after initial RCE |
| `credential_leak` solvability | — | ❌ No | S_Lateral owns post-exploitation credential extraction (Mimikatz, LAPS) and relay |
| `discovery` solvability | — | ❌ No | S_Lateral |
| `goal_access` solvability | — | ❌ No | DCSync belongs to S_Identity |

---

## Vulnerabilities

### Probe Vulnerabilities (type: REMOTE, SR 1.0)
| Name | OS Target |
|------|-----------|
| `Remote.Probe.Windows` | Windows (any) |
| `Remote.Probe.WindowsServer` | Windows Server (banner version) |

### Remote Access Vulnerabilities (type: REMOTE)
| Name | CVE | CVSS | SR | Service | Attack |
|------|-----|------|----|---------|--------|
| `Solvability.SMBGhost` | CVE-2020-0796 | 10.0 | 0.90 | FileServer, MSSQLServer | SMBv3 compression RCE (Win10 1903/1909) |
| `Solvability.MS08_067` | CVE-2008-4250 | 10.0 | 0.90 | FileServer | Server service RCE (WinXP/2003/2008) |
| `Solvability.SIGRed` | CVE-2020-1350 | 10.0 | 0.90 | DomainController | Windows DNS Server RCE via worm-capable vuln |
| `Solvability.HyperV_RCE` | CVE-2021-28476 | 9.9 | 0.90 | HyperVHost | Hyper-V guest→host RCE |
| `Solvability.BlueKeep` | CVE-2019-0708 | 9.8 | 0.90 | SalesWorkstation, AdminWorkstation | Pre-auth RDP RCE (Win7/2008) |
| `Solvability.DejaBlue` | CVE-2019-1182 | 9.8 | 0.90 | SalesWorkstation | RDP RCE variant (Win8.1/2012R2+) |
| `Solvability.RDP_RCE_1226` | CVE-2019-1226 | 9.8 | 0.90 | AdminWorkstation | RDP RCE (Win10/Server 2019) |
| `Solvability.IIS_HTTP_Stack` | CVE-2021-31166 | 9.8 | 0.90 | IISServer | HTTP.sys RCE (Win10/Server 2019) |
| `Solvability.IIS_RCE` | CVE-2022-21907 | 9.8 | 0.90 | IISServer | HTTP Protocol Stack RCE |
| `Solvability.Exchange_NTLM_Relay` | CVE-2024-21410 | 9.8 | 0.90 | ExchangeServer | Exchange Server NTLM relay → EoP/RCE (outcome is OS-level code execution; contrast S_Identity `NTLM_Relay_LDAP` whose outcome is AD attribute mutation) |
| `Solvability.TCPIP_RCE_1` | CVE-2021-24074 | 9.8 | 0.90 | FileServer | Windows TCP/IP RCE via IPv4 source routing |
| `Solvability.TCPIP_RCE_2` | CVE-2021-24094 | 9.8 | 0.90 | FileServer | Windows TCP/IP RCE via IPv6 |
| `Solvability.NFS_RCE_TCPIP` | CVE-2022-34715 | 9.8 | 0.90 | FileServer | Windows NFS RCE (TCP/IP stack) |
| `Solvability.HTTP3_RCE` | CVE-2023-23392 | 9.8 | 0.90 | IISServer | HTTP/3 Protocol Stack RCE |
| `Solvability.DNS_RCE_1` | CVE-2021-26897 | 9.8 | 0.90 | DomainController | Windows DNS Server zone-signing RCE |
| `Solvability.RPC_RCE_2` | CVE-2022-26809 | 9.8 | 0.90 | DomainController, FileServer | RPC Runtime RCE via MS-RPCE |
| `Solvability.WSD_RCE` | CVE-2023-28250 | 9.8 | 0.90 | FileServer | Windows Web Services Discovery RCE |
| `Solvability.iSCSI_RCE` | CVE-2023-21803 | 9.8 | 0.90 | FileServer | iSCSI Discovery Service RCE |
| `Solvability.RDP_Gateway_RCE_1` | CVE-2020-0609 | 9.8 | 0.90 | RDGateway | RD Gateway pre-auth RCE |
| `Solvability.RDP_Gateway_RCE_2` | CVE-2020-0610 | 9.8 | 0.90 | RDGateway | RD Gateway pre-auth RCE variant |
| `Solvability.Exchange_RCE_2018_1` | CVE-2018-8154 | 9.8 | 0.90 | ExchangeServer | Exchange Server RCE |
| `Solvability.Exchange_RCE_2018_2` | CVE-2018-8302 | 9.8 | 0.90 | ExchangeServer | Exchange RCE via memory corruption |
| `Solvability.Exchange_RCE_2019` | CVE-2019-0586 | 9.8 | 0.90 | ExchangeServer | Exchange RCE via crafted email |
| `Solvability.MSSQL_BufferOverflow` | CVE-2018-8273 | 9.8 | 0.90 | MSSQLServer | SQL Server buffer overflow RCE |
| `Solvability.DNS_UAF_2016` | CVE-2016-3227 | 9.8 | 0.90 | DomainController | DNS Server use-after-free RCE |
| `Solvability.DNS_WinSearch_RCE` | CVE-2017-11771 | 9.8 | 0.90 | DomainController | Windows Search RCE via DNS |
| `Solvability.DNS_RCE_2018` | CVE-2018-8626 | 9.8 | 0.90 | DomainController | DNS Server heap OOB RCE |
| `Solvability.HyperV_RCE_2016` | CVE-2016-0088 | 9.3 | 0.90 | HyperVHost | Hyper-V guest→host RCE (Server 2012R2) |
| `Solvability.ProxyShell` | CVE-2021-34473 | 9.1 | 0.90 | ExchangeServer | Exchange URL normalization bypass → RCE |
| `Solvability.ProxyLogon` | CVE-2021-26855 | 9.1 | 0.90 | ExchangeServer | Exchange pre-auth SSRF → RCE |
| `Solvability.HyperV_RCE_2019` | CVE-2019-0719 | 9.1 | 0.90 | HyperVHost | Hyper-V guest→host RCE (Server 2019) |

### Local Access Vulnerabilities (type: LOCAL — require owning the node first)
| Name | CVE | SR | Service | Attack |
|------|-----|----|---------|--------|
| `Solvability.SeImpersonatePrivEsc` | AD technique | 0.75 | All Windows nodes | Token impersonation → SYSTEM (JuicyPotato/RoguePotato) |
| `Solvability.AlwaysInstallElevated` | Misconfiguration | 0.70 | SalesWorkstation | MSI installer privilege escalation |
| `Solvability.UnquotedServicePath` | Misconfiguration | 0.65 | All Windows nodes | Unquoted service path hijack → SYSTEM |
| `Solvability.DLLHijacking_Windows` | Misconfiguration | 0.62 | AdminWorkstation | DLL search order hijack in writable path |
| `Solvability.Schtasks_EOP_1` | CVE-2019-1069 | 0.72 | All Windows nodes | Task Scheduler junction point → SYSTEM |
| `Solvability.Schtasks_EOP_2` | CVE-2019-1170 | 0.72 | All Windows nodes | Task Scheduler XML parser arbitrary write → SYSTEM |
| `Solvability.Schtasks_EOP_3` | CVE-2022-21960 | 0.72 | All Windows nodes | Task Scheduler DLL hijack → SYSTEM |
| `Solvability.Schtasks_EOP_4` | CVE-2023-21541 | 0.72 | All Windows nodes | Task Scheduler COM access control EoP → SYSTEM |

### Initial Access Vulnerabilities — Office / Document (type: REMOTE — user-interaction)
| Name | CVE | CVSS | SR | Service | Attack |
|------|-----|------|----|---------|--------|
| `Solvability.Follina` | CVE-2022-30190 | 7.8 | 0.75 | SalesWorkstation, AdminWorkstation | MSDT RCE via malicious Office document (no macros) |
| `Solvability.OfficeHTML_RCE` | CVE-2023-36884 | 8.3 | 0.78 | SalesWorkstation, FinanceWorkstation | Office HTML RCE bypassing Mark-of-the-Web |
| `Solvability.Outlook_Moniker` | CVE-2024-21413 | 9.8 | 0.88 | AdminWorkstation | Outlook Moniker Link RCE (no user interaction) |
| `Solvability.Office_RCE_1` | CVE-2022-21840 | 8.8 | 0.78 | SalesWorkstation | Office memory corruption RCE via crafted doc |
| `Solvability.Word_RCE` | CVE-2022-41031 | 7.8 | 0.72 | SalesWorkstation, FinanceWorkstation | Word memory handling RCE via crafted .docx |

### Initial Access Vulnerabilities — Netlogon OS Authentication (type: REMOTE)
| Name | CVE | CVSS | SR | Service | Attack |
|------|-----|------|----|---------|--------|
| `Solvability.Netlogon_EOP_1` | CVE-2022-38023 | 8.1 | 0.70 | DomainController | Netlogon session key brute-force → domain auth bypass |
| `Solvability.Netlogon_InfDisc` | CVE-2023-21526 | 7.4 | 0.65 | DomainController | Netlogon session key leak → forge domain requests |
| `Solvability.Netlogon_Vuln` | CVE-2023-21728 | 7.5 | 0.68 | DomainController | Netlogon service crash → domain authentication DoS |

### Initial Access Vulnerabilities — MSMQ (type: REMOTE — port 1801/TCP)
| Name | CVE | CVSS | SR | Service | Attack |
|------|-----|------|----|---------|--------|
| `Solvability.QueueJumper` | CVE-2023-21554 | 9.8 | 0.88 | MSMQServer | MSMQ unauthenticated SYSTEM RCE via port 1801 |
| `Solvability.MSMQ_RCE_2` | CVE-2023-35309 | 8.8 | 0.78 | MSMQServer | MSMQ heap overflow RCE from adjacent network |
| `Solvability.MSMQ_RCE_4` | CVE-2024-30080 | 9.8 | 0.88 | MSMQServer | MSMQ use-after-free unauthenticated SYSTEM RCE |

---

## Services and Ports

| Service | Primary Ports | Protocol | OS | GLOBALTECH Zone |
|---------|--------------|----------|----|----------------|
| `DomainController` | 88, 389, 636, 445, 3268, 53 | Kerberos, LDAP, SMB, DNS | Win Server 2019/2022 | Z1 Server Farm |
| `MSSQLServer` | 1433, 445 | MSSQL, SMB | Win Server 2019 | Z1 Server Farm |
| `FileServer` | 445, 139 | SMB, NetBIOS | Win Server 2019/2022 | Z1 Server Farm |
| `ExchangeServer` | 443, 80, 587, 25, 135 | HTTPS, SMTP, RPC | Win Server 2019 | Z1 Server Farm |
| `PrintServer` | 445, 9100 | SMB, RAW | Win Server | Z1 Server Farm |
| `IISServer` | 80, 443 | HTTP, HTTPS | Win Server | Z1 Server Farm |
| `SharePointServer` | 80, 443, 1433 | HTTP, HTTPS, MSSQL | Win Server | Z1 Server Farm |
| `RDGateway` | 443, 3389 | HTTPS, RDP | Win Server | Z1 Server Farm |
| `HyperVHost` | 5985, 3389 | WinRM, RDP | Win Server Core | Z1 Server Farm |
| `MSMQServer` | 1801, 445 | MSMQ, SMB | Win Server | Z1 Server Farm |
| `SalesWorkstation` | 3389, 445 | RDP, SMB | Windows 10/11 | Z1 HQ VLANs |
| `FinanceWorkstation` | 3389, 445 | RDP, SMB | Windows 10 | Z1 HQ VLANs |
| `RnDWorkstation` | 3389, 445 | RDP, SMB | Windows 10 | Z1 HQ VLANs |
| `AdminWorkstation` | 3389, 445, 5985, 5986 | RDP, SMB, WinRM | Windows 10 Pro | Z1 HQ VLANs |

---

## Goal Specification (Standalone)

```yaml
goal_config:
  num_goals: 1
  selection_strategy: diverse

SalesWorkstation:  value: 1000   is_goal: false   # Entry tier (Z1 VLAN entry)
FileServer:        value: 3500   is_goal: false   # Mid tier
MSSQLServer:       value: 6500   is_goal: false   # Near-goal tier
DomainController:  value: 10000  is_goal: true    # TERMINAL GOAL
```
