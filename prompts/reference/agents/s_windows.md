# S_Windows - Windows OS and Application Exploitation Specialist

This file is the authoritative prompt reference for `s_windows` scenario generation.
It is aligned to `/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml`.

## Role

Exploit Windows operating-system, IIS, Exchange, SMB/RDP, MSMQ, Hyper-V, and workstation/server vulnerabilities.

Domain boundary: Windows workstations, Windows servers, SMB, RDP, IIS, Exchange, MSSQL, Hyper-V, MSMQ, file and print servers.

Training scenarios for this specialist must be specialist-style fixed-pair compatible scenarios. In meta scenarios, the same collections define the specialist's usable action and observation surface.

## Fixed Action Collection

The specialist has exactly 50 actions:

| Action kind | Count |
|---|---:|
| Local vulnerabilities | 12 |
| Remote vulnerabilities | 21 |
| Connect ports | 17 |
| Total | 50 |

### Local Vulnerabilities

| Slot | Identifier |
|---:|---|
| 0 | `Solvability.SeImpersonatePrivEsc` |
| 1 | `Solvability.AlwaysInstallElevated` |
| 2 | `Solvability.UnquotedServicePath` |
| 3 | `Solvability.DLLHijacking_Windows` |
| 4 | `Solvability.Schtasks_EOP_1` |
| 5 | `Solvability.Schtasks_EOP_2` |
| 6 | `Solvability.Schtasks_EOP_3` |
| 7 | `Solvability.Schtasks_EOP_4` |
| 8 | `Solvability.Mimikatz_NTLM` |
| 9 | `Solvability.SAM_Dump` |
| 10 | `Solvability.LSA_Secrets` |
| 11 | `Solvability.HiveNightmare` |

### Remote Vulnerabilities

| Slot | Identifier |
|---:|---|
| 0 | `Solvability.SMBGhost` |
| 1 | `Solvability.MS08_067` |
| 2 | `Solvability.SIGRed` |
| 3 | `Solvability.BlueKeep` |
| 4 | `Solvability.DejaBlue` |
| 5 | `Solvability.RDP_RCE_1226` |
| 6 | `Solvability.IIS_HTTP_Stack` |
| 7 | `Solvability.IIS_RCE` |
| 8 | `Solvability.TCPIP_RCE_1` |
| 9 | `Solvability.TCPIP_RCE_2` |
| 10 | `Solvability.NFS_RCE_TCPIP` |
| 11 | `Solvability.HTTP3_RCE` |
| 12 | `Solvability.DNS_RCE_1` |
| 13 | `Solvability.RPC_RCE_2` |
| 14 | `Solvability.WSD_RCE` |
| 15 | `Solvability.iSCSI_RCE` |
| 16 | `Solvability.ProxyShell` |
| 17 | `Solvability.ProxyLogon` |
| 18 | `Solvability.QueueJumper` |
| 19 | `Solvability.HyperV_RCE` |
| 20 | `Solvability.Follina` |

### Connect Ports

| Slot | Identifier |
|---:|---|
| 0 | `HTTP` |
| 1 | `HTTPS` |
| 2 | `SMB` |
| 3 | `RDP` |
| 4 | `WinRM` |
| 5 | `FTP` |
| 6 | `SMTP` |
| 7 | `DNS` |
| 8 | `MSSQL` |
| 9 | `MySQL` |
| 10 | `PostgreSQL` |
| 11 | `VNC` |
| 12 | `Telnet` |
| 13 | `SNMP` |
| 14 | `NetBIOS` |
| 15 | `Kerberos` |
| 16 | `WMI` |

## Observation Context Collection

The scenario generator should preferentially use these service and property identifiers for this specialist. These are not extra actions; they are the specialist's observation context and vocabulary guidance.

| Context type | Count |
|---|---:|
| Service IDs | 27 |
| Property IDs | 44 |

### Service IDs

| Slot | Identifier |
|---:|---|
| 0 | `DomainController` |
| 1 | `MSSQLServer` |
| 2 | `FileServer` |
| 3 | `ExchangeServer` |
| 4 | `PrintServer` |
| 5 | `IISServer` |
| 6 | `SharePointServer` |
| 7 | `RDGateway` |
| 8 | `HyperVHost` |
| 9 | `MSMQServer` |
| 10 | `SalesWorkstation` |
| 11 | `FinanceWorkstation` |
| 12 | `RnDWorkstation` |
| 13 | `AdminWorkstation` |
| 14 | `iis_svc` |
| 15 | `smbd` |
| 16 | `winrm_svc` |
| 17 | `rdp_svc` |
| 18 | `mssql_svc` |
| 19 | `exchange_svc` |
| 20 | `print_spooler_svc` |
| 21 | `lsass` |
| 22 | `winlogon` |
| 23 | `dsapiservice` |
| 24 | `kdc` |
| 25 | `wsus_svc` |
| 26 | `wmi_svc` |

### Property IDs

| Slot | Identifier |
|---:|---|
| 0 | `Windows` |
| 1 | `Win7` |
| 2 | `Win10` |
| 3 | `Win11` |
| 4 | `Win2008` |
| 5 | `Win2012` |
| 6 | `Win2016` |
| 7 | `Win2019` |
| 8 | `Win2022` |
| 9 | `WinXP` |
| 10 | `Win8` |
| 11 | `Win2003` |
| 12 | `Workstation` |
| 13 | `LegacyWorkstation` |
| 14 | `AdminWorkstation` |
| 15 | `DeveloperWorkstation` |
| 16 | `LaptopUser` |
| 17 | `ModernWorkstation` |
| 18 | `IISServer` |
| 19 | `FileServer` |
| 20 | `PrintServer` |
| 21 | `MailServer` |
| 22 | `HyperVHost` |
| 23 | `MSMQServer` |
| 24 | `DatabaseServer` |
| 25 | `MSSQLServer` |
| 26 | `DomainController` |
| 27 | `ADCS` |
| 28 | `LDAPServer` |
| 29 | `ADIntegrated` |
| 30 | `Unpatched` |
| 31 | `Misconfigured` |
| 32 | `DomainJoined` |
| 33 | `DomainAdmin` |
| 34 | `LocalAdmin` |
| 35 | `NoLAPS` |
| 36 | `NTLMRelayable` |
| 37 | `WebServer` |
| 38 | `AppServer` |
| 39 | `Middleware` |
| 40 | `BackupServer` |
| 41 | `AuthServer` |
| 42 | `IdentityProvider` |
| 43 | `CertAuthority` |

## Generation Rules

- Use only identifiers from this file and the shared global vocabulary.
- Do not invent probe actions such as `Remote.Probe.*`.
- Do not use legacy scenario-only identifiers such as `External.*` or `Local.*`.
- Do not use off-vocabulary ports such as `BGP` or `Redis`; represent those concepts through service IDs or properties when needed.
- Every vulnerability emitted for this specialist must be one of the local or remote IDs listed above.
- Connect actions are represented only by the listed port names.
- Credentials are runtime objects, not vocabulary entries. They should target one of the listed services/ports and support valid fixed-pair connect actions.
- Multi-goal scenarios are allowed, but specialist actions must remain inside this 50-action collection.

## Scenario Intent

Use Windows remote exploits and local privilege escalation to obtain user/admin/system access on Windows nodes.
