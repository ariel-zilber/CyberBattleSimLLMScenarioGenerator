# S_Lateral - Lateral Movement and Credential Reuse Specialist

This file is the authoritative prompt reference for `s_lateral` scenario generation.
It is aligned to `/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml`.

## Role

Reuse credentials, hashes, tickets, relays, service execution, and post-exploitation primitives across zones.

Domain boundary: Credential relay, WinRM/SMB/LDAP execution, MSSQL pivots, Exchange relay, ADCS lateral paths, Kerberoasting, credential extraction, and cross-zone movement.

Training scenarios for this specialist must be specialist-style fixed-pair compatible scenarios. In meta scenarios, the same collections define the specialist's usable action and observation surface.

## Fixed Action Collection

The specialist has exactly 50 actions:

| Action kind | Count |
|---|---:|
| Local vulnerabilities | 34 |
| Remote vulnerabilities | 4 |
| Connect ports | 12 |
| Total | 50 |

### Local Vulnerabilities

| Slot | Identifier |
|---:|---|
| 0 | `Solvability.Mimikatz_LSASS` |
| 1 | `Solvability.LAPS_Password_Read` |
| 2 | `Solvability.GPP_Password_Decryption` |
| 3 | `Solvability.WinRM_Credential_Cache` |
| 4 | `Solvability.PrintNightmare_LocalPrivEsc` |
| 5 | `Solvability.PrintNightmare` |
| 6 | `Solvability.SpoolSample_Coerce` |
| 7 | `Solvability.Spooler_EOP_1` |
| 8 | `Solvability.Spooler_RCE` |
| 9 | `Solvability.Exchange_NTLM_Relay` |
| 10 | `Solvability.PrivExchange` |
| 11 | `Solvability.ProxyNotShell_NTLM` |
| 12 | `Solvability.Exchange_RCE_Lateral_1` |
| 13 | `Solvability.Exchange_RCE_Lateral_2` |
| 14 | `Solvability.MSSQL_xpCmdshell` |
| 15 | `Solvability.MSSQL_LinkedServer` |
| 16 | `Solvability.MSSQL_RCE_Lateral` |
| 17 | `Solvability.MSSQL_Privesc_Lateral` |
| 18 | `Solvability.ShadowCredentials` |
| 19 | `Solvability.RBCD_Write` |
| 20 | `Solvability.LDAP_AuthBypass_Lateral` |
| 21 | `Solvability.CloudIAM_LDAP_Write` |
| 22 | `Solvability.ADCS_CertSpoof_Lateral` |
| 23 | `Solvability.ADCS_EOP_Lateral` |
| 24 | `Solvability.LSA_Relay` |
| 25 | `Solvability.Outlook_NTLM_Relay` |
| 26 | `Solvability.PetitPotam_Relay` |
| 27 | `Solvability.Kerberoasting` |
| 28 | `Solvability.ASREPRoasting` |
| 29 | `Solvability.SpoolSample` |
| 30 | `Solvability.CLFS_Privesc` |
| 31 | `Solvability.Win_EOP_Cred` |
| 32 | `Solvability.BloodHound_Recon` |
| 33 | `Solvability.LDAP_Enum` |

### Remote Vulnerabilities

| Slot | Identifier |
|---:|---|
| 0 | `Solvability.NTLM_Relay_SMB` |
| 1 | `Solvability.NTLM_Relay_LDAP` |
| 2 | `Solvability.WinRM_Exec_Hash` |
| 3 | `Solvability.WinRM_Exec_Ticket` |

### Connect Ports

| Slot | Identifier |
|---:|---|
| 0 | `SSH` |
| 1 | `HTTP` |
| 2 | `HTTPS` |
| 3 | `SMB` |
| 4 | `RDP` |
| 5 | `WinRM` |
| 6 | `LDAP` |
| 7 | `LDAPS` |
| 8 | `MSSQL` |
| 9 | `SNMP` |
| 10 | `NetBIOS` |
| 11 | `Kerberos` |

## Observation Context Collection

The scenario generator should preferentially use these service and property identifiers for this specialist. These are not extra actions; they are the specialist's observation context and vocabulary guidance.

| Context type | Count |
|---|---:|
| Service IDs | 28 |
| Property IDs | 72 |

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
| 14 | `ADCS_Server` |
| 15 | `CyberArkPAM` |
| 16 | `sshd` |
| 17 | `smbd` |
| 18 | `winrm_svc` |
| 19 | `ldap_svc` |
| 20 | `ldaps_svc` |
| 21 | `mssql_svc` |
| 22 | `exchange_svc` |
| 23 | `print_spooler_svc` |
| 24 | `lsass` |
| 25 | `winlogon` |
| 26 | `kdc` |
| 27 | `wmi_svc` |

### Property IDs

| Slot | Identifier |
|---:|---|
| 0 | `Windows` |
| 1 | `Linux` |
| 2 | `Unix` |
| 3 | `Win7` |
| 4 | `Win10` |
| 5 | `Win11` |
| 6 | `Win2008` |
| 7 | `Win2012` |
| 8 | `Win2016` |
| 9 | `Win2019` |
| 10 | `Win2022` |
| 11 | `Ubuntu` |
| 12 | `Debian` |
| 13 | `Alpine` |
| 14 | `Workstation` |
| 15 | `LegacyWorkstation` |
| 16 | `AdminWorkstation` |
| 17 | `DeveloperWorkstation` |
| 18 | `LaptopUser` |
| 19 | `ModernWorkstation` |
| 20 | `WebServer` |
| 21 | `NginxServer` |
| 22 | `ApacheServer` |
| 23 | `IISServer` |
| 24 | `FileServer` |
| 25 | `PrintServer` |
| 26 | `MailServer` |
| 27 | `AppServer` |
| 28 | `HyperVHost` |
| 29 | `MSMQServer` |
| 30 | `APIGateway` |
| 31 | `Middleware` |
| 32 | `CacheServer` |
| 33 | `MessageBroker` |
| 34 | `BackupServer` |
| 35 | `DatabaseServer` |
| 36 | `MSSQLServer` |
| 37 | `MySQLServer` |
| 38 | `PostgreSQLServer` |
| 39 | `RedisServer` |
| 40 | `DomainController` |
| 41 | `ADCS` |
| 42 | `ADFS` |
| 43 | `LDAPServer` |
| 44 | `IdentityProvider` |
| 45 | `AuthServer` |
| 46 | `CertAuthority` |
| 47 | `ADIntegrated` |
| 48 | `Kubernetes` |
| 49 | `Pod` |
| 50 | `Container` |
| 51 | `WorkerNode` |
| 52 | `CloudInstance` |
| 53 | `AWS` |
| 54 | `EC2` |
| 55 | `IMDS` |
| 56 | `Firewall` |
| 57 | `VPN` |
| 58 | `NetworkDevice` |
| 59 | `Router` |
| 60 | `Switch` |
| 61 | `Bastion` |
| 62 | `DMZ` |
| 63 | `Unpatched` |
| 64 | `Misconfigured` |
| 65 | `DomainJoined` |
| 66 | `DomainAdmin` |
| 67 | `LocalAdmin` |
| 68 | `Kerberoastable` |
| 69 | `ASREProastable` |
| 70 | `NoLAPS` |
| 71 | `NTLMRelayable` |

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

Use cached credentials and post-exploitation actions to convert access on one node into access on another node or zone.
