# S_Identity - Active Directory and Identity Specialist

This file is the authoritative prompt reference for `s_identity` scenario generation.
It is aligned to `/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml`.

## Role

Exploit Active Directory, Kerberos, LDAP, ADCS, delegation, certificate, and domain-control weaknesses.

Domain boundary: Domain controllers, ADCS, Kerberos, LDAP/LDAPS, service tickets, delegation, domain admin paths, and identity infrastructure.

Training scenarios for this specialist must be specialist-style fixed-pair compatible scenarios. In meta scenarios, the same collections define the specialist's usable action and observation surface.

## Fixed Action Collection

The specialist has exactly 50 actions:

| Action kind | Count |
|---|---:|
| Local vulnerabilities | 15 |
| Remote vulnerabilities | 16 |
| Connect ports | 19 |
| Total | 50 |

### Local Vulnerabilities

| Slot | Identifier |
|---:|---|
| 0 | `Solvability.PassTheHash` |
| 1 | `Solvability.NTLM_Relay_LDAP` |
| 2 | `Solvability.ZeroLogon` |
| 3 | `Solvability.ConstrainedDelegation_S4U` |
| 4 | `Solvability.RBCD_Attack` |
| 5 | `Solvability.SilverTicket` |
| 6 | `Solvability.TokenImpersonation` |
| 7 | `Solvability.DCSync` |
| 8 | `Solvability.NTDS_Dump` |
| 9 | `Solvability.GoldenTicket` |
| 10 | `Solvability.ADCS_ESC1` |
| 11 | `Solvability.ADCS_ESC6` |
| 12 | `Solvability.DCShadow` |
| 13 | `Solvability.DSRM_Abuse` |
| 14 | `Solvability.ADCS_ESC8` |

### Remote Vulnerabilities

| Slot | Identifier |
|---:|---|
| 0 | `Solvability.ASREPRoasting` |
| 1 | `Solvability.Kerberoasting` |
| 2 | `Solvability.PrinterBug_Coercion` |
| 3 | `Solvability.PetitPotam` |
| 4 | `Solvability.UnconstrainedDelegation` |
| 5 | `Solvability.ShadowCredentials` |
| 6 | `Solvability.noPac` |
| 7 | `Solvability.Certifried` |
| 8 | `Solvability.ZeroLogon` |
| 9 | `Solvability.AD_Services_EOP` |
| 10 | `Solvability.NetNTLMv2_Downgrade` |
| 11 | `Solvability.Kerberos_EOP_2` |
| 12 | `Solvability.LSASS_EOP_AD` |
| 13 | `Solvability.noPac_2` |
| 14 | `Solvability.Kerberos_EOP` |
| 15 | `Solvability.MSAA_Priv` |

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
| 8 | `FTP` |
| 9 | `SMTP` |
| 10 | `DNS` |
| 11 | `MSSQL` |
| 12 | `MySQL` |
| 13 | `VNC` |
| 14 | `Telnet` |
| 15 | `SNMP` |
| 16 | `NetBIOS` |
| 17 | `Kerberos` |
| 18 | `WMI` |

## Observation Context Collection

The scenario generator should preferentially use these service and property identifiers for this specialist. These are not extra actions; they are the specialist's observation context and vocabulary guidance.

| Context type | Count |
|---|---:|
| Service IDs | 29 |
| Property IDs | 48 |

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
| 16 | `ldap_svc` |
| 17 | `ldaps_svc` |
| 18 | `kadmind` |
| 19 | `samba` |
| 20 | `lsass` |
| 21 | `winlogon` |
| 22 | `dsapiservice` |
| 23 | `kdc` |
| 24 | `adcs_svc` |
| 25 | `certsvc` |
| 26 | `exchange_svc` |
| 27 | `mssql_svc` |
| 28 | `wmi_svc` |

### Property IDs

| Slot | Identifier |
|---:|---|
| 0 | `Windows` |
| 1 | `Win2008` |
| 2 | `Win2012` |
| 3 | `Win2016` |
| 4 | `Win2019` |
| 5 | `Win2022` |
| 6 | `Workstation` |
| 7 | `AdminWorkstation` |
| 8 | `FileServer` |
| 9 | `PrintServer` |
| 10 | `MailServer` |
| 11 | `DatabaseServer` |
| 12 | `MSSQLServer` |
| 13 | `DomainController` |
| 14 | `ADCS` |
| 15 | `ADFS` |
| 16 | `LDAPServer` |
| 17 | `RadiusServer` |
| 18 | `IdentityProvider` |
| 19 | `AuthServer` |
| 20 | `CertAuthority` |
| 21 | `ADIntegrated` |
| 22 | `CloudInstance` |
| 23 | `AWS` |
| 24 | `Unpatched` |
| 25 | `Misconfigured` |
| 26 | `DomainJoined` |
| 27 | `DomainAdmin` |
| 28 | `LocalAdmin` |
| 29 | `Kerberoastable` |
| 30 | `ASREProastable` |
| 31 | `NoLAPS` |
| 32 | `UnconstrainedDelegation` |
| 33 | `ZeroLogonVulnerable` |
| 34 | `NTLMRelayable` |
| 35 | `IISServer` |
| 36 | `WebServer` |
| 37 | `AppServer` |
| 38 | `HyperVHost` |
| 39 | `MSMQServer` |
| 40 | `BackupServer` |
| 41 | `Serverless` |
| 42 | `CloudRDS` |
| 43 | `VPN` |
| 44 | `Bastion` |
| 45 | `ModernWorkstation` |
| 46 | `DeveloperWorkstation` |
| 47 | `LegacyWorkstation` |

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

Use identity-specific local and remote actions to move from a domain foothold to domain-level control.
