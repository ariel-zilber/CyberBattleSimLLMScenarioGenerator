# S_Network - Network Perimeter Specialist

This file is the authoritative prompt reference for `s_network` scenario generation.
It is aligned to `/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml`.

## Role

Compromise and operate network/security infrastructure such as firewalls, routers, VPN concentrators, load balancers, WAFs, and edge appliances.

Domain boundary: Network devices, perimeter appliances, VPN, WAF, routing, switching, and edge security infrastructure.

Training scenarios for this specialist must be specialist-style fixed-pair compatible scenarios. In meta scenarios, the same collections define the specialist's usable action and observation surface.

## Fixed Action Collection

The specialist has exactly 50 actions:

| Action kind | Count |
|---|---:|
| Local vulnerabilities | 18 |
| Remote vulnerabilities | 14 |
| Connect ports | 18 |
| Total | 50 |

### Local Vulnerabilities

| Slot | Identifier |
|---:|---|
| 0 | `Solvability.PanOS_LocalRootEsc` |
| 1 | `Solvability.CiscoNXOS_LocalBash` |
| 2 | `Solvability.FortiGate_LocalCmdExec` |
| 3 | `Solvability.PanOS_ConfigDump` |
| 4 | `Solvability.EnablePassword_Crack` |
| 5 | `Solvability.FortiGate_ConfigBackup` |
| 6 | `Solvability.F5_AdminToken` |
| 7 | `Solvability.JuniperJunos_ConfigExtract` |
| 8 | `Solvability.CiscoNXOS_AAA_Secret` |
| 9 | `Solvability.CiscoNXOS_CMDInject` |
| 10 | `Solvability.CiscoNXOS_CMDInject2` |
| 11 | `Solvability.CiscoNXOS_PrivEsc` |
| 12 | `Solvability.JuniperJunos_AuthBypass` |
| 13 | `Solvability.CiscoIOS_PhysicalBypass` |
| 14 | `Solvability.SNMP_CommunityDump` |
| 15 | `Solvability.NetworkDevice_DefaultCreds` |
| 16 | `Solvability.ConfigBackup_Exfil` |
| 17 | `Solvability.VLAN_Hop` |

### Remote Vulnerabilities

| Slot | Identifier |
|---:|---|
| 0 | `Solvability.PanOS_CMDInject` |
| 1 | `Solvability.FortiOS_SSLVPN_RCE` |
| 2 | `Solvability.FortiOS_AuthBypass` |
| 3 | `Solvability.CiscoASA_IKE_HeapOvf` |
| 4 | `Solvability.CiscoASA_SSLVPN_Bypass` |
| 5 | `Solvability.CiscoIOS_XE_PrivEsc` |
| 6 | `Solvability.F5_BIGIP_AuthBypass` |
| 7 | `Solvability.F5_BIGIP_RCE` |
| 8 | `Solvability.Citrix_Bleed` |
| 9 | `Solvability.Citrix_ADC_RCE` |
| 10 | `Solvability.PanOS_TOCTOU` |
| 11 | `Solvability.CiscoNXOS_LLDP` |
| 12 | `Solvability.CiscoIOS_RPKI` |
| 13 | `Solvability.Netgear_RCE` |

### Connect Ports

| Slot | Identifier |
|---:|---|
| 0 | `SSH` |
| 1 | `HTTP` |
| 2 | `HTTPS` |
| 3 | `SMB` |
| 4 | `RDP` |
| 5 | `WinRM` |
| 6 | `FTP` |
| 7 | `SMTP` |
| 8 | `DNS` |
| 9 | `MSSQL` |
| 10 | `MySQL` |
| 11 | `PostgreSQL` |
| 12 | `VNC` |
| 13 | `Telnet` |
| 14 | `SNMP` |
| 15 | `NetBIOS` |
| 16 | `Kerberos` |
| 17 | `WMI` |

## Observation Context Collection

The scenario generator should preferentially use these service and property identifiers for this specialist. These are not extra actions; they are the specialist's observation context and vocabulary guidance.

| Context type | Count |
|---|---:|
| Service IDs | 23 |
| Property IDs | 41 |

### Service IDs

| Slot | Identifier |
|---:|---|
| 0 | `PaloAltoFirewall` |
| 1 | `IPSAppliance` |
| 2 | `WAFAppliance` |
| 3 | `CiscoEdgeRouter` |
| 4 | `CiscoASA` |
| 5 | `CiscoFirepower` |
| 6 | `CiscoNXOS` |
| 7 | `FortiGateAppliance` |
| 8 | `F5LoadBalancer` |
| 9 | `CitrixADC` |
| 10 | `JuniperRouter` |
| 11 | `ISPRouter` |
| 12 | `MikroTikRouter` |
| 13 | `OpenWRTRouter` |
| 14 | `sshd` |
| 15 | `httpd` |
| 16 | `nginx` |
| 17 | `nginx_proxy` |
| 18 | `haproxy` |
| 19 | `snmpd` |
| 20 | `telnetd` |
| 21 | `vncd` |
| 22 | `consul_svc` |

### Property IDs

| Slot | Identifier |
|---:|---|
| 0 | `Linux` |
| 1 | `Unix` |
| 2 | `Ubuntu` |
| 3 | `Debian` |
| 4 | `Alpine` |
| 5 | `RedHat` |
| 6 | `WebServer` |
| 7 | `NginxServer` |
| 8 | `ApacheServer` |
| 9 | `LoadBalancer` |
| 10 | `ReverseProxy` |
| 11 | `APIGateway` |
| 12 | `CloudInstance` |
| 13 | `AWS` |
| 14 | `Firewall` |
| 15 | `VPN` |
| 16 | `WAF` |
| 17 | `NetworkDevice` |
| 18 | `Router` |
| 19 | `Switch` |
| 20 | `NGFW` |
| 21 | `SSLVPN` |
| 22 | `Bastion` |
| 23 | `DMZ` |
| 24 | `CiscoIOS` |
| 25 | `CiscoNXOS` |
| 26 | `CiscoASA` |
| 27 | `CiscoFirepower` |
| 28 | `JuniperJunos` |
| 29 | `FortiGate` |
| 30 | `PaloAlto` |
| 31 | `PANOS` |
| 32 | `GlobalProtect` |
| 33 | `F5BIGIP` |
| 34 | `Unpatched` |
| 35 | `Misconfigured` |
| 36 | `LocalAdmin` |
| 37 | `AppServer` |
| 38 | `Middleware` |
| 39 | `BackupServer` |
| 40 | `Serverless` |

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

Use network-device remote exploits, local device escalation, and configuration/credential extraction to create footholds into protected zones.
