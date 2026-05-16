# Agent 1: S_Network — Network Perimeter Specialist

**Zones:** Z4 Internet Edge, Z2 HQ Edge  
**CVE source:** `network_devices_cves.json`  
**Terminal goal (standalone):** `CiscoEdgeRouter` (value 10000, is_goal: true)

---

## Action Types

| CBS Action Category | type | Allowed? | Rationale |
|--------------------|------|----------|-----------|
| `probe` vulnerabilities | REMOTE | ✅ Yes | Fingerprint vendor OS before CVE selection |
| `remote_access` solvability | REMOTE | ✅ Yes | Network-reachable CVEs: PAN-OS, FortiOS, IOS, F5-TMOS, Citrix |
| `remote_access` solvability | LOCAL | ✅ Yes | Post-access CLI privilege escalation on the owned device |
| `credential_leak` solvability | LOCAL | ✅ Yes | Config file / running-config extraction after device is owned |
| `discovery` solvability | — | ❌ No | Belongs to S_Recon |
| `goal_access` solvability | — | ❌ No | No goal nodes exist in Z4/Z2 |
| `KNOWS` constraint | — | ❌ No | S_Recon owns all topology discovery |
| `LEAK_KNOWN_CREDENTIALS` constraint | — | ❌ No | S_Recon owns cross-node propagation |

---

## Vulnerabilities

### Probe Vulnerabilities (type: REMOTE, SR 1.0)
| Name | OS Target | Notes |
|------|-----------|-------|
| `Remote.Probe.PANOS` | PAN-OS | Management interface banner |
| `Remote.Probe.FortiOS` | FortiOS | SSL-VPN login page reveals version |
| `Remote.Probe.CiscoIOS` | IOS / NX-OS | SNMP sysDescr or SSH banner |
| `Remote.Probe.F5TMOS` | F5-TMOS | iControl REST `/mgmt/tm/sys/version` |
| `Remote.Probe.JunOS` | JunOS | NETCONF hello exchange |

### Remote Access Vulnerabilities (type: REMOTE)
| Name | CVE | CVSS | SR | Service | Attack |
|------|-----|------|----|---------|--------|
| `Solvability.PanOS_DOM_XSS` | CVE-2023-6790 | 8.8 | 0.85 | PaloAltoFirewall | DOM-based XSS → session theft |
| `Solvability.CiscoFirepower_MultiInstance` | CVE-2020-3514 | 8.2 | 0.75 | CiscoFirepower | Multi-instance feature privilege escalation |
| `Solvability.PanOS_Reflected_XSS` | CVE-2021-3052 | 8.0 | 0.85 | PaloAltoFirewall | Reflected XSS in GlobalProtect portal |
| `Solvability.CiscoASA_IKE_HeapOvf` | CVE-2018-0101 | 10.0 | 0.90 | CiscoASA | IKEv1/v2 heap overflow → unauthenticated RCE |
| `Solvability.CiscoASA_SSLVPN_Bypass` | CVE-2023-20269 | 9.1 | 0.90 | CiscoASA | SSL VPN unauthorized remote access |
| `Solvability.PanOS_TOCTOU` | CVE-2021-3054 | 7.2 | 0.85 | PaloAltoFirewall | TOCTOU race → arbitrary code execution |
| `Solvability.CiscoIOS_PhysicalBypass` | CVE-2020-3216 | 6.8 | 0.65 | CiscoEdgeRouter | IOS XE SD-WAN physical bypass |
| `Solvability.JuniperJunos_AuthBypass` | CVE-2018-0053 | 6.8 | 0.65 | JuniperRouter | SSH init script auth bypass |
| `Solvability.PanOS_ImproperAuth` | CVE-2021-3046 | 6.8 | 0.60 | PaloAltoFirewall | Improper authentication → unintended access |
| `Solvability.PanOS_Login_XSS` | CVE-2024-0007 | 6.8 | 0.85 | PaloAltoFirewall | XSS in Panorama web UI login |
| `Solvability.CiscoIOS_Shell_Access_Bypass` | CVE-2018-15371 | 6.7 | 0.75 | CiscoEdgeRouter | Shell access request mechanism bypass |
| `Solvability.CiscoNXOS_Python_PrivEsc` | CVE-2017-12301 | 6.7 | 0.75 | CiscoNXOS | Python scripting subsystem PrivEsc |
| `Solvability.CiscoNXOS_HashFile_Bypass` | CVE-2017-12331 | 6.7 | 0.75 | CiscoNXOS | Hash file bypass → root |
| `Solvability.CiscoNXOS_LocalFile_Bypass` | CVE-2017-12333 | 6.7 | 0.75 | CiscoNXOS | Local file bypass in system software |
| `Solvability.CiscoNXOS_CMDInject` | CVE-2017-12334 | 6.7 | 0.75 | CiscoNXOS | CLI command injection → root |
| `Solvability.CiscoNXOS_CMDInject2` | CVE-2017-12341 | 6.7 | 0.75 | CiscoNXOS | CLI command injection variant |
| `Solvability.CiscoNXOS_WriteErase_Bypass` | CVE-2018-0294 | 6.7 | 0.75 | CiscoNXOS | Write-erase feature bypass |
| `Solvability.CiscoNXOS_CLI_PrivEsc_1` | CVE-2019-1607 | 6.7 | 0.75 | CiscoNXOS | CLI privilege escalation |
| `Solvability.CiscoNXOS_CLI_PrivEsc_2` | CVE-2019-1608 | 6.7 | 0.75 | CiscoNXOS | CLI privilege escalation variant 2 |
| `Solvability.CiscoNXOS_CLI_PrivEsc_3` | CVE-2019-1609 | 6.7 | 0.75 | CiscoNXOS | CLI privilege escalation variant 3 |
| `Solvability.CiscoNXOS_CLI_PrivEsc_4` | CVE-2019-1610 | 6.7 | 0.75 | CiscoNXOS | CLI privilege escalation variant 4 |
| `Solvability.CiscoNXOS_CLI_PrivEsc_5` | CVE-2019-1611 | 6.7 | 0.75 | CiscoNXOS | CLI privilege escalation variant 5 |
| `Solvability.CiscoNXOS_CLI_PrivEsc_6` | CVE-2019-1613 | 6.7 | 0.75 | CiscoNXOS | CLI privilege escalation variant 6 |
| `Solvability.CiscoNXOS_ImageSig_Bypass` | CVE-2019-1615 | 6.7 | 0.75 | CiscoNXOS | Image signature verification bypass |

### Local Access Vulnerabilities (type: LOCAL — require owning the node first)
| Name | CVE | SR | Service | Attack |
|------|-----|----|---------|--------|
| `Solvability.PanOS_LocalRootEsc` | CVE-2021-3064 | 0.88 | PaloAltoFirewall | Stack overflow via LOCAL management process → root |
| `Solvability.CiscoNXOS_LocalBash` | CVE-2021-1588 | 0.75 | CiscoNXOS | Local bash shell escape from restricted CLI |
| `Solvability.FortiGate_LocalCmdExec` | CVE-2021-44168 | 0.68 | FortiGateAppliance | Arbitrary command execution via local file download |

### Credential Leak Vulnerabilities (type: LOCAL — on owned network device nodes)
| Name | SR | Service | What is leaked |
|------|----|---------|----------------|
| `Solvability.PanOS_ConfigDump` | 0.72 | PaloAltoFirewall | Admin credentials from running config XML |
| `Solvability.EnablePassword_Crack` | 0.68 | CiscoEdgeRouter | Enable secret from `show running-config` |
| `Solvability.FortiGate_ConfigBackup` | 0.70 | FortiGateAppliance | Plaintext credentials from FortiGate config backup |
| `Solvability.F5_AdminToken` | 0.75 | F5LoadBalancer | BIG-IP admin REST token from iControl |
| `Solvability.JuniperJunos_ConfigExtract` | 0.65 | JuniperRouter | Junos config export → RADIUS/TACACS+ secrets |
| `Solvability.CiscoNXOS_AAA_Secret` | 0.68 | CiscoNXOS | TACACS+ / RADIUS shared secret from running config |

---

## Services and Ports

| Service | Primary Ports | Protocol | OS Family | GLOBALTECH Zone |
|---------|--------------|----------|-----------|----------------|
| `PaloAltoFirewall` | 443, 4443 | HTTPS, GlobalProtect | PAN-OS | Z2 HQ Edge |
| `IPSAppliance` | 443 | HTTPS | PAN-OS | Z4 Internet Edge |
| `WAFAppliance` | 443, 80 | HTTPS, HTTP | Linux | Z4 Internet Edge |
| `CiscoEdgeRouter` | 22, 443 | SSH, HTTPS | IOS | Z2 HQ Edge |
| `CiscoASA` | 443, 500, 4500 | HTTPS, IKE, IKEv2 | CiscoASA | Z4 Internet Edge |
| `CiscoFirepower` | 443, 22 | HTTPS, SSH | CiscoFXOS | Z2 HQ Edge |
| `CiscoNXOS` | 22, 161, 830 | SSH, SNMP, NETCONF | NX-OS | Z2 Core Switch |
| `FortiGateAppliance` | 443, 10443 | HTTPS, SSL-VPN | FortiOS | Z2 HQ Edge |
| `F5LoadBalancer` | 443, 8443 | HTTPS, iControl REST | F5-TMOS | Z4 Internet Edge |
| `CitrixADC` | 443, 80 | HTTPS, HTTP | FreeBSD | Z4 Internet Edge |
| `JuniperRouter` | 22, 830 | SSH, NETCONF | JunOS | Z4 Internet Edge |
| `ISPRouter` | 22, 161 | SSH, SNMP | IOS | Z4 Internet Edge |
| `MikroTikRouter` | 8291, 22 | Winbox, SSH | RouterOS | Z5 Branch Edge |
| `OpenWRTRouter` | 80, 443, 22 | HTTP, HTTPS, SSH | Linux | Z5 Branch Edge |

---

## Goal Specification (Standalone)

```yaml
goal_config:
  num_goals: 1
  selection_strategy: diverse

# Service values:
IPSAppliance:     value: 1000   is_goal: false   # Entry tier
WAFAppliance:     value: 3500   is_goal: false   # Mid tier
PaloAltoFirewall: value: 6500   is_goal: false   # Near-goal tier
CiscoEdgeRouter:  value: 10000  is_goal: true    # TERMINAL GOAL
```
