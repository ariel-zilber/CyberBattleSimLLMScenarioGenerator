# Domain Architecture Rules: Networking Realism for CyberBattleSim

This document defines the mandatory networking rules for constructing realistic domain configurations. All generated environments are grounded in the **GLOBALTECH Enterprise Network Architecture** (`docs/reference/ref.md`), which serves as the universal base topology. These rules reflect actual enterprise security architectures and are critical for generating training data that prepares DRL agents for real-world penetration testing scenarios.

---

## 0. GLOBALTECH Enterprise Network Architecture — Mandatory Base Topology

All CyberBattleSim domain configurations MUST be derived from the **GLOBALTECH Enterprise Network Architecture** defined in `docs/reference/ref.md`. GLOBALTECH is a vendor-specific enterprise network skeleton for a fictitious organization. Generated environments embed specific attack scenarios into GLOBALTECH's extension points — they are never free-form arbitrary topologies.

### 0.1 GLOBALTECH Zone Hierarchy (CBS Domain Mapping)

The GLOBALTECH topology defines 8 named zones. Map generated CBS domains to these zones:

```
[Internet / Attacker — start_node: 0.0.0.0/0]
        │
        ▼
┌─────────────────────────────────────────────┐
│  Internet Edge (Z4) — 10.0.1.0/24           │
│  WAF, IPS, ISP-A/ISP-B routers              │
└─────────────────┬───────────────────────────┘
                  │ HTTPS / scrubbed traffic only
                  ▼
┌─────────────────────────────────────────────┐
│  HQ Edge (Z2) — 10.0.2.0/24                 │
│  Palo Alto PA-5200 firewalls (HA pair)       │
│  Cisco ISR 4451 Edge Router                  │
│  Cisco ISE (NAC), SolarWinds NPM             │
└─────────────────┬───────────────────────────┘
                  │ Internal LAN / 802.1X enforced
                  ▼
┌─────────────────────────────────────────────┐
│  Corporate HQ (Z1) — 10.1.0.0/16            │
│  Core: Catalyst 9600 switches + Server Farm  │
│  Dist: Catalyst 9500 switches                │
│  Access: Catalyst 9300 per VLAN              │
│  VLANs: Sales | R&D | Finance | Admin        │
│          WiFi | Guest                        │
└─────────────────┬───────────────────────────┘
                  │ Protocol-specific only
                  ▼
┌─────────────────────────────────────────────┐
│  Server Farm (Z1, HQ Core) — 10.1.10.0/24   │
│  DomainController, MSSQLServer, FileServer   │
│  ExchangeServer, PrintServer                 │
└─────────────────────────────────────────────┘

+ Branch Office (Z5): 10.2.0.0/24 — Cisco Meraki MX SD-WAN, Branch Router
+ Public Cloud AWS (Z6): 10.3.0.0/24 — Web Tier, App Tier, DB Tier (PostgreSQL)
+ Remote Users (Z7): 10.4.0.0/24 — SASE, Cisco AnyConnect VPN, BYOD
+ Key Management (Z8): 192.168.100.0/24 — Splunk SIEM, SolarWinds NPM, Cisco ISE
```

### 0.2 GLOBALTECH Extension Points

When generating a scenario, select one or more extension points from `docs/reference/ref.md` Part 3. All generated components must extend GLOBALTECH — never replace or discard base zones.

| Extension Point | Zone | How to Embed in CBS |
|-----------------|------|---------------------|
| Access Layer VLAN slot | Z1 | Add `HQ-ACC-0N` switch service + VLAN endpoint group |
| HQ Edge security insertion | Z2 | Insert DLP/CASB/NDR appliance service between firewalls and MEC |
| Branch Office replication | Z5 | Clone Branch domain as B-Site-01, B-Site-02, etc. |
| Cloud service addition | Z6 | Extend AWS domain with Lambda, EKS, S3, or add Azure/GCP zone |
| Remote access specialization | Z7 | Augment SASE with Zscaler/Netskope, add PAW/jump server |
| Management plane expansion | Z8 | Add CrowdStrike EDR, CyberArk PAM, SOAR platform |
| DMZ insertion | between Z4 & Z2 | Add public-facing services: reverse proxy, mail gateway, public DNS |
| Guest VLAN | Z1 | `HQ-ACC-06`: internet-only, no corporate routing |

---

## 1. Network Tiering Model

### 1.1 GLOBALTECH Tier Architecture

Multi-domain configurations MUST reflect the GLOBALTECH zone hierarchy. Traffic flows inward through the security stack:

```
[Internet — start_node]
       │
       ▼
  ┌──────────────┐
  │ Internet Edge │  (Z4) — WAF, IPS, ISP routers
  │ 10.0.1.0/24  │  First internet-facing CBS domain
  └──────┬───────┘
         │ HTTPS / scrubbed only
         ▼
  ┌──────────────┐
  │   HQ Edge    │  (Z2) — Palo Alto firewalls, ISR router, ISE
  │ 10.0.2.0/24  │  Perimeter security domain
  └──────┬───────┘
         │ Internal protocols (LDAP, RDP via VPN, etc.)
         ▼
  ┌──────────────┐
  │ Corporate HQ │  (Z1) — VLAN segments, workstations
  │ 10.1.0.0/16  │  User endpoint domain
  └──────┬───────┘
         │ MSSQL / LDAP / Kerberos only
         ▼
  ┌──────────────┐
  │ Server Farm  │  (Z1, HQ Core) — DC, databases, file servers
  │10.1.10.0/24  │  High-value goal domain
  └──────────────┘
```

**Rules:**
- Traffic flows INWARD only (Internet Edge → HQ Edge → HQ VLANs → Server Farm). No reverse connections.
- Internet Edge NEVER connects directly to the Server Farm or HQ VLANs.
- Each zone uses a dedicated, non-overlapping private subnet.
- The HQ Edge firewall pair (Palo Alto PA-5200) is the mandatory segmentation boundary between Z4 and Z1.

### 1.2 GLOBALTECH Subnet Allocation

| GLOBALTECH Zone | CBS Domain | Subnet | Notes |
|-----------------|-----------|--------|-------|
| Internet / Attacker | `start_node` | `0.0.0.0/0` or `203.0.113.0/24` | Public internet, never RFC 1918 |
| Internet Edge (Z4) | First domain | `10.0.1.0/24` | WAF, IPS, ISP-A/ISP-B routers |
| HQ Edge (Z2) | Second domain | `10.0.2.0/24` | Palo Alto firewalls, ISR router, ISE |
| HQ VLANs (Z1) | Third domain | `10.1.0.0/24`–`10.1.4.0/24` | Sales/R&D/Finance/Admin/WiFi/Guest |
| Server Farm (Z1) | Fourth domain | `10.1.10.0/24` | DC, MSSQL, File, Exchange servers |
| Branch Office (Z5) | Optional domain | `10.2.0.0/24` | SD-WAN, Branch Router, endpoints |
| Public Cloud AWS (Z6) | Optional domain | `10.3.0.0/24` | Web/App/DB tiers |
| Remote Users (Z7) | Optional domain | `10.4.0.0/24` | SASE, VPN clients, BYOD |
| Key Management (Z8) | Optional domain | `192.168.100.0/24` | Splunk SIEM, SolarWinds NPM, Cisco ISE |

**RFC 1918 Private Ranges (use ONLY for internal domains):**
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

**Public Ranges (use ONLY for `start_node`):**
- `203.0.113.0/24` (TEST-NET-3, documentation use)
- `198.51.100.0/24` (TEST-NET-2)
- `0.0.0.0/0` (symbolic public internet)

---

## 2. Firewall Segmentation Rules

### 2.1 Allowed Cross-Tier Protocols (GLOBALTECH Zone Boundaries)

The following table defines which protocols may traverse each GLOBALTECH zone boundary. These MUST be enforced via `inter_domain_constraints`.

| From → To (GLOBALTECH zones) | Allowed Protocols | Forbidden |
|------------------------------|-------------------|-----------|
| Internet → Internet Edge (Z4) | `HTTP`, `HTTPS` | `SMB`, `RDP`, `LDAP`, `MSSQL` |
| Internet Edge (Z4) → HQ Edge (Z2) | `HTTPS`, `REST` | `SMB`, `RDP`, `LDAP`, `MSSQL`, `MySQL` |
| HQ Edge (Z2) → HQ VLANs (Z1) | `HTTPS`, `Kerberos`, `LDAP`, `RDP` (via VPN) | `SMB` (direct), `ALL` |
| HQ VLANs (Z1) → Server Farm (Z1) | `LDAP`, `LDAPS`, `MSSQL`, `Kerberos`, `SMB` | `HTTP`, `ALL` |
| Server Farm → HQ VLANs | `Kerberos`, `LDAPS` (auth responses) | `HTTP`, `HTTPS` |
| HQ Edge (Z2) → Branch Office (Z5) | Site-to-Site VPN / `IPSEC` | direct `SMB`, `RDP` |
| AWS Cloud (Z6) internal | Web→App: `HTTPS`; App→DB: `PostgreSQL` (5432) | `SMB`, `RDP`, `ALL` |
| Any → Any | `ICMP` (optional, for monitoring only) | Do not use `ALL` |

### 2.2 Prohibited Direct Connections (GLOBALTECH)

These connections are NEVER permitted regardless of business requirements:

- Internet Edge (Z4) → Server Farm or HQ VLANs directly (must pass through HQ Edge firewall pair)
- Attacker start node → HQ VLANs (must compromise Internet Edge then HQ Edge first)
- Attacker start node → Server Farm (must pivot through Internet Edge → HQ Edge → HQ VLANs)
- Public internet → Internal services via `SMB`, `RDP`, or `LDAP`
- Branch Office (Z5) → Server Farm without traversing HQ Edge (Z2)
- AWS Cloud (Z6) web tier → AWS DB tier directly (must go through AWS App tier)

---

## 3. OS Assignment by Tier

### 3.1 Operating System Distribution Rules

Mix operating systems realistically. The OS assigned to a service should match its real-world role.

| Service Role | Required OS | GLOBALTECH Zone | Rationale |
|--------------|-------------|-----------------|-----------|
| Web servers (Nginx, Apache) | `Linux` | Z6 AWS Web Tier / DMZ | Linux dominates web server deployments |
| Load balancers, WAF, IPS | `Linux` | Z4 Internet Edge | HAProxy, Nginx, Suricata run on Linux |
| Application servers | `Windows` or `Linux` | Z6 AWS App Tier / Z1 Server Farm | Java/.NET apps run on both |
| Active Directory / Domain Controller | `Windows` only | Z1 Server Farm | AD DS is exclusively a Windows role |
| File servers (SMB shares) | `Windows` | Z1 Server Farm | Windows NTFS + SMB is the enterprise standard |
| MSSQL databases | `Windows` | Z1 Server Farm | SQL Server runs on Windows |
| PostgreSQL / MySQL | `Linux` | Z6 AWS DB Tier | Open-source DBs are Linux-first |
| Palo Alto PA-5200 firewalls | `Linux` (PAN-OS) | Z2 HQ Edge | GLOBALTECH perimeter security appliances |
| Cisco IOS XE routers/switches | `Linux` (IOS XE) | Z2 HQ Edge / Z1 Core | Cisco ISR 4451, Catalyst 9600/9500/9300 |
| Cisco Meraki MX SD-WAN | `Linux` (Meraki OS) | Z5 Branch Office | Branch SD-WAN appliance |
| SASE / VPN clients | `Windows` or `Linux` | Z7 Remote Users | BYOD endpoints running AnyConnect/SASE |
| Splunk SIEM / SolarWinds NPM | `Linux` | Z8 Key Management | Management plane tools |
| Kubernetes nodes | `Linux` | Z6 AWS Cloud | Container orchestration runs on Linux |

---

## 4. Lateral Movement Path Rules

### 4.1 Required Pivot Points

Every configuration MUST include at least one forced pivot: a node that the attacker must compromise before gaining access to the next tier. This is what trains the agent to perform sequential attack chains.

**Rule:** No configuration may allow the attacker to skip a tier.

Correct chain (GLOBALTECH standard path):
`Attacker → WAFAppliance (InternetEdge) → PaloAltoFirewall (HQ_Edge) → SalesWorkstation (HQ_VLANs) → DomainController (ServerFarm)`

Correct chain (GLOBALTECH cloud path):
`Attacker → AWSWebServer (AWSCloud) → AWSAppServer (AWSCloud) → AWSPostgreSQL (AWSCloud)`

Incorrect (skips HQ Edge — directly from Internet to HQ internal):
`Attacker → SalesWorkstation (HQ_VLANs)  ← FORBIDDEN: bypasses Palo Alto firewall`

### 4.2 Credential Propagation Paths

Credentials must have a logical propagation path. The following are realistic GLOBALTECH-grounded patterns:

| Source | Target | Mechanism | GLOBALTECH Zone |
|--------|--------|-----------|-----------------|
| `SalesWorkstation` | `FileServer` | Cached NTLM hash (SMB auth) | Z1 → Z1 Server Farm |
| `AdminWorkstation` | `DomainController` | Kerberos TGT (domain join) | Z1 → Z1 Server Farm |
| `AWSWebServer` | `AWSAppServer` | Web app config file credentials | Z6 Web → Z6 App |
| `AWSAppServer` | `AWSPostgreSQL` | Connection string in app config | Z6 App → Z6 DB |
| `AWSAppServer` | `DomainController` | Service account Kerberos | Z6 → Z1 Server Farm |
| `BranchWorkstation` | `FileServer` | SMB over VPN tunnel (MPLS path) | Z5 → Z1 Server Farm |
| `PaloAltoFirewall` | `CiscoISEAppliance` | Admin credential reuse | Z2 → Z8 |
| `RnDWorkstation` | `MSSQLServer` | SQL connection string in source repo | Z1 → Z1 Server Farm |

### 4.3 Minimum Solvability Requirements

- At least **1 remote exploit** must be applicable to the entry point group.
- At least **1 credential-leaking vulnerability** must be applicable to the entry point.
- At least **50% of all nodes** must have some credential-leaking capability.

---

## 5. Property-to-Exploit Alignment Rules

### 5.1 OS-Specific Exploit Binding

Exploits MUST be bound to the correct OS via `match_properties`. The following table shows correct bindings:

| Exploit | Required OS | Required Properties |
|---------|-------------|---------------------|
| EternalBlue (MS17-010) | `Windows` | `Win7`, `SMBv1`, `Unpatched` |
| Nginx LibCrypto RCE (CVE-2025-15467) | `Linux` | `WebServer`, `LibCrypto`, `Unpatched` |
| Mimikatz credential dump | `Windows` | `DomainJoined` |
| Kerberoasting | `Windows` | `Kerberoastable`, `ServiceAccount` |
| BloodHound AD recon | `Windows` | `DomainJoined` |
| SSH key theft | `Linux` | `SSH` |
| Docker escape | `Linux` | `Container`, `HostPID` |
| kubectl exec | `Linux` | `Kubernetes`, `Pod` |
| DCSync | `Windows` | `DomainController`, `DomainAdmin` |
| PrintNightmare | `Windows` | `Win2019`, `PrintSpooler` |
| ADCS ESC1 | `Windows` | `DomainController`, `ADCS` |
| Heartbleed | `Linux` | `WebServer`, `OpenSSL` |

### 5.2 Role-Specific Exploit Binding

Never apply web-specific exploits to databases, or database exploits to web servers.

| Wrong | Correct |
|-------|---------|
| `Creds.WebConfig` on a `DatabaseServer` | `Creds.WebConfig` on a `WebServer` |
| `EternalBlue` on `Linux` | `EternalBlue` on `Windows` + `Win7` |
| `SQLInjection` on a `DomainController` | `SQLInjection` on a `WebServer` |
| `DCSync` on an `AppServer` | `DCSync` on a `DomainController` |

---

## 6. Node Value Assignment Rules (GLOBALTECH-grounded)

Node values determine the RL agent's reward structure. Values must reflect GLOBALTECH asset importance.

| GLOBALTECH Node Type | Zone | Suggested Value | Rationale |
|----------------------|------|-----------------|-----------|
| `WAFAppliance`, `IPSAppliance` | Z4 Internet Edge | 100 – 300 | Entry stepping stones; limited data access |
| `PaloAltoFirewall`, `CiscoEdgeRouter` | Z2 HQ Edge | 500 – 1000 | Control plane access; pivots to interior |
| `SalesWorkstation`, `RnDWorkstation` | Z1 HQ VLANs | 100 – 300 | User endpoints; credential sources |
| `FinanceWorkstation`, `AdminWorkstation` | Z1 HQ VLANs | 300 – 700 | Higher-privilege endpoints |
| `FileServer` | Z1 Server Farm | 500 – 1500 | Contains sensitive documents |
| `AWSWebServer`, `AWSAppServer` | Z6 AWS Cloud | 300 – 800 | Public-facing but limited data |
| `MSSQLServer`, `AWSPostgreSQL` | Z1 Server Farm / Z6 | 3000 – 8000 | Contains sensitive data (goal) |
| `DomainController` | Z1 Server Farm | 5000 – 10000 | Full domain compromise (primary goal) |
| `SplunkSIEM`, `CyberArkPAM` | Z8 Key Management | 8000 – 10000 | Keys to the monitoring/secrets kingdom |

---

## 7. Subnet Routing Summary

### 7.1 Single-Domain Configurations (GLOBALTECH HQ Internal Scenario)

A single-domain scenario focuses on one GLOBALTECH zone. The attacker sits on the internet.

```
start_node:     0.0.0.0/0  (or 203.0.113.0/24) — public internet
HQ_VLANs:      10.1.0.0/24  — Corporate HQ VLAN segment (single domain)
```

### 7.2 Multi-Domain Configurations (GLOBALTECH Standard: Internet → HQ Edge → HQ Internal → Server Farm)

```
start_node:     0.0.0.0/0
InternetEdge:   10.0.1.0/24   (Z4 — WAF, IPS, ISP routers)
HQ_Edge:        10.0.2.0/24   (Z2 — Palo Alto firewalls, ISR router, ISE)
HQ_VLANs:      10.1.0.0/24   (Z1 — VLAN segments: Sales, R&D, Finance, Admin)
ServerFarm:     10.1.10.0/24  (Z1 HQ Core — DC, MSSQL, File servers)
```

### 7.3 Multi-Domain Configurations (GLOBALTECH Extended: + Branch + AWS + Remote + Management)

```
start_node:     203.0.113.0/24
InternetEdge:   10.0.1.0/24   (Z4)
HQ_Edge:        10.0.2.0/24   (Z2)
HQ_VLANs:      10.1.0.0/24   (Z1 — user segments)
ServerFarm:     10.1.10.0/24  (Z1 — high-value goals)
BranchOffice:   10.2.0.0/24   (Z5 — SD-WAN, Branch Router)
AWSCloud:       10.3.0.0/24   (Z6 — Web/App/DB tiers)
RemoteUsers:    10.4.0.0/24   (Z7 — SASE, VPN)
KeyManagement:  192.168.100.0/24  (Z8 — Splunk, SolarWinds, ISE)
```

---

## 8. GLOBALTECH Group and Service Naming Conventions

Consistent naming prevents parser confusion between service archetypes and group instances. All names MUST be derivable from GLOBALTECH device types.

| Pattern | Correct Usage | Incorrect |
|---------|--------------|-----------|
| `ServiceName` (singular) | Service definitions, `attack_flow.source_pattern`, `filler`, `mandatory_services` | Never in constraints `source`/`target` |
| `GroupName` (plural) | Constraint `source`/`target`, `entry_points.node` | Never as service definitions |
| Property names | `MUST_HAVE` target, `base_properties`, `match_properties`, `default_properties` | Never in constraints `source` |

**GLOBALTECH-derived naming examples:**

| Zone | Service (singular) | Group (plural) | Properties |
|------|--------------------|----------------|------------|
| Z4 Internet Edge | `WAFAppliance` | `WAFAppliances` | `Linux`, `NetworkDevice`, `WAF` |
| Z4 Internet Edge | `ISPRouter` | `ISPRouters` | `Router`, `NetworkDevice`, `BGP` |
| Z2 HQ Edge | `PaloAltoFirewall` | `PaloAltoFirewalls` | `Firewall`, `PaloAlto`, `PANOS`, `NetworkDevice` |
| Z2 HQ Edge | `CiscoEdgeRouter` | `CiscoEdgeRouters` | `Router`, `CiscoIOS`, `NetworkDevice` |
| Z1 HQ VLANs | `SalesWorkstation` | `SalesWorkstations` | `Windows`, `Workstation`, `DomainJoined` |
| Z1 HQ VLANs | `RnDWorkstation` | `RnDWorkstations` | `Windows`, `Workstation`, `DomainJoined` |
| Z1 HQ VLANs | `FinanceWorkstation` | `FinanceWorkstations` | `Windows`, `Workstation`, `DomainJoined` |
| Z1 HQ VLANs | `AdminWorkstation` | `AdminWorkstations` | `Windows`, `Workstation`, `DomainJoined`, `LocalAdmin` |
| Z1 Server Farm | `DomainController` | `DomainControllers` | `Windows`, `DomainController`, `DomainJoined`, `ADCS` |
| Z1 Server Farm | `MSSQLServer` | `MSSQLServers` | `Windows`, `MSSQLServer`, `DatabaseServer`, `DomainJoined` |
| Z1 Server Farm | `FileServer` | `FileServers` | `Windows`, `FileServer`, `SMBv1`, `DomainJoined` |
| Z5 Branch | `BranchWorkstation` | `BranchWorkstations` | `Windows`, `Workstation`, `DomainJoined` |
| Z5 Branch | `BranchSDWAN` | `BranchSDWANs` | `Linux`, `NetworkDevice`, `CiscoMeraki` |
| Z6 AWS | `AWSWebServer` | `AWSWebServers` | `Linux`, `WebServer`, `LibCrypto` |
| Z6 AWS | `AWSAppServer` | `AWSAppServers` | `Linux`, `AppServer`, `GoRuntime` |
| Z6 AWS | `AWSPostgreSQL` | `AWSPostgreSQLs` | `Linux`, `DatabaseServer` |
| Z7 Remote | `BYODLaptop` | `BYODLaptops` | `Windows`, `Workstation` |
| Z8 Management | `SplunkSIEM` | `SplunkSIEMs` | `Linux`, `AppServer`, `GoRuntime`, `SensitiveData` |

---

## 9. GLOBALTECH Network Device Topology Rules

Network device segments within GLOBALTECH require specific connectivity rules:

* **HQ Core Layer (Catalyst 9600):** Connected to Server Farm and Distribution Layer only. No direct internet connectivity.
* **HQ Distribution Layer (Catalyst 9500):** Connected to Core Layer (10Gbps) and Access Layer switches (1Gbps) only.
* **HQ Access Layer (Catalyst 9300):** One switch per VLAN. Each connected to one Distribution switch and its assigned endpoint group only.
* **HQ Edge (Palo Alto PA-5200 HA pair):** Both firewalls connect to Internet Edge routers (upstream) and MEC gateway (downstream). All inter-zone traffic must traverse this pair.
* **Cisco ISE (NAC):** Enforces 802.1X on Distribution Layer switches via RADIUS. ISE is management-plane only — it is never in the data-plane attack path.
* **Branch SD-WAN (Cisco Meraki MX):** Connects to MPLS/internet only. Branch endpoints are behind the Branch Router, not directly reachable from the internet.
* **No direct Access-to-Server-Farm connections:** Workstation VLANs (Sales, R&D, Finance, Admin) must traverse the Core and HQ Edge before reaching the Server Farm.

## 10. Zero Trust Principles (NIST SP 800-207)
Modern networks implement Zero Trust models. Configurations reflecting this framework must enforce:
* **No Implicit Trust:** Connections require continuous verification properties. Internal domains cannot rely solely on perimeter defense.
* **Micro-segmentation:** Lateral movement within the same tier (e.g., AppServer to AppServer) may also be constrained by unique access rules.
* **Enforcement:** Use specific port protocols (e.g., `gRPC`, `REST_API`) and ensure `Unauthenticated` is never applied to internal Zero Trust nodes.

## 11. Compliance Tier Mapping
Regulatory frameworks mandate strict data isolation. When building domains targeting compliance regimes:
* **PCI-DSS:** Cardholder data environments must be heavily isolated from general IT. Use `PCI` and `PaymentCard` properties.
* **SOX:** Financial systems are isolated to prevent unauthorized tampering. Use `FinancialData` properties on MSSQL and file server goal nodes.
* **GDPR:** Customer data stores must be identifiable. Use `CustomerData` and `GDPR` properties on database nodes containing PII.

## 12. Cloud / Hybrid Architecture (GLOBALTECH AWS Zone Z6)

The GLOBALTECH Public Cloud (AWS) zone (Z6) is connected via Direct Connect (10Gbps) to the internet through Transit Gateway TGW-2, with an internal VPC managed by TGW-1. Rules:
* **AWS Web Tier:** Public-facing (via TGW-2 → Internet). Equivalent to a DMZ. Services: `AWSWebServer` (`Linux`, `WebServer`, `LibCrypto`).
* **AWS App Tier:** Private (via TGW-1). Reachable only from Web Tier. Services: `AWSAppServer` (`Linux`, `AppServer`, `GoRuntime`).
* **AWS DB Tier (PostgreSQL):** Private (via TGW-1). Reachable only from App Tier. Services: `AWSPostgreSQL` (`Linux`, `DatabaseServer`). No direct exploit path — credential-only access.
* **Direct Connect path:** TGW-2 is internet-accessible. The attacker may enter Z6 via the Web Tier's public HTTPS endpoint.
* **Hybrid connectivity:** Use `AssumeRoleCapable` and `IAM_API` properties to model IAM-based lateral movement between AWS services. The AWS zone may also connect to the HQ Edge via Direct Connect, enabling cross-zone pivots.

## 13. GLOBALTECH Branch-to-HQ Connectivity Rules

Branch Office (Z5) connectivity follows these strict rules based on the GLOBALTECH architecture:

* **SD-WAN Primary Path:** Branch endpoints always egress via the Cisco Meraki MX SD-WAN appliance to the MPLS cloud, not directly to the internet.
* **Site-to-Site VPN Fallback:** The HQ Edge Router (Cisco ISR 4451) maintains a Site-to-Site VPN tunnel to the MPLS cloud as a failover path.
* **Branch-to-HQ Traffic:** All branch-to-HQ traffic terminates at the HQ Edge firewall pair (Palo Alto PA-5200). Branch endpoints cannot bypass the HQ Edge.
* **No Direct Branch → Server Farm:** Branch workstations must pivot through the HQ Edge and HQ internal segments to reach the Server Farm.
* **Branch Isolation:** Each branch site (B-Site-01, B-Site-02, etc.) is isolated from other branch sites — inter-branch traffic must traverse the MPLS/HQ path.
* **MPLS Cloud as WAN Hub:** The MPLS cloud connects to both the Internet and the HQ Edge Router. This makes it a potential pivot point if compromised via the internet path.

## 14. Container / Microservice Stack (Bitnami Tier Model)

Linux-only or hybrid scenarios based on real Bitnami Helm chart images follow a five-tier architecture grounded in CVE data from `data/vulnerability_db/bitnami_cves.json`.

### 14.1 Tier Definitions

The container/microservice stack maps to the GLOBALTECH **AWS Cloud Zone (Z6)** or to a specialized VLAN extension of the Corporate HQ (Z1). These tiers are always embedded within the GLOBALTECH topology — never stand-alone.

| Tier | GLOBALTECH Embedding | CBS Role | Typical Services | Entry from Internet? |
|------|----------------------|----------|-----------------|----------------------|
| WebTier | Z6 AWS Web Tier OR Z1 DMZ extension | Public-facing | `NginxServer`, `WordPressServer`, `DrupalServer`, `HaproxyServer` | Yes — public HTTPS via TGW-2 |
| AppTier | Z6 AWS App Tier | Application | `JenkinsServer`, `GrafanaServer`, `VaultServer`, `KongGateway` | No — only from WebTier |
| DataTier | Z6 AWS DB Tier | Data / Storage | `MongoDBServer`, `RedisServer`, `MySQLServer`, `ElasticsearchServer` | No — only from AppTier |
| AuthTier | Z6 or Z8 Key Management | Identity | `KeycloakServer`, `OAuth2ProxyServer` | No — HTTPS/8080 from AppTier only |
| WorkerTier | Z6 AWS (compute events) | Compute / Events | `KafkaServer`, `AirflowServer`, `RabbitmqServer` | No — only from AppTier/DataTier |

### 14.2 Connectivity Rules (GLOBALTECH Z6 internal)

* **Z6 WebTier → Z6 AppTier:** HTTPS, REST_API only. Never SSH or database ports.
* **Z6 AppTier → Z6 DataTier:** Port-specific only — MongoDB (27017), Redis (6379), MySQL (3306), Elasticsearch (9200). No blanket TCP.
* **Z6 AppTier → Z6 AuthTier:** HTTPS (8080/8443) only. No AuthTier direct access from Z6 WebTier.
* **Z6 WorkerTier → Z6 DataTier:** AMQP (5672) or Kafka broker (9092) only.
* **No Z6 WebTier → Z6 DataTier:** Direct AWS-web-to-database connections are strictly prohibited (same rule as HQ: no Internet Edge → Server Farm).
* **No Z6 WebTier → Z6 AuthTier:** OAuth flows must proxy through Z6 AppTier (e.g., via Kong or oauth2-proxy in AppTier).
* **Z6 → Z1 cross-zone:** Any Z6 service reaching Z1 Server Farm must traverse the HQ Edge (Z2) firewall pair — typically modeled via `MUST_REACH` + `IPSEC` or `Direct Connect` protocol.

### 14.3 CVE Property Constraints

* **GoRuntime:** All Go-based images (grafana, vault, oauth2-proxy, mongodb, redis) carry `GoRuntime`. This enables `Solvability.Vault_GoStdlib`, `Solvability.Grafana_GoStdlib`, etc.
* **LibCrypto:** Alpine-based images (nginx, redis) may carry `LibCrypto` to enable `Solvability.Nginx_LibCrypto_Critical` (CVSS 9.8).
* **ImageMagick:** WordPress and Drupal carry `ImageMagick` to enable `Solvability.WordPress_ImageMagick` (CVSS 9.8).
* **Misconfigured:** MongoDB and Redis ship with no auth by default. Assign `Misconfigured` to model unauthenticated access.

### 14.4 PostgreSQL / Alpine Exception

`PostgreSQLServer` and `RabbitmqServer` (Alpine/minimal images) return near-zero CVEs from Trivy scans. **Assign no `remote_access` solvability vulnerabilities to these nodes.** They are credential-only access points — the agent must discover credentials from another compromised node (e.g., `wp-config.php`, container env vars) and reuse them.

### 14.5 Standard Subnet Layout (5-Tier Linux — GLOBALTECH AWS Z6 embedding)

When the microservice stack maps to the GLOBALTECH AWS Cloud zone (Z6), subnets are allocated within the `10.3.0.0/16` range:

```
10.3.1.0/24  WebTier  (Z6 AWS Web — public-facing via TGW-2)
10.3.2.0/24  AppTier  (Z6 AWS App — internal, reachable from WebTier only)
10.3.3.0/24  DataTier (Z6 AWS DB — internal, reachable from AppTier only)
10.3.4.0/24  AuthTier (Z6 AWS Identity — internal, reachable from AppTier only)
10.3.5.0/24  WorkerTier (Z6 AWS Compute — internal, reachable from AppTier/DataTier)
```

The `10.0.1.0/24` range is reserved for GLOBALTECH Z4 Internet Edge. Do NOT assign container tiers to `10.0.x.0/24` — those are Z4 and Z2 ranges.

### 14.6 Hybrid Windows + Linux Layout (GLOBALTECH Extended Enterprise)

When mixing Windows AD and Linux microservices in a GLOBALTECH scenario, Linux services occupy the AWS Cloud zone `10.3.x.0/24` and Windows services occupy the Server Farm `10.1.10.0/24` and HQ VLANs `10.1.0.0–4.0/24`. The AuthTier contains **both** Keycloak (Linux, in Z6) and the Windows DomainController (in Z1 Server Farm) — with the DC as the primary goal and Keycloak as a secondary goal. Inter-domain constraints must enforce that the DC is unreachable from WebTier directly; all Z6→Z1 pivots must traverse the HQ Edge (Z2) Palo Alto firewall pair.

---

## 15. Cross-Tier Shared Services (Hub Nodes) — GLOBALTECH AWS Z6

Real microservice deployments (as found in the GLOBALTECH AWS Cloud Zone Z6) exhibit extreme hub-and-spoke topology: a small number of services are called by a disproportionate share of all others (empirically, one service handles calls from ~19% of the entire fleet). These **hub services** appear in multiple tier-to-tier connection paths and represent high-value pivot points for lateral movement within the AWS zone.

### 15.1 Hub Service Rule

Every microservice configuration with ≥3 tiers SHOULD include exactly **one hub DataTier service** reachable from multiple upstream tiers. This models the shared cache/broker pattern prevalent in production Kubernetes environments.

| Typical Hub Services | Property | Reachable From |
|----------------------|----------|----------------|
| `RedisServer` | `GoRuntime`, `Misconfigured` | AppTier AND WorkerTier |
| `ElasticsearchServer` | `Java` | AppTier AND WorkerTier |
| `KafkaServer` | `Java`, `MessageBroker` | AppTier AND WorkerTier |

### 15.2 Hub Node Constraints (GLOBALTECH Z6 example)

Model a hub service within the GLOBALTECH AWS Zone (Z6) by adding **two separate `inter_domain_constraints` entries** — one from the AWS App tier and one from the AWS Worker tier — both targeting the same AWS Data tier group:

```yaml
inter_domain_constraints:
  - source_domain: AWSCloud_App      # Z6 App Tier (10.3.2.0/24)
    target_domain: AWSCloud_Data     # Z6 Data Tier (10.3.3.0/24)
    constraints:
      - source: AWSAppServers
        target: SharedRedisCache     # Redis hub — GoRuntime, Misconfigured
        relation: MUST_CONNECT
        protocol: Redis              # port 6379
  - source_domain: AWSCloud_Worker   # Z6 Worker Tier (10.3.5.0/24)
    target_domain: AWSCloud_Data     # Z6 Data Tier (10.3.3.0/24)
    constraints:
      - source: AWSWorkerNodes
        target: SharedRedisCache     # same Redis hub — cross-tier propagation path
        relation: MUST_CONNECT
        protocol: Redis
```

### 15.3 Hub Node Attack Surface

A `Misconfigured` hub service (Redis or MongoDB with no-auth enabled) that is reachable from multiple tiers creates a **cross-tier credential propagation path**:

```
WorkerTier compromise → Redis hub (noauth dump) → session tokens / app credentials → AppTier lateral move
```

This is distinct from the standard vertical chain (WebTier → AppTier → DataTier) and forces the DRL agent to learn non-linear attack strategies.

**Hub node value:** 4000–7000 (high, because compromise yields data from multiple tiers).

---

## 16. Hidden Runtime Dependency Paths

Empirical analysis of production microservice fleets shows that 28.5% of services have less than 50% similarity between their static dependency graph and their actual runtime call graph. This means real environments contain **undocumented cross-tier connections** — services that communicate at runtime through paths not visible in configuration files or service mesh policies.

### 16.1 Shadow Connection Rule

In approximately **20–30% of generated microservice configs**, add one optional `MUST_REACH` constraint between non-adjacent tiers. This models a misconfigured or undocumented runtime path that bypasses the intended firewall segmentation.

**Allowed shadow connections** (use at most one per config):

| Shadow Path | Plausible Cause | Protocol |
|-------------|-----------------|----------|
| WorkerTier → DataTier (direct) | Airflow DAG writing results directly to MongoDB | `MongoDB` (27017) |
| WebTier → AuthTier (direct) | Nginx auth_request bypassing AppTier oauth2-proxy | `HTTPS` (8443) |
| AppTier → WorkerTier (reverse) | Jenkins triggering Kafka producers directly | `AMQP` (5672) |

### 16.2 Modeling Shadow Connections in YAML (GLOBALTECH Z6 example)

Use `MUST_REACH` (not `MUST_CONNECT`) to indicate an undocumented path within the GLOBALTECH AWS Zone (Z6) that does not appear in formal firewall policy but exists at runtime:

```yaml
inter_domain_constraints:
  - source_domain: AWSCloud_Worker   # Z6 Worker Tier (10.3.5.0/24)
    target_domain: AWSCloud_Data     # Z6 Data Tier (10.3.3.0/24)
    constraints:
      - source: AWSWorkerNodes
        target: AWSDataStores
        relation: MUST_REACH         # undocumented Airflow→MongoDB runtime path
        protocol: MongoDB
```

### 16.3 Attack Path Implication

Shadow connections create **tier-skipping attack paths** that the DRL agent must discover. An attacker who compromises an AWS Worker tier node in Z6 may directly reach the AWS Data tier via the undocumented MongoDB path, bypassing the AWS App tier pivot requirement.

This makes generated scenarios harder and more realistic: the agent must explore non-obvious paths rather than always following the canonical vertical chain.

**Important:** Shadow connections must still use specific protocols (never `ALL`). They represent misconfigured access, not intentional firewall holes.