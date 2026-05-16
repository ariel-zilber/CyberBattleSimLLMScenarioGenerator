# GLOBALTECH Enterprise Network Architecture — Template Prompt & Extraction

> **Purpose**: This file serves dual purposes: (1) a detailed image-generation prompt that fully reconstructs the GLOBALTECH Enterprise Network Architecture, and (2) a structured template for downstream LLM pipelines to embed more specific, domain-tailored sub-networks into the base topology. The base architecture represents a realistic, vendor-specific enterprise network skeleton; downstream pipelines should treat each zone as an extension point.

---

## PART 1 — IMAGE GENERATION PROMPT

Generate a highly detailed, professional enterprise network architecture diagram titled **"GLOBALTECH ENTERPRISE NETWORK ARCHITECTURE"** in a clean, flat-vector technical style. The layout is landscape-oriented with a white or very light gray background, clear section boundaries drawn with rounded rectangles, and standard IT vector icons (routers, firewalls, switches, servers, cloud, user endpoints). Use solid lines for wired connections, dashed lines for wireless/VPN tunnels, double lines for redundant links, and dotted lines for SatCom links. Include a legend box in the top-right corner defining these four line types.

The diagram is divided into seven named regional zones, arranged as follows:

---

### Zone 1 — Corporate HQ / Main Site (left third of diagram)

Draw a large outer bounding box labeled **"Corporate HQ / Main Site"** containing three stacked sub-zones plus a VLAN row at the bottom.

#### 1a. Core Layer (top sub-zone of HQ)
- Label: **"Core Layer"**
- Two high-performance Cisco Catalyst 9600 Multi-Chassis switches in a redundant pair:
  - Left switch labeled **"HQ-CORE-01/02"** with sub-label: *"Cisco Catalyst 9600 / Multi-Chassis / Two Layer high-performance"*
  - Right switch labeled **"HQ-CORE-02"** with sub-label: *"Cisco Catalyst 9600 / Two Layer high-performance"*
- A bidirectional link between the two core switches labeled **"100Gbps / EtherChannel (MEC)"**
- A **"Server Farm"** block on the far left of this sub-zone, connected to HQ-CORE-01/02
- A **"User Segments"** label at the bottom-right of this sub-zone indicating downstream segments
- All links within the Core Layer are 100Gbps

#### 1b. Distribution Layer (middle sub-zone of HQ)
- Label: **"Distribution Layer"**
- Two Cisco Catalyst 9500 switches arranged side-by-side:
  - **"HQ-DIST-01"** (left) and **"HQ-DIST-02"** (right), both labeled *"Catalyst 9500"*
- Cross-links at **10Gbps** from each Core switch down to each Distribution switch (full-mesh: 4 links total)
- A horizontal redundant link between HQ-DIST-01 and HQ-DIST-02

#### 1c. Access Layer (bottom sub-zone of HQ)
- Label: **"Access Layer"**
- Five Cisco Catalyst 9300 access switches arranged horizontally:
  - **HQ-ACC-01** — VLAN1 (Sales)
  - **HQ-ACC-02** — VLAN2 (R&D)
  - **HQ-ACC-03** — VLAN3 (Finance)
  - **HQ-ACC-04** — VLAN4 (Admin)
  - **HQ-ACC-05** — WiFi / AP VLAN (connects to HQ-AP-01-10 via dashed wireless links)
- Each switch connects downward (1Gbps) to its respective VLAN endpoint group
- HQ-ACC-01 through HQ-ACC-04 connect to HQ-DIST-01; HQ-ACC-05 connects to HQ-DIST-02

#### 1d. User VLANs (bottom row of HQ box)
- Five labeled endpoint blocks in a horizontal row below the Access Layer:
  - **"User ID"** (authentication/identity icon)
  - **"Sales"** (workstation icon)
  - **"R&D"** (workstation icon)
  - **"Finance"** (workstation icon)
  - **"Admin"** (workstation icon)
  - **"WiFi APs"** — labeled *"HQ-AP-01-10"* (wireless AP icon), connected via dashed line from HQ-ACC-05

---

### Zone 2 — HQ Edge (center-left, vertically between HQ and the Internet)

Draw a labeled bounding box **"HQ Edge"** containing the perimeter security and WAN gateway stack.

- **Multi-Chassis EtherChannel Gateway (MEC)**: top of the HQ Edge box; this is the downlink handoff point toward the Corporate HQ Core Layer. Label it *"Multi-Chassis / EtherChannel"*
- **Redundant Firewall Pair (Active/Passive HA)**: two parallel firewall icons:
  - **"HQ-FW-01"** — labeled *"Palo Alto PA-5200 (HA Active)"*
  - **"HQ-FW-02"** — labeled *"Palo Alto PA-5200 (HA Passive)"*, cross-linked to HQ-FW-01
- **Cisco ISE (NAC)**: identity/access control appliance, labeled *"Cisco ISE (NAC)"*, on the right side of HQ Edge
- **SolarWinds NPM**: network monitoring appliance, labeled *"SolarWinds NPM"*, on the right side of HQ Edge
- **Edge Router**: labeled **"Edge Router / Cisco ISR 4451"**, below the firewall pair, directly connected to both HQ-FW-01 and HQ-FW-02
- **Site-to-Site WAN/VPN**: a dashed outbound arrow from the Edge Router labeled *"Site-to-Site WAN/VPN"* pointing toward the MPLS cloud in the Branch Office zone

---

### Zone 3 — Internet (center of diagram)

- A central cloud icon labeled **"INTERNET"** — this is the connectivity hub of the entire diagram
- All external zones radiate from or connect through this node

---

### Zone 4 — Internet Edge (between Internet cloud and HQ Edge)

Draw a labeled sub-zone **"Internet Edge"** containing:
- Two ISP routers side-by-side representing carrier diversity:
  - **"ISP-A"** (left router) — connects upward to the Internet cloud and downward to HQ-FW-01
  - **"ISP-B"** (right router) — connects upward to the Internet cloud and downward to HQ-FW-02
- **Web Gateway**: inline proxy appliance icon labeled *"Web Gateway"*, connected to the Internet cloud
- **WAF**: Web Application Firewall icon labeled *"WAF"*, connected to the Internet cloud
- **Security Stack (IPS)**: an inline IPS appliance icon labeled *"Security Stack (IPS)"*, connected to the Internet cloud above

---

### Zone 5 — Branch Office (top-center-right of diagram)

Draw a labeled bounding box **"Branch Office"** containing:
- **SD-WAN appliance**: labeled **"SD-WAN / Cisco Meraki MX"** at the top
- **MPLS cloud**: labeled **"MPLS"**, connected to the SD-WAN above and to the Branch Router below
- **Branch Router**: at the bottom of the Branch box
- The MPLS cloud connects leftward to the Internet cloud and receives the Site-to-Site WAN/VPN dashed link from the HQ Edge Router

---

### Zone 6 — Public Cloud / AWS (top-right of diagram)

Draw a labeled bounding box **"Public Cloud (AWS)"** with a distinct light blue or purple tint, containing:
- **VPC** inner bounding box containing three tiers arranged vertically or in an L-shape:
  - **Web Tier**: web server icons
  - **App Tier**: application server icons
  - **DB Tier**: database icon labeled *"(PostgreSQL)"*
- **Transit Gateway TGW-1**: connects to the VPC tiers
- **Transit Gateway TGW-2**: connects to TGW-1 and provides the external uplink
- **Direct Connect**: a 10Gbps dedicated link arrow from TGW-2 down to the Internet cloud, labeled *"Direct Connect / 10Gbps"*

---

### Zone 7 — Remote Users (bottom-right of diagram)

Draw a labeled bounding box **"Remote Users"** containing:
- **SASE**: labeled *"SASE / Cloud-based SASE Edge"* with a cloud-security icon
- **Client-to-Site VPN**: labeled *"Client-to-Site VPN / Cisco AnyConnect"*
- **Remote Workers / BYOD**: laptop icons labeled *"Remote Workers / BYOD"*, connecting via dashed lines upward to VPN and SASE nodes
- VPN and SASE connect upward via dashed lines to the Internet cloud

---

### Zone 8 — Key Management (bottom-center of diagram)

Draw a labeled section **"Key Management"** outside the main HQ box, containing three tool icons in a horizontal row:
- **SolarWinds NPM** — labeled *"SolarWinds NPM / Monitoring"*
- **Splunk SIEM** — labeled *"Splunk SIEM / Security"*
- **Cisco ISE** — labeled *"Cisco ISE / NAC & Identity"* with the Cisco ISE icon

---

### Legend (top-right corner)
A small box titled **"Legend"** with four entries:
- Solid line — Wired
- Dashed line — Wireless / VPN
- Double line — Redundant Links
- Dotted line — SatCom Links

---

### Visual Style
- **Background**: white or very light gray (#f8f9fa)
- **Font**: clean sans-serif (e.g. Inter, Roboto), 9–11pt for labels, 13pt bold for zone titles
- **Icon style**: flat-vector, monochrome or lightly colored; standard Cisco-style or generic IT icons
- **Color coding by zone**:
  - HQ / Corporate: light gray border (#424242)
  - Core Layer: light purple (#f3e5f5)
  - Distribution Layer: deeper purple (#ede7f6)
  - Access Layer: light indigo (#e8eaf6)
  - HQ Edge: light red (#ffebee)
  - Internet Edge: amber/yellow (#fff8e1)
  - AWS/Cloud: light blue-indigo (#e8eaf6)
  - Branch Office: yellow-green (#f9fbe7)
  - Remote Users: light pink (#fce4ec)
  - Key Management: light teal (#e0f2f1)

---

## PART 2 — EXTRACTED NETWORK ARCHITECTURE

> This section is the structured, machine-readable representation of the network extracted from the reference image. Downstream LLM pipelines should read this section to understand the base topology and determine where to embed additional sub-networks.

### 2.1 Topology Overview

| Property | Value |
|---|---|
| Organization | GLOBALTECH |
| Diagram title | GLOBALTECH Enterprise Network Architecture |
| Layout direction | Top-Down (TD) with lateral regional groupings |
| Design pattern | Hierarchical enterprise LAN + SD-WAN branch + cloud egress + SASE remote access |
| Redundancy model | Dual-homed ISPs, redundant firewall pairs, dual core switches (MEC), cross-linked distribution |
| WAN transport | MPLS (branch), Direct Connect (cloud), Site-to-Site VPN (branch fallback), SASE (remote users) |

---

### 2.2 Zone Inventory

| Zone ID | Zone Name | Role | Extension Point |
|---|---|---|---|
| Z1 | Corporate HQ / Main Site | Primary campus LAN (Core/Dist/Access hierarchy) | Yes — Access Layer VLANs are open for sub-network embedding |
| Z2 | HQ Edge | Perimeter security, WAN handoff | Yes — additional security appliances or SD-WAN can be inserted |
| Z3 | Internet | Public internet hub | No |
| Z4 | Internet Edge | ISP uplink, IPS, DLP | Yes — additional ISPs or scrubbing centers can be added |
| Z5 | Branch Office | Remote site via SD-WAN / MPLS | Yes — entire zone is a template for N branch replications |
| Z6 | Public Cloud (AWS) | IaaS workloads (Web/App/DB tiers) | Yes — additional cloud services, regions, or providers can be nested |
| Z7 | Remote Users | SASE + VPN remote workforce | Yes — additional SASE providers or device types can be added |
| Z8 | Key Management | Monitoring, SIEM, identity | Yes — additional tools (EDR, IPAM, etc.) can be added |

---

### 2.3 Device Inventory

#### Internet & Internet Edge (Z3, Z4)
| Device | Type | Model / Label | Connects To |
|---|---|---|---|
| INTERNET | Cloud hub | — | ISP-A, ISP-B, MPLS, AWS Direct Connect, CVPN, SASE |
| ISP-A | Router | ISP-A (Carrier A) | INTERNET, HQ-FW-01 |
| ISP-B | Router | ISP-B (Carrier B) | INTERNET, HQ-FW-02 |
| Web Gateway | Inline proxy | — | INTERNET |
| WAF | Web Application Firewall | — | INTERNET |
| Security Stack (IPS) | Inline IPS | — | INTERNET |

#### HQ Edge (Z2)
| Device | Type | Model / Label | Connects To |
|---|---|---|---|
| HQ-FW-01 | Firewall | Palo Alto PA-5200 (HA Active) | ISP-A, HQ-FW-02, Edge Router, MEC |
| HQ-FW-02 | Firewall | Palo Alto PA-5200 (HA Passive) | ISP-B, HQ-FW-01, Edge Router, MEC |
| Edge Router | Router | Cisco ISR 4451 | HQ-FW-01, HQ-FW-02, MPLS (Site-to-Site VPN) |
| Cisco ISE | NAC / Identity | Cisco Identity Services Engine | HQ Edge (802.1X enforcement, management plane) |
| SolarWinds NPM | Network monitoring | SolarWinds Network Performance Monitor | HQ Edge (management plane) |
| MEC Gateway | Switch/Aggregation | Multi-Chassis EtherChannel (MEC) | HQ-FW-01, HQ-FW-02, HQ-CORE-01/02, HQ-CORE-02 |

#### Corporate HQ — Core Layer (Z1)
| Device | Type | Model / Label | Connects To |
|---|---|---|---|
| HQ-CORE-01/02 | Switch | Cisco Catalyst 9600 Multi-Chassis, 100Gbps | MEC, HQ-CORE-02 (100Gbps MEC), Server Farm, HQ-DIST-01, HQ-DIST-02 |
| HQ-CORE-02 | Switch | Cisco Catalyst 9600, 100Gbps | HQ-CORE-01/02 (100Gbps MEC), MEC, HQ-DIST-01, HQ-DIST-02 |
| Server Farm | Server cluster | — | HQ-CORE-01/02 |

#### Corporate HQ — Distribution Layer (Z1)
| Device | Type | Model / Label | Connects To |
|---|---|---|---|
| HQ-DIST-01 | Switch | Cisco Catalyst 9500 | HQ-CORE-01/02, HQ-CORE-02, HQ-DIST-02, HQ-ACC-01, HQ-ACC-02, HQ-ACC-03 |
| HQ-DIST-02 | Switch | Cisco Catalyst 9500 | HQ-CORE-01/02, HQ-CORE-02, HQ-DIST-01, HQ-ACC-04, HQ-ACC-05 |

#### Corporate HQ — Access Layer (Z1)
| Device | Type | Model / Label | VLAN | Connects To |
|---|---|---|---|---|
| HQ-ACC-01 | Switch | Cisco Catalyst 9300 | VLAN1 — Sales | HQ-DIST-01, Sales Users |
| HQ-ACC-02 | Switch | Cisco Catalyst 9300 | VLAN2 — R&D | HQ-DIST-01, R&D Users |
| HQ-ACC-03 | Switch | Cisco Catalyst 9300 | VLAN3 — Finance | HQ-DIST-01, Finance Users |
| HQ-ACC-04 | Switch | Cisco Catalyst 9300 | VLAN4 — Admin | HQ-DIST-02, Admin Users |
| HQ-ACC-05 | Switch | Cisco Catalyst 9300 | WiFi/AP | HQ-DIST-02, HQ-AP-01-10 (wireless) |
| HQ-ACC-06 | Switch | Cisco Catalyst 9300 | Guest VLAN (internet-only) | HQ-DIST-02, Guest endpoints |
| HQ-ACC-07 | Switch | Cisco Catalyst 9300 | IoT VLAN (micro-segmented) | HQ-DIST-02, IoT devices |

#### Corporate HQ — User VLANs (Z1)
| Endpoint Group | Type | VLAN | Access Switch |
|---|---|---|---|
| User ID | Authentication / identity endpoint | — | HQ-ACC-01 |
| Sales Users | Workstations / endpoints | VLAN1 | HQ-ACC-01 |
| R&D Users | Workstations / endpoints | VLAN2 | HQ-ACC-02 |
| Finance Users | Workstations / endpoints | VLAN3 | HQ-ACC-03 |
| Admin Users | Workstations / endpoints | VLAN4 | HQ-ACC-04 |
| WiFi APs (HQ-AP-01-10) | Wireless access points | WiFi VLAN | HQ-ACC-05 (wireless, dashed) |
| Guest Endpoints | User devices (unmanaged) | Guest VLAN | HQ-ACC-06 |
| IoT Devices | Cameras, printers, badge readers | IoT VLAN | HQ-ACC-07 |

#### Branch Office (Z5)
| Device | Type | Model / Label | Connects To |
|---|---|---|---|
| SD-WAN / Cisco Meraki MX | SD-WAN appliance | Cisco Meraki MX | MPLS |
| MPLS | WAN cloud | — | SD-WAN, Branch Router, INTERNET, HQ Edge Router (VPN) |
| Branch Router | Router | — | MPLS |

#### Public Cloud — AWS (Z6)
| Device | Type | Label | Connects To |
|---|---|---|---|
| Transit Gateway TGW-2 | AWS TGW | TGW-2 | INTERNET (Direct Connect 10Gbps), TGW-1 |
| Transit Gateway TGW-1 | AWS TGW | TGW-1 | TGW-2, Web Tier, App Tier, DB Tier |
| Web Tier | Server (VPC) | Web Tier | TGW-1 |
| App Tier | Server (VPC) | App Tier | TGW-1 |
| DB Tier | Database (VPC) | DB Tier (PostgreSQL) | TGW-1 |

#### Remote Users (Z7)
| Device | Type | Label | Connects To |
|---|---|---|---|
| SASE / Cloud-based SASE Edge | Security service | SASE / Cloud-based SASE Edge | INTERNET (dashed) |
| Client-to-Site VPN | VPN endpoint | Client-to-Site VPN / Cisco AnyConnect | INTERNET (dashed) |
| Remote Workers / BYOD | Endpoints (laptops, personal devices) | Remote Workers / BYOD | CVPN (dashed), SASE (dashed) |

#### Key Management (Z8)
| Tool | Type | Label |
|---|---|---|
| SolarWinds NPM | Network monitoring | SolarWinds NPM — Monitoring |
| Splunk SIEM | SIEM / log management | Splunk SIEM — Security |
| Cisco ISE | NAC / identity | Cisco ISE — NAC & Identity |

---

### 2.4 Link / Edge Inventory

| Source | Target | Link Type | Speed / Label |
|---|---|---|---|
| INTERNET | ISP-A | Wired | — |
| INTERNET | ISP-B | Wired | — |
| INTERNET | MPLS | Wired | — |
| INTERNET | CVPN | VPN / dashed | — |
| INTERNET | SASE | VPN / dashed | — |
| INTERNET | Web Gateway | Wired | — |
| INTERNET | WAF | Wired | — |
| INTERNET | Security Stack (IPS) | Wired | — |
| TGW-2 | INTERNET | Direct Connect | 10Gbps |
| ISP-A | ISP-B | Redundant | — |
| ISP-A | HQ-FW-01 | Wired | — |
| ISP-B | HQ-FW-02 | Wired | — |
| HQ-FW-01 | HQ-FW-02 | Redundant (HA) | — |
| HQ-FW-01 | Edge Router | Wired | — |
| HQ-FW-02 | Edge Router | Wired | — |
| HQ-FW-01 | MEC | Wired | — |
| HQ-FW-02 | MEC | Wired | — |
| Edge Router | MPLS | Site-to-Site VPN / dashed | WAN/VPN |
| MEC | HQ-CORE-01/02 | Wired | 100Gbps |
| MEC | HQ-CORE-02 | Wired | 100Gbps |
| HQ-CORE-01/02 | HQ-CORE-02 | Redundant MEC | 100Gbps |
| HQ-CORE-01/02 | Server Farm | Wired | — |
| HQ-CORE-01/02 | HQ-DIST-01 | Wired | 10Gbps |
| HQ-CORE-01/02 | HQ-DIST-02 | Wired | 10Gbps |
| HQ-CORE-02 | HQ-DIST-01 | Wired | 10Gbps |
| HQ-CORE-02 | HQ-DIST-02 | Wired | 10Gbps |
| HQ-DIST-01 | HQ-DIST-02 | Redundant | — |
| HQ-DIST-01 | HQ-ACC-01 | Wired | 1Gbps |
| HQ-DIST-01 | HQ-ACC-02 | Wired | 1Gbps |
| HQ-DIST-01 | HQ-ACC-03 | Wired | 1Gbps |
| HQ-DIST-02 | HQ-ACC-04 | Wired | 1Gbps |
| HQ-DIST-02 | HQ-ACC-05 | Wired | 1Gbps |
| HQ-ACC-01 | VLAN1 Sales Users | Wired | — |
| HQ-ACC-02 | VLAN2 R&D Users | Wired | — |
| HQ-ACC-03 | VLAN3 Finance Users | Wired | — |
| HQ-ACC-04 | VLAN4 Admin Users | Wired | — |
| HQ-ACC-05 | WiFi APs (HQ-AP-01-10) | Wireless / dashed | — |
| HQ-DIST-02 | HQ-ACC-06 | Wired | 1Gbps |
| HQ-DIST-02 | HQ-ACC-07 | Wired | 1Gbps |
| HQ-ACC-06 | Guest Endpoints | Wired | — |
| HQ-ACC-07 | IoT Devices | Wired | — |
| Cisco ISE | HQ-DIST-01 | RADIUS / dashed | 802.1X enforcement |
| Cisco ISE | HQ-DIST-02 | RADIUS / dashed | 802.1X enforcement |
| SD-WAN / Meraki MX | MPLS | Wired | — |
| MPLS | Branch Router | Wired | — |
| TGW-2 | TGW-1 | Wired | — |
| TGW-1 | Web Tier | Wired | — |
| TGW-1 | App Tier | Wired | — |
| TGW-1 | DB Tier | Wired | — |
| Remote Workers / BYOD | CVPN | VPN / dashed | — |
| Remote Workers / BYOD | SASE | Secure tunnel / dashed | — |

---

## PART 3 — DOWNSTREAM EMBEDDING INSTRUCTIONS

> This section is addressed directly to downstream LLM pipelines that receive this file as context. It specifies how to embed a specific sub-network into this base topology.

### 3.1 What This Template Represents

This document describes a **generic, vendor-agnostic enterprise network skeleton** for a fictitious organization called GLOBALTECH. It is intentionally generic so that it can be specialized for any industry or use case (healthcare, OT/ICS, government, finance, retail, etc.) by embedding domain-specific sub-networks into one or more of its extension points.

### 3.2 Extension Points

Each row in the table below is an open slot where a downstream LLM pipeline should inject a more specific sub-network:

| Extension Point | Zone | How to Embed |
|---|---|---|
| **Access Layer VLAN slot** | Z1 — Corporate HQ, Access Layer | Add a new Cisco Catalyst 9300 switch (HQ-ACC-0N) connected to HQ-DIST-01 or HQ-DIST-02, and attach domain-specific endpoints (e.g. medical devices, OT sensors, kiosks) as a new VLAN |
| **HQ Edge security insertion** | Z2 — HQ Edge | Insert additional inline appliances (e.g. DLP proxy, CASB, NDR sensor) between the Palo Alto PA-5200 firewall pair and the MEC, or between the firewalls and the Cisco ISR 4451 Edge Router |
| **Branch Office replication** | Z5 — Branch Office | Clone the entire Branch zone (SD-WAN + MPLS + Branch Router) as B-Site-01, B-Site-02, etc., each with its own subnet and local LAN below the Branch Router |
| **Cloud service addition** | Z6 — Public Cloud (AWS) | Add additional AWS services (Lambda, EKS, S3, GuardDuty), or replicate the AWS zone as a second cloud provider (Azure, GCP) with its own TGW equivalent |
| **Remote access specialization** | Z7 — Remote Users | Replace or augment the SASE node with a specific provider (Zscaler, Netskope, Palo Alto Prisma), add IoT/OT remote devices, or add a jump server / PAW for privileged access |
| **ISP / upstream redundancy** | Z4 — Internet Edge | Add a second ISP (ISP-B) with its own router pair and a BGP peering link, or add a scrubbing center / DDoS mitigation appliance upstream of the firewalls |
| **Management plane expansion** | Z8 — Key Management | Add additional tools: EDR console (CrowdStrike/SentinelOne), IPAM, vulnerability scanner, PAM (CyberArk), or a SOAR platform |
| **DMZ insertion** | Between Z4 and Z2 | Add a DMZ subgraph between Internet Edge and HQ Edge containing public-facing services (reverse proxy, mail gateway, public DNS, WAF) |
| **Guest VLAN** | Z1 — Corporate HQ, Access Layer | Add a new Cisco Catalyst 9300 switch (HQ-ACC-06) connected to HQ-DIST-02, serving a dedicated Guest VLAN with internet-only egress and no route to any corporate VLAN (VLAN1–VLAN4). Guest traffic should be steered via the SASE/Web Gateway path, not the corporate firewall. |
| **IoT VLAN** | Z1 — Corporate HQ, Access Layer | Add a new Cisco Catalyst 9300 switch (HQ-ACC-07) connected to HQ-DIST-02, serving a dedicated IoT VLAN for cameras, printers, badge readers, and other non-managed devices. Apply strict micro-segmentation ACLs: IoT devices may not initiate traffic to any user VLAN or the Data Center; inbound management traffic from the Cisco ISE (NAC) segment only. |

### 3.3 Embedding Protocol for Downstream LLMs

When generating a specialized variant of this network, follow these steps:

1. **Select one or more extension points** from the table above that match the target domain.
2. **Keep all base zones and devices unchanged** unless the task explicitly requires replacing a component. Additions only — do not delete base components.
3. **Name new devices consistently** with the existing convention:
   - HQ campus devices: `HQ-<ROLE>-<NN>` (e.g. `HQ-ACC-06`, `HQ-OT-SW-01`)
   - Branch devices: `B<NN>-<ROLE>-<NN>` (e.g. `B02-RTR-01`, `B02-ACC-01`)
   - Cloud resources: use AWS/Azure/GCP service naming
4. **Preserve link types**: wired for LAN, dashed for VPN/wireless, redundant for HA pairs.
5. **Update the Device Inventory and Link Inventory tables** in Parts 2.3 and 2.4 with all new components.
6. **Label new VLANs** with descriptive names matching the domain (e.g. `OT-VLAN`, `MedDevice-VLAN`, `POS-VLAN`).
7. **Add a new zone row to Section 2.2** for any entirely new logical zone introduced.
8. **Output format**: return an updated version of this full document (Parts 1, 2, and 3) with the new components integrated, plus a regenerated Mermaid `.mmd` source file and render the PNG using `mmdc -s 4 -t neutral`.

### 3.4 Example Embedding Prompts

The following are example instructions a downstream pipeline might receive (do not execute — illustrative only):

- *"Embed an OT/ICS network segment into the GLOBALTECH base topology. Add a Purdue Model hierarchy (Levels 0–3) as a new VLAN under HQ-ACC-06, separated by a unidirectional data diode from the IT network."*
- *"Extend GLOBALTECH with a healthcare sub-network: add a MedDevice-VLAN under HQ-ACC-06 containing PACS servers, infusion pumps, and nurse call systems, compliant with HIPAA segmentation requirements."*
- *"Add three branch offices (B-Site-01 through B-Site-03) to the GLOBALTECH topology, each with local SD-WAN, a small access switch, and 50–200 endpoint nodes. Show MPLS and VPN failover paths."*
- *"Extend the Public Cloud zone with a second region (AWS eu-west-1) connected via VPC peering, and add an Azure AD Tenant connected to the on-prem SolarWinds ISE via Azure AD Connect."*
- *"Add a Guest VLAN (HQ-ACC-06, internet-only, no corporate routing) and an IoT VLAN (HQ-ACC-07, micro-segmented, ISE-managed) to the GLOBALTECH Access Layer. Show explicit ACL deny rules between the new VLANs and VLAN1–VLAN4."*
