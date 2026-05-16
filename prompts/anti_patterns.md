# Anti-Patterns: Common LLM Hallucinations and Structural Mistakes

This document catalogs every known failure mode observed when LLMs generate domain configuration YAML files. Each section includes the incorrect pattern, the correct pattern, and the exact parser error it causes.

---

## Category 1: Top-Level Structure Errors

### AP-001: `solvability_vulnerabilities` formatted as a list

**WRONG — Parser will crash:**
```yaml
solvability_vulnerabilities:
  - name: Solvability.EternalBlue
    type: REMOTE
    ...
```

**CORRECT — Must be a dictionary with exactly four keys:**
```yaml
solvability_vulnerabilities:
  remote_access:
    - name: Solvability.EternalBlue
      type: REMOTE
      ...
  credential_leak:
    - ...
  discovery:
    - ...
  goal_access:
    - ...
```

**Why it fails:** The parser calls `data['solvability_vulnerabilities']['remote_access']` — if the top-level is a list, this raises a `TypeError: list indices must be integers or slices, not str`.

---

### AP-002: `constraint_vulnerabilities` formatted as a list

**WRONG:**
```yaml
constraint_vulnerabilities:
  - name: Local.Credentials.Leak
    type: LOCAL
    ...
  - name: Local.Network.Discovery
    type: LOCAL
    ...
```

**CORRECT — Must be a dictionary with exactly two keys:**
```yaml
constraint_vulnerabilities:
  leak_known_credentials:
    name: Local.Credentials.Leak
    type: LOCAL
    ...
  leak_neighbors:
    name: Local.Network.Discovery
    type: LOCAL
    ...
```

---

### AP-003: `start_node.vulnerabilities` formatted as a list

**WRONG:**
```yaml
start_node:
  vulnerabilities:
    - name: External.Discovery
      type: LOCAL
      ...
    - name: External.CredLeak
      type: LOCAL
      ...
```

**CORRECT — Must be a dictionary with exactly two keys:**
```yaml
start_node:
  vulnerabilities:
    discovery:
      name: External.Discovery
      type: LOCAL
      ...
    credential_leak:
      name: External.CredLeak
      type: LOCAL
      ...
```

---

## Category 2: Constraint Targeting Errors

### AP-004: Using ServiceName instead of GroupName in constraints

**WRONG — Uses singular service name:**
```yaml
constraints:
  - source: AWSAppServer
    target: AWSPostgreSQL
    relation: MUST_CONNECT
    protocol: PostgreSQL
```

**CORRECT — Uses plural group name (GLOBALTECH convention):**
```yaml
constraints:
  - source: AWSAppServers
    target: AWSPostgreSQLs
    relation: MUST_CONNECT
    protocol: PostgreSQL
```

**Why it fails:** The constraint engine looks up nodes by group name. If the group name doesn't match, the constraint is silently ignored and the network topology is broken.

---

### AP-005: Placing cross-zone rules in local domain constraints

**WRONG — Internet Edge-to-Server Farm rule placed inside the Internet Edge domain's `constraints` block:**
```yaml
domains:
  - name: InternetEdge
    constraints:
      - source: WAFAppliances
        target: MSSQLServers   # MSSQLServers is in ServerFarm domain!
        relation: MUST_CONNECT
        protocol: MSSQL
```

**CORRECT — Cross-zone rules belong in `inter_domain_constraints` (GLOBALTECH zones):**
```yaml
inter_domain_constraints:
  - source_domain: HQ_VLANs
    target_domain: ServerFarm
    constraints:
      - source: AdminWorkstations
        target: MSSQLServers
        relation: MUST_CONNECT
        protocol: MSSQL
```

**Why it fails:** The local domain constraint engine only resolves groups within the same domain. References to groups in other domains are silently dropped.

---

### AP-006: Using property name as constraint `source` or `target`

**WRONG — `Unpatched` is a property, not a group:**
```yaml
constraints:
  - source: Unpatched
    target: DomainControllers
    relation: MUST_CONNECT
```

**CORRECT — For property assignment, use `MUST_HAVE` with the property as `target`:**
```yaml
constraints:
  - source: LegacyWorkstations
    target: Unpatched
    relation: MUST_HAVE
```

---

## Category 3: Reward Field Errors

### AP-007: Using integers for reward fields

**WRONG — Reward is an integer:**
```yaml
solvability_vulnerabilities:
  remote_access:
    - name: Solvability.EternalBlue
      reward: 100
```

**CORRECT — Reward must be a descriptive string:**
```yaml
solvability_vulnerabilities:
  remote_access:
    - name: Solvability.EternalBlue
      reward: "Remote code execution via EternalBlue on unpatched Windows host"
```

**Why it fails:** The cyberbattle library expects a string for `reward_string`. Passing an integer causes a `TypeError` during node construction.

---

### AP-008: `constraint_vulnerabilities` reward missing `{target}` placeholder

**WRONG:**
```yaml
constraint_vulnerabilities:
  leak_known_credentials:
    reward: "Credentials leaked"
```

**CORRECT — Must include `{target}` for template substitution:**
```yaml
constraint_vulnerabilities:
  leak_known_credentials:
    reward: "Leaked credentials for {target}"
```

---

## Category 4: Property Registration Errors

### AP-009: Using properties not declared in `base_properties`

**WRONG — `ADCS` used in match_properties but never declared:**
```yaml
identifiers:
  base_properties:
    - Windows
    - DomainController
    # ADCS is missing!

solvability_vulnerabilities:
  remote_access:
    - name: Solvability.ADCSEsc1
      match_properties: [Windows, DomainController, ADCS]
```

**CORRECT — Register every property:**
```yaml
identifiers:
  base_properties:
    - Windows
    - DomainController
    - ADCS           # Must be here

solvability_vulnerabilities:
  remote_access:
    - name: Solvability.ADCSEsc1
      match_properties: [Windows, DomainController, ADCS]
```

---

### AP-010: Missing `breach_node` in `base_properties`

**WRONG:**
```yaml
identifiers:
  base_properties:
    - Windows
    - Linux
    # breach_node is missing!
```

**CORRECT:**
```yaml
identifiers:
  base_properties:
    - Windows
    - Linux
    - breach_node    # Required — always include this
```

---

## Category 5: Goal Node Errors

### AP-011: No service has `is_goal: true`

**WRONG:**
```yaml
services:
  DatabaseServer:
    is_goal: false
  DomainController:
    is_goal: false
```

**CORRECT — At least one service must be a goal:**
```yaml
services:
  DatabaseServer:
    is_goal: true
    value: 10000
```

---

### AP-012: Goal node has `Unauthenticated` property

**WRONG:**
```yaml
services:
  DatabaseServer:
    is_goal: true
    default_properties: [Windows, DatabaseServer, Unauthenticated]  # BAD!
```

**CORRECT — Goal nodes must require authentication:**
```yaml
services:
  DatabaseServer:
    is_goal: true
    default_properties: [Windows, DatabaseServer, MSSQL, DomainJoined]
```

---

## Category 6: Vulnerability Field Errors

### AP-013: Missing `probability` field in solvability vulnerabilities

**WRONG:**
```yaml
solvability_vulnerabilities:
  remote_access:
    - name: Solvability.EternalBlue
      type: REMOTE
      cost: 1.0
      success_rate: 0.65
      # probability is missing!
```

**CORRECT:**
```yaml
solvability_vulnerabilities:
  remote_access:
    - name: Solvability.EternalBlue    # CVE-2017-0144, CVSS 8.8
      type: REMOTE
      cost: 1.5
      success_rate: 0.88              # CVE-derived, not hand-authored
      probability: 0.65               # HIGH severity → 0.65
```

---

### AP-014: Using hand-authored `success_rate` instead of CVE-derived values

**WRONG — Round numbers signal hand-authored guesses:**
```yaml
solvability_vulnerabilities:
  remote_access:
    - name: Solvability.EternalBlue
      success_rate: 0.65  # Round number — not CVE-derived
    - name: Solvability.RCE_WebShell
      success_rate: 1.0   # Never 1.0 for exploits
```

**CORRECT — Use exact CVE-derived values from the vulnerability catalog:**
```yaml
solvability_vulnerabilities:
  remote_access:
    - name: Solvability.EternalBlue      # CVE-2017-0144, CVSS 8.8
      success_rate: 0.88                 # = 8.8/10 × 1.0 (AV:N, AC:H→×0.7 not applied here)
      cost: 1.5
    - name: Solvability.Nginx_LibCrypto_Critical  # CVE-2025-15467, CVSS 9.8
      success_rate: 0.90                           # = min(0.90, 9.8/10)
      cost: 1.0
```

*Exception: Trivial discovery actions like ping sweeps may use `success_rate: 1.0`. All other values MUST come from `docs/reference/vulnerability_catalog.md`.*

---

### AP-015: OS-vulnerability mismatch

**WRONG — EternalBlue (Windows SMB exploit) on a Linux AWS web server:**
```yaml
services:
  AWSWebServer:
    allowed_os: [Linux]
    default_properties: [Linux, WebServer, LibCrypto]

solvability_vulnerabilities:
  remote_access:
    - name: Solvability.EternalBlue
      match_properties: [Linux, WebServer]  # EternalBlue requires Windows!
```

**CORRECT — Match properties must reflect actual OS and GLOBALTECH role:**
```yaml
solvability_vulnerabilities:
  remote_access:
    - name: Solvability.Nginx_LibCrypto_Critical   # CVE-2025-15467 — Z6 AWSWebServer
      match_properties: [Linux, WebServer, LibCrypto]
    - name: Solvability.EternalBlue                # CVE-2017-0144 — Z1 FileServer
      match_properties: [Windows, Win7, SMBv1, Unpatched]
    - name: Solvability.PanOS_CMDInject            # CVE-2024-3400 — Z2 PaloAltoFirewall
      match_properties: [Firewall, PaloAlto, PANOS, GlobalProtect]
```

---

## Category 7: Network Topology Errors

### AP-016: Attacker start node inside internal subnet

**WRONG — Attacker placed inside a GLOBALTECH internal zone:**
```yaml
start_node:
  subnet: 10.0.1.0/24   # This is the GLOBALTECH Internet Edge (Z4) — internal!
  ip: 10.0.1.100
```

**CORRECT — Attacker must be on public internet, outside all GLOBALTECH zones:**
```yaml
start_node:
  subnet: 0.0.0.0/0     # Public internet — outside GLOBALTECH Z4 through Z8
  ip: 203.0.113.5
```

---

### AP-017: Internet Edge directly connected to Server Farm (bypassing GLOBALTECH security stack)

**WRONG — Internet Edge (Z4) connected directly to Server Farm, bypassing HQ Edge firewalls:**
```yaml
inter_domain_constraints:
  - source_domain: InternetEdge
    target_domain: ServerFarm
    constraints:
      - source: WAFAppliances
        target: MSSQLServers
        relation: MUST_CONNECT
        protocol: MSSQL   # Direct Z4 → Server Farm bypasses Palo Alto firewall!
```

**CORRECT — Traffic must pass through HQ Edge (Z2) and HQ VLANs (Z1) first:**
```yaml
inter_domain_constraints:
  - source_domain: InternetEdge
    target_domain: HQ_Edge
    constraints:
      - source: WAFAppliances
        target: PaloAltoFirewalls
        relation: MUST_CONNECT
        protocol: HTTPS
  - source_domain: HQ_VLANs
    target_domain: ServerFarm
    constraints:
      - source: AdminWorkstations
        target: MSSQLServers
        relation: MUST_CONNECT
        protocol: MSSQL
```

---

### AP-018: Overlapping subnets between GLOBALTECH domains

**WRONG:**
```yaml
domains:
  - name: HQ_Edge
    subnet: 10.0.2.0/24
  - name: HQ_VLANs
    subnet: 10.0.2.0/24   # Same subnet as HQ Edge!
```

**CORRECT — Each GLOBALTECH zone domain must have a unique, non-overlapping subnet:**
```yaml
domains:
  - name: InternetEdge
    subnet: 10.0.1.0/24   # Z4
  - name: HQ_Edge
    subnet: 10.0.2.0/24   # Z2
  - name: HQ_VLANs
    subnet: 10.1.0.0/24   # Z1 user segments
  - name: ServerFarm
    subnet: 10.1.10.0/24  # Z1 server farm
  - name: AWSCloud
    subnet: 10.3.0.0/24   # Z6
```

---

## Category 8: Service Definition Errors

### AP-019: Missing required service keys

**WRONG — `allowed_os` and `is_goal` are missing:**
```yaml
services:
  AWSAppServer:
    port: 8080
    value: 800
    default_properties: [Linux, AppServer, GoRuntime]
```

**CORRECT — All five fields are required (GLOBALTECH service example):**
```yaml
services:
  AWSAppServer:
    port: 8080
    value: 800
    allowed_os: [Linux]
    default_properties: [Linux, AppServer, GoRuntime]
    is_goal: false
```

---

### AP-020: Constraint `protocol` field left blank or set to "ALL"

**WRONG:**
```yaml
constraints:
  - source: WebServers
    target: AppServers
    relation: MUST_CONNECT
    protocol: ALL   # Too permissive, unrealistic
```

**CORRECT — Always specify the exact protocol:**
```yaml
constraints:
  - source: WebServers
    target: AppServers
    relation: MUST_CONNECT
    protocol: HTTPS
```

---

## Category 9: Missing or Malformed Metadata Block

### AP-021: `metadata` block absent or placed after `config`

**WRONG — No metadata block:**
```yaml
config:
  min_total_nodes: 30
  max_total_nodes: 250
  ...
```

**WRONG — metadata after config:**
```yaml
config:
  min_total_nodes: 30
  ...
metadata:
  scenario_id: S-LIN-01
```

**CORRECT — metadata is always the first key:**
```yaml
metadata:
  scenario_id: S-LIN-01-META
  agent: S_Linux
  training_mode: meta
  zones: [Z6_WebTier, Z6_AppTier, Z6_WorkerTier, Z6_DataTier]
  terminal_goal: AWSPostgreSQL
  intermediate_goals:
    - name: AWSRedis
      value: 6500
      reason: hub near-goal reward
  node_range: [30, 250]
  attack_path:
    - "Probe — Remote.Probe.Linux on AWSWebServer"
    - "WebTier exploit → AWSAppServer"
    - "Credential extraction — Local.Cloud.EnvCredLeak on AppServer"
    - "WorkerTier → DataTier MUST_CONNECT → AWSPostgreSQL (TERMINAL)"
  notes: |
    AWSPostgreSQL (Alpine) has no REMOTE CVEs — credential-only access.

config:
  min_total_nodes: 30
  max_total_nodes: 250
  ...
```

**Why it matters:** Tools that read `metadata.terminal_goal` and `metadata.attack_path` depend on the block being present and first. A missing block causes pipeline report generation and quality evaluation to fail silently with incomplete data.

---

### AP-022: `metadata.node_range` out of sync with `config`

**WRONG — node_range disagrees with config:**
```yaml
metadata:
  node_range: [30, 250]   # says 250

config:
  min_total_nodes: 30
  max_total_nodes: 200    # but config says 200!
```

**CORRECT — both must match exactly:**
```yaml
metadata:
  node_range: [30, 200]

config:
  min_total_nodes: 30
  max_total_nodes: 200
```

---

### AP-023: `metadata.terminal_goal` does not match `is_goal: true` service

**WRONG — terminal_goal names a service that is not marked as goal:**
```yaml
metadata:
  terminal_goal: AWSPostgreSQL   # but below it is not a goal!

services:
  AWSPostgreSQL:
    is_goal: false
  AWSRedis:
    is_goal: true                # actual goal is Redis
```

**CORRECT:**
```yaml
metadata:
  terminal_goal: AWSPostgreSQL

services:
  AWSPostgreSQL:
    is_goal: true
  AWSRedis:
    is_goal: false
```
