# Schema Definition: CyberBattleSim Domain Configuration YAML

This document provides a complete, human-readable breakdown of every key in the domain configuration YAML format. Each field specifies its data type, whether it is required or optional, valid values, and a description.

---

## Top-Level Structure

```
metadata                         (required — scenario identity and narrative)
config
identifiers
os_management_ports
start_node
attack_flow
constraint_vulnerabilities
probe_vulnerabilities
solvability_vulnerabilities
services
domains
inter_domain_constraints         (required for multi-domain scenarios)
entry_points
solvability_rules
```

---

## 0. `metadata`

**Type:** Dictionary  
**Required:** Yes — every domain config YAML must open with this block.

Provides scenario identity, narrative intent, and the intended attack path. Used by pipeline reports, the quality evaluator, and MCP tools to cross-check that the structural YAML realises the described scenario.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `scenario_id` | String | Yes | Catalog ID matching `SCENARIO_CATALOG.md` (e.g. `S-LIN-01-META`, `M-ST2-01`) |
| `agent` | String | Yes | Primary specialist agent: `S_Network`, `S_Linux`, `S_Windows`, `S_Identity`, `S_Recon`, or `Meta` |
| `training_mode` | String | Yes | One of: `standalone`, `meta`, `adversarial` |
| `zones` | List[String] | Yes | GLOBALTECH zones present (e.g. `[Z4_InternetEdge, Z2_HQEdge]`) |
| `terminal_goal` | String | Yes | Service name of the terminal goal node (must match a service with `is_goal: true`) |
| `intermediate_goals` | List[Dictionary] | Optional | Near-goal nodes that earn shaped reward but do not end the episode |
| `intermediate_goals[].name` | String | Yes (if present) | Service name of the intermediate node |
| `intermediate_goals[].value` | Integer | Yes (if present) | Node value in the config |
| `intermediate_goals[].reason` | String | Yes (if present) | Why this node earns shaped reward (e.g. `hub near-goal reward`) |
| `node_range` | List[Integer, Integer] | Yes | `[min_total_nodes, max_total_nodes]` — must match `config` block exactly |
| `attack_path` | List[String] | Yes | Ordered steps of the intended attack chain. Each step is a plain-English string. Used by the quality evaluator to verify the chain is realizable. |
| `notes` | String (multiline) | Optional | Free-text prose for design decisions, prerequisites, and non-obvious constraints. Replaces the old YAML comment header. |

### `metadata` Example

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
      reason: hub near-goal reward — reachable without credential chain
  node_range: [30, 250]
  attack_path:
    - "Probe — Remote.Probe.Linux fingerprints AWSWebServer (breach node)"
    - "WebTier exploit — remote CVE on AWSWebServer → AWSAppServer"
    - "AppTier pivot — remote CVE on AWSAppServer → AWSWorkerNode"
    - "Credential extraction — Local.Cloud.EnvCredLeak on owned AppServer extracts PostgreSQL connection string"
    - "Data tier access — WorkerTier → DataTier MUST_CONNECT with extracted creds → AWSPostgreSQL (TERMINAL)"
  notes: |
    AWSPostgreSQL runs Alpine — zero REMOTE CVEs; access is credential-only.
    AWSRedis must carry the Misconfigured property to enable Redis_NoAuth and Redis_Noauth_Config_Rewrite.
    In standalone training (slin_cloud_standalone_v1) AWSRedis is the terminal goal instead.
```

**Validation rules:**
- `terminal_goal` value must match the service name that has `is_goal: true` in the `services` block.
- `node_range[0]` must equal `config.min_total_nodes`; `node_range[1]` must equal `config.max_total_nodes`.
- `attack_path` must have at least 2 entries (probe + at least one exploit step).
- `agent` must be one of the five specialist names or `Meta`.

---

## 1. `config`

**Type:** Dictionary  
**Required:** Yes

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `min_total_nodes` | Integer | Yes | Minimum number of nodes the generator must create |
| `max_total_nodes` | Integer | Yes | Maximum number of nodes the generator may create |
| `goal_config` | Dictionary | Yes | Configuration for goal selection |
| `goal_config.num_goals` | Integer | Yes | Number of goal nodes to designate per episode. Set `> 1` for goal redundancy (multiple acceptable target nodes, agent wins by reaching any one). |
| `goal_config.selection_strategy` | String | Yes | How to select goals. Use `diverse` to spread goals across tiers |
| `goal_config.shared_goal_name` | String | Optional | If set, every goal node receives this property and `goal_name` attribute, making all goals observable as instances of one goal class. Combined with `stop_at_goal_reached: true` at training time, the reward fires only on first acquisition — even with `num_goals > 1`. Must be listed in `identifiers.base_properties` AND in `default_properties` of every `is_goal: true` service. |

---

## 2. `identifiers`

**Type:** Dictionary  
**Required:** Yes

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `standard_ports` | List[String] | Yes | Port names used in this scenario (e.g., `RDP`, `SSH`, `HTTPS`, `SMB`) |
| `standard_ports_extra` | List[String] | Optional | Additional minor ports (e.g., `DNS`, `NTP`, `ICMP`) |
| `base_properties` | List[String] | Yes | **Exhaustive** list of every property label used anywhere in the file. Must include `breach_node`. Used by the parser to validate all references. |

**Critical rule:** Every string used in `services.default_properties`, `solvability_vulnerabilities.match_properties`, or `constraints.target` (for `MUST_HAVE`) MUST be listed here.

---

## 3. `os_management_ports`

**Type:** Dictionary  
**Required:** Yes

Maps OS family names to their remote management port protocol.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `Windows` | String | Recommended | Port for Windows management (typically `RDP`) |
| `Linux` | String | Recommended | Port for Linux management (typically `SSH`) |
| `default` | String | Yes | Fallback port if OS not matched |

---

## 4. `start_node`

**Type:** Dictionary  
**Required:** Yes

Defines the external attacker's initial position.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `subnet` | String (CIDR) | Yes | Must be a public address space (e.g., `0.0.0.0/0` or `203.0.113.0/24`). Must NOT overlap with any domain subnet. |
| `ip` | String | Yes | Specific IP address for the attacker node |
| `properties` | List[String] | Yes | Must include `breach_node`. These properties are applied to the start node. |
| `default_entry_port` | String | Yes | Default port the attacker uses to connect to the first target |
| `preferred_entry_ports` | List[String] | Yes | Ordered list of preferred ports for initial access |
| `entry_node_count` | Integer | Yes | Number of entry nodes. Typically `1`. |
| `leaked_node_coverage` | Float (0.0–1.0) | Yes | Fraction of internal nodes the attacker starts with some knowledge of |
| `min_leaked_nodes` | Integer | Yes | Minimum number of nodes visible to attacker at start |
| `port_selection` | String | Yes | How ports are selected. Use `random`. |
| `vulnerabilities` | Dictionary | Yes | Must be a DICTIONARY (not a list) with exactly two keys: `discovery` and `credential_leak` |

### `start_node.vulnerabilities` Sub-fields

Both `discovery` and `credential_leak` share the same structure:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Unique vulnerability identifier (e.g., `External.Phishing.CredHarvest`) |
| `type` | String | Yes | Must be `LOCAL` for start node vulnerabilities |
| `description` | String | Yes | Human-readable explanation of the exploit |
| `cost` | Float | Yes | Action cost for the RL agent |
| `success_rate` | Float (0.0–1.0) | Yes | Probability the exploit succeeds. Use 0.40–0.80 for realism. |
| `reward` | String | Yes | Descriptive reward string. Must NOT be an integer. |

---

## 5. `attack_flow`

**Type:** List of Dictionaries  
**Required:** Yes

Defines which service types can pivot to which other service types.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `source_pattern` | String | Yes | The `ServiceName` (singular) that serves as pivot source |
| `targets` | List[String] | Yes | List of `ServiceName` values the source can pivot to |

---

## 6. `constraint_vulnerabilities`

**Type:** Dictionary  
**Required:** Yes  
**CRITICAL:** Must be a DICTIONARY, NOT a list. Contains exactly two keys.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `leak_known_credentials` | Dictionary | Yes | Global credential-leaking mechanic applied probabilistically |
| `leak_neighbors` | Dictionary | Yes | Global network discovery mechanic applied probabilistically |

### Sub-fields for both `leak_known_credentials` and `leak_neighbors`:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Unique vulnerability name |
| `type` | String | Yes | Must be `LOCAL` |
| `description` | String | Yes | Human-readable description |
| `cost` | Float | Yes | RL action cost |
| `success_rate` | Float | Yes | Probability of success |
| `reward` | String | Yes | Must include `{target}` placeholder for template substitution |
| `node_probability` | Float (0.0–1.0) | Yes | Fraction of applicable source nodes that receive this vulnerability |
| `target_coverage` | Float (0.0–1.0) | Yes | For each source node, fraction of target nodes it affects |
| `min_targets` | Integer | Yes | Minimum number of targets each source node must affect |
| `default_port` | String | Optional | Port used for this constraint. Only valid in `leak_known_credentials`. |

---

## 7. `probe_vulnerabilities`

**Type:** List of Dictionaries  
**Required:** Yes

Defines OS identification probes used before exploitation.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Identifier (e.g., `Remote.Probe.Windows`) |
| `os` | String | Yes | The OS family this probe detects (e.g., `Windows`, `Linux`) |
| `type` | String | Yes | Must be `REMOTE` |
| `description` | String | Yes | What the probe does |
| `cost` | Float | Yes | RL action cost |
| `success_rate` | Float | Yes | Probability of successful OS identification. Can be 0.90–1.0. |

---

## 8. `solvability_vulnerabilities`

**Type:** Dictionary  
**Required:** Yes  
**CRITICAL:** Must be a DICTIONARY with exactly four keys. Each key maps to a LIST.

The four required keys are:
- `remote_access`
- `credential_leak`
- `discovery`
- `goal_access`

### Fields for each vulnerability in the lists:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Unique exploit identifier |
| `type` | String | Yes | `REMOTE` or `LOCAL` |
| `description` | String | Yes | Human-readable description |
| `cost` | Float | Yes | RL action cost |
| `success_rate` | Float (0.30–0.90) | Yes | CVE-derived probability — use exact values from `vulnerability_catalog.md` (CRITICAL → 0.86–0.90; HIGH → 0.52–0.81; technique → 0.40–0.70). |
| `reward` | String | Yes | Descriptive string reward. NEVER an integer. |
| `match_properties` | List[String] | Yes | All properties a node must have for this exploit to be applicable. All values must exist in `base_properties`. |
| `probability` | Float (0.0–1.0) | Yes | Fraction of qualifying nodes that actually receive this vulnerability |
| `target_coverage` | Float (0.0–1.0) | Optional | For credential-leaking vulns: fraction of targets affected |
| `min_targets` | Integer | Optional | Minimum number of targets for credential-leaking vulns |
| `goal_category` | String | Optional | For `goal_access` vulns: `dump`, `privesc`, `ransomware`, or `persistence` |

---

## 9. `services`

**Type:** Dictionary of ServiceName → Dictionary  
**Required:** Yes

Defines the archetypes for network nodes.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `port` | Integer or String | Yes | Primary service port (can be number like `443` or name like `HTTPS`) |
| `value` | Integer | Yes | Reward value for the RL agent when this node is compromised. Set high (e.g., `10000`) for goals. |
| `allowed_os` | List[String] | Yes | OS families permitted for this service type |
| `default_properties` | List[String] | Yes | Properties automatically applied to all instances of this service. All values must be in `base_properties`. |
| `is_goal` | Boolean | Yes | If `true`, instances of this service are designated as goal nodes. At least one service must have this set to `true`. |

**Rule:** If `is_goal: true`, the service must NOT include `Unauthenticated` in `default_properties`.

---

## 10. `domains`

**Type:** List of Dictionaries  
**Required:** Yes

Each domain represents a physical subnet / network tier.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Unique logical name for this domain — use GLOBALTECH zone names (e.g., `InternetEdge`, `HQ_Edge`, `HQ_VLANs`, `ServerFarm`, `AWSCloud`) |
| `subnet` | String (CIDR) | Yes | Private RFC 1918 CIDR block. Must not overlap with `start_node.subnet` or other domains. |
| `filler` | List[String] | Optional | Service names used to fill the domain to `min_total_nodes` |
| `mandatory_services` | List[String] | Optional | Service names that must have at least one instance |
| `groups` | List[Dictionary] | Yes | Explicit node populations (see below) |
| `constraints` | List[Dictionary] | Yes | Intra-domain firewall and relationship rules (see below) |

### `groups` sub-fields:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Group name (plural, e.g., `AppServers`). Used in constraints. |
| `service` | String | Yes | The service archetype name (singular, e.g., `AppServer`) |
| `min_count` | Integer | Yes | Minimum number of nodes in this group |
| `max_count` | Integer | Yes | Maximum number of nodes in this group |

### `constraints` sub-fields:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `source` | String | Yes | **Group name** (plural). NEVER a service name or property. |
| `target` | String | Yes | **Group name** (plural) for firewall/cred rules; **Property name** for `MUST_HAVE`/`MUST_NOT_HAVE`. |
| `relation` | String | Yes | One of: `MUST_CONNECT`, `MUST_REACH`, `CLIENT_OF`, `LEAK_KNOWN_CREDENTIALS`, `KNOWS`, `MUST_HAVE`, `MUST_NOT_HAVE` |
| `protocol` | String | Optional | Required for `MUST_CONNECT`, `LEAK_KNOWN_CREDENTIALS`, `CLIENT_OF`. Must be a specific protocol name (e.g., `HTTPS`, `SMB`). Never `ALL`. |

### Relation Semantics:

| Relation | Effect | Notes |
|----------|--------|-------|
| `MUST_CONNECT` | Opens a firewall rule from source to target on the specified protocol | Deterministic |
| `MUST_REACH` | Opens all ports from source to target | Use sparingly; too permissive |
| `CLIENT_OF` | Alias for `LEAK_KNOWN_CREDENTIALS` | Probabilistic |
| `LEAK_KNOWN_CREDENTIALS` | Source nodes can leak credentials for target nodes | Probabilistic; uses `constraint_vulnerabilities.leak_known_credentials` |
| `KNOWS` | Source nodes discover target node IDs | Probabilistic; uses `constraint_vulnerabilities.leak_neighbors` |
| `MUST_HAVE` | Adds a property to all source nodes | Deterministic; target must be a property from `base_properties` |
| `MUST_NOT_HAVE` | Removes a property from source nodes | Deterministic |

---

## 11. `inter_domain_constraints`

**Type:** List of Dictionaries  
**Required:** For multi-domain scenarios (strongly recommended)

Controls firewall rules and relationships across domain boundaries.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `source_domain` | String | Yes | Name of the source domain |
| `target_domain` | String | Yes | Name of the target domain |
| `constraints` | List[Dictionary] | Yes | Same format as intra-domain constraints: `source`, `target`, `relation`, `protocol` |

**Rule:** `source` and `target` in constraints still refer to GROUP NAMES, not service names.

---

## 12. `entry_points`

**Type:** List of Dictionaries  
**Required:** Yes

Defines where the attacker's initial foothold can be established.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `domain` | String | Yes | Domain name where the entry point exists |
| `node` | String | Yes | Group name of the entry point nodes |

---

## 13. `solvability_rules`

**Type:** Dictionary  
**Required:** Yes

Ensures the environment is solvable for the RL agent.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `entry_point_requirements` | Dictionary | Yes | Requirements for entry point nodes |
| `entry_point_requirements.min_remote_vulnerabilities` | Integer | Yes | Minimum remote exploits on entry nodes |
| `entry_point_requirements.min_credential_leaking_vulnerabilities` | Integer | Yes | Minimum credential-leak vulns on entry nodes |
| `lateral_movement_requirements` | Dictionary | Yes | Requirements for lateral movement feasibility |
| `lateral_movement_requirements.min_credential_leaking_nodes` | Float (0.0–1.0) | Yes | Fraction of nodes that must be able to leak credentials |
| `auto_fix_enabled` | Boolean | Yes | If `true`, the post-processor automatically patches solvability gaps |
| `auto_fix_strategies` | List[String] | Yes | Ordered list of fix strategies to apply |

### Valid `auto_fix_strategies` values:
- `add_remote_vulnerability_to_entry`
- `add_credential_leakage`
- `add_lateral_movement_vulnerabilities`
