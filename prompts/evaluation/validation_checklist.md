# Validation Checklist: Pre-Run Audit for Generated Domain Configurations

Use this 11-point checklist to manually audit a newly generated YAML domain configuration before passing it to the Python parser. This checklist catches both semantic issues (realistic design) and syntactic issues (parser compliance).

---

## How to Use This Checklist

For each item below, mark it as **PASS**, **FAIL**, or **N/A** (if the item doesn't apply to a single-domain scenario).

If any item is marked **FAIL**, fix it before running the generator. A failed scenario will either crash the parser or produce an untrainable RL environment.

---

## Point 0: `metadata` Block Is Present, First, and Internally Consistent

**Check:**
1. Is `metadata:` the first top-level key in the YAML (before `config:`)?
2. Are all required fields present: `scenario_id`, `agent`, `training_mode`, `zones`, `terminal_goal`, `node_range`, `attack_path`?
3. Does `metadata.terminal_goal` match the service name that has `is_goal: true`?
4. Do `metadata.node_range[0]` and `[1]` equal `config.min_total_nodes` and `config.max_total_nodes` exactly?
5. Does `metadata.attack_path` have at least 2 entries?

**Pass example:**
```yaml
metadata:
  scenario_id: S-NET-01
  agent: S_Network
  training_mode: standalone
  zones: [Z4_InternetEdge, Z2_HQEdge]
  terminal_goal: CiscoEdgeRouter
  node_range: [26, 114]
  attack_path:
    - "Probe — Remote.Probe.CiscoIOS on ISPRouter"
    - "Z4 entry — CiscoASA_IKE_HeapOvf on CiscoASA"
    - "Z2 pivot — PanOS_TOCTOU on PaloAltoFirewall"
    - "Goal — EnablePassword_Crack on CiscoEdgeRouter (TERMINAL)"

config:
  min_total_nodes: 26
  max_total_nodes: 114
```

**Fail examples:**
```yaml
# FAIL: metadata missing entirely
config:
  min_total_nodes: 26

# FAIL: node_range out of sync
metadata:
  node_range: [26, 200]   # disagrees with config below
config:
  max_total_nodes: 114

# FAIL: terminal_goal names a non-goal service
metadata:
  terminal_goal: PaloAltoFirewall
services:
  PaloAltoFirewall:
    is_goal: false          # must be true
  CiscoEdgeRouter:
    is_goal: true
```

---

## Point 1: Attacker Entry Point Is External

**Check:** Does `start_node.subnet` use a public IP address or `0.0.0.0/0`?

- The subnet must NOT be an RFC 1918 private range (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`).
- The attacker must NOT start inside any domain subnet.

**Pass example:**
```yaml
start_node:
  subnet: 0.0.0.0/0
  ip: 203.0.113.10
```

**Fail example:**
```yaml
start_node:
  subnet: 10.0.1.0/24   # FAIL: attacker is inside the internal network
```

---

## Point 2: No Direct Internet Edge → Server Farm Connection (GLOBALTECH Rule)

**Check:** Does the `inter_domain_constraints` block show ANY entry where `source_domain` is `InternetEdge` (Z4) and `target_domain` is `ServerFarm`, `HQ_VLANs`, or any Z1 domain?

- If yes: **FAIL.** Internet Edge (Z4) must only connect to HQ Edge (Z2). HQ VLANs connect to Server Farm.
- If no: **PASS.**

Also check: does the `AWSCloud` (Z6) web tier connect directly to the DB tier without going through the App tier?

**Fail examples:**
```yaml
inter_domain_constraints:
  - source_domain: InternetEdge
    target_domain: ServerFarm   # FAIL: bypasses Palo Alto HQ Edge firewall
  - source_domain: AWSCloud_Web
    target_domain: AWSCloud_DB  # FAIL: bypasses AWS App tier
```

**Correct (GLOBALTECH standard path):**
```yaml
inter_domain_constraints:
  - source_domain: InternetEdge
    target_domain: HQ_Edge      # PASS: Z4 → Z2 via Palo Alto firewalls
  - source_domain: HQ_Edge
    target_domain: HQ_VLANs    # PASS: Z2 → Z1 user segments
  - source_domain: HQ_VLANs
    target_domain: ServerFarm   # PASS: Z1 user → Z1 Server Farm
```

---

## Point 3: All Properties Are Declared in `base_properties`

**Check:** Extract every string from:
- `services[*].default_properties`
- `solvability_vulnerabilities.*.match_properties`
- `constraints[*].target` (for `MUST_HAVE` relations)

Every string must appear in `identifiers.base_properties`. Missing entries will cause a `KeyError` in the parser.

**Quick scan:** Search the YAML for all values under `default_properties:` and `match_properties:`. Paste them into a set and diff against `base_properties`.

**Common missed properties:** `DomainJoined`, `Kerberoastable`, `ServiceAccount`, `AdminCredentials`, `WebAppCredentials`

---

## Point 4: `breach_node` Is in `base_properties`

**Check:** Does `identifiers.base_properties` contain the exact string `breach_node`?

This is the single most common omission. Without it, the start node cannot be created.

```yaml
identifiers:
  base_properties:
    - breach_node   # Must be present
```

---

## Point 5: At Least One Goal Node Exists and Is Not `Unauthenticated`

**Check:**
1. Does at least one service have `is_goal: true`?
2. Does that service's `default_properties` NOT contain `Unauthenticated`?

A scenario with no goals cannot be trained. A goal node with `Unauthenticated` creates a trivially exploitable target that invalidates the training signal.

---

## Point 6: `solvability_vulnerabilities` and `constraint_vulnerabilities` Are Dictionaries

**Check:** Verify that these two blocks are NOT formatted as YAML lists (no leading `-` hyphen on the first level).

**Correct:**
```yaml
solvability_vulnerabilities:
  remote_access:      # key, not list item
    - name: ...
  credential_leak:    # key, not list item
    - name: ...
```

**Incorrect:**
```yaml
solvability_vulnerabilities:
  - name: ...         # FAIL: top level is a list
```

---

## Point 7: All `solvability_vulnerabilities` Have a `probability` Field

**Check:** Scan every item in `remote_access`, `credential_leak`, `discovery`, and `goal_access` under `solvability_vulnerabilities`. Each must have a `probability:` field with a float value between 0.0 and 1.0.

**Also check:** Every vulnerability has a `reward:` field that is a **string**, not an integer.

---

## Point 8: Constraints Use Group Names (Plural), Not Service Names (Singular)

**Check:** In every `domains[*].constraints` and `inter_domain_constraints[*].constraints` block, verify that `source` and `target` (when not a property name for `MUST_HAVE`) match a `name` in the domain's `groups` list.

**Quick test:** List all `groups[*].name` values for a domain. Every `source` and `target` in that domain's constraints should be in this list (except `MUST_HAVE` targets which are property names).

---

## Point 9: `success_rate` Values Are Realistic

**Check:** No exploit in `solvability_vulnerabilities` should have `success_rate: 1.0`.

Scan for any `success_rate:` values above `0.80` in the `solvability_vulnerabilities` block. These should be reviewed and lowered unless they represent trivial reconnaissance.

**Rule:** `success_rate: 1.0` is only acceptable in `probe_vulnerabilities` and `constraint_vulnerabilities` (discovery actions), never on actual exploits.

---

## Point 10: Each Service Has All Five Required Fields

**Check:** Every key under `services:` must have ALL FIVE of these fields:
1. `port`
2. `value`
3. `allowed_os`
4. `default_properties`
5. `is_goal`

Missing any of these causes a `KeyError` or `AttributeError` in `domain_loader.py`.

**Quick scan:** For each service definition, count the keys. There should be at least 5.

---

## Bonus Point: GLOBALTECH Semantic Realism Check

These checks don't crash the parser but produce unrealistic training environments:

| Question | Correct Answer |
|----------|----------------|
| Are services named after GLOBALTECH device types (e.g., `PaloAltoFirewall`, `SalesWorkstation`, `AWSWebServer`)? | Yes — generic names like `WebServer1` are a red flag |
| Are GLOBALTECH zones mapped correctly to CBS domains (Z4 → InternetEdge, Z2 → HQ_Edge, Z1 → HQ_VLANs/ServerFarm)? | Yes |
| Does the topology follow the GLOBALTECH zone hierarchy? (Internet Edge → HQ Edge → HQ VLANs → Server Farm) | Yes |
| Are any Windows exploit `match_properties` applied to Linux-only services? | Should be NO |
| Does the exploit chain provide a full path from start_node → goal (respecting GLOBALTECH zone boundaries)? | At least one complete path must exist |
| Are all `success_rate` values CVE-derived from `vulnerability_catalog.md`? (CRITICAL→0.90, HIGH→0.52–0.81, technique→0.40–0.70) | Yes |
| Are GLOBALTECH network device vulnerabilities used for Z2/Z4 services? (e.g., `PanOS_CMDInject` for `PaloAltoFirewall`) | Yes |
| Do goal nodes have higher `value` than entry nodes? | Yes — goals should be 10x–100x higher |
| Are there at least 2–3 different solvability vulns per category? | Recommended for diverse training |
| Do `inter_domain_constraints` use specific protocols (not blank)? | Yes — never leave `protocol:` empty |

---

## Automated Validation

After passing this manual checklist, run the automated Python validator:

```bash
python validate_data.py --config path/to/your_config.yaml
```

If validation passes, run the generator:

```bash
python universal_generator.py --config path/to/your_config.yaml --output ./output/
```

Check the output for warnings about:
- Auto-fix interventions (means `solvability_rules.auto_fix_enabled` triggered)
- Zero nodes matching a vulnerability (means `match_properties` is too restrictive)
- No path from entry to goal (means lateral movement chain is broken)
