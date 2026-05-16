# Scenario Quality Evaluation Criteria

This document defines the rubric used to assess whether a generated CyberBattleSim domain configuration is realistic enough to serve as a valid DRL training environment. Each dimension is scored 0–10.

---

## Dimension 1: Network Topology Realism

**What it measures:** Does the network layout reflect how real enterprise networks are designed?

### Scoring Criteria

| Finding | Deduction |
|---------|-----------|
| `start_node.subnet` is an RFC 1918 private address (attacker inside the network) | −4 |
| A domain subnet is not RFC 1918 (internal nodes on public IPs) | −2 per domain |
| Two or more domains share overlapping subnets | −3 |
| A domain has 100% single-OS distribution (no Linux/Windows mix) | −1 per domain |
| `min_total_nodes` is fewer than 5 | −1 |
| Min/max node range ratio is less than 1.5× (too narrow) | −1 |

### What "good" looks like (GLOBALTECH-grounded)
- `start_node.subnet: 0.0.0.0/0` or `203.0.113.0/24` — outside all GLOBALTECH zones
- GLOBALTECH zone subnets used correctly: Z4=`10.0.1.0/24`, Z2=`10.0.2.0/24`, Z1=`10.1.x.0/24`, Z5=`10.2.0.0/24`, Z6=`10.3.x.0/24`, Z8=`192.168.100.0/24`
- Services named after GLOBALTECH components: `PaloAltoFirewall`, `SalesWorkstation`, `AWSWebServer`, `DomainController`
- OS distribution: Linux for Z4/Z6 services, Windows for Z1 Server Farm (DC/MSSQL/FileServer)
- `min_total_nodes ≥ 10`, `max_total_nodes ≥ 20` for a meaningful scenario
- Multi-domain configs follow GLOBALTECH zone hierarchy: Internet Edge → HQ Edge → HQ VLANs → Server Farm

---

## Dimension 2: Properties & Vulnerabilities Realism

**What it measures:** Do the vulnerabilities and properties reflect real-world cybersecurity techniques?

### Scoring Criteria

| Finding | Deduction |
|---------|-----------|
| Any non-discovery vulnerability has `success_rate = 1.0` | −2 |
| Remote exploit `success_rate` is a round number (0.60, 0.65, 0.70, 0.75, 0.80) not in CVE catalog | −1 |
| Any vulnerability is missing `match_properties` | −2 (total, not per vuln) |
| Vulnerability names are generic (e.g., "Attack1", "Exploit_Generic") | −1 |
| No `REMOTE`-type vulnerabilities exist | −3 |
| No `LOCAL`-type vulnerabilities exist | −1 |
| Fewer than 3 of 4 solvability categories are populated | −2 |
| `leak_known_credentials` missing from `constraint_vulnerabilities` | −2 |
| `leak_neighbors` missing from `constraint_vulnerabilities` | −2 |
| `leak_known_credentials.node_probability < 0.40` | −1 |

### What "good" looks like
- Exploit names and parameters match the CVE catalog exactly: `Solvability.EternalBlue` (SR=0.88), `Solvability.BlueKeep` (SR=0.90), `Solvability.Nginx_LibCrypto_Critical` (SR=0.90), `Solvability.DCSync` (technique)
- `success_rate` is CVE-derived (CRITICAL → 0.86–0.90; HIGH → 0.52–0.81; technique/AD → 0.40–0.70); 1.0 only for trivial probes
- `match_properties` includes both OS type and role (e.g., `[Windows, DomainController, ADCS]`)
- All 4 solvability categories (`remote_access`, `credential_leak`, `discovery`, `goal_access`) contain at least one entry
- `node_probability` on credential leakage ≥ 0.55

---

## Dimension 3: Scenario Difficulty

**What it measures:** Is the scenario suitably challenging for DRL training — neither trivially easy nor impossibly hard?

### Scoring Criteria

| Finding | Deduction |
|---------|-----------|
| No `attack_flow` defined | −2 |
| `attack_flow` has fewer than 2 hops | −3 |
| `min_total_nodes < 5` | −3 |
| `min_total_nodes < 10` | −1 |
| No goal services defined | −5 |
| More than 30% of services are goals | −2 |
| `min_credential_leaking_nodes < 0.50` | −1 |
| No `remote_access` vulnerabilities in solvability | −2 |
| No `goal_access` vulnerabilities in solvability | −2 |
| Mean vulnerability `probability > 0.85` (too easy) | −1 |
| Mean vulnerability `probability < 0.40` (too hard) | −1 |

### What "good" looks like
- `attack_flow` with ≥ 3 hops from entry to goal
- 1–3 goal services, representing ≤ 15% of all service types
- `min_total_nodes ≥ 15` for training variety
- `min_credential_leaking_nodes ≥ 0.55`
- Mean vulnerability probability in 0.55–0.75 range
- At least 1 entry in each solvability category

---

## Dimension 4: Firewall Rules Realism

**What it measures:** Do the inter-domain and intra-domain constraints accurately model enterprise firewall policies?

### Scoring Criteria

| Finding | Deduction |
|---------|-----------|
| Multi-domain config has no `inter_domain_constraints` | −4 |
| Any constraint uses protocol `ALL`, `ANY`, or blank | −2 per violation |
| Direct InternetEdge→ServerFarm connection (bypassing HQ Edge) | −4 |
| InternetEdge→HQ Edge constraint uses `SMB`, `RDP`, `LDAP`, or `MSSQL` | −2 per violation |
| Entry point is placed in the core/database tier | −3 |
| Single-domain config has no intra-domain constraints | −2 |

### What "good" looks like (GLOBALTECH zone protocols)
- Internet → Internet Edge (Z4): `HTTP`, `HTTPS` only
- Internet Edge (Z4) → HQ Edge (Z2): `HTTPS`, `REST` only (scrubbed traffic)
- HQ Edge (Z2) → HQ VLANs (Z1): `HTTPS`, `Kerberos`, `LDAP` (no direct SMB)
- HQ VLANs (Z1) → Server Farm (Z1): `LDAP`, `LDAPS`, `MSSQL`, `Kerberos`, `SMB`
- Entry points in Internet Edge or AWS Web Tier, never directly in Server Farm
- No protocol `ALL` anywhere — every constraint names a specific protocol
- Prohibited direct connections: Internet→ServerFarm, InternetEdge→ServerFarm (bypassing Palo Alto HQ Edge)

### Standard GLOBALTECH zone protocol table

| From → To (GLOBALTECH zones) | Allowed Protocols | Forbidden |
|------------------------------|-------------------|-----------|
| Internet → Internet Edge (Z4) | `HTTP`, `HTTPS` | `SMB`, `RDP`, `LDAP`, `MSSQL` |
| Internet Edge (Z4) → HQ Edge (Z2) | `HTTPS`, `REST` | `SMB`, `RDP`, `LDAP`, `MSSQL` |
| HQ Edge (Z2) → HQ VLANs (Z1) | `HTTPS`, `Kerberos`, `LDAP` | `SMB`, `ALL` |
| HQ VLANs (Z1) → Server Farm (Z1) | `LDAP`, `MSSQL`, `Kerberos`, `SMB` | `HTTP`, `ALL` |
| AWS Web Tier → AWS App Tier (Z6) | `HTTPS`, `REST` | `SMB`, `RDP`, `LDAP` |
| AWS App Tier → AWS DB Tier (Z6) | `PostgreSQL`, `MySQL`, `MongoDB` | `HTTP`, `ALL` |

---

## Dimension 5: General Realism

**What it measures:** Does the scenario as a whole reflect a plausible, coherent real-world environment?

### Scoring Criteria

| Finding | Deduction |
|---------|-----------|
| Generic service names (e.g., `Service1`, `Node1`, `Generic`) | −1 |
| A goal service has `value < 1000` | −1 per goal |
| Fewer than 3 distinct service types | −2 |
| A domain has no `groups` defined | −1 per domain |
| A group has `max_count < min_count` | −1 per group |
| `num_goals > 5` | −1 |
| `attack_flow` does not target any goal service | −1 |
| No `probe_vulnerabilities` defined | −1 |

### What "good" looks like (GLOBALTECH-grounded)
- Service names come from GLOBALTECH device types: `PaloAltoFirewall`, `SalesWorkstation`, `AWSWebServer`, `DomainController`
- Goal services reflect GLOBALTECH high-value targets: `value ≥ 5000` for `DomainController`, `≥ 3000` for `MSSQLServer` or `AWSPostgreSQL`
- ≥ 5 distinct service types across all domains for a believable GLOBALTECH scenario
- `probe_vulnerabilities` includes OS fingerprinting entries
- Attack narrative is coherent and follows GLOBALTECH zone hierarchy: entry via Internet Edge / AWS Web Tier → pivot through HQ Edge / AWS App Tier → goal is Server Farm DC or AWS DB

---

## Overall Grade Scale

| Score | Grade | Interpretation |
|-------|-------|----------------|
| 9.0–10 | A+    | Excellent — publish-ready, highly realistic scenario |
| 8.0–8.9 | A   | Good — minor issues, suitable for training |
| 7.0–7.9 | B   | Above average — a few realism gaps to address |
| 6.0–6.9 | C   | Average — several dimensions need improvement |
| 5.0–5.9 | D   | Below average — significant realism problems |
| < 5.0  | F    | Poor — fundamental structural or realism failures |

---

## How to Use This Rubric in an LLM Evaluation

When asked to evaluate a domain configuration for quality, follow this process:

1. **Read the full YAML** and identify the scenario type (single-domain, multi-domain, cloud, branch, or GLOBALTECH extended enterprise)
2. **Evaluate each dimension independently** using the criteria above
3. **Apply deductions** for every violation found — do not skip minor issues
4. **Compute the dimension score** as `max(0, 10 − sum_of_deductions)`
5. **Compute the overall score** as the average of all 5 dimension scores
6. **Produce a structured report** with:
   - Per-dimension score + grade + list of findings
   - Top issues (critical and fail findings)
   - Specific YAML fixes for each issue found
   - Overall summary with the computed grade

### Common Red Flags (Automatic Fails on Specific Dimensions)

- `start_node.subnet` in RFC 1918 space → Topology score ≤ 6
- No `REMOTE` vulnerabilities → Vulnerability score ≤ 7
- No goal services → Difficulty score = 0
- Direct InternetEdge→ServerFarm connection (bypassing HQ Edge) → Firewall score ≤ 6
- Multi-domain with no `inter_domain_constraints` → Firewall score ≤ 6
