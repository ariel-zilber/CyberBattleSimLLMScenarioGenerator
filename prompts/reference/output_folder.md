# CyberBattleSim Dataset Output Folder Specification

**Version:** 1.0  
**DATASET_ROOT:** configured in `.env` — key `DATASET_ROOT`  
**Default (Google Drive / Colab):** `/content/drive/MyDrive/thesis/code/datasets/poc/claude`

This document is the authoritative reference for every file and directory written
by the generation pipeline. All tools, MCP server functions, and LLM prompts that
read or write output MUST conform to this layout.

---

## Top-Level Layout

```
DATASET_ROOT/
├── phase1/                      ← Phase 1: config validation & quality reports
│   └── <domain_config_stem>/    ← e.g. enterprise_ad_v1, globaltech_hq_v1
│       ├── 01_fetched_vulns.yaml
│       ├── 02_config_enriched.yaml
│       ├── 03_config_check.json
│       ├── 04_topology.html
│       ├── 05_scenarios/
│       ├── 06_evaluation.json
│       ├── 07_pipeline_report.txt
│       └── phase1_report.txt    ← Quality evaluator scorecard (per-dim findings)
├── phase2/                      ← Phase 2: stratified scenarios + evaluation
│   └── <domain_config_stem>/    ← same stem as the YAML file in data/
│       ├── stratified_manifest.json
│       ├── DATASET_EVALUATION_PROMPT.txt
│       ├── phase2_report.txt    ← EDA analysis (text)
│       ├── phase2_report.pdf    ← EDA analysis + Phase 1 quality section (PDF)
│       ├── all_scenarios_combined.pdf
│       ├── figures/             ← 20 PNGs (16 EDA + 4 CVE grounding)
│       ├── scenario_graphs/     ← PNG thumbnails per scenario
│       ├── train/small/<scenario>/
│       │   ├── nodes/           ← PRIMARY INPUT to CyberBattleSim
│       │   ├── identifiers/identifiers.yaml
│       │   ├── vulnerability_library/vulnerability_library.yaml
│       │   ├── graphs/          ← SVG + PNG topology visualisations
│       │   ├── run_metrics.json ← Full evaluation metrics (see schema below)
│       │   └── report.pdf       ← Per-scenario combined PDF
│       └── test/small/<scenario>/
│           └── ...              ← same as train/
├── logs/                        ← Step-by-step pipeline run logs
│   └── <domain>_<YYYYMMDD_HHMMSS>.log
├── executive_report.pdf         ← Cross-domain executive summary (all domains)
├── executive_report.tex         ← LaTeX source for executive_report.pdf
└── detailed_report.pdf          ← Per-domain detailed EDA appendix (merged PDF)
```

`<domain_config_stem>` = the filename of the domain config YAML without the `.yaml`
extension, preserving the version suffix (e.g. `enterprise_ad_v1` from
`data/enterprise_ad_v1.yaml`).

---

## Phase 1 Output Tree

Produced by `tools/pipeline.py`.

```
DATASET_ROOT/phase1/<domain_config_stem>/
├── 01_fetched_vulns.yaml         # CVE templates fetched from NVD/EPSS/KEV
│                                 # (empty placeholder when --skip-fetch is used)
├── 02_config_enriched.yaml       # Base config merged with fetched vuln snippets
├── 03_config_check.json          # Config checker results: errors, warnings, metrics
├── 04_topology.html              # Interactive network topology DAG (open in browser)
├── 05_scenarios/                 # Probe scenarios generated during Phase 1
│   └── 02_config_enriched/      # Scenarios from the enriched config
│       ├── stratified_manifest.json
│       ├── train/
│       │   └── small/
│       │       └── CyberBattleSim-<slug>-small-<NNNN>/   ← probe scenario dir
│       │           ├── nodes/                             ← per-node YAML files
│       │           ├── identifiers/identifiers.yaml
│       │           ├── graphs/                            ← SVG + PNG topology graphs
│       │           └── vulnerability_library/
│       │               └── vulnerability_library.yaml
│       └── test/
│           └── small/
│               └── CyberBattleSim-<slug>-small-1<NNNN>/
│                   └── ...                               ← same structure as train
├── 06_evaluation.json            # Per-scenario structural quality metrics
└── 07_pipeline_report.txt        # Human-readable Phase 1 summary report
```

### Phase 1 File Descriptions

| File | Description |
|------|-------------|
| `01_fetched_vulns.yaml` | Raw vulnerability templates from NVD API. Empty if `--skip-fetch`. |
| `02_config_enriched.yaml` | Domain config with fetched vulnerabilities merged in. Used as input for Phase 2. |
| `03_config_check.json` | JSON dict with keys: `errors` (list), `warnings` (list), `metrics` (dict), `status` (str). |
| `04_topology.html` | Self-contained HTML file with a D3.js / vis.js network DAG. Open in any browser. |
| `05_scenarios/` | Probe scenarios: small set generated to test config correctness before Phase 2. |
| `06_evaluation.json` | Structural quality metrics: `solvable`, `cred_chain_ratio`, `discovery_ratio`, `fairness_score`. |
| `07_pipeline_report.txt` | Formatted Phase 1 report: quality score, grade, issues, recommendations. |

---

## Phase 2 Output Tree

Produced by `tools/stratified_generator.py` (generation),
`tools/test_env_integration.py` (evaluation),
`tools/phase2_human_report.py` (EDA reports + figures), and
`tools/generate_scenario_graph.py` (topology graphs).

```
DATASET_ROOT/phase2/<domain_config_stem>/
├── stratified_manifest.json      # Generation manifest: counts, strata, config path
├── DATASET_EVALUATION_PROMPT.txt # Master prompt for LLM dataset review
├── phase2_report.txt             # EDA analysis report (text, appended by human_report.py)
├── phase2_report.pdf             # Full combined EDA report as PDF
├── all_scenarios_combined.pdf    # Master PDF: all scenario topology graphs
├── figures/                      # Dataset-level EDA figures (PNG)
│   ├── node_graphs.png
│   ├── scenario_graphs.png
│   ├── security_graphs.png
│   ├── properties_graphs.png
│   ├── services_graphs.png
│   ├── vuln_rates_graphs.png
│   ├── firewall_graphs.png
│   ├── complexity_dashboard.png
│   ├── data_quality.png
│   ├── diversity.png
│   ├── class_balance.png
│   ├── reward_signal.png
│   ├── global_coverage.png
│   ├── cross_domain.png
│   ├── statistical_comparison.png
│   ├── cross_domain_coverage.png
│   └── cve_grounding/            # CVE-grounding figures (4 per domain)
│       ├── <stem>_cve_01_success_rate.png
│       ├── <stem>_cve_02_attack_surface.png
│       ├── <stem>_cve_03_cost_os_coverage.png
│       └── <stem>_cve_04_grounding_scorecard.png
├── scenario_graphs/              # Per-scenario network topology thumbnails (PNG)
│   ├── CyberBattleSim-<slug>-small-<NNNN>.png   ← train scenarios
│   └── CyberBattleSim-<slug>-small-1<NNNN>.png  ← test scenarios
├── train/
│   └── small/
│       ├── CyberBattleSim-<slug>-small-0001/     ← NNNN = 0001..0005 for 5 train
│       ├── CyberBattleSim-<slug>-small-0002/
│       ├── CyberBattleSim-<slug>-small-0003/
│       ├── CyberBattleSim-<slug>-small-0004/
│       └── CyberBattleSim-<slug>-small-0005/
└── test/
    └── small/
        ├── CyberBattleSim-<slug>-small-10001/    ← NNNN = 10001..10002 for 2 test
        └── CyberBattleSim-<slug>-small-10002/
```

### Per-Scenario Directory Structure

Every scenario directory (both train and test) has the same internal layout:

```
CyberBattleSim-<slug>-<stratum>-<NNNN>/
├── nodes/                              # ← PRIMARY INPUT to CyberBattleSim
│   ├── start.yaml                      #   Attacker start node (breach_node)
│   ├── <Domain>_<ServiceGroup>_<N>.yaml #   One file per filler node
│   ├── <Domain>_<ServiceGroup>_<N>.yaml
│   └── ...                             #   Mandatory nodes use GroupName_N naming
├── identifiers/
│   └── identifiers.yaml               # Port names, property IDs, vulnerability IDs
├── vulnerability_library/
│   └── vulnerability_library.yaml     # Vulnerability definitions for this scenario
├── graphs/                            # Topology visualisations
│   ├── network_graph.svg              # Full network graph (nodes + edges)
│   ├── network_graph.png
│   ├── attack_paths.svg               # Attack-path subgraph (entry → goals)
│   ├── attack_paths.png
│   ├── subnet_topology.svg            # Subnet-level topology (domain layout)
│   ├── subnet_topology.png
│   ├── compact_subnet_topology.svg    # Compact subnet view
│   ├── compact_subnet_topology.png
│   └── 00_title_separator.svg        # Title card for PDF compilation
├── run_metrics.json                   # Heuristic-agent evaluation result
└── report.pdf                         # Per-scenario combined PDF report
```

### Phase 2 File Descriptions

| File | Description |
|------|-------------|
| `stratified_manifest.json` | Records `domain`, `strata`, `train_count`, `test_count`, `config_file`, `generated_at`. |
| `DATASET_EVALUATION_PROMPT.txt` | Master LLM prompt containing aggregated evaluation data for all scenarios. |
| `phase2_report.txt` | EDA text report: solve rates, structural metrics, diversity stats. Appended by `phase2_human_report.py`. |
| `phase2_report.pdf` | Full EDA report rendered as PDF (same content as `.txt` with embedded figures). |
| `all_scenarios_combined.pdf` | Master PDF with every scenario's topology graphs in order. |
| `figures/` | 16 standard EDA PNGs + 4 CVE-grounding PNGs = 20 total. |
| `scenario_graphs/` | Top-level PNG thumbnails of each scenario's network graph (used in reports). |
| `nodes/*.yaml` | Per-node YAML files directly loadable by CyberBattleSim. Each file describes one node: `ip`, `subnet`, `os`, `properties`, `services`, `vulnerabilities`. |
| `identifiers/identifiers.yaml` | Scenario-level identifier registry: port names, property list, vulnerability ID list. |
| `vulnerability_library/vulnerability_library.yaml` | All vulnerability definitions used in this scenario, in CyberBattleSim `VulnerabilityInfo` format. |
| `run_metrics.json` | Keys: `is_solved` (bool), `best_reward` (float), `best_steps` (int), `episodes_attempted` (int), `solve_rate` (float), `scenario_id` (str). |
| `report.pdf` | Per-scenario PDF: topology graphs + evaluation metrics. |

---

## Scenario Naming Convention

```
CyberBattleSim-<slug>-<stratum>-<NNNN>
```

| Component | Rule | Example |
|-----------|------|---------|
| `<slug>` | `domain_config_stem` with underscores replaced by hyphens | `network-device-infra-v1` |
| `<stratum>` | `small`, `medium`, or `large` | `small` |
| `<NNNN>` | Train: 4-digit zero-padded integer starting at `0001` | `0001`, `0002`, ... |
| | Test: same format starting at `10001` (ensures no collision with train) | `10001`, `10002`, ... |

**Stratum size bounds** (configured in `cli.py` / `.env`):

| Stratum | `min_total_nodes` | `max_total_nodes` |
|---------|-------------------|-------------------|
| `small` | 20 | 80 |
| `medium` | 80 | 200 |
| `large` | 200 | 500 |

---

## Node YAML Format

Each file in `nodes/` describes a single network node. CyberBattleSim loads all
files in the `nodes/` directory to reconstruct the full environment.

```yaml
# nodes/<Domain>_<Group>_<N>.yaml
node_id: <Domain>_<Group>_<N>         # Unique ID matching the filename stem
ip: 10.x.x.x                          # IPv4 address within the domain subnet
subnet: 10.x.x.0/24                   # CIDR subnet
os: Windows | Linux                    # Operating system
group: <Group>                         # Service group name (from domain config)
domain: <DomainName>                   # Domain name from config
properties:                            # Properties list (from base_properties)
  - Linux
  - AppServer
  - GoRuntime
  - ...
services:                              # List of exposed services
  - name: <service_name>
    port: HTTPS                        # Port identifier from standard_ports
    allowedCredentials:                # Credentials accepted by this service
      - cred_<id>
is_entry: false                        # True for the first hop from start node
is_goal: false                         # True for goal nodes
vulnerabilities:                       # Assigned vulnerabilities (keyed by name)
  Solvability.ExploitName:
    type: REMOTE | LOCAL
    description: "..."
    rates:
      successRate: 0.90
    cost: 1.0
    reward_string: "..."
    outcome:                           # One of: LeakedCredentials, LeakedNodesId,
      ...                              #          PrivilegeEscalation
```

### `start.yaml` Format

```yaml
node_id: start
ip: 203.0.113.x                        # Public IP (internet-facing)
subnet: 0.0.0.0/0
os: Linux
properties:
  - breach_node
services: []
is_entry: true
is_goal: false
vulnerabilities:
  External.<Domain>.Recon:
    type: LOCAL
    ...
  External.<Domain>.DefaultBrute:
    type: LOCAL
    ...
```

---

## Identifiers YAML Format

```yaml
# identifiers/identifiers.yaml
ports:
  - RDP
  - SSH
  - HTTPS
  - HTTP
  - SMB
  - ...                               # All standard_ports + standard_ports_extra
properties:
  - breach_node
  - Windows
  - Linux
  - ...                               # All base_properties declared in domain config
local_vulnerabilities:
  - Solvability.CredentialHarvest
  - Solvability.MimikatzNTLM
  - ...
remote_vulnerabilities:
  - Solvability.BlueKeep
  - Solvability.EternalBlue
  - ...
```

---

## Vulnerability Library YAML Format

```yaml
# vulnerability_library/vulnerability_library.yaml
vulnerabilities:
  Solvability.BlueKeep:
    type: REMOTE
    description: "CVE-2019-0708 ..."
    cost: 1.0
    successRate: 0.90
    reward_string: "BlueKeep RCE ..."
  Solvability.MimikatzNTLM:
    type: LOCAL
    description: "NTLM hash dump from LSASS ..."
    cost: 0.5
    successRate: 0.65
    reward_string: "NTLM hash for {target} extracted"
  ...
```

---

## run_metrics.json Schema

Written by `tools/test_env_integration.py` into each scenario directory. Mirrors the metrics recorded by `TrainingCallback` in `cyberbattle/runners/common/callbacks.py` so that evaluation data is directly comparable to DRL training logs.

```json
{
  "scenario_name":          "CyberBattleSim-enterprise-ad-v1-small-0001",
  "stratum":                "small",
  "is_solved":              true,
  "episodes_required":      3,
  "steps_taken":            675,
  "steps_to_first_goal":    210,
  "steps_to_final_goal":    674,
  "goals_captured":         "2/2",
  "goals_captured_ratio":   1.0,
  "nodes_owned":            5,
  "nodes_discovered":       42,
  "nodes_not_discovered":   19,
  "owned_percentage":       0.082,
  "discovered_percentage":  0.689,
  "credentials_discovered": 81,
  "credentials_in_cache":   40,
  "credentials_discovered_pct": 0.75,
  "total_reward":           2018.0,
  "topology_metrics": {
    "routing":   { "node_count": 61, "edge_count": 3542, "density": 0.9678, "diameter": 2, ... },
    "segmentation": { "isolated_subnets_count": 1, "two_way_routing_zones_count": 1 },
    "payloads":  { "total_vulnerability_instances": 156, "unique_vulnerabilities": 8, ... }
  },
  "network_structure": {
    "tree_ratio":    58.07,
    "density":       0.9678,
    "diameter":      2,
    "node_count":    61,
    "topology_type": "mesh"
  },
  "action_stats": {
    "local_attacks_success_rate":    0.45,
    "remote_attacks_success_rate":   0.61,
    "port_connections_success_rate": 0.78,
    "overall_actions_success_rate":  0.55,
    "local_attacks_rate":   0.30,
    "remote_attacks_rate":  0.25,
    "port_connections_rate": 0.35,
    "movements_rate":        0.10
  },
  "action_outcomes": {
    "LeakedCredentials":   176,
    "LeakedNodesId":       170,
    "LateralMove":         4,
    "PrivilegeEscalation": 0,
    "AdminEscalation":     0,
    "SystemEscalation":    0,
    "ProbeSucceeded":      110,
    "ExploitFailed":       0
  },
  "firewall_metrics": {
    "nodes_with_firewall":  60,
    "total_incoming_rules": 240,
    "total_outgoing_rules": 180,
    "total_rules":          420,
    "allow_rules":          380,
    "block_rules":          40,
    "avg_rules_per_node":   7.0,
    "firewall_coverage":    0.98,
    "blocked_ports":        ["RDP", "SMB"],
    "allowed_ports":        ["*", "LDAP", "HTTPS"]
  }
}
```

### Field Reference

| Field | Description |
|-------|-------------|
| `is_solved` | `true` if all goals were captured in any episode |
| `steps_taken` | Steps in the best episode (most goals captured) |
| `steps_to_first_goal` / `steps_to_final_goal` | Step indices when first/last goal was reached |
| `goals_captured` | `"achieved/total"` string |
| `nodes_owned` | Nodes owned (pwned) by the attacker at episode end |
| `nodes_discovered` | Nodes discovered but not yet owned |
| `owned_percentage` / `discovered_percentage` | Fraction of total nodes |
| `credentials_discovered` | Unique credentials found |
| `credentials_in_cache` | Credentials usable for lateral movement at episode end |
| `network_structure.tree_ratio` | `density × n`; ≈1 = tree-like, > 10 = full mesh |
| `network_structure.topology_type` | `"tree-like"` / `"hierarchical"` / `"mesh"` |
| `action_stats.*_success_rate` | Fraction of actions of each type that earned positive reward |
| `action_stats.*_rate` | Fraction of all actions that were of each type |
| `action_outcomes.*` | Total count of each `VulnerabilityOutcome` type fired across all episodes |
| `firewall_metrics.*` | Static counts derived from per-node firewall YAML; `allow_rules` vs `block_rules` shows segmentation strength |

---

## stratified_manifest.json Schema

Written by `tools/stratified_generator.py` into each domain's Phase 2 root.

```json
{
  "domain":         "network_device_infra_v1",
  "config_file":    "data/network_device_infra_v1.yaml",
  "generated_at":   "2026-04-21T14:00:00",
  "strata": {
    "small": {
      "train": 5,
      "test":  2,
      "train_ids": ["0001", "0002", "0003", "0004", "0005"],
      "test_ids":  ["10001", "10002"]
    }
  },
  "total_scenarios": 7,
  "success_rate":   1.0
}
```

---

## Environment Variables (`.env`)

All paths and generation parameters are controlled by `.env` at the repo root.

| Variable | Default | Description |
|----------|---------|-------------|
| `DATASET_ROOT` | *(required)* | Absolute path to all output. Google Drive: `/content/drive/MyDrive/thesis/code/datasets/poc/claude` |
| `MAX_RETRIES` | `10` | Max Phase 1 → Phase 2 retry attempts in the full pipeline |
| `PHASE1_MIN_SCORE` | `7.0` | Minimum quality score (0–10) to proceed from Phase 1 to Phase 2 |
| `PHASE2_MIN_SOLVE_RATE` | `0.50` | Minimum heuristic solve rate (0–1) for Phase 2 to pass |
| `PHASE2_TRAIN_COUNT` | `5` | Training scenarios per stratum |
| `PHASE2_TEST_COUNT` | `2` | Test scenarios per stratum |
| `PHASE2_STRATA` | `small` | Strata to generate (`small`, `small,medium`, or `small,medium,large`) |
| `PHASE2_MAX_STEPS` | `5000` | Max steps per episode for heuristic evaluation |
| `PHASE2_NUM_AGENTS` | `3` | Cooperative heuristic agent swarm size |
| `PHASE2_MAX_EPISODES` | `3` | Episodes per scenario before marking as unsolved |

---

## Pipeline Command Reference

### Phase 1 — Validate & Quality-Check a Domain Config

```bash
python3 tools/pipeline.py \
  --config data/<domain_config_stem>.yaml \
  --skip-fetch \
  --train 5 --test 2 \
  --strata small
# Output: DATASET_ROOT/phase1/<domain_config_stem>/
```

### Phase 2a — Generate Stratified Scenarios

```bash
python3 tools/stratified_generator.py \
  --config data/<domain_config_stem>.yaml \
  --out-dir "$DATASET_ROOT/phase2" \
  --train 5 --test 2 \
  --strata small \
  --workers 4
# Output: DATASET_ROOT/phase2/<domain_config_stem>/train/small/ and test/small/
```

### Phase 2b — Evaluate Scenarios (Heuristic Agent)

```bash
/home/ariel/miniconda3/envs/cybersim/bin/python tools/test_env_integration.py \
  --data-dir "$DATASET_ROOT/phase2/<domain_config_stem>" \
  --steps 5000 --num-agents 3 --episodes 3
# Output: run_metrics.json in each scenario dir + DATASET_EVALUATION_PROMPT.txt
```

### Phase 2c — Generate EDA Report + Figures

```bash
touch "$DATASET_ROOT/phase2/<domain_config_stem>/phase2_report.txt"
/home/ariel/miniconda3/envs/cybersim/bin/python tools/phase2_human_report.py \
  --scenarios-dir "$DATASET_ROOT/phase2/<domain_config_stem>" \
  --append-to    "$DATASET_ROOT/phase2/<domain_config_stem>/phase2_report.txt" \
  --config data/<domain_config_stem>.yaml \
  --phase1-report "$DATASET_ROOT/phase1/<domain_config_stem>/phase1_report.txt"
# The --phase1-report flag embeds the per-dimension quality scorecard (with
# explanations for each score deduction) into the phase2_report.pdf.
# Output: phase2_report.txt, phase2_report.pdf, figures/ (20 PNGs), per-scenario report.pdf
```

### Phase 2d — Generate Topology SVG/PDF Graphs

```bash
python3 tools/generate_scenario_graph.py \
  --recursive --pdf \
  "$DATASET_ROOT/phase2/<domain_config_stem>"
# Output: graphs/ in each scenario dir + all_scenarios_combined.pdf
```

### Phase 3 — Generate Executive Report (all domains)

```bash
python3 tools/generate_executive_report.py \
  --phase2-root "$DATASET_ROOT/phase2" \
  --output      "$DATASET_ROOT/executive_report.pdf" \
  --title       "CyberBattleSim Scenario Dataset — 5-Domain Benchmark"
# Output: DATASET_ROOT/executive_report.pdf
#         DATASET_ROOT/executive_report.tex  (LaTeX source)
#         DATASET_ROOT/detailed_report.pdf   (per-domain EDA appendix, merged)
```

### Structured All-in-One Runner (Recommended)

Use `tools/run_full_pipeline.py` to run all 7 steps for one or more domains with:
- Step-by-step TUI display (numbered steps, timestamps, pass/fail)
- Timestamped run log written to `DATASET_ROOT/logs/<domain>_<timestamp>.log`
- Automatic `phase1_report.txt` generation
- Automatic executive report (Step 8) after all domains complete

```bash
python3 tools/run_full_pipeline.py data/enterprise_ad_v1.yaml
python3 tools/run_full_pipeline.py data/*.yaml   # all domains
python3 tools/run_full_pipeline.py data/*.yaml --exec-report-title "My Dataset"
python3 tools/run_full_pipeline.py data/enterprise_ad_v1.yaml --skip-exec-report
```

The runner writes a complete audit log to `DATASET_ROOT/logs/<domain>_<timestamp>.log`
with every command run, its output, and pass/fail status.

---

## Report Index

Complete list of every report file and its location:

| Report | Path | Tool | Format |
|--------|------|------|--------|
| Config validation | `phase1/<domain>/07_pipeline_report.txt` | `pipeline.py` | Text |
| Interactive topology | `phase1/<domain>/04_topology.html` | `pipeline.py` | HTML |
| Quality scorecard | `phase1/<domain>/phase1_report.txt` | `run_full_pipeline.py` or MCP | Text |
| EDA analysis | `phase2/<domain>/phase2_report.txt` | `phase2_human_report.py` | Text |
| EDA + Quality PDF | `phase2/<domain>/phase2_report.pdf` | `phase2_human_report.py` | PDF |
| Per-scenario PDF | `phase2/<domain>/train/small/<scenario>/report.pdf` | `phase2_human_report.py` | PDF |
| All scenarios PDF | `phase2/<domain>/all_scenarios_combined.pdf` | `generate_scenario_graph.py` | PDF |
| Executive summary | `executive_report.pdf` | `generate_executive_report.py` | PDF |
| Detailed appendix | `detailed_report.pdf` | `generate_executive_report.py` | PDF |
| Run log | `logs/<domain>_<YYYYMMDD_HHMMSS>.log` | `run_full_pipeline.py` | Text |

---

## Executive Report

Produced by `tools/generate_executive_report.py`. Aggregates all domains into a
single advisor-facing PDF report.

### Output Files

| File | Description |
|------|-------------|
| `executive_report.pdf` | Main report: cross-domain overview, quality scores, solve rates, per-domain attack summaries, Jaccard similarity heatmaps. |
| `executive_report.tex` | Auto-generated LaTeX source for `executive_report.pdf`. Reproducible: re-run `pdflatex` on it to rebuild without Python. |
| `detailed_report.pdf` | Merged PDF of all 5 per-domain `phase2_report.pdf` files — full EDA appendix. |

### What the Executive Report Contains

1. **Cover page** — title, date, domain count, total scenario count, mean quality score.
2. **Cross-domain summary table** — one row per domain: Phase 1 quality score + grade, solve rate, mean steps, mean nodes owned, mean credentials discovered.
3. **Quality vs solve-rate bar chart** — Phase 1 quality (0–10) and runtime solve rate (×10) side-by-side for all domains.
4. **Per-domain section** (one section per domain):
   - Scenario overview and attacker progression narrative (from YAML header comments)
   - Solve-rate donut chart
   - Quality dimension bar chart (6 dimensions: topology realism, vuln realism, difficulty, firewall realism, general realism, CVE grounding)
   - Topology graph (representative subnet topology PNG)
   - Node group summary table (service types, min/max node counts)
   - Runtime metrics (mean steps, mean reward, nodes/creds owned)
5. **Cross-scenario diversity appendix**:
   - Property frequency tables (which properties appear in how many scenarios)
   - Vulnerability frequency tables
   - Universal and unique items across all domains
   - Jaccard similarity heatmaps (property overlap and vulnerability overlap between domains)
6. **Quality metric reference appendix** — grading rubric and dimension descriptions.

### CLI Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--phase2-root` | Yes | Path to `DATASET_ROOT/phase2/`. Scans subdirectories for `stratified_manifest.json`. |
| `--output` | Yes | Output path for the executive PDF. |
| `--configs-root` | No | Extra directory to search for domain YAML configs (defaults to `phase2_root/../configs`). The repo `data/` directory is always searched automatically. |
| `--extra-configs` | No | Additional config directories (space-separated). |
| `--title` | No | Report title string (default: `"CyberBattleSim Scenario Dataset"`). |

---

## Current Dataset Summary

Five reference domains have been fully processed (Phase 1 + Phase 2, all 7/7 scenarios solved):

| Domain Config | Domain | Stratum | Train | Test | Solve Rate | Phase 1 | Phase 2 |
|---------------|--------|---------|-------|------|------------|---------|---------|
| `globaltech_hq_v1.yaml` | GLOBALTECH HQ (AD + Server Farm) | small | 5 | 2 | ≥ 85% | ✓ | ✓ |
| `globaltech_aws_v1.yaml` | GLOBALTECH AWS Cloud (Z6) | small | 5 | 2 | 100% | ✓ | ✓ |
| `globaltech_branch_v1.yaml` | GLOBALTECH Branch Office (Z5) | small | 5 | 2 | 100% | ✓ | ✓ |
| `globaltech_network_infra_v1.yaml` | GLOBALTECH Network Devices (Z2/Z4) | small | 5 | 2 | 100% | ✓ | ✓ |
| `globaltech_extended_v1.yaml` | GLOBALTECH Extended Enterprise | medium | 10 | 4 | ≥ 80% | ✓ | ✓ |
