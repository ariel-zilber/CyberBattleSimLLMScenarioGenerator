# CLAUDE.md — CyberBattleSimLLMScenarioGenerator

This is a thesis project that generates synthetic enterprise network environments for
[CyberBattleSim](https://github.com/microsoft/CyberBattleSim), used as DRL training data.
The pipeline is LLM-driven: Claude generates YAML domain configs, evaluates them, and repairs
them in an actor-critic loop until a quality threshold is met.

---

## Repository Layout

```
pipeline/cbsim/              Core network generator package (UniversalNetworkGenerator)
pipeline/data_preprocessing/ One-time data acquisition + CVE curation (run before pipeline)
pipeline/           Python package — per-run generation pipeline
  phase1/           01_template_validator → 02_config_checker → 03_validate_zone_coverage
                    (static soundness: schema, CVE catalog, zone coverage, agent-category allowlist)
                    quality_evaluator.py is an import shim → phase2/_04_quality_evaluator
  phase2/           01_generator → 02_test_env_integration → 03_evaluator
                    → _04_quality_evaluator (LLM CRITIC) → _05_apply_critic_fixes (LLM ACTOR)
                    (dynamic quality: BFS solvability, LLM critic score, actor repair)
  reporting/        01_scenario_graph → 02_human_report / 02_executive / 02_presentation (parallel)
mcp_server/         MCP server exposing pipeline to Claude (domain_generator_mcp.py)
prompts/            LLM context library
  system_prompt.md            Master generation instructions
  anti_patterns.md            AP-001–AP-023 failure modes
  reference/
    vulnerability_catalog.md  All valid CVE anchors + success_rate values
    allowed_properties.md     All valid node property tokens
  reference/agents/           Per-agent specs (s_network.md … s_mgmt.md + README.md)
  schema/                     YAML schema definition + architecture rules
  evaluation/                 Critic rubric, validation checklist
  examples/                   Golden single/cross-domain YAML examples
data/scenarios/     Domain config YAML files (6 complete, more in tasks/)
tasks/              Task tracking per agent type (snet/, slin/, swin/, sid/, slat/, meta/)
```

---

## How the Reference Files Were Built

`prompts/reference/vulnerability_catalog.md` and `prompts/reference/allowed_properties.md` are **not hand-written** — they are the output of a one-time LLM-assisted curation step:

1. Raw CVEs fetched from NVD / Trivy / Bitnami vulndb (`pipeline/data/`)
2. CVEs enriched with MITRE ATT&CK tactic tags and equalized across domains
3. LLM (Claude) mapped each CVE to CBS vocabulary: service name, node properties, `success_rate`, `match_properties`, vulnerability type (REMOTE/LOCAL)
4. Output curated into `vulnerability_catalog.md` and `allowed_properties.md`

These files are the **single source of truth** for what is valid in any generated config. Do not add CVEs or property tokens to configs that are not already in these files.

---

## Domain Config Conventions

- **File prefix** matches agent: `snet_`, `slin_`, `swin_`, `sid_`, `slat_`, `meta_`
- **File naming**: `<prefix>_<descriptor>_<architecture>_v<N>.yaml` — e.g. `swin_serverfarm_standalone_v1.yaml`
- **Every config must open with a `metadata:` block** — required fields: `scenario_id`, `agent`, `stage`, `zones`, `node_range`, `terminal_goal`
- **Properties** must come from `prompts/reference/allowed_properties.md` only — no invented tokens
- **CVE anchors** must come from `prompts/reference/vulnerability_catalog.md` — no invented CVEs or success_rates
- **Scenarios live at** `data/scenarios/<name>.yaml`

---

## Agent Naming

5 specialists + 1 meta. Authoritative spec: `/home/ariel/Documents/thesis/CyberBattleSimDomainGenerator/prompts/docs/reference/specialist_agent_spec.md`

| Agent | Codename | File prefix | Zones | Spec |
|-------|----------|------------|-------|------|
| Network perimeter | `S_Network` | `snet_` | Z4, Z2 | `prompts/reference/agents/s_network.md` |
| Linux / cloud | `S_Linux` | `slin_` | Z6 | `prompts/reference/agents/s_linux.md` |
| Windows OS | `S_Windows` | `swin_` | Z1 VLANs + Server Farm | `prompts/reference/agents/s_windows.md` |
| Active Directory | `S_Identity` | `sid_` | Z1 Server Farm | `prompts/reference/agents/s_identity.md` |
| Lateral movement | `S_Lateral` | `slat_` | All zones (post-exploitation) | `prompts/reference/agents/s_lateral.md` |
| Meta-agent | `Meta` | `meta_` | Full topology | `prompts/reference/agents/meta_agent.md` |

**Tier → Phase 2 train count:** ≤50 nodes → 5 · 50–200 → 3 · 200–500 → 2 · 500–1000 → 1

---

## Running the Pipeline

```bash
# Full pipeline (generation → validation → BFS eval → actor-critic → reports)
python pipeline/run.py data/scenarios/<name>.yaml

# With actor-critic loop (up to 3 repair rounds targeting score 8.0)
python pipeline/run.py data/scenarios/<name>.yaml --target-score 8.0 --max-bfs-rounds 3

# Phase 1 only
python pipeline/phase1/pipeline.py --config data/scenarios/<name>.yaml --skip-fetch

# Quality evaluation only
python pipeline/phase1/quality_evaluator.py data/scenarios/<name>.yaml
```

Via MCP (Claude slash commands):
```
/full-pipeline <description>          # generate + run full pipeline
/evaluate-domain <name>               # phase 1 + quality score only
/phase2 <config_path>                 # phase 2 on existing config
```

---

## Key Constraints

- **Do not invent node properties** — only tokens from `prompts/reference/allowed_properties.md`
- **Do not invent CVEs** — only entries from `prompts/reference/vulnerability_catalog.md`
- **All config YAMLs must be BFS-solvable** — the terminal goal must be reachable via REMOTE/LOCAL exploit chains
- **`LEAK_KNOWN_CREDENTIALS` (IDC) constraints** propagate credentials between nodes — required for credential-chain scenarios (S_Lateral, S_Identity); not needed for direct-exploit agents (S_Linux, S_Network)
- **Zone assignment** must match `data/zone_manifest.yaml` for the relevant agent

---

## LLM Context Files (what to load when generating a config)

| Task | Load these files |
|------|-----------------|
| Generate a new config | `system_prompt.md`, `schema/definition.md`, `schema/architecture.md`, `anti_patterns.md`, `reference/vulnerability_catalog.md`, `reference/allowed_properties.md`, relevant agent spec from `reference/agents/`, matching golden example |
| Critique / repair a config | `evaluation/critique_template.md`, `evaluation/quality_criteria.md`, `anti_patterns.md`, `reference/vulnerability_catalog.md`, `reference/allowed_properties.md` |
| Understand topology | `schema/topology.md`, `schema/topology.png`, `reference/agents/README.md` |

---

## Output Locations

All generated datasets and reports go to Google Drive:
`/content/drive/MyDrive/thesis/code/datasets/poc/claude/`

Local structure under `DATASET_ROOT` (set in `.env`):
```
datasets/
  phase1/<domain>/          Validation results, phase1_report.txt
  phase2/<domain>/          Generated scenarios (train/ + test/ per stratum)
    bfs_metrics.json        Aggregated BFS solve metrics
    quality_evaluation.json LLM critic score (6 dimensions)
  reports/
    executive_report.pdf
    detailed_report.pdf
    presentation.pdf
```
