# Technical Specification: Standardized Pipeline Output Structure
**Status:** DRAFT (Proposed 2026-05-16)

## 1. Overview
This specification defines a mandatory hierarchical directory structure for all pipeline outputs. It replaces the legacy "Phase 1/Phase 2" scattered structure with a Domain-Centric model designed for research readability and automation.

## 2. Base Structure
All outputs are rooted at `DATASET_ROOT` (defined in `.env`).

```text
output/
└── <domain_name>/                 # e.g., sid_kerberoast_v1
    ├── config/                    # Phase 1: Inputs and Enriched Configs
    │   ├── 01_fetched_vulns.yaml  # CVE data from NVD
    │   ├── 02_enriched.yaml       # Merged YAML (The Source of Truth)
    │   ├── 03_validation.json     # Result of 02_config_checker.py
    │   ├── user_prompt.txt        # The raw natural language task
    │   └── schema_diagram.png     # Visual architecture diagram
    │
    ├── scenarios/                 # Phase 2: Generated Instances
    │   ├── train/                 # Seeds 1-10,000
    │   │   └── CyberBattleSim-<domain>-0001/
    │   └── test/                  # Seeds 10,001-20,000
    │       └── CyberBattleSim-<domain>-10001/
    │
    ├── metrics/                   # Aggregated Data
    │   ├── bfs_metrics.json       # Solver performance
    │   ├── telemetry.json         # Tool timing and retries
    │   └── quality_evaluation.json# LLM Critic scores
    │
    └── reports/                   # Human-Readable Documentation
        ├── phase1_summary.txt     # Design-time report
        ├── phase2_eda.pdf         # Cross-scenario statistical analysis
        ├── detailed_report.pdf    # Per-scenario graphs and paths
        └── all_scenarios_combined.pdf
```

## 3. Mandatory Artifacts
Every successful run **MUST** produce:
- **`config/user_prompt.txt`**: The original request.
- **`config/schema_diagram.png`**: A high-level topology overview.
- **`metrics/telemetry.json`**: Performance data.
- **`reports/detailed_report.pdf`**: The visual evidence of attack paths.

## 4. Implementation Guidelines
- Scripts in `pipeline/` must use absolute paths derived from the `domain_name`.
- Legacy files like `07_pipeline_report.txt` are deprecated and should be merged into `reports/phase1_summary.txt`.
