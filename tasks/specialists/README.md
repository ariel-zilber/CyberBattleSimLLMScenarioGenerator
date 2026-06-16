# Specialist-Style Meta Dataset Tasks

Target experiment: `/home/ariel/Documents/thesis/CyberBattleSimMetaAgentImproved/research_proposal/v3/proposal_plan_style.tex`

This task set replaces the older standalone-specialist queue for the new dataset-generation pass. The output target is **1,000 specialist-style meta scenarios** built from the five fixed specialist collections:

- `s_network`
- `s_linux`
- `s_windows`
- `s_identity`
- `s_lateral`

The primitive action vocabulary is controlled by `/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml` and described for generation in `prompts/reference/agents/`.

## Dataset Target

| Size group | Node range | Scenario count | Train | Test |
|---|---:|---:|---:|---:|
| Small | `<= 50` | 250 | 200 | 50 |
| Medium | `51-200` | 250 | 200 | 50 |
| Large | `201-500` | 250 | 200 | 50 |
| X-Large | `501-1000` | 250 | 200 | 50 |
| Total | - | 1000 | 800 | 200 |

Implementation shape:

```text
5 scenario families x 4 size variants x 50 generated scenarios
= 20 YAML configs x (40 train + 10 test)
= 1,000 total scenarios
```

## Task Files

| File | Purpose |
|---|---|
| `01_create_config_templates.md` | Create the 20 new YAML configs under `data/scenarios/specialists/`. |
| `02_enforce_vocabulary.md` | Add hard validation so generation cannot emit off-vocabulary identifiers. |
| `03_run_two_phase_pipeline.md` | Run the existing two-phase generation/evaluation pipeline safely. |
| `04_quality_and_coverage_checks.md` | Verify final dataset counts, vocabulary coverage, solvability, and specialist usability. |
| `05_training_handoff.md` | Prepare the generated dataset for SpecialistGymEnv/DRQN training. |

## Required Invariants

- All generated vulnerabilities must be in `global_vocabulary.yaml`.
- No generated scenario may use legacy identifiers such as `Remote.Probe.*`, `External.*`, `Local.*`, `Solvability.ARP_Table_Dump`, or `Solvability.Nmap_Internal`.
- No generated scenario may use removed specialist roles such as `S_Recon`.
- All scenario configs must be specialist-style meta scenarios with multiple goals.
- Each generated scenario should contain valid fixed-pair opportunities for the relevant specialists.
- The final train/test split must be exactly 800/200.

## Execution Log

### Completed on 2026-06-13

- Moved the old root-level `data/scenarios/*.yaml` templates into `data/scenarios/old/`.
- Created the new final-config target folder: `data/scenarios/specialists/`.
- Rewrote the prompt reference files under `prompts/reference/agents/` for the five fixed specialists:
  - `s_network`
  - `s_linux`
  - `s_windows`
  - `s_identity`
  - `s_lateral`
- Confirmed the specialist prompt counts match the proposal table:
  - `s_network`: 18 local, 14 remote, 18 connect, 23 services, 41 properties.
  - `s_linux`: 19 local, 17 remote, 14 connect, 30 services, 52 properties.
  - `s_windows`: 12 local, 21 remote, 17 connect, 27 services, 44 properties.
  - `s_identity`: 15 local, 16 remote, 19 connect, 29 services, 48 properties.
  - `s_lateral`: 34 local, 4 remote, 12 connect, 28 services, 72 properties.
- Created the specialist task plan in `tasks/specialists/`.
- Created 20 final specialist-style meta source configs under `data/scenarios/specialists/`.
- Added `tools/validate_specialist_vocabulary.py`.
- Updated `pipeline/run.py` so shell environment variables override `.env`; this is required for commands such as `DATASET_ROOT=... PHASE2_TRAIN_COUNT=...`.
- Ran vocabulary validation:
  - New configs: passed, 20/20.
  - Old `specialist_meta` example: failed as expected with 51 violations.
- Ran existing Phase 1 checks:
  - `pipeline/phase1/template_validator.py`: passed, 20/20.
  - `pipeline/phase1/config_checker.py` non-strict: zero blocking errors, 20/20.
- Ran pilot generation:
  - Config: `data/scenarios/specialists/specialist_perimeter_to_domain_escalation_small_v1.yaml`.
  - Output root: `output_specialists_final_pilot/`.
  - Counts: 4 train, 1 test, 5 total.
  - BFS solve rate: 4/5.
  - LLM quality score: 9.3/10.
  - EDA report written to `output_specialists_final_pilot/specialist_perimeter_to_domain_escalation_small_v1/reports/phase2_eda.pdf`.
- Reduced credential leak probabilities/coverage in the 20 source configs:
  - `solvability_vulnerabilities.credential_leak[*].probability` values above 0.25 were set to 0.22.
  - `constraint_vulnerabilities.leak_known_credentials.node_probability` values above 0.30 were set to 0.25.
  - `constraint_vulnerabilities.leak_known_credentials.target_coverage` values above 0.30 were set to 0.25.
  - Total changed fields: 132.
- Revalidated after the credential-density change:
  - Vocabulary validation: passed, 20/20.
  - Phase 1 non-strict config checker: zero blocking errors, 20/20.
- Ran accepted low-credential pilot generation:
  - Output root: `output_specialists_final_pilot_lowcred/`.
  - Counts: 4 train, 1 test, 5 total.
  - BFS solve rate: 4/5.
  - LLM quality score: 9.7/10.
  - EDA report written to `output_specialists_final_pilot_lowcred/specialist_perimeter_to_domain_escalation_small_v1/reports/phase2_eda.pdf`.

### Current Blockers Before Full 1,000-Scenario Run

- Credential leak probabilities were reduced and the accepted low-credential pilot passed. This blocker is resolved for the first family/size pilot, but full-batch monitoring should confirm the same behavior across all families and sizes.
- Recursive topology SVG generation currently hits `AttributeError: 'list' object has no attribute 'endswith'` in `pipeline/reporting/scenario_graph.py`; the pipeline still completed, but graph output is incomplete.
- Gemini representative image generation returned HTTP 400 during the pilot. This is not required for the dataset, but it is a reporting artifact failure.
- Strict `config_checker.py --strict` still fails because it treats warnings as blocking. Main warnings are expected for the proposal design: xlarge node sizes and `goal_config.num_goals` being larger than explicit `is_goal` service count.

### Full Run Started on 2026-06-14

- Added skip flags to `pipeline/run.py` for the non-dataset reporting artifacts:
  - `--skip-phase2-report`
  - `--skip-graphs`
  - `--skip-image`
- Added `tools/run_specialist_final_dataset.sh` as a thin shell wrapper around the existing two-phase pipeline. It validates each specialist YAML, then runs `pipeline/run.py` with 40 train and 10 test scenarios per config.
- Preserved interrupted/partial attempts instead of deleting them:
  - `output_specialists_final_interrupted_20260614_000339/`
  - `output_specialists_final_partial_20260614_000858/`
- Active final output root:
  - `output_specialists_final/`
- Completed config:
  - `specialist_branch_to_hq_lateral_movement_large_v1`: 50 scenarios, BFS 46/50, LLM quality 9.6/10.
  - `specialist_branch_to_hq_lateral_movement_medium_v1`: 50 scenarios, BFS 37/50, LLM quality 8.7/10.
  - `specialist_branch_to_hq_lateral_movement_small_v1`: 50 scenarios, BFS 39/50, LLM quality 9.7/10.
  - `specialist_branch_to_hq_lateral_movement_xlarge_v1`: 50 scenarios, BFS 33/50, LLM quality 9.7/10.
  - `specialist_cicd_to_production_compromise_large_v1`: 50 scenarios, BFS 50/50, LLM quality 9.3/10.
  - `specialist_cicd_to_production_compromise_medium_v1`: 50 scenarios, BFS 50/50, LLM quality 9.6/10.
  - `specialist_cicd_to_production_compromise_small_v1`: 50 scenarios, BFS 50/50, LLM quality 8.6/10.
- Active config:
  - `specialist_cicd_to_production_compromise_xlarge_v1`
- Long-running execution:
  - tmux session: `specialist_dataset_run`
  - command: `tmux attach -t specialist_dataset_run`
  - active log: `output_specialists_final/logs/specialist_cicd_to_production_compromise_xlarge_v1_pipeline_stdout.log`
