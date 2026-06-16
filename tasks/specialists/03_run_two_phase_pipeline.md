# Task 03 - Run the Existing Two-Phase Pipeline

## Goal

Generate the final dataset using the existing two-phase pipeline, not a separate new generator.

Authoritative runner:

```text
pipeline/run.py
```

## Process

For each config under `data/scenarios/specialists/`:

1. Run vocabulary preflight.
2. Run Phase 1 validation/reporting.
3. Run Phase 2 scenario generation.
4. Run BFS evaluation.
5. Run LLM quality evaluation/repair if configured.
6. Produce reports and graphs.

The actual command shape should be:

```bash
DATASET_ROOT=/path/to/final/output \
PHASE2_TRAIN_COUNT=40 \
PHASE2_TEST_COUNT=10 \
python pipeline/run.py data/scenarios/specialists/<config>.yaml \
  --skip-exec-report \
  --skip-presentation
```

Use a fresh output root for final data, for example:

```text
output_specialists_final/
```

Do not mix final generation with the old `output_specialist_meta_pipeline/` data.

## Pilot First

Before full batch generation:

- [x] Run one small config with `PHASE2_TRAIN_COUNT=4`, `PHASE2_TEST_COUNT=1`.
- [x] Inspect generated `identifiers/identifiers.yaml`.
- [x] Verify no off-vocabulary IDs appear.
- [x] Verify `run_metrics.json` exists for generated scenarios.
- [x] Verify BFS can solve at least some generated scenarios.

## Full Batch

After pilot passes:

- [ ] Generate 20 configs.
- [ ] Each config must produce 40 train and 10 test scenarios.
- [ ] Record per-config manifest results.
- [ ] Do not accept partial manifests as final.

## Done Criteria

- [ ] 20 manifests exist.
- [ ] Each manifest reports `train_count: 40`, `test_count: 10`, `total: 50`.
- [ ] Total generated scenarios: 1,000.
- [ ] Train scenarios: 800.
- [ ] Test scenarios: 200.
- [ ] Output root is separate from old generated data.

## Execution Notes

Pilot started and completed on 2026-06-13.

Command used:

```bash
DATASET_ROOT=/home/ariel/Documents/thesis/CyberBattleSimLLMScenarioGenerator/output_specialists_final_pilot \
PHASE2_TRAIN_COUNT=4 \
PHASE2_TEST_COUNT=1 \
PHASE2_STRATA=small \
python pipeline/run.py \
  data/scenarios/specialists/specialist_perimeter_to_domain_escalation_small_v1.yaml \
  --skip-exec-report \
  --skip-presentation
```

Pilot manifest:

```text
output_specialists_final_pilot/specialist_perimeter_to_domain_escalation_small_v1/scenarios/manifest.json
```

Manifest result:

```json
{
  "train_count": 4,
  "test_count": 1,
  "total": 5
}
```

Pilot quality result:

- BFS solve rate: 4/5 scenarios.
- LLM quality score: 9.3/10.
- EDA report: `output_specialists_final_pilot/specialist_perimeter_to_domain_escalation_small_v1/reports/phase2_eda.pdf`.
- Per-scenario PDFs: 5/5.

Pilot warnings to address before full batch:

- Recursive topology SVG generation failed in `pipeline/reporting/scenario_graph.py` with `AttributeError: 'list' object has no attribute 'endswith'`.
- Gemini representative image generation returned HTTP 400.
- `scenario_expander` import failed during topology standardization with `No module named 'pipeline'`.

Credential-density follow-up:

- Updated all 20 source configs to lower high credential leak probabilities and coverage.
- Changed fields: 132.
- Revalidated after the edit:
  - Vocabulary validation: passed 20/20.
  - Phase 1 non-strict config checker: zero blocking errors.
- Reran the pilot using:

```bash
DATASET_ROOT=/home/ariel/Documents/thesis/CyberBattleSimLLMScenarioGenerator/output_specialists_final_pilot_lowcred \
PHASE2_TRAIN_COUNT=4 \
PHASE2_TEST_COUNT=1 \
PHASE2_STRATA=small \
python pipeline/run.py \
  data/scenarios/specialists/specialist_perimeter_to_domain_escalation_small_v1.yaml \
  --skip-exec-report \
  --skip-presentation
```

Accepted low-credential pilot result:

- Manifest: `output_specialists_final_pilot_lowcred/specialist_perimeter_to_domain_escalation_small_v1/scenarios/manifest.json`.
- Counts: 4 train, 1 test, 5 total.
- BFS solve rate: 4/5.
- LLM quality score: 9.7/10.
- Credential leak probabilities were accepted by the critic at 0.22.
- EDA report: `output_specialists_final_pilot_lowcred/specialist_perimeter_to_domain_escalation_small_v1/reports/phase2_eda.pdf`.

The reporting failures are non-blocking for raw scenario generation but should be fixed before treating the reporting artifacts as final.

## Full Dataset Run

Started on 2026-06-14 after the accepted low-credential pilot.

The first full-batch attempt reached raw generation and BFS for
`specialist_branch_to_hq_lateral_movement_large_v1`, but then spent a long time
inside `pipeline/reporting/human_report.py`. The reporting process was CPU-active
and the Phase 2 report file stayed empty. Because the final dataset requires the
scenario YAML folders and runtime metrics, not per-config EDA/PDF artifacts, the
runner was updated with explicit skip flags for heavyweight post-generation
artifacts:

```bash
--skip-phase2-report
--skip-graphs
--skip-image
```

The generation/evaluation command used by the wrapper is:

```bash
DATASET_ROOT=/home/ariel/Documents/thesis/CyberBattleSimLLMScenarioGenerator/output_specialists_final \
PHASE2_TRAIN_COUNT=40 \
PHASE2_TEST_COUNT=10 \
PHASE2_STRATA=small,medium,large,xlarge \
python pipeline/run.py "$cfg" \
  --skip-phase2-report \
  --skip-graphs \
  --skip-image \
  --skip-exec-report \
  --skip-presentation
```

The active final run is being executed in a foreground terminal session because
background jobs launched through the tool environment were cleaned up when the
launching command exited.

Current active output root:

```text
output_specialists_final/
```

Preserved interrupted/partial output roots:

```text
output_specialists_final_interrupted_20260614_000339/
output_specialists_final_partial_20260614_000858/
```

Completed configs:

- `specialist_branch_to_hq_lateral_movement_large_v1`
  - Raw generation: 50 scenarios.
  - Manifest: present.
  - BFS solve rate: 46/50.
  - LLM quality score: 9.6/10.
  - Step 5/6/7 report artifacts were skipped as intended.
- `specialist_branch_to_hq_lateral_movement_medium_v1`
  - Raw generation: 50 scenarios.
  - Manifest: present.
  - BFS solve rate: 37/50.
  - LLM quality score: 8.7/10.
  - Step 5/6/7 report artifacts were skipped as intended.
- `specialist_branch_to_hq_lateral_movement_small_v1`
  - Raw generation: 50 scenarios.
  - Manifest: present.
  - BFS solve rate: 39/50.
  - LLM quality score: 9.7/10.
  - Step 5/6/7 report artifacts were skipped as intended.
- `specialist_branch_to_hq_lateral_movement_xlarge_v1`
  - Raw generation: 50 scenarios.
  - Manifest: present.
  - BFS solve rate: 33/50.
  - LLM quality score: 9.7/10.
  - Step 5/6/7 report artifacts were skipped as intended.
- `specialist_cicd_to_production_compromise_large_v1`
  - Raw generation: 50 scenarios.
  - Manifest: present.
  - BFS solve rate: 50/50.
  - LLM quality score: 9.3/10.
  - Step 5/6/7 report artifacts were skipped as intended.
- `specialist_cicd_to_production_compromise_medium_v1`
  - Raw generation: 50 scenarios.
  - Manifest: present.
  - BFS solve rate: 50/50.
  - LLM quality score: 9.6/10.
  - Step 5/6/7 report artifacts were skipped as intended.
- `specialist_cicd_to_production_compromise_small_v1`
  - Raw generation: 50 scenarios.
  - Manifest: present.
  - BFS solve rate: 50/50.
  - LLM quality score: 8.6/10.
  - Step 5/6/7 report artifacts were skipped as intended.

Current active config:

- `specialist_cicd_to_production_compromise_xlarge_v1`
  - Raw generation: active.
  - Verbose output is redirected to `output_specialists_final/logs/specialist_cicd_to_production_compromise_xlarge_v1_pipeline_stdout.log`.

Notes:

- Previous partial xlarge outputs were moved aside as `specialist_branch_to_hq_lateral_movement_xlarge_v1_partial_20260614_021645` and `specialist_branch_to_hq_lateral_movement_xlarge_v1_partial_20260614_023642`.
- The durable run is inside tmux session `specialist_dataset_run`.
