#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/home/ariel/Documents/thesis/CyberBattleSimLLMScenarioGenerator"
OUT="${DATASET_ROOT:-$REPO_ROOT/output_specialists_final}"

cd "$REPO_ROOT"
mkdir -p "$OUT/logs"

configs=(data/scenarios/specialists/*.yaml)

printf 'Starting full specialist generation: %s configs\n' "${#configs[@]}"
printf 'Output root: %s\n' "$OUT"
printf 'Per config target: 40 train + 10 test\n'

idx=0
for cfg in "${configs[@]}"; do
  idx=$((idx + 1))
  name="$(basename "$cfg" .yaml)"
  scenario_dir="$OUT/$name/scenarios"

  printf '\n===== [%02d/%02d] %s =====\n' "$idx" "${#configs[@]}" "$name"

  if [[ -f "$scenario_dir/manifest.json" ]]; then
    metrics_count="$(find "$scenario_dir" -type f -name run_metrics.json 2>/dev/null | wc -l)"
    if [[ "$metrics_count" -eq 50 ]]; then
      printf 'Already complete: manifest.json + 50 run_metrics.json files; skipping.\n'
      continue
    fi
  fi

  python tools/validate_specialist_vocabulary.py "$cfg"

  log_file="$OUT/logs/${name}_pipeline_stdout.log"
  printf 'Running pipeline; verbose output -> %s\n' "$log_file"

  DATASET_ROOT="$OUT" \
  PHASE2_TRAIN_COUNT=40 \
  PHASE2_TEST_COUNT=10 \
  PHASE2_STRATA=small,medium,large,xlarge \
  python -u pipeline/run.py "$cfg" \
    --skip-phase2-report \
    --skip-graphs \
    --skip-image \
    --skip-exec-report \
    --skip-presentation >"$log_file" 2>&1 || {
      status=$?
      printf 'Pipeline failed for %s with exit code %s\n' "$name" "$status"
      printf 'Last 80 log lines from %s:\n' "$log_file"
      tail -n 80 "$log_file" || true
      exit "$status"
    }

  printf '===== DONE [%02d/%02d] %s =====\n' "$idx" "${#configs[@]}" "$name"
done

printf '\nFULL SPECIALIST GENERATION COMPLETE\n'
