#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/home/ariel/Documents/thesis/CyberBattleSimLLMScenarioGenerator"
OUT="${DATASET_ROOT:-$REPO_ROOT/output_specialists_final}"
MAX_PARALLEL="${MAX_PARALLEL:-3}"

cd "$REPO_ROOT"
mkdir -p "$OUT/logs"

configs=(data/scenarios/specialists/*.yaml)

running_count() {
  pgrep -af 'python.*pipeline/run.py .*data/scenarios/specialists/specialist_.*\.yaml' \
    | grep -v grep \
    | wc -l
}

wait_for_slot() {
  while [[ "$(running_count)" -ge "$MAX_PARALLEL" ]]; do
    printf '[%s] Active pipelines: %s/%s; waiting...\n' \
      "$(date '+%Y-%m-%d %H:%M:%S')" "$(running_count)" "$MAX_PARALLEL"
    sleep 60
  done
}

is_complete() {
  local name="$1"
  local scenario_dir="$OUT/$name/scenarios"
  [[ -f "$scenario_dir/manifest.json" ]] || return 1
  local metrics_count
  metrics_count="$(find "$scenario_dir" -type f -name run_metrics.json 2>/dev/null | wc -l)"
  [[ "$metrics_count" -eq 50 ]]
}

is_running() {
  local name="$1"
  pgrep -af "python.*pipeline/run.py .*${name}\\.yaml" | grep -qv grep
}

run_one() {
  local cfg="$1"
  local idx="$2"
  local total="$3"
  local name
  name="$(basename "$cfg" .yaml)"
  local root="$OUT/$name"
  local log_file="$OUT/logs/${name}_pipeline_stdout.log"

  if is_complete "$name"; then
    printf '===== SKIP [%02d/%02d] %s: complete =====\n' "$idx" "$total" "$name"
    return 0
  fi

  if [[ -d "$root" ]]; then
    local metrics_count
    metrics_count="$(find "$root/scenarios" -type f -name run_metrics.json 2>/dev/null | wc -l)"
    if [[ "$metrics_count" -ne 50 ]]; then
      local backup="${root}_partial_$(date +%Y%m%d_%H%M%S)"
      printf 'Moving incomplete output aside: %s -> %s\n' "$root" "$backup"
      mv "$root" "$backup"
    fi
  fi

  printf '===== START [%02d/%02d] %s =====\n' "$idx" "$total" "$name"
  printf 'Verbose output -> %s\n' "$log_file"

  python tools/validate_specialist_vocabulary.py "$cfg"

  DATASET_ROOT="$OUT" \
  PHASE2_TRAIN_COUNT=40 \
  PHASE2_TEST_COUNT=10 \
  PHASE2_STRATA=small,medium,large,xlarge \
  python -u pipeline/run.py "$cfg" \
    --skip-phase2-report \
    --skip-graphs \
    --skip-image \
    --skip-exec-report \
    --skip-presentation >"$log_file" 2>&1

  printf '===== DONE [%02d/%02d] %s =====\n' "$idx" "$total" "$name"
}

printf 'Starting parallel specialist generation: %s configs\n' "${#configs[@]}"
printf 'Output root: %s\n' "$OUT"
printf 'Max parallel pipelines: %s\n' "$MAX_PARALLEL"
printf 'Per config target: 40 train + 10 test\n'

idx=0
for cfg in "${configs[@]}"; do
  idx=$((idx + 1))
  name="$(basename "$cfg" .yaml)"

  if is_complete "$name"; then
    printf '===== SKIP [%02d/%02d] %s: complete =====\n' "$idx" "${#configs[@]}" "$name"
    continue
  fi

  if is_running "$name"; then
    printf '===== SKIP [%02d/%02d] %s: already running =====\n' "$idx" "${#configs[@]}" "$name"
    continue
  fi

  wait_for_slot
  run_one "$cfg" "$idx" "${#configs[@]}" &
  sleep 2
done

wait
printf '\nPARALLEL SPECIALIST GENERATION COMPLETE\n'
