#!/usr/bin/env bash
# Run the 13 remaining specialist scenarios (0 train scenarios) through the full pipeline.
# Runs up to 4 in parallel. Logs to output_specialist_meta_pipeline/logs/

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Auto-detect python in the cybersim conda env
if conda run -n cybersim python --version &>/dev/null 2>&1; then
  PYTHON="conda run -n cybersim python"
elif [ -x "$HOME/miniconda3/envs/cybersim/bin/python" ]; then
  PYTHON="$HOME/miniconda3/envs/cybersim/bin/python"
elif [ -x "$HOME/anaconda3/envs/cybersim/bin/python" ]; then
  PYTHON="$HOME/anaconda3/envs/cybersim/bin/python"
elif [ -x "$HOME/mambaforge/envs/cybersim/bin/python" ]; then
  PYTHON="$HOME/mambaforge/envs/cybersim/bin/python"
else
  PYTHON="python3"
fi
LOG_DIR="$REPO/output_specialist_meta_pipeline/logs"
MASTER_LOG="$LOG_DIR/_master_remaining.log"
PARALLEL=4

mkdir -p "$LOG_DIR"
cd "$REPO"
export PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}"

SCENARIOS=(
  data/scenarios/specialists/specialist_branch_to_hq_lateral_movement_xlarge_v1.yaml
  data/scenarios/specialists/specialist_cicd_to_production_compromise_small_v1.yaml
  data/scenarios/specialists/specialist_cicd_to_production_compromise_medium_v1.yaml
  data/scenarios/specialists/specialist_cicd_to_production_compromise_large_v1.yaml
  data/scenarios/specialists/specialist_cicd_to_production_compromise_xlarge_v1.yaml
  data/scenarios/specialists/specialist_cloud_to_corp_identity_pivot_small_v1.yaml
  data/scenarios/specialists/specialist_cloud_to_corp_identity_pivot_medium_v1.yaml
  data/scenarios/specialists/specialist_cloud_to_corp_identity_pivot_large_v1.yaml
  data/scenarios/specialists/specialist_cloud_to_corp_identity_pivot_xlarge_v1.yaml
  data/scenarios/specialists/specialist_hybrid_enterprise_crown_jewels_small_v1.yaml
  data/scenarios/specialists/specialist_hybrid_enterprise_crown_jewels_medium_v1.yaml
  data/scenarios/specialists/specialist_hybrid_enterprise_crown_jewels_large_v1.yaml
  data/scenarios/specialists/specialist_hybrid_enterprise_crown_jewels_xlarge_v1.yaml
)

log() { echo "$1" | tee -a "$MASTER_LOG"; }

running=0
pids=()
names=()

for cfg in "${SCENARIOS[@]}"; do
  name=$(basename "$cfg" .yaml)
  run_log="$LOG_DIR/${name}.log"
  log "[$(date '+%H:%M:%S')] START  $name"
  "$PYTHON" pipeline/run.py "$cfg" --target-score 8.0 --max-bfs-rounds 3 --skip-graphs \
    > "$run_log" 2>&1 &
  pids+=($!)
  names+=("$name")
  (( running++ ))

  if (( running >= PARALLEL )); then
    oldest_pid=${pids[0]}
    oldest_name=${names[0]}
    wait "$oldest_pid" \
      && log "[$(date '+%H:%M:%S')] OK     $oldest_name" \
      || log "[$(date '+%H:%M:%S')] FAIL   $oldest_name  (see $LOG_DIR/${oldest_name}.log)"
    pids=("${pids[@]:1}")
    names=("${names[@]:1}")
    (( running-- ))
  fi
done

for i in "${!pids[@]}"; do
  wait "${pids[$i]}" \
    && log "[$(date '+%H:%M:%S')] OK     ${names[$i]}" \
    || log "[$(date '+%H:%M:%S')] FAIL   ${names[$i]}  (see $LOG_DIR/${names[$i]}.log)"
done

log ""
log "=== All 13 remaining scenarios complete. Logs: $LOG_DIR ==="
