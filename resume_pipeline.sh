#!/usr/bin/env bash
# Resume pipeline: skip completed templates (≥40 train + ≥10 test), run the rest.

REPO="/Users/ariel.zilbershteyin/Documents/thesis/CyberBattleSimLLMScenarioGenerator"
PYTHON="/Users/ariel.zilbershteyin/miniconda3/envs/cybersim/bin/python"
OUTDIR="$REPO/output_specialist_meta_pipeline"
LOG_DIR="$OUTDIR/logs"
PARALLEL=4

export PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}"
export MLFLOW_ALLOW_FILE_STORE=true
export DATASET_ROOT="$OUTDIR"

mkdir -p "$LOG_DIR"
cd "$REPO"

SCENARIOS=(
  data/scenarios/specialists/specialist_perimeter_to_domain_escalation_small_v1.yaml
  data/scenarios/specialists/specialist_perimeter_to_domain_escalation_medium_v1.yaml
  data/scenarios/specialists/specialist_perimeter_to_domain_escalation_large_v1.yaml
  data/scenarios/specialists/specialist_perimeter_to_domain_escalation_xlarge_v1.yaml
  data/scenarios/specialists/specialist_branch_to_hq_lateral_movement_small_v1.yaml
  data/scenarios/specialists/specialist_branch_to_hq_lateral_movement_medium_v1.yaml
  data/scenarios/specialists/specialist_branch_to_hq_lateral_movement_large_v1.yaml
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

_count_dirs() { ls -d "$1"/*/ 2>/dev/null | wc -l | tr -d ' '; }

running=0
pids=()
names=()

for cfg in "${SCENARIOS[@]}"; do
  name=$(basename "$cfg" .yaml)
  train_dir="$OUTDIR/$name/scenarios/train"
  test_dir="$OUTDIR/$name/scenarios/test"
  n_train=$(_count_dirs "$train_dir")
  n_test=$(_count_dirs "$test_dir")

  if [ "$n_train" -ge 40 ] && [ "$n_test" -ge 10 ]; then
    echo "[$(date '+%H:%M:%S')] SKIP   $name  (train=$n_train test=$n_test)"
    continue
  fi

  echo "[$(date '+%H:%M:%S')] START  $name  (train=$n_train test=$n_test)"
  log="$LOG_DIR/${name}.log"
  "$PYTHON" pipeline/run.py "$cfg" --target-score 8.0 --max-bfs-rounds 3 --skip-graphs \
    > "$log" 2>&1 &
  pids+=($!)
  names+=("$name")
  (( running++ ))

  if (( running >= PARALLEL )); then
    oldest_pid=${pids[0]}; oldest_name=${names[0]}
    wait "$oldest_pid" && echo "[$(date '+%H:%M:%S')] OK     $oldest_name" \
                       || echo "[$(date '+%H:%M:%S')] FAIL   $oldest_name"
    pids=("${pids[@]:1}"); names=("${names[@]:1}")
    (( running-- ))
  fi
done

for i in "${!pids[@]}"; do
  wait "${pids[$i]}" && echo "[$(date '+%H:%M:%S')] OK     ${names[$i]}" \
                     || echo "[$(date '+%H:%M:%S')] FAIL   ${names[$i]}"
done

echo ""
echo "=== Resume complete. Logs: $LOG_DIR ==="
