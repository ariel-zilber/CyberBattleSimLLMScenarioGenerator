#!/usr/bin/env bash
# Run all 20 specialist scenario configs through the full pipeline.
# Runs up to 4 in parallel using background jobs + wait.
# Logs per-scenario to output_specialist_meta_pipeline/logs/

REPO="/Users/ariel.zilbershteyin/Documents/thesis/CyberBattleSimLLMScenarioGenerator"
PYTHON="/Users/ariel.zilbershteyin/miniconda3/envs/cybersim/bin/python"
LOG_DIR="$REPO/output_specialist_meta_pipeline/logs"
PARALLEL=4

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

running=0
pids=()
names=()

for cfg in "${SCENARIOS[@]}"; do
  name=$(basename "$cfg" .yaml)
  log="$LOG_DIR/${name}.log"
  echo "[$(date '+%H:%M:%S')] START  $name"
  "$PYTHON" pipeline/run.py "$cfg" --target-score 8.0 --max-bfs-rounds 3 --skip-graphs \
    > "$log" 2>&1 &
  pids+=($!)
  names+=("$name")
  (( running++ ))

  if (( running >= PARALLEL )); then
    # Wait for the oldest job to finish
    oldest_pid=${pids[0]}
    oldest_name=${names[0]}
    wait "$oldest_pid" && echo "[$(date '+%H:%M:%S')] OK     $oldest_name" \
                       || echo "[$(date '+%H:%M:%S')] FAIL   $oldest_name  (see $LOG_DIR/${oldest_name}.log)"
    pids=("${pids[@]:1}")
    names=("${names[@]:1}")
    (( running-- ))
  fi
done

# Wait for remaining jobs
for i in "${!pids[@]}"; do
  wait "${pids[$i]}" && echo "[$(date '+%H:%M:%S')] OK     ${names[$i]}" \
                     || echo "[$(date '+%H:%M:%S')] FAIL   ${names[$i]}  (see $LOG_DIR/${names[$i]}.log)"
done

echo ""
echo "=== All 20 scenarios complete. Logs: $LOG_DIR ==="
