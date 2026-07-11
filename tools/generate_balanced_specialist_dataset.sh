#!/usr/bin/env bash
# tools/generate_balanced_specialist_dataset.sh
#
# Generates the small-tier specialist dataset with per-config scenario counts
# reweighted for more even specialist-zone representation across the whole
# dataset, instead of a uniform 40 train + 10 test per config.
#
# Why: each config only touches the zones its narrative crosses (they are
# Meta-agent scenarios, not single-specialist ones) -- 3 of 5 configs have
# ZERO node exposure to one or two specialist zones (branch_to_hq: no
# S_Network/S_Linux; cloud_to_corp: no S_Network; hybrid: no S_Linux;
# perimeter: no S_Linux/S_Windows). Uniform scenario counts per config
# therefore produce a ~1.76x max/min imbalance in total node exposure per
# specialist zone across the dataset.
#
# These counts were derived by solving for the allocation that minimizes the
# max relative deviation between specialist-zone totals, bounded to a
# realistic per-config range (20-100 scenarios) and a similar overall dataset
# size to the uniform baseline (~250 scenarios). Verified against real
# generated output (not just the linear model): reduces the max/min zone
# imbalance from 1.76x to 1.29x, with solvability and slot coverage
# unaffected (identical to the uniform-count baseline).
#
# Exact equal representation is NOT achievable via count reweighting alone --
# it would require ~1000 total scenarios (cicd alone at 610) because configs
# with zero exposure to a zone can never be compensated by generating more of
# themselves. True equality would require editing config content to broaden
# zone coverage (a separate, larger effort).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="${1:-output_balanced_specialist_dataset}"
WORKERS="${WORKERS:-8}"

declare -A TRAIN=(
  [branch_to_hq_lateral_movement]=16
  [cicd_to_production_compromise]=56
  [cloud_to_corp_identity_pivot]=46
  [hybrid_enterprise_crown_jewels]=36
  [perimeter_to_domain_escalation]=47
)
declare -A TEST=(
  [branch_to_hq_lateral_movement]=4
  [cicd_to_production_compromise]=14
  [cloud_to_corp_identity_pivot]=11
  [hybrid_enterprise_crown_jewels]=9
  [perimeter_to_domain_escalation]=12
)

for cfg in "${!TRAIN[@]}"; do
  echo "=== $cfg (train=${TRAIN[$cfg]} test=${TEST[$cfg]}) ==="
  PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}" python3 pipeline/phase2/generator.py \
    --config "data/scenarios/specialists/specialist_${cfg}_small_v1.yaml" \
    --out-dir "${OUT_DIR}/${cfg}" \
    --train "${TRAIN[$cfg]}" --test "${TEST[$cfg]}" \
    --require-solvable --max-retries 2 --workers "$WORKERS"
done
