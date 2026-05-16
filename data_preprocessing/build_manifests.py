"""
tools/build_manifests.py
=========================
Build per-agent training manifests and a meta-agent manifest from the
stratified scenario directories under DATASET_ROOT/phase2/.

Outputs:
  data/manifests/agent_1_train.json   (Discovery)
  data/manifests/agent_2_train.json   (Initial Access)
  data/manifests/agent_3_train.json   (Cred + Lateral Movement)
  data/manifests/agent_4_train.json   (PrivEsc + Persistence)
  data/manifests/agent_5_train.json   (Collection + Impact)
  data/manifests/meta_agent_train.json
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, List, Tuple

DATASET_ROOT = Path("/content/drive/MyDrive/thesis/code/datasets/poc/claude")
PHASE2_DIR   = DATASET_ROOT / "phase2"
MANIFEST_DIR = Path(__file__).resolve().parent.parent / "data" / "manifests"

# ── Config → agent mapping ────────────────────────────────────────────────────
# Each tuple: (config_name, [agent_ids])
# Agent IDs: 1=Discovery, 2=InitialAccess, 3=Cred+Lateral, 4=PrivEsc+Persist, 5=Collection+Impact
# Meta configs go to agent 0 (meta only)
CONFIG_AGENT_MAP: Dict[str, List[int]] = {
    # Existing enterprise / legacy configs
    "enterprise_ad_v6":             [3, 4, 5],     # best version only
    "jenkins_cicd_v2":              [4],
    "network_device_infra_v3":      [1, 2],
    "scada_ad_hybrid_v1":           [3, 5],
    "scada_ics_v2":                 [5],
    "ta0001_initial_access_v2":     [2],
    "ta0002_execution_v2":          [2],
    "ta0007_discovery_v2":          [1],
    "wordpress_ad_hybrid_v3":       [3, 5],
    "wordpress_jenkins_hybrid_v1":  [4],
    "wordpress_web_stack_v3":       [2],

    # Phase 1 tactic configs
    "ta0003_persistence_v1":        [4],
    "ta0004_privesc_v1":            [4],
    "ta0006_credential_access_v1":  [3],
    "ta0008_lateral_movement_v1":   [3],
    "ta0009_collection_v1":         [5],
    "ta0040_impact_v1":             [5],

    # Phase 2 specialist configs
    "flat_mixed_os_v1":             [1],
    "bitnami_cloud_native_v1":      [2],
    "deep_linux_hub_v1":            [3],
    "windows_privesc_v1":           [4],
    "it_ot_dual_goal_v1":           [5],

    # Phase 3 meta-agent configs (meta only — not used by specialists)
    "meta_killchain_v1":            [],
    "meta_ambiguous_v1":            [],
    "meta_deadend_v1":              [],
    "meta_multicluster_xl_v1":      [],
    "meta_it_ot_hybrid_v1":         [],
}

# Stratum sampling weights per agent
AGENT_WEIGHTS: Dict[int, Dict[str, float]] = {
    1: {"small": 0.15, "medium": 0.35, "large": 0.50, "xl": 0.00},
    2: {"small": 0.55, "medium": 0.35, "large": 0.10, "xl": 0.00},
    3: {"small": 0.15, "medium": 0.55, "large": 0.30, "xl": 0.00},
    4: {"small": 0.35, "medium": 0.50, "large": 0.15, "xl": 0.00},
    5: {"small": 0.10, "medium": 0.40, "large": 0.50, "xl": 0.00},
    0: {"small": 0.20, "medium": 0.35, "large": 0.35, "xl": 0.10},   # meta
}

AGENT_NAMES = {
    1: "discovery",
    2: "initial_access",
    3: "credential_lateral",
    4: "privesc_persistence",
    5: "collection_impact",
    0: "meta",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _count_scenarios(config_path: Path) -> Tuple[Dict[str, int], Dict[str, int]]:
    """Return (train_per_stratum, test_per_stratum) scenario counts."""
    train: Dict[str, int] = {}
    test:  Dict[str, int] = {}
    for split, d in [("train", train), ("test", test)]:
        split_dir = config_path / split
        if not split_dir.exists():
            continue
        for s in sorted(split_dir.iterdir()):
            if not s.is_dir():
                continue
            n = sum(1 for x in s.iterdir()
                    if x.is_dir() and x.name.startswith("CyberBattleSim"))
            if n > 0:
                d[s.name] = n
    return train, test


def _scenario_paths(config_path: Path, split: str) -> List[str]:
    """Return relative paths for all scenario directories in a split."""
    paths = []
    split_dir = config_path / split
    if not split_dir.exists():
        return paths
    for s in sorted(split_dir.iterdir()):
        if not s.is_dir():
            continue
        for scenario in sorted(s.iterdir()):
            if scenario.is_dir() and scenario.name.startswith("CyberBattleSim"):
                paths.append(str(scenario.relative_to(DATASET_ROOT)))
    return paths


# ── Build ─────────────────────────────────────────────────────────────────────

def build_agent_manifest(agent_id: int) -> dict:
    configs = [c for c, agents in CONFIG_AGENT_MAP.items() if agent_id in agents]
    train_paths: List[str] = []
    test_paths:  List[str] = []
    total_train = 0
    total_test  = 0
    config_details = []

    for config in sorted(configs):
        cfg_dir = PHASE2_DIR / config
        if not cfg_dir.exists():
            print(f"  [warn] {config} not found at {cfg_dir}")
            continue
        tr, te = _count_scenarios(cfg_dir)
        t_tr = sum(tr.values())
        t_te = sum(te.values())
        total_train += t_tr
        total_test  += t_te
        train_paths += _scenario_paths(cfg_dir, "train")
        test_paths  += _scenario_paths(cfg_dir, "test")
        config_details.append({
            "config": config,
            "strata": sorted(set(list(tr) + list(te))),
            "train_per_stratum": tr,
            "test_per_stratum": te,
            "train_total": t_tr,
            "test_total": t_te,
        })

    return {
        "agent": AGENT_NAMES[agent_id],
        "agent_id": agent_id,
        "configs": configs,
        "config_details": config_details,
        "stratum_weights": AGENT_WEIGHTS[agent_id],
        "total_train_scenarios": total_train,
        "total_test_scenarios": total_test,
        "train_scenario_paths": train_paths,
        "test_scenario_paths": test_paths,
    }


def build_meta_manifest(per_agent_manifests: List[dict]) -> dict:
    # Meta uses ALL configs (specialist + hybrid)
    all_configs = sorted(CONFIG_AGENT_MAP.keys())
    train_paths: List[str] = []
    test_paths:  List[str] = []
    total_train = 0
    total_test  = 0
    config_details = []

    for config in all_configs:
        cfg_dir = PHASE2_DIR / config
        if not cfg_dir.exists():
            continue
        tr, te = _count_scenarios(cfg_dir)
        t_tr = sum(tr.values())
        t_te = sum(te.values())
        total_train += t_tr
        total_test  += t_te
        train_paths += _scenario_paths(cfg_dir, "train")
        test_paths  += _scenario_paths(cfg_dir, "test")
        config_details.append({
            "config": config,
            "strata": sorted(set(list(tr) + list(te))),
            "train_per_stratum": tr,
            "test_per_stratum": te,
            "train_total": t_tr,
            "test_total": t_te,
        })

    return {
        "agent": "meta",
        "agent_id": 0,
        "configs": all_configs,
        "config_details": config_details,
        "stratum_weights": AGENT_WEIGHTS[0],
        "total_train_scenarios": total_train,
        "total_test_scenarios": total_test,
        "train_scenario_paths": train_paths,
        "test_scenario_paths": test_paths,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)

    per_agent = []
    for aid in [1, 2, 3, 4, 5]:
        m = build_agent_manifest(aid)
        per_agent.append(m)
        out = MANIFEST_DIR / f"agent_{aid}_train.json"
        out.write_text(json.dumps(m, indent=2))
        print(f"agent_{aid} ({AGENT_NAMES[aid]:25s}): "
              f"{m['total_train_scenarios']:3d} train  "
              f"{m['total_test_scenarios']:3d} test  "
              f"({len(m['configs'])} configs)")

    meta = build_meta_manifest(per_agent)
    out = MANIFEST_DIR / "meta_agent_train.json"
    out.write_text(json.dumps(meta, indent=2))
    print(f"\nmeta                              : "
          f"{meta['total_train_scenarios']:3d} train  "
          f"{meta['total_test_scenarios']:3d} test  "
          f"({len(meta['configs'])} configs)")
    print(f"\nManifests written to {MANIFEST_DIR}")
