---
name: GLOBALTECH Dataset Pipeline Status
description: Current run status for all specialist CBS configs in GLOBALTECH dataset as of 2026-05-11
type: project
---

Pipeline run status as of 2026-05-11 (ongoing):

| Config | File | Status | Score |
|--------|------|--------|-------|
| S-NET-01 | snet_perimeter_standalone_v1.yaml | ✅ DONE | 8.3/10 (21 scenarios) |
| S-LIN-01 standalone | slin_cloud_standalone_v1.yaml | ✅ DONE (Step 6 EDA still running) | 8.5/10 (21 scenarios) |
| S-WIN-01 | swin_serverfarm_standalone_v1.yaml | ✅ DONE (Step 6 EDA still running) | 8.5/10 (21 scenarios) |
| S-LIN-01 meta | slin_cloud_meta_v1.yaml | 🔄 RUNNING (Phase 1) | — |
| S-ID-01 | sid_ad_standalone_v1.yaml | 🔄 RUNNING (Phase 1) | — |
| S-REC-01 | srec_recon_standalone_v1.yaml | 🔄 RUNNING (Phase 1) | — |

**Remaining configs not yet written:**
- slin_cloud_meta_v1.yaml exists (validated) — just started pipeline

**Why:** All configs need pipeline score ≥ 8.0. Generate 5 train + 2 test × 3 strata (small/medium/large) = 21 scenarios each.

**How to apply:** When resuming, check logs in output/logs/ for latest status. Run `ps aux | grep run_full_pipeline` to see what's active.
