# Mac Agent Prompt: Depth-Collapse De-Shortcut Pass

You are running on the Mac machine in this project folder:

```bash
/Users/ariel.zilbershteyin/Documents/thesis/CyberBattleSimLLMScenarioGenerator
```

Use the current code in this folder. Do not assume previous chat context — everything you need is
below. This is a decision-and-implementation task, not a rerun of a known-good script.

## Background: the depth-collapse bug

Generated scenarios are supposed to require a multi-hop attack chain (per the scenario's
`attack_flow` config) to reach a goal node from `start`. Instead, many goals were landing at
BFS-hop-depth 2 from `start` (i.e. `start -> entry -> goal`, a trivial shortcut) regardless of
topology. Measured on `cicd_to_production_compromise` and `cloud_to_corp_identity_pivot`: **100% of
goals at depth 2 across 15 sampled instances each, zero variance.**

### Root cause

`find_reachable_targets()` (the function that decides which nodes a credential-leak or discovery
vulnerability on some source node is allowed to target) falls back to **every non-start node in the
network** whenever the source node doesn't match any `attack_flow` `source_pattern`. This
unrestricted pool includes goal nodes. Any node that fails to match a pattern — which happens
often, e.g. `InternetEdge_WAFs_1` (an entry node) with a `Container_EnvVars` credential leak — can
therefore get a target list that includes the goal directly, wiring a random direct shortcut.

This logic is duplicated in two places (a known "stale fork" pair):
- `pipeline/cbsim/components/solvability/shared/reachability.py::find_reachable_targets()`
  (canonical, used by `SolvabilityPostProcessor` after a recent refactor)
- `pipeline/cbsim/components/solvability_constraint_processor.py` /
  `pipeline/cbsim/components/solvability/constraint_processor/` (`SolvabilityConstraintProcessor`,
  an earlier-running separate processor with its own independent copy of the same fallback bug)

### What was already tried, and why it's currently parked

Branch `wip/depth-collapse-fix` (commit `7a2fd9e`, based on old pre-refactor `main` at `ec19805`)
excluded goal nodes from the fallback pool in both processors, and made
`SolvabilityPostProcessor._ensure_goal_reachable()`'s own fallback deterministic (directly seeds a
credential leak on a chosen node using the goal's own credentials, instead of relying on generic
random target selection that could no longer include the goal).

Result: depth diversity was restored (cicd: 12@depth-2 / 18@depth-3 across 10 seeds, vs 100% depth-2
before). But **dynamic BFS solvability dropped to ~40% (2/5 solved) on a 5-seed sample, down from a
~100% baseline**, and this reproduces even at full step/episode budget (5000 steps / 3 episodes) —
not a thin-budget artifact. One failing instance (`inst_4`) was traced to the agent thrashing
blocked RDP-connect attempts against a domain controller — looked like a firewall-rule gap or
precondition mismatch on whatever credential-leak path was supposed to reach that node, but the
exact mechanism was never confirmed for all 3 failing instances.

Full investigation notes: `git notes show 7a2fd9e` (and `git notes show 0bc0232` for the refactor
plan that split these files afterward). **Do not just re-diff `wip/depth-collapse-fix` against
current `main`** — three refactor commits (`0bc0232`, `04c82ff`, `7e55571`) landed on `main` after
that WIP commit's base and split both monolithic processor files into
`pipeline/cbsim/components/solvability/{shared,post_processor,constraint_processor}/`. The WIP fix
was never ported to that new structure, and `shared/reachability.py` currently has a docstring that
says as much explicitly:

> "This fallback is intentionally unrestricted for now (matches current main behavior exactly) —
> goal-node exclusion is a deliberate follow-up change, not part of this refactor."

The diagnosis for *why* the WIP fix regressed solvability: `find_reachable_targets`'s unrestricted
fallback pool was doing double duty — both the source of unwanted depth-collapse shortcuts, AND
(silently, undocumented) part of the implicit reachability guarantee for at least one other call
site. Restricting it fixed diversity but broke that other guarantee, and even the deterministic
`_ensure_goal_reachable()` patch didn't cover every case.

## The decision: use a de-shortcut pruning pass instead, not a fallback-pool restriction

Editing the shared `find_reachable_targets()` fallback (or its constraint-processor duplicate) is
higher-risk: it changes behavior for every call site that relies on it, several of which are
solvability-guarantee code that was never fully audited. Given the WIP branch already burned time on
that path and regressed solvability 100% → 40%, the chosen approach instead is:

**Leave every existing guarantee-generating code path completely untouched. Add one new, isolated
pass that runs at the very end of the pipeline, after solvability is already guaranteed, and prunes
only the specific shortcut edges that are provably redundant.**

### Design

1. Run the entire existing pipeline unchanged — `SolvabilityPostProcessor`,
   `SolvabilityConstraintProcessor`, all existing guarantee passes, zero modifications. This keeps
   the ~100% solvability baseline intact by construction.
2. After `SolvabilityPostProcessor.process()` finishes (i.e. after `_ensure_goal_reachable()`), add a
   new method, e.g. `_prune_shortcut_edges()`, called last from `process()`.
3. Build the actual generated attack graph the same way `pipeline/phase2/evaluator.py` already does
   for scoring — reuse `_build_attack_edges()` (evaluator.py:102) and `_bfs_depth()`
   (evaluator.py:240) as the reference implementation/logic to port or import, rather than
   reinventing graph traversal. (Check whether these can be imported directly without pulling in
   unrelated evaluator dependencies; if not, port the minimal logic.)
4. For each goal node, compute its current BFS hop-depth from `start` over the real generated graph.
5. If a goal's depth is suspiciously shallow (e.g. == 2, i.e. a direct entry→goal edge) relative to
   the scenario's intended `attack_flow` stage count, find the specific edge(s) causing that depth —
   the specific credential-leak (`LeakedCredentials` → target) or discovery (`LeakedNodesId` →
   target) entry on the shallow source node that points at the goal.
6. Before removing it, **verify live**: recompute `_bfs_depth(start, goal)` on the graph with that
   one edge hypothetically removed. If the goal is still reachable (an alternate, deeper path
   exists), remove the edge for real (drop the goal from that node's `LeakedNodesId.nodes` list, or
   drop that one `CachedCredential` entry from that node's `LeakedCredentials.credentials` list —
   whichever produced the edge). If removing it would make the goal unreachable, leave it alone —
   that instance's topology genuinely has no other path to that goal, and solvability must win.
7. Log every prune (`self.fixes_applied.append(...)`, consistent with existing conventions) and every
   skip-because-only-path, so results are auditable.

This is deliberately a **ceiling-limited** fix: it can only remove existing shortcuts, never
manufacture new multi-hop paths where the topology doesn't structurally support them. Depth
diversity after this pass is capped at whatever the scenario's topology allows. That tradeoff is
accepted — it's what keeps this safe.

## What to do

1. `cd` to the repository, confirm you're on a clean `main` (or a new branch off `main` — do not
   build this on top of `wip/depth-collapse-fix`, that branch's approach is being set aside, not
   continued).
2. Read `pipeline/cbsim/components/solvability/post_processor/goal_reachable.py` and
   `pipeline/cbsim/components/solvability/post_processor/core.py` to find exactly where
   `_ensure_goal_reachable()` is called from `process()`, and how `fixes_applied` / node
   vulnerability dicts are structured in the refactored code (do not assume the WIP diff's method
   bodies still match line-for-line — the surrounding class was reorganized).
3. Implement `_prune_shortcut_edges()` (or equivalent, in whichever new submodule file fits the
   existing `post_processor/` split best — likely a new file, e.g. `post_processor/deshortcut.py`,
   following the pattern of the other extracted modules) and wire it in as the last step of
   `process()`.
4. Do **not** modify `shared/reachability.py`, `find_reachable_targets()`, or
   `SolvabilityConstraintProcessor`'s fallback pool. Those stay exactly as they are on `main` today.
5. Verify using the same methodology the WIP branch used, so results are comparable:
   - Generate the same 5-seed sample used before for `cicd_to_production_compromise` (and ideally
     `cloud_to_corp_identity_pivot`), before and after this change.
   - Dynamic solvability: `python3 pipeline/phase2/test_env_integration.py --data-dir <scenarios_dir> --num-agents 3 --episodes 3`
     at full budget (5000 steps / 3 episodes) — confirm solve rate holds at the ~100% baseline, not
     the ~40% WIP regression.
   - Depth distribution: use `_build_attack_edges` / `_bfs_depth` (or the new pass's own accounting
     of what it pruned vs. what it left) to report the depth-2 vs depth-3(+) split before and after,
     same as the WIP commit's "12@depth-2/18@depth-3 across 10 seeds" comparison point.
6. If solvability regresses at all versus current `main` baseline, that means the "verify live before
   removing" check in step 6 of the design has a bug — stop and fix the check, do not relax it into
   an unconditional removal.

## Deliverable

- Code change implementing `_prune_shortcut_edges()` as described, wired into
  `SolvabilityPostProcessor.process()`.
- A short status note (in the commit message and/or a note under `handoffs/` or `reports/`) with:
  before/after solve rate on the 5-seed sample, before/after depth distribution, and how many
  shortcut edges were pruned vs. how many were left in place because removal would have broken
  reachability.
- Do not commit directly to `main` without the user's review — leave the change on a branch (e.g.
  `fix/depth-collapse-deshortcut`) and report back rather than merging/pushing.

## Constraints

- Do not edit `find_reachable_targets()` in `shared/reachability.py` or the equivalent fallback in
  `SolvabilityConstraintProcessor` — that path was already tried (see `wip/depth-collapse-fix`) and
  is explicitly being avoided in favor of this lower-risk approach.
- Do not touch `wip/depth-collapse-fix` itself; leave it as-is for reference.
- Do not delete or rerun existing generated scenario batches under `output_*/` as part of this work.
- Do not change any pipeline prompt text, critic prompt, or LLM evaluation/repair prompts.
- Solvability must not regress below the current `main` baseline. Depth-diversity improvement is the
  goal, but only ever as a side effect of removing edges *proven* redundant at verification time —
  never speculatively.
- If you find evidence of the actual root cause behind the WIP branch's `inst_4`-style dynamic BFS
  failures (firewall gap / precondition mismatch) while poking around, note it, but do not go fix it
  as part of this task unless it turns out to also affect this new pass's own verification step.
