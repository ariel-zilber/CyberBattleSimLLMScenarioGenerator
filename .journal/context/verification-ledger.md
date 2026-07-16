# Verification ledger

Last updated: 2026-07-15, after the user challenged the validity of the issue
list. This ledger supersedes blanket uses of “confirmed” elsewhere in the
journal.

## Evidence labels

- **Runtime reproduced**: executed against the connected improved CyberBattleSim
  actuator or an authoritative pipeline run.
- **Artifact reproduced**: observed in generated/compiled files or isolated
  component execution, but not necessarily in full training runtime.
- **Current-source confirmed**: the current worktree directly implements the
  stated behavior; consequence has not yet been reproduced end to end.
- **Documented boundary**: intentionally outside the component's stated scope;
  not counted as a hidden defect.
- **Hypothesis**: plausible but insufficiently verified; must not be reported as
  an established bug.
- **Withdrawn**: contradicted by stronger evidence.

## Production generator P0 findings

| Index | Short finding | Current verdict | Authoritative evidence | Remaining verification |
|---:|---|---|---|---|
| 19 | Fixed-scale regeneration retains stale YAML | Current-source confirmed | `phase2/generator.py` and `cli.py` create existing directories and overwrite present node IDs without reconciling removed IDs | Reproduce with two real main-generator attempts having different node sets |
| 20 | `--require-solvable` retries contaminate one directory | Current-source confirmed | `_generate_one()` reuses one `scenario_dir` across all retry seeds; the called writer does not clear it | Force an unsolved first attempt and compare the second attempt's files |
| 28 | Numeric seeds vary with `PYTHONHASHSEED` | Artifact reproduced | Same config/seed 4242 produced different node/vulnerability placement across hash seeds | Determine whether all acceptance-critical outputs differ and isolate every unordered source |
| 29 | Failed depth certificates do not fail generation | Artifact reproduced + current-source confirmed | Generated run printed `VIOLATION`; generator only prints certificate status and continues | Confirm the violating final artifact is included by the full batch manifest |
| 30 | Coverage mutates after depth certification | Current-source confirmed | `CertifiedAttackSpineBuilder.apply()` runs before `ensure_full_coverage()`; no recertification follows in generator | Produce a case where coverage creates a measurable shortcut |
| 33 | GoalNormalizer reads policy from wrong YAML level | Artifact reproduced + current-source confirmed | sentinel nested config retained explicit count but silently produced default strategy/promote behavior and no shared name | Verify through one complete generated scenario |
| 37 | Serialized subnet policy differs from runtime firewall graph | Runtime reproduced in both directions | one exact-subnet-invalid edge connected; one intended edge missing outgoing port was blocked | Determine dataset-level effect on goal solvability and shortcuts |
| 39 | Static solvability does not use runtime firewall semantics | Artifact/component reproduced | the static evaluator included the exact generated edge that the improved actuator blocked | Show a whole-scenario static-pass/dynamic-fail verdict caused solely by firewall |
| 41 | Evaluator node cap 100 versus xlarge 700–950 | Withdrawn | real 778-node artifact loaded and reset successfully; improved observations are neighborhood-size invariant | None unless a different consumer of the bound is identified |
| 42 | Evaluator credential bounds versus xlarge | Artifact reproduced + current-source confirmed | 1,554 unique credentials; max 1,552 in one action; observation high 1,000; statistics denominator 100 | Execute the large leak and test observation-space validity and planner behavior |

These are not all runtime-proven. Only the evidence label should be quoted when
reporting them.

## Experimental object-generator P0 findings

The object generator is an isolated, untracked MVP. Its README explicitly says
exact environment replay is not part of the MVP. Findings here must not be mixed
with production-dataset failures without an integration path.

| Index | Short finding | Current verdict | Evidence |
|---:|---|---|---|
| 55 | Initial BFS state differs from compiled artifact | Artifact reproduced; partially runtime observed | Compiler turns initial discovery into an action and drops initial credentials/non-start privilege |
| 56 | Local prerequisites validated on target, compiled on source | Artifact reproduced | Valid spec compiled a source precondition for a property absent from source |
| 57 | Remote exploit firewall mismatch | Withdrawn | Runtime also omits firewall checks for remote vulnerability exploits |
| 59 | Blocked Connect emits allow then deny | Artifact reproduced + runtime-source confirmed | Runtime uses first same-port rule, so emitted earlier allow defeats later deny |
| 62 | Legacy DSL output path traversal | Artifact reproduced | `../escaped` wrote outside `nodes/` in an isolated temporary directory |
| 63 | Recompile retains stale object nodes | Artifact reproduced | Removed `old` node remained after second compile |
| 64 | Declared `start` is overwritten | Artifact reproduced | Validated user node became synthetic attacker in compiled output |
| 67 | Remote/Connect high privilege grant is lost | Artifact reproduced + runtime-source confirmed | BFS System grant compiles to LateralMove/Connect; runtime grants LocalUser |
| 68 | Zero-rate edge is accepted by BFS | Artifact reproduced | Valid rate-0 transition received solved depth-1 certificate |
| 69 | Probe owner/type/property mismatch | Artifact reproduced + runtime-source confirmed | Source-held type-3 probe references target property; runtime evaluates remote vuln on target |

## Corrections already made

1. Remote-exploit firewall mismatch was withdrawn.
2. The preferred object example does bypass its Admin gate, but the claimed
   numeric 9-to-8 collapse was withdrawn: compiled initial discovery adds an
   action, leaving the adapted runtime sequence at 9 actions.
3. The 53.7% firewall figure is exact serialized-policy failure, not dynamic
   blocking. Actual current actuator semantics predict 15.8% blocked and 103
   policy-invalid edges over-permitted.

## Reporting rule

The numerical index is an audit inventory, not a count of proven production
bugs. Final summaries must separate production from experimental code and must
state the evidence label for every material claim.
