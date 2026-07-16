# Gate Integrity and Final-Artifact Consistency

Status: confirmed by orchestration source inspection.

## Evaluator failure is conflated with partial solve

The Phase 2 evaluator is invoked with error abortion disabled. Exit code zero is
reported as all solved; every nonzero code is reported as a completed partial
solve. There is no branch separating a valid “some scenarios unsolved” exit from
process failure.

The following can therefore masquerade as realistic difficulty:

- Python/import failure;
- malformed scenario load;
- evaluator crash;
- missing dependency;
- permission or filesystem error.

Because runtime aggregation recursively reads existing `run_metrics.json`, stale
files may supply plausible-looking numbers after a failed fresh evaluation.

Suggested fix: define explicit evaluator exit codes and require a current run
manifest. Abort on execution error; accept partial solve only when a machine
readable result says evaluation completed and accounts for every expected slot.

## Stale metrics after replacement

The orchestration collects `_rm_quick`, then may replace unsolved scenarios. The
replacement helper reevaluates scenarios, but the caller does not recollect
`_rm_quick` before checking goal completeness. Thus the goal decision describes
the pre-replacement population.

Suggested fix: recollect and validate scenario accounting immediately after every
mutation/replacement. Treat the dataset as a versioned snapshot: mutation
invalidates every derived metric until recomputed.

## Expanded-config validation gap

Topology standardization occurs after all generation and evaluation. It writes a
new `<config>_expanded.yaml`, while explicitly noting that existing scenarios were
generated from the original config. No static audit, generated sample, dynamic
BFS, depth check, coverage audit, or quality evaluation is run against the
expanded config.

This creates two incompatible final artifacts:

- a validated dataset generated from the original config;
- an unvalidated expanded config advertised as the DRL training artifact.

Suggested fix: either make expansion a pre-generation transformation and run the
entire pipeline on the expanded config, or label it clearly as an unvalidated
design proposal. Never pair it with metrics from scenarios generated under a
different config hash.

## Non-fatal failed coverage

The coverage audit can mark step 9 failed but does not raise. The main run then
sets `success=True`. This violates the intuitive meaning of successful pipeline
completion when full specialist coverage is a required data contract.

Suggested fix: introduce explicit required/optional gate policy. Overall success
must be derived from required step states, not merely absence of an exception.
Reports and exit status should expose `passed`, `failed`, `skipped`, and
`inconclusive` separately.
