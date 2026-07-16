# Regeneration and Retry Contamination

Status: confirmed by generation control-flow inspection.

## Stale files in fixed-scale generation

The fixed-scale generator computes a scenario directory, calls
`mkdir(exist_ok=True)`, and writes generated files into it. Neither the worker nor
`cli.generate_scenario` removes an existing scenario directory or clears its
`nodes/` contents.

Suppose attempt A emits nodes `{start, A, B, C}` and attempt B emits
`{start, X, Y}` into the same directory. After B, old `A.yaml`, `B.yaml`, and
`C.yaml` can remain alongside `X.yaml` and `Y.yaml`. Identifiers and vulnerability
library are overwritten, producing a hybrid scenario whose node files may no
longer agree with the current generated vocabulary.

The post-static audit might catch some vocabulary disagreement, but it cannot
identify which files belong to which seed, and a compatible stale node may pass.

## Retry contamination

With `--require-solvable`, all seed attempts reuse that same directory without
cleanup between attempts. The solvability check can therefore approve a union of
multiple generations rather than the last seed's output.

This is P0 because it directly corrupts sample identity and invalidates seed-level
reproducibility.

## Misnamed solvability check

The helper `_is_bfs_solvable` calls `pipeline.phase2.evaluator.evaluate_scenario`
and reads a static `solvable` flag. It does not load and execute the CBS dynamic
BFS used later. It inherits the static evaluator's information-as-ownership and
privilege-state omissions.

## Unenforced timeout

The CLI exposes `--timeout` and passes it through `_run_parallel` to
`_generate_one`, but `_generate_one` never applies it. `ProcessPoolExecutor` waits
for all futures, so a hung generation can hold the batch open indefinitely.

## Suggested fix

- Generate into a fresh temporary sibling directory.
- Validate that temporary artifact completely.
- Atomically rename it into the final slot only after success.
- Persist its seed/provenance.
- Never reuse a directory across seed attempts.
- Rename the static check accurately or replace it with the authoritative dynamic
  acceptance evaluator.
- Enforce timeout at the process/future boundary and classify timeout explicitly.
