# Hash-Seed Nondeterminism

Status: dynamically reproduced.

## Cause

Credential banks store IDs in sets. Selection unions those sets into another set,
then converts it directly to a list before probability filtering or
`random.sample`. Set iteration order depends on Python's randomized hash seed and
is not controlled by `random.seed(scenario_seed)`.

Other generation paths also use sets and convert them to sequences without a
canonical sort, including coverage/placement operations. Thus a numeric scenario
seed is not a complete seed for the generated artifact.

## Reproduction

The same command was run in two fresh processes, differing only in
`PYTHONHASHSEED`:

```text
PYTHONHASHSEED=1 python cli.py <same-config> /tmp/cbsgen_hashseed_1 --seed 4242
PYTHONHASHSEED=2 python cli.py <same-config> /tmp/cbsgen_hashseed_2 --seed 4242
```

Both completed successfully and wrote 52 files. `diff -qr` reported differences
in identifiers and most node YAML files. The generator logs also reported
different shortcut edges being severed. A filtered recursive diff showed
different node placement for many `Solvability.*` actions, not only cosmetic
property ordering.

A minimal set-order probe produced three different list orders for hash seeds
1, 2, and 3.

## Impact

- A saved numeric seed cannot reproduce a suspicious sample reliably.
- Parallel workers and different machines can create different datasets from the
  same manifest.
- BFS failure debugging cannot reconstruct the original causal graph from seed
  alone.
- Train/test experiments may drift across operating environments.
- Hash comparisons and caching cannot assume deterministic generation.

## Suggested fix

- Never feed unordered set/dict-derived collections into random selection.
- Canonically sort candidates by stable IDs before every RNG operation.
- Use an explicit per-generator `random.Random(seed)` instance rather than global
  module state.
- Pass that RNG through every component; do not independently reseed globals.
- Persist Python/generator versions and verify deterministic golden hashes across
  at least two `PYTHONHASHSEED` values and worker counts.
