# Provenance and Resume Safety

Status: confirmed by source inspection.

## What is currently durable

Scenario directories contain node YAML, identifiers, vulnerability library, and
eventually runtime metrics/trajectory files. The batch generator computes seeds
from split/slot/retry offsets, but the single-scenario writer does not emit a
provenance record.

## Unsafe resume predicate

The resume helper reads `run_metrics.json` and returns true based on
`is_solved`. It does not bind that verdict to:

- the exact scenario content;
- the config content used to generate it;
- the seed and generator version;
- the global vocabulary version;
- the BFS/evaluator implementation;
- the active acceptance parameters, including minimum depth.

Therefore changing code, config, vocabulary, or validation thresholds can leave
old slots falsely accepted during `--resume`.

## Suggested contract

Write a small immutable provenance JSON for every generated slot containing:

- seed and retry number;
- SHA-256 of input config and vocabulary;
- generator commit/version and schema version;
- hashes of generated node/identifier/vulnerability files;
- requested acceptance policy.

Write validation metadata alongside `run_metrics.json` containing evaluator
version/hash, measured BFS result, exact/inconclusive status, and input content
hash. Resume only when both provenance and validation fingerprints match the
current requested contract. Otherwise revalidate or regenerate.

This is especially important for debug training: a manifest should make every
accepted episode/scenario reproducible without reconstructing seed arithmetic
from logs.
