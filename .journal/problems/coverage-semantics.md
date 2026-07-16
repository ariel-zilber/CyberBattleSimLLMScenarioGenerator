# Coverage Semantics

Status: confirmed by coverage-tool and runtime-metric implementations.

## Three different meanings currently share “coverage”

1. Config definition coverage: the slot is declared in YAML.
2. Instance placement coverage: the slot name appears as a vulnerability key in
   at least one generated node file.
3. Training/action coverage: the action is valid under reachable state, becomes
   unmasked, executes, changes state productively, and contributes observations.

The dataset audit establishes only (2), but its documentation calls the result a
“definitive guarantee.” For specialist training legitimacy, (3) is the important
contract. The previously observed depth-1 privilege bug demonstrates why presence
is insufficient: the System action existed but its prerequisite property was
missing at runtime.

## Runtime metric is still structural

`_compute_slot_coverage_metrics` reads node YAML and counts vulnerability keys per
node. Despite living in runtime metrics, it does not inspect action masks,
attempts, successes, productive transitions, or state visitation.

## Silent file omission

The function uses `yaml.safe_load` and catches all exceptions with `continue`.
Other code in this repository already documents that start-node YAML can contain
Python-specific tags rejected by `safe_load`. The shared coverage scanner was
changed to avoid exactly that disagreement, but runtime slot metrics still use the
old behavior.

Consequences:

- start-only discovery/credential actions may disappear from coverage;
- `unique_slots_seen` and entropy are understated;
- tail slots sent to the repair actor can be wrong;
- skipped-file counts are not reported, so the metric looks complete.

## Suggested coverage ladder

Report distinct names and denominators:

- `declared_slot_coverage`;
- `placed_slot_coverage`;
- `reachable_slot_coverage`;
- `unmasked_slot_coverage`;
- `attempted_slot_coverage`;
- `productive_slot_coverage`.

Every scan must report files expected, parsed, skipped, and reasons. A required
coverage gate should fail or become inconclusive when files are skipped.
