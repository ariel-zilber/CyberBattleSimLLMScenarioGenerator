# Goal Normalization Policy Defects

Status: confirmed by configuration and control-flow inspection.

## Wrong configuration level

The main generator obtains the target count from:

```text
config.goal_config.num_goals
```

and passes only that integer into `GoalNormalizer`. Inside the normalizer, all
other goal options are loaded from:

```text
goal_config
```

at the YAML root. Current specialist configs place `goal_config` inside `config`.
Therefore the requested count works, while these fields can silently be ignored:

- `selection_strategy`;
- `allow_promote` / `allow_demote`;
- `min_goal_value`;
- `shared_goal_name` / `shared_goal_names`;
- depth/diversity/value weights;
- decoy markers and credential-target limits.

This split behavior is especially dangerous because the visible goal count makes
the feature appear configured while its semantic policy is defaulted.

## Early return skips tagging

When the initial goal count already equals the target, `normalize()` returns
before shared goal properties are applied and before non-goal copies of those
properties are stripped. Goal-class observation/reward semantics therefore depend
on whether normalization happened to add/remove a node, not solely on config.

## Fail-open goal count and reachability

If promotion/demotion cannot achieve the requested count, the normalizer prints a
warning and returns. When a promoted goal cannot be made discoverable or reachable,
it remains marked `is_goal=True`. Neither condition blocks serialization.

The later attack-spine builder may report violations, but those are also
non-blocking, compounding the failure.

## Nondeterministic tie breaking

Goal selection converts candidates to a set and uses `max` without a stable
secondary key. Equal scores are resolved by hash-dependent set iteration, another
path through which `PYTHONHASHSEED` changes goal identity.

## Suggested fix

- Define one authoritative `config.goal_config` schema and pass the complete
  validated object.
- Apply goal tagging regardless of whether count changes.
- Make exact count and every required goal's dynamic reachability hard acceptance
  invariants.
- Roll back failed promotions.
- Use stable sorted candidate order and explicit deterministic tie-break keys.
- Persist final goal IDs, types, predicates, and selection rationale.
