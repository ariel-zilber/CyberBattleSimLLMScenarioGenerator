# Dynamic Evaluator Capacity and Acceptance

Status: confirmed by evaluator construction and current xlarge configs.

## Withdrawn node-capacity mismatch

The evaluator constructs every `ImprovedCyberBattleEnv` with:

```text
maximum_node_count = 100
```

Current xlarge specialist configs specify:

```text
min_total_nodes = 700
max_total_nodes = 950
```

Adversarial verification against a real 778-node xlarge artifact showed that the
improved environment constructed and reset successfully with
`maximum_node_count=100`. The current improved observation space is explicitly
neighborhood-size invariant (`neighborhood_size=30` in the evaluator), and the
legacy full-network `validate_environment()` bound is not applied on this path.

The earlier claim that xlarge “cannot be faithfully represented” was therefore
unsupported and is withdrawn. The numeric argument remains misleading/dead
configuration unless another consumer uses it, but that is not a P0 data defect.

No node-capacity fix is recommended without evidence of a consumer that actually
uses this bound on the improved path.

## Credential-bound mismatch (artifact reproduced)

The tested 778-node xlarge artifact contains 1,554 unique accepted/leaked
credential IDs. Its largest single vulnerability outcome contains 1,552
credentials.

The evaluator constructs an observation bound of 1,000 while allowing 5,000
credentials discovered per action. The improved environment's cache is not
truncated at 1,000; instead, `number_discovered_credentials` can exceed its Gym
Box high. Separately, statistics divide cache length by the loaded model's
`maximum_total_credentials`, which was 100 for this artifact, permitting wildly
invalid percentages.

The previous statement that credentials could be “lost” is not supported and is
removed. Confirmed effects are inconsistent bounds/denominators; actual policy or
agent failure after receiving 1,552 credentials still needs an executed action.

## Replay is diagnostic, not a gate

The planner marks `any_solved=True` if any planning episode captures all goals.
It then replays the chosen action sequence five times. Even if replay succeeds
zero times, `any_solved` is unchanged and the scenario increments dataset
`success_count`.

This contradicts the printed claim that replay proves transfer through the normal
agent interface. If replay is required evidence of executable legitimacy, its
failure must yield failed or inconclusive acceptance. If it is only a stochastic
robustness metric, reports must not call the scenario unconditionally verified.

## Empty input passes

Scenario discovery recursively searches for directories named `nodes`. If none
are found, both `success_count` and total count are zero, so equality holds and
the process exits zero.

## Suggested fix

- Size node and credential limits from parsed scenario counts plus validated
  headroom, and record truncation/overflow explicitly.
- Test every supported stratum, especially xlarge, under the same evaluator path.
- Define replay acceptance policy and enforce it consistently.
- Treat zero discovered scenarios as a hard input error.
- Emit an evaluation manifest accounting for every expected scenario ID.
