# Opinion: Best Solution For The Depth-Collapse Bug

## Verdict

The best solution is to add a final, isolated de-shortcut pruning pass after all solvability and coverage guarantees have run.

Do not modify `find_reachable_targets()` right now.

## Why

The depth-collapse bug is real: generated scenarios that should require multi-hop attack chains were frequently collapsing to BFS depth 2:

```text
start -> entry -> goal
```

That is scientifically bad because the scenario narrative claims multi-step attack depth, while the actual generated graph gives the agent a trivial shortcut.

However, the obvious source-level fix was already tested and failed operationally. Restricting the fallback pool in `find_reachable_targets()` restored depth diversity, but dynamic solvability dropped from about 100% to about 40% on the tested sample. That means the unrestricted fallback is ugly, but currently load-bearing.

So the right move is not to rewrite the fallback logic yet. The right move is to preserve the existing solvability machinery and remove only shortcut edges that are proven redundant.

## Recommended Invariant

Use this rule:

```text
A direct shortcut to a goal may remain only if it is necessary for reachability.
If an alternate path exists, remove the shortcut.
```

Do not use this rule:

```text
Goal nodes must never appear in fallback target pools.
```

The second rule is conceptually cleaner, but the evidence says it is unsafe in the current pipeline.

## Implementation Recommendation

Add a method such as `_prune_shortcut_edges()` to:

```text
pipeline/cbsim/components/solvability_post_processor.py
```

In this local checkout, the code is monolithic. The refactored paths named in the handoff prompt do not exist here:

```text
pipeline/cbsim/components/solvability/post_processor/core.py
pipeline/cbsim/components/solvability/post_processor/goal_reachable.py
```

Also, in this checkout `ensure_solvability()` runs `_ensure_full_coverage()` after `_ensure_goal_reachable()`. Therefore the pruning pass should run last:

```text
_ensure_goal_reachable()
_ensure_full_coverage()
_prune_shortcut_edges()
```

Running the pass earlier is risky because the coverage sweep could add new shortcut edges after pruning.

## Pruning Logic

For each goal node:

1. Build the attack graph using the same semantics as `pipeline/phase2/evaluator.py`.
2. Compute BFS depth from `start` to the goal.
3. If the goal is shallow, identify direct shortcut edges into the goal.
4. Consider only edges caused by:
   - `LeakedCredentials` entries targeting the goal
   - `LeakedNodesId` entries listing the goal
5. Temporarily remove one candidate edge.
6. Recompute reachability.
7. If the goal remains reachable, remove the edge for real.
8. If the goal becomes unreachable, keep the edge and log it as required for solvability.

This pass should never manufacture new paths and should never remove the only path.

## Verification Requirement

Static BFS is necessary but not sufficient.

The WIP branch failure likely involved firewall, credential, or precondition mismatch. A graph can say a goal is reachable while dynamic execution still fails. Therefore verification must include both:

```text
static BFS depth distribution
dynamic test_env_integration.py solvability
```

If dynamic solvability regresses, the pruning pass is wrong or the static graph abstraction is too weak for this decision.

## What Not To Do

Do not change `find_reachable_targets()` as part of this pass.

Do not modify the constraint processor fallback pool.

Do not rely on prompt text to solve this.

Do not prune shortcuts unconditionally.

Do not treat a better BFS depth distribution as success if dynamic solvability regresses.

## Thesis Framing

The defensible thesis framing is:

```text
We preserve the generator's solvability guarantees, then run a conservative final pass that removes only redundant goal shortcuts. This restores attack-depth diversity without sacrificing dynamic solvability.
```

That is stronger than claiming the generator never creates shortcuts. The important claim is that the accepted final scenarios do not contain unnecessary shortcuts that collapse the intended attack depth.

## Final Opinion

The de-shortcut pruning pass is the best solution for the current state of the project.

It is not the purest architectural fix, but it is the right engineering fix: narrow blast radius, measurable effect, auditable logs, and solvability preserved as the top priority.
