# Runtime Metric Semantics

Status: confirmed by metric construction order and formulas.

## Replay volatility is never used initially

`generate_llm_quality_prompt` constructs `run_metrics`, immediately calls
`calculate_difficulty_score`, and writes JSON. At that moment
`replay_verification` is the empty default. Replay runs afterward and replaces the
field, but difficulty is not recomputed.

Therefore the comment “Prefer replay verification” does not describe metrics
produced by this path. `stochastic_volatility` uses failure outcome counts from the
best planner episode instead.

## Per-action-type rates are not rates for those action types

The environment exposes outcome counts, not attempt counts partitioned by action
type. The metric infers type from outcome:

- `LateralMove` and `LeakedCredentials` count toward both remote and port success;
- every local/remote/port numerator is divided by the same all-attack denominator;
- there is no local-attempt, remote-attempt, or port-attempt denominator.

These values are proportions of all attacks producing selected outcomes, not
success rates conditional on action type. Using them in CSR or difficulty formulas
creates false quantitative precision.

## Episode count mislabeled

The recorded `episodes_required` receives the configured `max_episodes` after the
loop completes. It does not record the first or successful episode number, so a
scenario solved immediately and one solved only on the final retry report the same
value.

## Goal denominator aggregation

The code comment calls `num_goals_expected` the most-common denominator, but uses
`max`. A dataset containing mixed goal counts should be rejected or reported as a
distribution; selecting the maximum hides which count dominates.

## Critic prompt provenance

The LLM prompt says “3 agents × 3 episodes/scenario” literally. Both values are
environment-overridable constants. The actual values are not stored in the
aggregate input used to render that sentence.

## Suggested fix

- Compute derived metrics only after replay and all source fields are final.
- Record attempts and successes keyed by actual action kind at environment step
  time.
- Rename any outcome-share metrics honestly if retained.
- Persist configured episodes plus episodes executed, successful episodes, and
  first-success episode separately.
- Report goal-count distribution and fail required consistency mismatches.
- Build prompt provenance from recorded runtime parameters, never literals.
