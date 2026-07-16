# Training-run audit: full s_lateral and s_windows

Date: 2026-07-16

Read-only sources:

- `/home/ariel/Documents/thesis/CyberBattleSim/runs/full_s_lateral_20260711/seed_42/logs`
- `/home/ariel/Documents/thesis/CyberBattleSim/runs/full_s_windows_20260711/seed_42/logs`

The Windows run was still growing during inspection; lateral was complete at
episode 10,000. Values for Windows after roughly episode 8,400 are a live
snapshot.

## Confirmed logging/resume anomaly in both runs

Both CSVs begin at episode 356 and contain a single backward transition:

```text
... 605, 606, 607, 501, 502, 503 ...
```

Episodes 501–607 occur twice (107 duplicated episode IDs). The duplicate rows are
identical in scenario, state seed, reward and outcome. Both runs also contain
`state_stop_000355.pt`, a checkpoint at 500, and three TensorBoard event files.
The evidence is consistent with stop/resume from checkpoint 500 after an earlier
attempt reached episode 607.

Consequences:

- naive CSV aggregates double-count 107 episodes;
- chronological plots have a rewind;
- the repeated block can be mistaken for independent training evidence;
- whether replayed episodes also caused repeated Q updates requires checkpoint
  execution-history evidence, not just the CSV.

## BFS telemetry discontinuity

BFS depth fields are populated for only 252 early rows, ending at the pre-resume
episode 607 segment. After resume, `bfs_depth=-1` throughout the main training
run. Every evaluation checkpoint reports:

```text
bfs_evaluated_pairs = 0
bfs_solvable_pair_rate = null
bfs_exact_depth_rate = null
bfs_inconclusive_rate = null
```

Therefore these runs cannot substantiate BFS solvability/depth quality over the
full training or held-out evaluation populations.

## s_lateral: meaningful learning with a large generalization gap

Deduplicated training behavior becomes nearly perfect shortly after episode
1,000:

```text
episodes 2000–3999: target System success 99.7%
episodes 8000–10000: target System success 99.9%
late training invalid-action rate: about 17–20%
```

Held-out checkpoints do not transfer:

```text
best held-out System success: 36% (episode 4000)
final held-out System success: 28%
final invalid-action rate: 91.7%
final Q overestimation bias: 65.89
final productive-action margin: -0.90
final productive-action rank: 18.32
```

Training and evaluation paths do not overlap. The evaluation set is drawn from
the declared test assignment, so this gap is not explained by direct path-level
train leakage. Evaluation has a somewhat larger hard-pair fraction, but not
enough evidence to explain near-perfect training versus 28% evaluation.

The final 28% held-out success is approximately seven times its 4% unmasked
random baseline. The model has therefore learned meaningful behavior. The large
training/evaluation gap and high invalid-action rate show weaker generalization
than Windows, but do **not** prove the model is bad or the data corrupt.

Evaluation intentionally uses unmasked greedy action selection, matching the
training objective that the policy must learn action validity without a mask.
High invalid-action rate is thus a genuine performance limitation, not evidence
that the evaluator is accidentally bypassing its intended protocol.

## s_windows: useful learning followed by degradation

Windows learns more slowly and transfers much better:

```text
episode 2000 held-out System success: 80%
episode 4000 held-out System success: 96%
episode 5000 held-out System success: 92%
episode 8000 held-out System success: 90%
```

But later evaluation quality degrades:

```text
invalid-action rate: 40.9% at episode 4000 -> 62.8% at episode 8000
productive-action rank: 7.42 at episode 4000 -> 13.94 at episode 8000
productive-action margin: +0.19 at episode 4000 -> -0.01 at episode 8000
```

Verdict: Windows is a strong model relative to its 8–12% random baseline. On the
recorded fixed manifest, checkpoint 4,000 has the best headline success and
validity metrics; later checkpoints remain good but are not uniformly better.

## Additional interpretation cautions

- `target_owned=True` is foothold ownership, not necessarily target privilege;
  it may coexist with `target_reached_system=False` legitimately.
- Despite its name, `target_reached_system` succeeds at the pair's configured
  target maximum, commonly Admin represented as privilege 2 in these logs.
- About 12.5% of lateral successes and 14.2% of Windows successes take one step.
  Some are legitimate already-owned local privilege tasks, but they should be
  analyzed separately from multistep chains rather than pooled into one success
  rate.
- `attempted_episodes` and `valid_episodes` mirror the global episode number in
  each row, so they are not per-pair attempt counts.

## Recommended research actions

1. Deduplicate CSV rows by episode, retaining the last resumed occurrence, and
   preserve restart boundaries separately.
2. Describe lateral as above-baseline but weaker on held-out generalization;
   diagnose invalid reasons before deciding whether 28% meets the deployment
   threshold.
3. Treat Windows episode 4,000 as the current best candidate and validate it on a
   larger fixed evaluation manifest before preferring later checkpoints.
4. Re-enable identical BFS telemetry across resume and evaluation, or remove BFS
   claims from this run.
5. Report one-step pre-owned/local tasks separately from multistep ownership and
   escalation tasks.
