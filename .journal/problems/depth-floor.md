# Depth-Floor Acceptance Defects

Status: confirmed by source inspection; dynamic regression tests still needed.

## Silent bypass

`pipeline/phase2/dataset.py::_specialist_from_name` returns `None` when a custom
domain name lacks one of a small set of substrings. `_bfs_verify` then guards the
entire requested depth check with:

```python
if min_solution_depth is not None and specialist_type is not None:
```

Therefore a user can explicitly request `--min-solution-depth N`, receive no
error, and accept samples without measuring depth.

Suggested fix: require an explicit specialist argument or derive it from
validated config metadata. If the filter is requested and specialist resolution
fails, reject configuration before generation.

## Any-goal acceptance

`_min_depth_floor_ok` returns `True` as soon as one goal has a depth at least the
floor. In a multi-goal scenario, another goal can have a much shorter path.

Suggested fix: define the contract explicitly:

- first-goal curriculum: use the minimum depth over all valid goals and require
  that minimum to meet the floor;
- terminal-goal curriculum: select one stable terminal goal by ID/type and check
  only that goal;
- all-goal curriculum: require every required goal to be solvable and meet its
  configured floor.

Do not use existential “any goal” semantics unless that is intentionally exposed
in the CLI name and report.

## Artificial search ceiling

The verifier searches only through `floor + 8`. A scenario may be solvable with
a minimum depth above that cap, yet returns `None` and is rejected.

Suggested fix: distinguish `unsolvable` from `budget_exhausted`. Either use a
configured absolute cap with an inconclusive result, or first test for paths
shorter than the floor and separately prove solvability with a larger budget.

## Discovery semantics

The target is manually marked discovered before the shortest-path search. This
may be correct for fixed-pair specialist training, but it is not end-to-end
scenario depth. Reports must name it `fixed_pair_depth` and must not compare it
directly with whole-environment BFS steps.
