# Static Ownership Classification

Status: confirmed semantic defect.

`pipeline/phase2/evaluator.py` defines `_REMOTE_OWNING_OUTCOMES` to include:

- `lateral_move`
- `privilege_escalation`
- `leaked_credentials`
- `leaked_nodes_id`
- `customer_data`

The latter three are information/data effects, not proof that the attacked node
became owned. The set is used by the basic attack graph, owned-node closure,
enriched graph, and new static A* planner. Consequently one classification error
can affect several reported depths and solvability claims.

Impact:

- information-only remote vulnerabilities become ownership edges;
- goal nodes can be counted as captured without a genuine ownership transition;
- static action counts can understate the real executable path;
- apparent agreement between several static metrics is not independent evidence,
  because all reuse the same faulty set.

Suggested fix:

1. Separate outcome effects into explicit predicates such as
   `owns_target`, `raises_privilege`, `adds_credentials`, `discovers_nodes`, and
   `captures_data`.
2. Model remote execution success separately from ownership outcome according to
   CyberBattleSim's actual transition semantics.
3. Add table-driven tests for every serialized outcome type.
4. Cross-check static plans by replaying each proposed action sequence in a real
   environment; label non-replayed plans optimistic and non-authoritative.

## Privilege state is absent

The A* state contains owned nodes, discovered nodes, credentials, executed local
actions, and captured goal labels. It contains no per-node privilege level or
privilege property. Local actions are retained only when they add nodes or
credentials, so a pure Admin/System escalation is discarded.

This means the planner may report a goal captured immediately after foothold even
when the actual curriculum requires Admin or System. It is therefore unsuitable
as a validator for the target-privilege work until privilege is part of both state
and goal predicates.

Suggested fix: model privilege monotonically per owned node, apply local escalation
effects, evaluate vulnerability preconditions against the evolving state, and
define capture as satisfying the configured goal predicate—not merely owning a
node ID.
