# Object-generator compiler safety and identity failures

Confirmed 2026-07-15 by source inspection and isolated `/tmp` reproductions.
No project implementation or dataset files were changed.

## P0: legacy DSL names can escape the requested output directory

The restricted AST parser accepts arbitrary string literals for scenario and
node IDs. `write_compiled_scenario()` uses `output_dir / spec.name`, and node
files use `nodes_dir / f"{node_id}.yaml"`, without rejecting separators,
absolute paths, `.` or `..` components.

Reproduction: node ID `../escaped` passed validation and wrote
`safe/escaped.yaml` outside `safe/nodes/`. Absolute IDs or scenario names have a
still broader write scope under ordinary `pathlib` joining. The preferred Lark
grammar restricts `NAME`, but the CLI deliberately keeps `.dsl` support.

Impact: model-controlled or user-supplied legacy DSL can overwrite files outside
the selected scenario directory with generated YAML.

Recommended fix: define one strict identifier grammar for both parsers; reject
absolute paths, separators, dot components, and names outside the allowed
character set. Resolve every destination and assert it remains beneath the
resolved output root before writing.

## P0: recompilation leaves stale node YAML

The compiler creates `nodes/` with `exist_ok=True` and overwrites files whose IDs
still exist, but never removes or rejects old YAML files.

Reproduction: compiling scenario `same` with nodes `old, goal`, then recompiling
`same` with only `goal`, left `old.yaml` alongside `goal.yaml` and `start.yaml`.

Impact: the runtime and post-static tools consume a hybrid scenario containing
nodes absent from the new spec and hash. This can alter reachability, coverage,
metrics, and training data.

Recommended fix: compile into a new temporary directory, verify it, then publish
atomically; or require a nonexistent destination. Never update a scenario node
directory in place without a complete stale-file reconciliation.

## P0: the reserved `start` node can be declared and is silently replaced

Validation includes `start` in the known-ID set but does not prohibit it in
`spec.nodes`. The compiler first compiles user nodes and then assigns the
synthetic attacker to `compiled["start"]`, overwriting the declaration.

Reproduction: a declared Linux `start` with custom properties and SSH service
validated and BFS-solved. The compiled node instead had image `attacker`, only
`breach_node`, and no services.

Impact: BFS and validator reason over one node definition while runtime receives
another, invalidating prerequisites, services, topology, and depth.

Recommended fix: reserve `start` at parse/validation time and reject any node
declaration using it. Centralize reserved identifiers and test every parser.

## P1: per-zone `/24` allocation has no capacity validation

Each zone is assigned a `/24`, and addresses start at offset 10 with an
unbounded counter. Validation imposes no node-per-zone limit and the compiler
does not check host/broadcast membership.

Reproduction: in one zone, `a245` received `10.1.0.255` (broadcast), and `a246`
received `10.1.1.0` while its declared subnet remained `10.1.0.0/24`.

Impact: sufficiently populated specs compile invalid or misrepresented network
interfaces; continued overflow can eventually collide with other assigned
zone ranges.

Recommended fix: allocate from `network.hosts()` with explicit exhaustion, size
subnets from validated zone cardinality, and enforce global address uniqueness
plus address-in-subnet checks before writing.

## P1: duplicate node declarations collapse before validation

Both parsers construct a dictionary keyed by node ID. A repeated declaration
overwrites the earlier node before `validate()` sees the spec.

Reproduction: a Lark scenario declared `x` first as `linux_server` and then as
`database`; parsing retained only `database`, and validation returned valid.

Impact: LLM output with accidental duplicates silently changes templates,
properties, services, and transition semantics rather than producing repair
feedback.

Recommended fix: detect duplicates while transforming/parsing, before dictionary
construction, and return a source-positioned parse/validation error.
