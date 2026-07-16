# Object Generator MVP

This package is an isolated alternative to the mutation-heavy scenario pipeline.
Its preferred input is a compact Lark DSL with static node templates, specialist
profiles, firewall policies, and path contracts. The earlier restricted
`Scenario(...)` AST syntax remains available for comparison and is never executed.

## Flow

```text
LLM Scenario DSL
  -> restricted parser
  -> semantic validation
  -> privilege-aware minimum-path BFS
  -> deterministic nodes/*.yaml compiler
  -> human attack-chain and validation reports
```

The current generator remains unchanged. This MVP supports discovery, probing,
remote exploitation, credential leaks, credential connections, and local
privilege escalation.

Compilation also derives `identifiers/identifiers.yaml` from the final node
artifacts and emits the required empty global `vulnerability_library` file, so
the output has the directory contract expected by CyberBattleSim's dynamic
loader. No CyberBattleSim source files are modified.

## Run

Install the parser dependency in the active environment:

```bash
python -m pip install "lark>=1.1,<2"
```

```bash
python -m pipeline.object_generator.cli \
  examples/object_generator/perimeter_to_domain.larkdsl \
  --output output_object_generator
```

To load the compiled artifact in the existing simulator and replay the exact
symbolic minimum path:

```bash
python -m pipeline.object_generator.cli \
  examples/object_generator/perimeter_to_domain.larkdsl \
  --output output_object_generator \
  --verify-runtime \
  --cyberbattle-root /path/to/CyberBattleSim
```

Runtime verification imports the simulator as a dependency and never edits its
source or configuration. Declared initial visibility is replayed as a bootstrap
action and reported separately from attack-chain depth.

## Immutable base expansion

An expansion adds typed nodes, transitions, firewall policies, and a new goal to
a deep copy of a validated base scenario:

```bash
python -m pipeline.object_generator.cli \
  --base examples/object_generator/perimeter_to_domain.larkdsl \
  --expansion examples/object_generator/perimeter_to_database.expansion.larkdsl \
  --output output_object_generator \
  --verify-runtime \
  --cyberbattle-root /path/to/CyberBattleSim
```

Expansion refuses node replacement, validates the merged model, and records the
unchanged base fingerprint plus addition counts in `expansion_validation.json`.
The base source is never written or modified.

The command refuses compilation when the scenario is invalid, unsolvable, or
has a shortest path below `Goal.minimum_depth`.

## LLM Integration

`lark_generator.generate_lark_with_model()` accepts a provider callback. This keeps
Anthropic credentials and SDK details outside the semantic core:

```python
result = generate_lark_with_model(request, lambda prompt: claude(prompt))
```

Invalid output is returned to the model as compact validation feedback for the
next attempt.

To generate directly through the installed Claude Code CLI:

```bash
python -m pipeline.object_generator.cli \
  --request "Create a depth 7 perimeter-to-domain scenario" \
  --claude-model sonnet \
  --claude-timeout 120 \
  --output output_object_generator
```

Claude receives the complete compact language reference and a valid example.
Its output is parsed, semantically validated, checked for shortcuts, and retried
up to three times before any files are compiled. The provider disables MCP and
session persistence for this bounded generation call.

When runtime verification is requested, `runtime_validation.json` is always
written. A failed replay returns exit status 4 and leaves an explicit rejected
record; only a file with `"passed": true` is runtime-accepted.

## Current Boundary

The compiled YAML matches the existing evaluator's node-file shape. Exact
environment action replay is not part of this MVP yet; it should be added only
after comparing the object BFS with CyberBattleSim behavior across a small
scenario corpus. The existing evaluator is node-reachability based and does not
count local privilege transitions, so its graph depth is not the object model's
System-level action depth.
