# Static Audit Scope Versus Acceptance Claims

Status: confirmed by command construction and auditor defaults.

## Pipeline invocation

The pipeline invokes the post-generation auditor with only:

```text
<scenarios root> --config <config> --out <report>
```

It does not enable:

- `--full-yaml-parse`;
- `--strict`;
- `--require-run-metrics` (runtime evaluation has not happened yet).

The runner then prints “Post-generation static audit passed” and marks the
filesystem contract completed.

## What the default audit establishes

The default mode is useful for:

- expected directories and files;
- start/goal count sanity;
- manifest/split counts and IDs;
- vocabulary membership extracted from generated text;
- duplicate top-level properties/services/vulnerability IDs;
- dataset slot presence;
- coarse leakage and goal-density warnings.

It does not establish:

- that every node YAML fully parses;
- that warnings are absent;
- that runtime metrics exist or are current;
- dynamic reachability or exact BFS depth;
- privilege-precondition satisfiability;
- executable credential/discovery chains.

## Regex inspection risk

Unless full parsing is requested, node files are read as text and important fields
are extracted by regular expressions/line structure. A malformed or truncated
YAML file can potentially satisfy several textual checks. Runtime loading should
catch many such cases, but the Phase 2 runner currently conflates evaluator crash
with partial solvability, so the two weaknesses compound.

## Suggested fix

Name this early gate precisely, e.g. `filesystem_and_fast_text_audit`. At final
acceptance, rerun with full YAML parsing, required current runtime artifacts, and
the desired warning policy. Add a separate dynamic causal/depth gate rather than
implying static structure proves solvability.

## Preflight warning policy

Preflight is called without `--strict`; warnings are allowed. This may be a valid
policy, but the result should be reported as “passed with N warnings” rather than
an unqualified pass, especially when the user asks whether there were no notes or
errors.
