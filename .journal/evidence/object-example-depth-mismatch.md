# Object example path mismatch (numeric-depth claim corrected)

Date: 2026-07-15

Input: `examples/object_generator/perimeter_to_domain.larkdsl`

CLI result:

```text
valid true
solved true
minimum_depth 9
required_minimum_depth 9
bypassable_mandatory []
```

Compiled escalation gates:

```text
DomainAdminEscalation precondition DomainController|Windows outcome level 2
SystemEscalation      precondition DomainController|Windows outcome level 3
```

The DSL declares System escalation `from ADMIN to SYSTEM`, but compilation omits
the Admin requirement. The condition solver's proof derives System directly from
`owned(dc, USER)` and never uses `DomainAdminEscalation`; it reports causal depth
7 because independent discoveries/leaks are represented as parallel dependency
levels.

## Improved-runtime adapter verification

The emitted object scenario is not natively loadable because identifiers and the
vulnerability library are absent. A temporary adapter constructed the identifier
vocabulary from the compiled nodes and loaded those nodes into the connected
improved actuator. The executed sequence showed:

```text
after credential Connect: dc privilege USER
execute SystemEscalation without DomainAdminEscalation
after action: dc privilege SYSTEM
```

However, the total executed sequence was 9 actions, not 8. The compiler turns
the BFS's initially discovered gateway into an executable `Initial.Discovery`
action. That extra action offsets the skipped Admin escalation in this fixture.
Therefore this evidence confirms a path/gate mismatch, not a numeric minimum
depth mismatch for the preferred example.

The temporary compiled scenario and adapter state were removed after the probe.
