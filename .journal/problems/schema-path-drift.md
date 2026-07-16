# Schema Path Drift

Status: confirmed with source search and direct scoring probe.

## Start-node scoring defect

The static template-alignment dimension reads:

```text
config_settings.start_node
```

The generator, Phase 1 checker, and all current specialist configs use top-level:

```text
start_node
```

Repository scan found zero specialist configs with `config_settings:` and 20 with
top-level `start_node:`. A direct alignment-score probe on the perimeter small
config returned 9/10 with the sole failure:

```text
config_settings.start_node missing — breach entry undefined
```

The breach entry is actually defined and used by generation. This injects a false
negative into every current specialist template-alignment score and into the
overall seven-dimension score.

## Broader schema duplication

Field paths are manually embedded in many modules rather than accessed through a
validated canonical model. Confirmed drift includes:

- `config.goal_config` versus top-level `goal_config`;
- top-level `start_node` versus `config_settings.start_node`.

This permits a dangerous state where Phase 1 validates one field, runtime ignores
it, and reporting penalizes a third location.

## Suggested fix

- Define and version one typed configuration model.
- Parse once and pass normalized objects to generator, validators, evaluators,
  repair prompts, and reports.
- Reject legacy aliases or migrate them explicitly with a recorded warning.
- Add contract tests that load every production config and assert all consumers
  resolve identical values for critical paths.
