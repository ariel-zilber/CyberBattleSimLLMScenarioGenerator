# Task 02 - Enforce Global Vocabulary Before Generation

## Goal

Add a hard validation step that prevents the pipeline from generating scenarios from configs that do not match:

```text
/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml
```

This must happen before Phase 2 generation.

## Why

The specialist DRQN environment maps observations and actions through a fixed global vocabulary. If the generator emits identifiers outside that vocabulary, the scenario may still load in CyberBattleSim but will not match the proposal-defined specialist action spaces.

## Validator Requirements

The validator must fail on:

- local vulnerabilities not in `local_vulnerabilities`
- remote vulnerabilities not in `remote_vulnerabilities`
- ports not in `ports`
- service IDs not in `service_ids`
- properties not in `properties`
- removed roles such as `S_Recon`
- legacy pseudo-actions such as `Remote.Probe.*`, `External.*`, and `Local.*`

## Suggested Implementation

Add a script such as:

```text
tools/validate_specialist_vocabulary.py
```

or integrate the check into:

```text
pipeline/phase1/config_checker.py
```

Minimum CLI:

```bash
python tools/validate_specialist_vocabulary.py \
  --vocab /home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml \
  data/scenarios/specialists/*.yaml
```

## Pipeline Integration

The check should run before:

```bash
python pipeline/run.py data/scenarios/specialists/<config>.yaml
```

If the vocabulary check fails, the two-phase pipeline should not start.

## Done Criteria

- [x] Validator exists and is documented.
- [x] Validator passes on all 20 new specialist configs.
- [x] Validator fails on a known old `specialist_meta` config containing legacy IDs.
- [x] Pipeline invocation includes the validator or documents it as a mandatory preflight.
- [x] Validation output lists exact offending identifier, YAML file, and YAML path/context.

## Completion Notes

Completed on 2026-06-13.

Implemented:

```text
tools/validate_specialist_vocabulary.py
```

Positive validation:

```bash
python tools/validate_specialist_vocabulary.py data/scenarios/specialists/*.yaml
```

Result:

```text
Specialist vocabulary validation passed: 20 file(s)
```

Negative validation against an old template:

```bash
python tools/validate_specialist_vocabulary.py \
  data/scenarios/specialist_meta/meta_perimeter_to_domain_escalation_small_v1.yaml
```

Result:

```text
Specialist vocabulary validation failed: 51 issue(s)
```

The validator reports the YAML file, dotted YAML path, issue type, and offending value. It allows `breach_node` because the existing Phase 1 template validator requires it for the synthetic attacker start node, and it allows port labels in property slots because the current generator schema treats `identifiers.standard_ports` as valid property labels.

Also updated:

```text
pipeline/run.py
```

The runner now gives shell environment variables precedence over `.env`, so documented commands with `DATASET_ROOT`, `PHASE2_TRAIN_COUNT`, and `PHASE2_TEST_COUNT` work as expected.
