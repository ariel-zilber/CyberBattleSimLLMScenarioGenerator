# Task 05 - Training Handoff

## Goal

Prepare the generated specialist-style meta dataset for the CyberBattleSim specialist training code.

## Required Inputs

Training code expects:

- fixed global vocabulary
- specialist action maps
- scenario train/test pool
- scenario loader compatible with generated scenario folders
- valid fixed source-target pair sampling
- randomized episode state

## Handoff Artifacts

Create or document:

- [ ] Final output root path.
- [ ] Train scenario manifest with 800 scenario folder paths.
- [ ] Test scenario manifest with 200 scenario folder paths.
- [ ] Global vocabulary path.
- [ ] Per-specialist coverage summary.
- [ ] Known limitations or excluded configs.

## Training Compatibility Checks

Before training:

- [ ] `GlobalVocabulary.from_yaml()` loads the vocabulary.
- [ ] `SPECIALIST_ACTION_MAPS` still matches proposal counts.
- [ ] Generated scenario folders load through the existing CyberBattleSim folder loader.
- [ ] `SpecialistGymEnv` can reset on at least one generated scenario.
- [ ] `sample_valid_pair()` returns valid pairs for each specialist on pilot scenarios.
- [ ] One random episode can run for each specialist without shape/action errors.

## Important Risk

Check that specialist pair sampling and action translation compare vulnerabilities by vocabulary ID, not by incompatible scenario-local index. If index spaces differ, generated scenarios may be valid but specialist actions will map incorrectly.

## Done Criteria

- [ ] One smoke-training run starts successfully on a small generated scenario.
- [ ] Observations have shape `(832,)`.
- [ ] Specialist action space is exactly `Discrete(50)`.
- [ ] Episode terminates on target ownership or `T_max`.
- [ ] Metrics are written for a short smoke run.

## Current Status

Updated on 2026-06-13.

Prepared inputs:

- Global vocabulary path:

```text
/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml
```

- Source config path:

```text
/home/ariel/Documents/thesis/CyberBattleSimLLMScenarioGenerator/data/scenarios/specialists/
```

- Accepted pilot output root:

```text
/home/ariel/Documents/thesis/CyberBattleSimLLMScenarioGenerator/output_specialists_final_pilot_lowcred/
```

Pilot scenario folders available for training smoke tests:

```text
output_specialists_final_pilot_lowcred/specialist_perimeter_to_domain_escalation_small_v1/scenarios/train/
output_specialists_final_pilot_lowcred/specialist_perimeter_to_domain_escalation_small_v1/scenarios/test/
```

Verified so far:

- 5 pilot scenario folders generated.
- Every pilot scenario has `run_metrics.json`.
- BFS solved 4/5 pilot scenarios.
- The accepted pilot still uses the fixed global vocabulary source configs.

Not yet verified:

- `GlobalVocabulary.from_yaml()` load smoke test.
- `SPECIALIST_ACTION_MAPS` count smoke test.
- `SpecialistGymEnv.reset()` on generated scenario folders.
- `sample_valid_pair()` against generated scenario folders for each specialist.
- Observation shape `(832,)`.
- Specialist action space `Discrete(50)`.
- One short smoke-training run.

Known risk still open:

`pair_sampler.py` should be checked before training. The training environment must compare vulnerabilities by global vocabulary ID, not by scenario-local index. If scenario-local indexes are compared directly with global specialist action indexes, generated scenarios can be valid while specialist actions map incorrectly.
