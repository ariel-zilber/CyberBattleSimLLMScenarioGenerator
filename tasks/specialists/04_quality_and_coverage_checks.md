# Task 04 - Quality and Coverage Checks

## Goal

Verify that the generated dataset is compatible with the proposal and with the specialist environment.

## Dataset Count Checks

Required totals:

- [ ] 250 small scenarios.
- [ ] 250 medium scenarios.
- [ ] 250 large scenarios.
- [ ] 250 xlarge scenarios.
- [ ] 800 train scenarios.
- [ ] 200 test scenarios.
- [ ] 1,000 total scenarios.

## Vocabulary Checks

Scan every generated scenario folder:

```text
scenarios/train/*/identifiers/identifiers.yaml
scenarios/test/*/identifiers/identifiers.yaml
scenarios/*/*/vulnerability_library/vulnerability_library.yaml
scenarios/*/*/nodes/*.yaml
```

Required:

- [ ] Every local vulnerability is in the global local vocabulary.
- [ ] Every remote vulnerability is in the global remote vocabulary.
- [ ] Every port is in the 20 global ports.
- [ ] Every property is in the 110 global properties.
- [ ] Every service ID is in the 93 global service IDs.
- [ ] No legacy IDs appear.

## Specialist Action Coverage

For each specialist, compute:

- how many of its 50 actions appear at least once in the dataset
- how many train scenarios contain at least one runtime-valid action for that specialist
- how many test scenarios contain at least one runtime-valid action for that specialist

Minimum acceptance:

- [ ] Each specialist has useful coverage in train and test.
- [ ] No specialist is starved of valid source-target pairs.
- [ ] No size group is dominated by only one specialist surface.

## Solvability and Difficulty

From `run_metrics.json` and aggregate BFS metrics:

- [ ] Scenarios are solvable often enough to be usable.
- [ ] Solve rate is not trivially 100% across all configs.
- [ ] Mean steps scale upward with size group.
- [ ] Credentials exist but are not so dense that connect actions become trivial.
- [ ] Multi-goal behavior is present in every size group.

## Done Criteria

- [ ] A final dataset quality report exists.
- [ ] The report lists counts, vocabulary violations, specialist action coverage, and solve metrics.
- [ ] All blocking vocabulary violations are fixed before training handoff.

## Pilot Quality Results

Completed on 2026-06-13 for the accepted low-credential pilot:

```text
output_specialists_final_pilot_lowcred/specialist_perimeter_to_domain_escalation_small_v1/
```

Generated artifact checks:

- `manifest.json`: exists.
- `identifiers/identifiers.yaml`: exists for all 5 generated scenarios.
- `vulnerability_library/vulnerability_library.yaml`: exists for all 5 generated scenarios.
- `run_metrics.json`: exists for all 5 generated scenarios.
- `phase2_eda.pdf`: exists.
- Per-scenario PDFs: 5/5.

Pilot counts:

| Split | Count |
|---|---:|
| Train | 4 |
| Test | 1 |
| Total | 5 |

Pilot runtime quality:

| Metric | Result |
|---|---:|
| BFS solve rate | 4/5 |
| LLM quality score | 9.7/10 |
| EDA solve rate | 0.8 |

Vocabulary scan:

```bash
rg -n --glob '*.yaml' --glob '*.json' --glob '*.txt' \
  "Remote\\.Probe|External\\.|Local\\.|S_Recon|BranchRouter|BranchSDWAN|\\bBGP\\b|port: Redis|protocol: Redis|Solvability\\.(ARP_Table_Dump|Nmap_Internal|CDP_Neighbors|CiscoASA_OSPF|Cilium_Critical|Container_NetScan|Nginx_LibCrypto_Critical|Outlook_NTLM\\b|Vault_GoStdlib|Vault_SecretsDump|WordPress_ImageMagick)|AWSHTTP" \
  output_specialists_final_pilot_lowcred/specialist_perimeter_to_domain_escalation_small_v1/scenarios
```

Result:

```text
No matches in YAML, JSON, or TXT artifacts.
```

Important caveat:

The generated scenario schema uses service IDs as node properties and sometimes stores service labels in fields named `port` inside generated credential/firewall structures. A naive global-vocabulary scan over every YAML scalar produces false positives. The final quality checker must be schema-aware instead of only key-name based.

Remaining full-dataset checks:

- Run the same vocabulary/legacy scan across the full 1,000 scenarios.
- Build a schema-aware generated-output validator for service-label-as-property and generated credential structures.
- Compute specialist action coverage for all five specialists.
- Verify the final split totals: 800 train, 200 test, 1,000 total.
- Verify size totals: 250 small, 250 medium, 250 large, 250 xlarge.
