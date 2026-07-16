# Hash-Seed Reproduction Evidence

Date: 2026-07-15

Config:

```text
data/scenarios/specialists/specialist_perimeter_to_domain_escalation_small_v1.yaml
```

Fixed generator seed: `4242`.

Process A: `PYTHONHASHSEED=1`.
Process B: `PYTHONHASHSEED=2`.

Observed:

- both exits were zero;
- both outputs contained 52 files;
- identifiers differed;
- node YAML differed throughout the scenario;
- reported shortcut-pruning edges differed;
- multiple `Solvability.*` vulnerabilities were placed on different nodes.

The temporary evidence directories are `/tmp/cbsgen_hashseed_1` and
`/tmp/cbsgen_hashseed_2`. They are diagnostic only and are not repository data.
