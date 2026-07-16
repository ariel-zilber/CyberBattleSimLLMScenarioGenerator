# Firewall Edge Audit

Date: 2026-07-15

Artifact:

```text
/tmp/cbsgen_hashseed_1
```

The read-only probe parsed node YAML, extracted cross-node leaked credential
tuples, resolved source/target subnets, and matched ALLOW rules by exact port and
remote subnet.

```text
cross_node_edges 272
incomplete 146
rate 0.537
missing_out 92
missing_in 93
```

This probe establishes structural firewall mismatch. Dynamic replay is still the
authoritative evidence for whether each specific edge is executable under full
environment semantics.

## Runtime-semantics correction (Pass 21)

CyberBattleSim's current `__is_passing_firewall_rules` implementation ignores
the supplied peer address/subnet and returns on the first rule whose port
matches. Re-evaluating the same 272 non-start edges under that exact behavior:

```text
runtime-incomplete 43
runtime-incomplete-rate 0.158
runtime-missing-out 42
runtime-missing-in 2
exact-policy-missing-but-runtime-allowed 103
```

Thus 53.7% remains the exact serialized port+subnet policy violation rate, not
the dynamic blocking rate. The dynamic blocking rate predicted by the actual
actuator is 15.8%; 103 policy-incomplete edges become over-permitted because the
runtime ignores subnet scope.
