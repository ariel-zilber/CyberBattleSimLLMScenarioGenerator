# Evaluator Capacity Evidence

Main evaluator constants:

```text
maximum_node_count=100
maximum_total_credentials=1000
maximum_discoverable_credentials_per_action=5000
```

Current xlarge config bounds found across multiple specialist families:

```text
min_total_nodes: 700
max_total_nodes: 950
```

This is a direct contract contradiction; no runtime inference is needed to show
that the evaluator's declared maximum is below the generator's declared minimum.
