# Dataset Manifest Accuracy

Status: confirmed by allocation and metadata source inspection.

## Deleted config reference

For each stratum, the builder writes a temporary YAML containing stratum-specific
node bounds. Per-stratum `is_trained.json` records that temporary pathname as
`config_file`. Immediately after train/test generation, the temporary file is
deleted.

The metadata therefore references an artifact that no longer exists, preventing
inspection of the exact effective config. Recording the original config path is
also insufficient because scaling and stratum bounds were applied in memory.

Suggested fix: store the effective config content or its canonical hash in durable
dataset provenance before deleting temporary files.

## Count over-allocation

For each config:

```text
per_stratum = ceil(config_count / n_strata)
```

That same value is assigned to every stratum. If the requested count is not
divisible by the number of strata, the actual target is
`n_strata * ceil(count/n_strata)`, which exceeds `count_target`.

Suggested fix: use an exact integer distribution across strata, as already done
for counts across configs. Record requested, allocated, accepted, and on-disk
counts separately.

## Incorrect scaled bounds

When `--scale` is active, generation uses scaled stratum bounds. The manifest's
`strata.*.bounds` is nevertheless populated from `DEFAULT_STRATA`, not the scaled
mapping. Downstream consumers cannot know the actual node range requested.

Suggested fix: serialize the effective bounds and scale factor, plus observed
node-count distribution after acceptance.
