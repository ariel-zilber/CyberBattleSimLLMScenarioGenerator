# Object-generator hash and provenance defects

Confirmed 2026-07-15 using identical input under two Python hash seeds.

## P1: semantic spec hashing is hash-seed dependent

`ScenarioSpec.to_dict()` converts sets and frozensets to lists without sorting.
Lark template services are also inserted by iterating a frozenset. The compiler
then hashes a YAML serialization of this non-canonical structure.

Reproduction using the preferred Lark example:

```text
PYTHONHASHSEED=1 03203f134ec6c1d31f3ffa537f4e877849a64ec563ef593894e6f0c4561f4bf8
PYTHONHASHSEED=2 831c1b91f19a63e5852659326c4f6fb057db87cf308c0170acabea8fc0056a82
```

Diffs showed reordered node properties, services, and transition prerequisites.

Impact: the same semantic scenario has different identity across processes and
machines, defeating deduplication, cache keys, and reproducibility claims.

Recommended fix: canonicalize unordered collections with stable, documented
sort keys before serialization; add a subprocess regression across several
`PYTHONHASHSEED` values and require byte-identical output and digest.

## P1: `scenario.sha256` is not an artifact integrity hash

The digest covers `yaml.safe_dump(spec.to_dict())`, not the emitted `nodes/*.yaml`
or reports. A stale, modified, missing, or compiler-version-dependent node file
does not update the digest if the source spec is unchanged.

Impact: consumers can mistake the file for verification of the executable
scenario even though it proves only a non-canonical source-model serialization.
This is especially unsafe alongside in-place recompilation that retains stale
nodes.

Recommended fix: distinguish `spec_digest` from an artifact manifest. After all
files are written, hash canonical relative paths and bytes for every runtime
input, record compiler/schema versions, and verify the manifest before loading.
