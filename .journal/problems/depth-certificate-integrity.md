# Depth Certificate Integrity

Status: confirmed by source trace and live generation output.

## Violations are non-blocking and non-durable

`CertifiedAttackSpineBuilder.apply()` returns per-goal certificates and an
`all_certified` flag. The generator prints `OK` or `VIOLATION`, then continues.
The certificate is not written into the scenario directory, manifest, or final
metrics, and no exception or rejected-generation status follows a violation.

The hash-seed reproduction generated successfully while printing:

```text
[VIOLATION] goal=InternetEdge_WAFs_1 target_depth=6 verified_depth=5
```

Thus “certified attack spine” is currently diagnostic rather than an acceptance
certificate.

## Certification occurs before final mutation

Immediately after certification, `ensure_full_coverage` force-places every
missing slot. Depending on category it can add:

- `LeakedNodesId` exposing arbitrary early nodes;
- `LeakedCredentials`;
- `LateralMove` remote outcomes;
- System privilege escalation.

No shortest-path or dynamic BFS check runs after that sweep inside generation.
The final serialized scenario can therefore contain shortcuts or state changes
that were absent when depth was measured.

## Oracle is not executable CBS depth

The certificate's adjacency graph treats credential/node leaks as abstract edges.
Its ownership fixed point executes all local actions on owned nodes without
checking their preconditions and treats several remote information outcomes as
ownership. It tracks no privilege state.

This cannot prove the specialist action sequence is unmasked and executable in
the actual environment, particularly for Admin/System curricula.

## Remote coverage placement mismatch

The sweep restricts candidate nodes to `_compute_owned_live`, then places remote
vulnerabilities on those nodes. Reachability/ownership of the node does not prove
that a remote exploit targeting it is a useful training action; the target may
already be owned, making the action redundant or masked depending on environment
rules.

## Suggested fix

1. Perform every graph-mutating placement before final certification.
2. Run authoritative dynamic shortest-path validation on the exact serialized
   scenario artifact.
3. Persist certificate, scenario hash, target predicate, solver version, depth,
   exhaustion state, and replayable action path.
4. Reject/resample on any violation or inconclusive search.
5. Measure coverage action usability in environment state, not node ownership.
