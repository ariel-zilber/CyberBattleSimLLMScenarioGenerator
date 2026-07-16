# Pipeline Map

## Main flow

1. Phase 1 validates and optionally repairs the domain YAML.
2. Phase 2 generates scenario directories containing nodes, identifiers, and a
   vulnerability library.
3. Post-generation checks inspect the filesystem and vocabulary/coverage.
4. Dynamic evaluation loads CyberBattleSim environments and runs heuristic/BFS
   agents.
5. Quality evaluation combines static structure, dynamic results, and LLM
   judgment.
6. Failed scenario slots may be deleted, regenerated, and reevaluated.
7. Reports summarize the final artifacts and metrics.

## Validity layers

These layers must not be collapsed into one “pass” result:

- Schema validity: YAML and required fields load correctly.
- Catalog validity: identifiers and techniques belong to allowed vocabularies.
- Placement validity: required vulnerabilities can actually be placed.
- Static causal validity: credentials, discoveries, ownership, and prerequisites
  form a plausible chain.
- Dynamic solvability: CyberBattleSim can execute a route to the intended goal.
- Depth validity: the shortest dynamic route matches the intended curriculum.
- Dataset validity: all accepted samples satisfy the same contract and the split
  is complete and uncontaminated.
- Reporting validity: missing or skipped measurements remain unknown, not false.

## High-risk source areas

- `pipeline/cbsim/components/` — placement, credentials, attack spine, and
  solvability post-processing.
- `pipeline/phase1/config_checker.py` — pre-generation acceptance.
- `pipeline/phase2/dataset.py` — generation and BFS/depth acceptance.
- `pipeline/phase2/evaluator.py` — static reachability and action-depth metrics.
- `pipeline/run.py` — orchestration, replacement, phase verdicts, and reporting.
- `tools/post_generation_static_audit.py` and
  `tools/check_specialist_coverage.py` — post-generation gates.
