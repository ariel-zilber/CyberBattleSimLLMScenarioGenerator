# Prioritized Problems

## Confirmed

1. **P1 — Depth-floor filtering can be silently disabled.**
   `--min-solution-depth` is only enforced when a specialist is inferred from a
   scenario name. Ambiguous names yield `None`, and the sample proceeds without
   the requested check.
2. **P1 — Static reachability treats information outcomes as ownership.**
   Remote `leaked_credentials`, `leaked_nodes_id`, and `customer_data` outcomes
   are classified as owning the target, causing optimistic paths and depths.
3. **P1 — A multi-goal sample passes the depth floor when any one goal passes.**
   Shortcuts to other goals are ignored, so the accepted scenario need not obey
   the advertised minimum-depth contract globally.
4. **P2 — The depth filter's search cap can reject valid deep scenarios.**
   A scenario whose true minimum is greater than `floor + 8` is reported as
   unsolvable for acceptance purposes.
5. **P2 — Depth-floor mode does not inherit retry-forever behavior.**
   The CLI changes the default retry count to infinite for maximum-BFS and random
   filters, but omits `--min-solution-depth`, allowing incomplete datasets after
   five rejected attempts.
6. **P2 — Replacement generation failures are ignored.**
   Exact-slot regeneration uses `abort_on_error=False`; a failed generator call
   can leave a deleted/missing slot until a later stage notices it.
7. **P1 — Static action planning erases privilege-state requirements.**
   Pure local privilege-escalation actions are excluded and goal capture depends
   only on node ownership. The resulting action count cannot validate Admin/System
   target-privilege curricula.
8. **P3 — Dataset coverage tests have a long silent scan phase.**
   Collection finds 203 tests. After 15 fast assertions, the session-scoped
   coverage fixture scans the large default dataset before 188 per-slot assertions
   can run. This is a performance/observability issue, not a confirmed deadlock.
9. **P1 — Resume accepts stale validation artifacts.**
   A slot is skipped when `run_metrics.json` merely says `is_solved=true`; no
   config hash, scenario hash, vocabulary hash, evaluator version, or requested
   depth contract is checked.
10. **P1 — Accepted samples lack durable generation provenance.**
    Seeds are calculated by the dataset generator but are not written into each
    scenario directory. Exact reproduction of a bad or suspicious sample is not
    guaranteed.
11. **P1 — BFS process errors are labeled as partial solvability.**
    Any nonzero evaluator exit is marked `completed` with “partial solve rate,”
    even when the cause is an import error, crash, malformed scenario, or missing
    dependency. Old `run_metrics.json` files can then be aggregated.
12. **P1 — Goal completeness uses stale pre-replacement metrics.**
    After unsolved slots are regenerated and reevaluated, `_rm_quick` is not
    refreshed before the goal-completeness decision. Newly generated incomplete
    goals can escape that enforcement pass.
13. **P1 — The advertised expanded training config is not validated with its data.**
    Topology standardization writes a new expanded YAML only after generation,
    static audit, BFS, and quality evaluation. No scenarios are generated from it
    and it is not revalidated, yet users are told to use it for DRL training.
14. **P2 — Coverage failure is explicitly non-fatal.**
    Step 9 can mark coverage `failed`, but the pipeline still sets overall
    `success=True`. A successful command exit therefore does not mean all declared
    validation gates passed.
15. **P1 — Malformed LLM responses receive a default passing-looking score.**
    Every unparsed dimension defaults to 7/10. Any nonempty response—including
    refusal text or unrelated prose—is accepted and becomes an apparently valid
    quality evaluation with no issues.
16. **P2 — Partial LLM responses are silently imputed as 7/10.**
    A response containing only one dimension leaves the other five at defaults,
    biasing the score and hiding missing evidence instead of failing parsing.
17. **P1 — The pipeline's post-generation “static audit passed” is not a final
    acceptance audit.** It omits full YAML parsing, strict warnings, and required
    runtime artifacts. Node YAML is largely inspected with text/regex extraction.
18. **P2 — Preflight warnings are presented under a simple passed banner.**
    The runner does not use preflight `--strict`, so warnings do not block and the
    console says “Preflight static gate passed” without surfacing that distinction
    in the headline.
19. **P0 — Fixed-scale regeneration can retain stale node YAML.**
    The generator creates/overwrites an existing scenario directory without
    clearing it first. If the new seed emits a different or smaller node set,
    files from the previous generation remain and become part of the scenario.
20. **P0 — `--require-solvable` retries contaminate one another.**
    Each retry writes into the same uncleared directory, so a later attempt can
    be evaluated together with nodes left by earlier failed attempts.
21. **P1 — `--require-solvable` is not dynamic BFS.**
    It calls the static Phase 2 evaluator and checks its `solvable` graph field,
    inheriting optimistic ownership and precondition modeling defects.
22. **P2 — The advertised per-scenario generation timeout is unused.**
    `--timeout` is passed through function signatures but never enforced around
    worker generation, so a stuck worker can stall the batch indefinitely.
23. **P1 — Stratum metadata points to a deleted temporary config.**
    Each stratum records the `/tmp/gendataset_*.yaml` path used for generation,
    then deletes that file. The recorded generation input cannot be inspected.
24. **P2 — Dataset counts can exceed `--count`.**
    Per-stratum allocation uses `ceil(config_count / n_strata)` for every stratum,
    so non-divisible requested counts over-generate while the manifest still calls
    the original value `count_target`.
25. **P2 — Scaled dataset manifests record unscaled bounds.**
    Generation uses scaled `strata_to_run`, but the manifest serializes
    `DEFAULT_STRATA`, misreporting the node-count contract when `--scale != 1`.
26. **P1 — “Coverage” measures textual placement, not usable training actions.**
    A slot counts as covered when its name appears as a node vulnerability key,
    even if prerequisites are impossible, the action is always masked, or it is
    never reached/executed.
27. **P1 — Runtime coverage silently skips YAML it cannot `safe_load`.**
    `_compute_slot_coverage_metrics` catches every parse exception and continues.
    Start-node YAML with Python-specific tags can be omitted, hiding start-only
    slots and corrupting entropy/tail-slot repair signals.
28. **P0 — Numeric generation seeds are not reproducible across Python hash
    seeds.** Credential and coverage selection consume unordered sets. Two fresh
    processes with identical config and `--seed 4242` produced different
    vulnerability placements and shortcut-pruning decisions.
29. **P0 — Failed depth certificates do not fail generation.**
    Certificate violations are printed, stored only in the in-memory generator,
    and then discarded. The scenario is still written and accepted by later
    structural coverage checks.
30. **P0 — Coverage sweep mutates the graph after depth certification.**
    Forced discovery/credential/remote outcomes are added after the shortcut
    guard, but depth is never recertified. The final serialized graph need not
    match the printed certificate.
31. **P1 — The certificate oracle ignores executable prerequisites.**
    Its graph and ownership fixed point do not evaluate vulnerability
    preconditions/privilege state and classify information outcomes as ownership.
32. **P1 — Forced remote coverage is placed on already-owned nodes.**
    Restricting all coverage placement to the live-owned set makes presence easy
    but does not prove a remote specialist action is a valid/productive attack on
    a target that still requires ownership.
33. **P0 — GoalNormalizer reads goal policy from the wrong YAML level.**
    The generator reads `config.goal_config.num_goals`, but the normalizer reads
    other policy fields from top-level `goal_config`. Current specialist configs
    nest them under `config`, so strategy, promotion/demotion controls, shared goal
    names, thresholds, and weights silently fall back to defaults.
34. **P1 — Shared goal tags are skipped when goal count is already correct.**
    `normalize()` returns immediately before applying shared-goal naming, so the
    configured observation/reward class is absent in the common no-count-change
    case.
35. **P1 — Failure to reach the requested goal count is non-blocking.**
    The normalizer only prints a warning and generation proceeds with a different
    training objective.
36. **P1 — Unreachable promoted goals remain goals.**
    Discovery/credential injection failures are warnings; promotion is not rolled
    back and no authoritative post-normalization solvability gate runs there.
37. **P0 — Serialized firewall policy and runtime connectivity sharply diverge.**
    Of 272 credential edges, 146 (53.7%) lack exact port+subnet authorization,
    but runtime blocks only 43 (15.8%); 103 policy-invalid edges are over-permitted
    because the actuator ignores subnet.
38. **P1 — Firewall generation deduplicates by port while YAML claims subnet
    scope.** This erases intended peer distinctions, while the runtime's port-only
    matching turns the same defect into cross-subnet over-permission.
39. **P0 — Static solvability and depth certification ignore firewalls.**
    Credential edges are treated as traversable from their outcome alone, so
    certificates can pass for paths the environment blocks.
40. **P1 — Wildcard firewall intent is not implemented consistently.** Metrics
    skip wildcard rules and the actuator performs exact port equality, so a
    start-node `*` allow does not authorize concrete ports at runtime.
41. **WITHDRAWN — The improved evaluator's `maximum_node_count=100` does not
    prevent xlarge loading.** A real 778-node scenario constructed and reset
    successfully; its current observation design is neighborhood-size invariant.
42. **P1 — Credential bounds contradict real xlarge artifacts.** One 778-node
    artifact has 1,554 unique credentials and an action returning 1,552, while
    the evaluator observation bound is 1,000 and statistics divide by model
    maximum 100. Cache truncation was not observed or claimed.
43. **P1 — Replay failure does not invalidate a solved result.**
    A scenario is counted solved from the planning episodes even when all five
    replay trials fail; the process can still exit zero for the dataset.
44. **P1 — An empty scenario search exits successfully.**
    With zero discovered `nodes/` directories, the evaluator reports 0/0 solved
    and returns code zero.
45. **P1 — Difficulty is calculated before replay and never recomputed.**
    The advertised replay-based stochastic-volatility component always uses the
    fallback planning-episode outcome counts in newly generated metrics.
46. **P1 — Local, remote, and port success rates have invalid denominators and
    overlapping numerators.** Outcome classes do not identify action type, yet all
    three rates divide by total attacks and some outcomes count in multiple types.
47. **P2 — `episodes_required` always reports the configured maximum.**
    The metric receives `max_episodes`, not the episode index at first solution.
48. **P2 — Goal-count aggregation says “most common” but computes maximum.**
    Mixed goal-count datasets are summarized with the largest denominator rather
    than a mode or explicit mismatch distribution.
49. **P3 — The LLM critic prompt hardcodes 3 agents × 3 episodes.**
    Runtime constants are environment-overridable, so prompt provenance can differ
    from the evaluation actually performed.
50. **P2 — Train/test contamination checks do not hash scenario content.**
    Numeric ID separation, coarse histograms, and vulnerability-name Jaccard are
    used instead of canonical graph/action/credential content hashes.
51. **P2 — Structural duplicates are warnings and the signature is lossy.**
    It contains only counts/histograms, ignoring edge endpoints, credential flows,
    firewall rules, preconditions, values, and goal identity.
52. **P2 — Diversity analysis includes only scenarios with run metrics and
    silently skips unparseable nodes.** Missing/failed samples disappear from its
    denominators and start-node vulnerabilities may be omitted.
53. **P2 — Template-alignment scoring reads a legacy `config_settings.start_node`
    path.** All 20 specialist configs define top-level `start_node`, so each is
    falsely penalized and reported as having no breach entry.
54. **P2 — Schema-path knowledge is duplicated across validators and runtime.**
    Goal and start-node fields are already read from conflicting locations,
    allowing one checker to validate a field another component ignores.
55. **P0 — Object-generator initial state is lost during compilation.** BFS uses
    initial credentials and non-start privileges that compiled YAML does not
    preserve, so a certified path can be unavailable at runtime.
56. **P0 — Object-generator local prerequisites are validated on the wrong
    node.** The validator checks the target, while local vulnerabilities are
    compiled onto and evaluated against the source.
57. **WITHDRAWN — Remote exploits bypass firewall checks in both object BFS and
    CyberBattleSim.** Runtime inspection showed this is consistent behavior;
    only credential Connect is firewall-gated in the current simulator.
58. **P1 — Object-generator Probe actions can never enter a BFS path.** Probe
    changes no modeled state, and identical candidate states are discarded.
59. **P0 — A firewall-blocked Connect compiles conflicting allow and deny
    rules.** BFS rejects the path, while compilation emits an allow pair and an
    equal-priority target deny for the same connection.
60. **P1 — Object-generator BFS truncation is reported as unsolvability.** State
    cap exhaustion and exhaustive queue exhaustion have the same result shape.
61. **P1 — Mandatory-bypass reporting examines the wrong transitions.** It
    ignores mandatory actions absent from one chosen shortest path and can label
    an alternate action as "bypassable mandatory."
62. **P0 — Legacy object DSL identifiers can escape the output directory.**
    Scenario and node strings become unchecked filesystem path components.
63. **P0 — Object-generator recompilation retains stale node files.** Writing a
    smaller spec to an existing scenario directory produces a hybrid artifact.
64. **P0 — A user-declared `start` node is silently replaced by the compiler.**
    Validation/BFS use the declaration, but runtime YAML contains the synthetic
    attacker definition.
65. **P1 — Object-generator `/24` allocation has no zone capacity check.** It
    assigns a broadcast address and then addresses outside the declared subnet.
66. **P1 — Duplicate object-generator node declarations silently overwrite.**
    The parsers collapse them before semantic validation can report an error.
67. **P0 — Remote/Connect privilege grants are not preserved by compilation.**
    BFS can grant System in one step, while runtime LateralMove/Connect grants
    only LocalUser.
68. **P0 — Zero-success transitions are accepted as deterministic BFS edges.**
    A path with execution probability zero can receive a solved certificate.
69. **P0 — Probe compilation has inconsistent owner/type/property semantics.**
    The target-validated properties are emitted in a remote vulnerability stored
    on the source.
70. **P1 — Required source privilege is not represented in compiled actions.**
    The preferred fixture executes System escalation directly from User, but its
    tested runtime action count remains 9 because compiled initial discovery adds
    one action; no numeric depth collapse is claimed for that fixture.
71. **P1 — The condition solver treats zero-rate vulnerabilities as usable.**
    It cannot catch BFS certificates whose only compiled path has success
    probability zero.
72. **P1 — Object-generator hashes vary with `PYTHONHASHSEED`.** Unsorted sets
    reorder spec/report serialization and give identical semantics different
    digests.
73. **P1 — `scenario.sha256` does not hash the compiled artifact.** It covers
    only the source spec, so stale, missing, modified, or compiler-drifted node
    YAML is undetectable.

## Previously confirmed in the connected CyberBattleSim investigation

- Depth-1 tasks can set numeric/Admin ownership without adding the matching
  runtime privilege property, leaving the System action masked and BFS-unsolvable.
- Background remote lateral-move outcomes can create three-step shortcuts through
  longer intended chains.
- Training accepted estimated depth without requiring exact BFS agreement.
- Online debug runs did not preserve enough seed/manifest state for exact replay.

Those defects are upstream/downstream integration risks; they are recorded here
because generator output must be validated against them, but their fixes may live
in the sibling CyberBattleSim repository.

## Open

- Whether static MST “campaign depth” is being interpreted as an executable
  directed campaign even though pairwise edges are converted to undirected MST
  weights.
- Whether the new placement-feasibility check covers every property source used
  by node construction, rather than only the identifier universe.
- Whether replacement preserves manifests and all derived artifacts after exact
  slot regeneration.
- Whether post-static coverage and Phase 1 share exactly the same live-slot
  extraction semantics for every supported outcome shape.
