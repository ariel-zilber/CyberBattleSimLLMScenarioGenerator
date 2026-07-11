# Path-First Certified Attack Spine Plan

## Verdict

For thesis-quality depth variance, the best solution is **path-first certified attack spine generation**.

The earlier de-shortcut pruning pass is a useful safety cleanup, but it cannot guarantee variance. It can remove redundant shortcuts only when a deeper alternate path already exists. If every generated scenario has the same alternate depth, pruning may simply move the dataset from all depth-2 goals to all depth-3 goals.

Path-first generation makes depth intentional.

## Core Idea

Instead of:

```text
generate topology -> add solvability -> discover shortcuts -> prune shortcuts
```

use:

```text
sample target depth -> construct certified attack spine -> add noise -> reject shortcuts -> verify
```

For each scenario:

```text
1. Sample target_depth D.
2. Choose a goal node.
3. Choose D-1 intermediate nodes between start and goal.
4. Inject real attack mechanisms for every hop.
5. Mark those spine edges as protected.
6. Remove or reject any non-spine edge that makes BFS(start, goal) < D.
7. Write a depth_certificate.json.
8. Verify static BFS depth and dynamic solvability.
```

Example spine:

```text
start
  -> InternetEdge_WAFs_1
  -> CICDRunner_1
  -> SecretsVault_1
  -> AdminWorkstation_1
  -> DomainController_1
```

Example certificate:

```json
{
  "goal": "DomainController_1",
  "target_depth": 5,
  "verified_bfs_depth": 5,
  "path": [
    "start",
    "InternetEdge_WAFs_1",
    "CICDRunner_1",
    "SecretsVault_1",
    "AdminWorkstation_1",
    "DomainController_1"
  ],
  "edge_mechanisms": [
    "credential",
    "remote_exploit",
    "credential_dump",
    "credential",
    "remote_exploit"
  ]
}
```

## Why This Is Better Than Pruning Alone

Pruning is reactive. It can only remove bad edges that already have a deeper replacement path.

Path-first generation is constructive. It creates the desired depth first, then protects it.

Benefits:

- Depth variance is created by construction.
- Each scenario can carry a proof artifact.
- Dataset balancing becomes explicit.
- Shortcut violations become validation failures.
- The thesis claim becomes stronger: the accepted scenarios have certified minimum attack depth.

## Required Code Changes

### 1. Add Attack Spine Builder

Create:

```text
pipeline/cbsim/components/attack_spine.py
```

Responsibilities:

- sample or receive a target depth
- choose a goal node
- choose intermediate nodes
- inject edge mechanisms along the path
- open firewall rules for credential edges
- ensure target services accept injected credentials
- add required remote vulnerabilities where needed
- mark protected spine edges
- detect and remove non-protected shortcuts
- return a certificate object

Suggested public API:

```python
class CertifiedAttackSpineBuilder:
    def __init__(self, nodes, config, seed=None, target_depths=(3, 4, 5, 6)):
        ...

    def apply(self) -> dict:
        """Mutate nodes in place and return a depth certificate."""
```

### 2. Modify Universal Generator

Modify:

```text
pipeline/cbsim/generator.py
```

Current relevant flow:

```text
SolvabilityConstraintProcessor
create start node
SolvabilityPostProcessor.ensure_solvability()
GoalNormalizer.normalize()
return nodes
```

Add the certified spine pass after all existing solvability and goal-normalization passes:

```python
post_processor.ensure_solvability()

if goal_cfg.get("num_goals"):
    normalizer.normalize()

spine_builder = CertifiedAttackSpineBuilder(
    nodes=self.all_nodes,
    config=self.config,
    seed=self.seed,
)
self.depth_certificate = spine_builder.apply()
```

The pass should run late because earlier passes may add credential leaks, discovery vulns, or coverage vulns that create shortcuts.

### 3. Modify CLI Serialization

Modify:

```text
cli.py
```

After generation, write:

```text
depth_certificate.json
```

beside:

```text
nodes/
identifiers/
vulnerability_library/
```

Implementation shape:

```python
cert = getattr(gen, "depth_certificate", None)
if cert:
    _save_json(cert, os.path.join(out_dir, "depth_certificate.json"))
```

### 4. Add Certificate Validator

Create:

```text
pipeline/phase2/depth_certificate.py
```

Responsibilities:

- load `nodes/*.yaml`
- load `depth_certificate.json`
- build attack edges using the same semantics as `pipeline/phase2/evaluator.py`
- verify the certified path exists
- verify `BFS(start, goal) == target_depth`
- verify no shortcut makes the goal shallower than the target
- report depth distribution across a scenario directory

Suggested CLI:

```bash
python3 -m pipeline.phase2.depth_certificate \
  --scenarios-dir <scenarios_dir> \
  --expect-depths 3,4,5,6
```

### 5. Extend Evaluator Metrics

Modify:

```text
pipeline/phase2/evaluator.py
```

Add certificate-derived fields to the scenario result:

```text
target_depth
verified_bfs_depth
certificate_valid
shortcut_violation
depth_bucket
certified_goal
```

This makes depth certification visible in existing reports and `run_metrics.json`.

### 6. Extend Dataset Generator Flags

Modify:

```text
pipeline/phase2/generator.py
```

Add flags:

```text
--require-depth-certified
--target-depths 3,4,5,6
--depth-retries 5
```

When `--require-depth-certified` is enabled:

```text
generate scenario
validate depth_certificate.json
if invalid, retry with a fresh seed
if still invalid after retries, mark generation failure
```

## Shortcut Guard Algorithm

After the certified spine is injected:

```text
while BFS(start, goal) < target_depth:
    shortest_path = find shortest path from start to goal
    find a non-protected edge on that path
    remove the underlying credential/discovery edge
    recompute BFS

    if no removable non-protected edge exists:
        fail this scenario and regenerate
```

Protected spine edges must never be removed.

The removable edge types should initially be limited to:

```text
LeakedCredentials -> goal/intermediate target
LeakedNodesId -> goal/intermediate target
```

Do not remove remote vulnerabilities in the first implementation unless there is a clear reason. Removing a remote vuln may affect multiple paths and is riskier than deleting a single leaked target.

## Edge Mechanisms

Each spine hop needs a real CyberBattleSim mechanism.

Use a small set first:

```text
credential edge:
  source has LOCAL LeakedCredentials for target
  target has service accepting that credential
  firewall allows source -> target on that service port

discovery + remote edge:
  source has LOCAL LeakedNodesId containing target
  target has REMOTE owning vulnerability

credential dump edge:
  source has LOCAL credential dump
  dump leaks credential for next target
```

Keep the first implementation boring. The goal is certified depth variance, not maximal realism in the first pass.

## Tests

### Unit Tests

Create:

```text
tests/test_attack_spine.py
tests/test_depth_certificate.py
```

Required tests:

```text
creates depth-3 certificate
creates depth-5 certificate
certified path nodes all exist
certified path edges all exist
protected spine edges are not removed
direct start-to-goal shortcut is removed
entry-to-goal shortcut is removed
scenario fails when target depth cannot be achieved
certificate fails when BFS depth is too short
certificate fails when goal is unreachable
certificate passes when BFS depth equals target depth
```

Run:

```bash
pytest tests/test_attack_spine.py tests/test_depth_certificate.py -q
```

### Static Generation Test

Generate a small dataset:

```bash
python3 pipeline/phase2/generator.py \
  --config data/scenarios/<one_config>.yaml \
  --out-dir /tmp/depth_spine_test \
  --train 10 \
  --test 0 \
  --require-solvable \
  --require-depth-certified \
  --target-depths 3,4,5
```

Validate certificates:

```bash
python3 -m pipeline.phase2.depth_certificate \
  --scenarios-dir /tmp/depth_spine_test/scenarios \
  --expect-depths 3,4,5
```

Expected result:

```text
all scenarios certificate_valid=true
no shortcut_violation=true
depth distribution includes multiple buckets
```

### Dynamic Solvability Test

Run the existing dynamic solver:

```bash
python3 pipeline/phase2/test_env_integration.py \
  --data-dir /tmp/depth_spine_test/scenarios \
  --num-agents 3 \
  --episodes 3
```

Acceptance:

```text
dynamic solve rate should not regress versus current main baseline
static certificate success alone is not enough
```

## Acceptance Criteria

The implementation is successful only if:

```text
1. Every accepted scenario has depth_certificate.json.
2. Every certificate path is valid.
3. BFS(start, goal) equals the target depth.
4. No accepted scenario has a shortcut below target depth.
5. Depth distribution spans multiple buckets.
6. Dynamic solvability does not regress.
7. Existing evaluator tests still pass.
8. The old fallback behavior in find_reachable_targets() is not modified.
```

## Recommended Rollout

### Phase 1: Certificate Validator Only

Build `pipeline/phase2/depth_certificate.py` first.

Use it to measure current generated data. This gives a baseline:

```text
how many scenarios are depth-collapsed
what depths exist after removing obvious shortcuts
which configs lack enough structural path length
```

### Phase 2: Spine Builder Prototype

Implement the builder for one domain family only, using simple credential and remote-exploit hops.

Target:

```text
10 scenarios across depth buckets 3, 4, 5
```

### Phase 3: Integrate With Generator

Add generator flags and retry logic.

### Phase 4: Full Dynamic Validation

Run static and dynamic validation on the same seed set used by the earlier depth-collapse investigation.

## Final Recommendation

Use path-first certified attack spines as the long-term solution.

Keep the conservative de-shortcut pruning pass as a short-term cleanup or as a final safety guard, but do not rely on pruning alone for thesis-quality variance.

The final architecture should be:

```text
existing generator
existing solvability guarantees
goal normalization
certified attack spine construction
shortcut guard
certificate validation
dynamic solvability validation
```

This gives the project a stronger claim:

```text
The dataset is not merely solvable. It is solvable with certified, varied minimum attack depth.
```
