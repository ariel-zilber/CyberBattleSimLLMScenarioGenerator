# Object-generator semantic gaps

Status: confirmed by source inspection and minimal in-memory reproductions on
2026-07-15. No implementation or generated data was changed.

## P0: initial BFS state is not preserved by compilation

`state_bfs._initial()` consumes every entry in `initial_state.privileges` and
`initial_state.credentials`. `compiler.compile_nodes()` instead hardcodes all
ordinary nodes to privilege 0 and the synthetic `start` node to System. It emits
initial discovery as a vulnerability but emits neither initial credentials nor
non-start initial privileges.

Reproduction: a valid scenario gave `pivot` User privilege and credential
`cred` initially, then used them for a one-step Connect to the goal. BFS solved
it at depth 1. The compiled pivot had privilege 0, and the start node contained
only `Initial.Discovery`.

Impact: minimum-depth certification can describe a different initial state than
the scenario executed by CyberBattleSim. A certified path may be unavailable.

Recommended fix: either compile all supported initial state into runtime-native
state or reject initial credentials/non-start privileges until exact compilation
exists. Add an integration test that loads the compiled scenario and executes
the certified first action.

## P0: local prerequisites are validated on the wrong node

The validator checks every transition's prerequisites against the target node.
The compiler places Discover, LeakCredential, and Escalate vulnerabilities on
the source node, where CyberBattleSim evaluates their preconditions.

Reproduction: a LeakCredential prerequisite `Needed` existed only on the target.
Validation returned no errors. Compilation placed the vulnerability and
`Needed` precondition on a source whose property list was empty.

Impact: validation accepts masked local actions and can also reject valid local
actions whose source, but not target, has the necessary property.

Recommended fix: select the prerequisite owner with the same action-to-owner
rule used by the compiler, centralize that rule, and test both acceptance and
rejection through the runtime loader/available-action mask.

## Withdrawn: remote exploits bypass the firewall model

`firewall_allows()` returns true for every action other than Connect. A remote
exploit can therefore pass BFS across zones without an allow policy. The
compiler places its vulnerability on the target but emits no matching incoming
or outgoing rules.

Reproduction: a valid two-zone scenario with a remote exploit from an initially
owned source to a discovered goal was solved at depth 1; both compiled firewall
rule lists were empty.

Follow-up inspection of the connected CyberBattleSim actuator showed that
`exploit_remote_vulnerability()` also does not consult firewall rules. Firewall
checks occur in `connect_to_remote_machine()`. Therefore the absence of remote
exploit firewall rules is consistent with this runtime and is not a confirmed
BFS/compiler mismatch. This item is retained as an audit correction rather than
counted as an open defect.

If the intended domain policy later requires firewalls to constrain exploits as
well as credential traffic, that is a coordinated simulator/model feature
change, not a generator-only fix.

## P0: remote and Connect privilege grants are not compiled

BFS applies `transition.grants_privilege` to RemoteExploit and Connect, including
Admin or System. A compiled remote exploit always emits `lateral_move`; a
compiled Connect emits only firewall rules. The CyberBattleSim actuator handles
both successful operations by marking the target at its default LocalUser
privilege.

Reproduction: RemoteExploit and Connect transitions granting System were
certified as one-step System solutions. Their compiled artifacts contained no
System grant. Runtime source confirms `LateralMove` and credential Connect call
the ownership helper without a higher privilege argument.

Impact: System/Admin depth and solvability certificates can be false even for
otherwise valid compiled scenarios.

Recommended fix: restrict these transition types to USER grants and require
explicit Escalate steps for higher levels, or introduce a runtime-native outcome
that faithfully grants the declared level. Validate and replay exact privilege
after every certificate action.

## P0: zero-success transitions are deterministic BFS edges

Validation accepts `success_rate=0.0`; BFS does not inspect success rate and
treats the transition as guaranteed.

Reproduction: a zero-rate remote exploit granting System validated and was
certified at depth 1. Compilation correctly retained successRate 0.0, making the
certified action unable to succeed dynamically.

Impact: the generator can certify a path with zero execution probability.

Recommended fix: reject zero success on every required/reachable certificate
edge and define whether BFS depth is conditional-on-success or probabilistic.
At minimum, report stochastic assumptions separately from proven reachability.

## P0: Probe compilation does not represent the declared source-to-target action

Probe is excluded from the compiler's local-action set, but its vulnerability is
still placed on the source by the fallback owner rule and marked type REMOTE.
Its discovered properties and precondition are derived from target-validated
prerequisites. CyberBattleSim evaluates the remote vulnerability on the selected
target, while the emitted vulnerability sits on the source; if executed where
present, `ProbeSucceeded` also asserts discovered properties belong to that
runtime node.

Reproduction: target property `Secret` passed validation; compiled source had no
properties but held a type-3 Probe whose precondition/outcome named `Secret`.

Impact: Probe is not merely absent from BFS paths; its compiled ownership and
property semantics are internally inconsistent and may be unavailable or hit a
runtime assertion.

Recommended fix: define Probe as a target-hosted remote vulnerability (or a
source-local operation) consistently across model, validation, BFS, and
compiler, then execute it in an environment integration test.

## P1: required source privilege is absent from compiled actions

BFS gates every transition on the declared source privilege. Compilation emits
only static property preconditions and does not encode the source privilege for
remote exploits, Connect, or higher-level local actions. CyberBattleSim checks
that the source is owned but generally not that it has the DSL-declared level.

Impact: runtime can expose actions earlier than BFS, creating shorter paths and
invalidating the minimum-depth floor.

The repository's own `perimeter_to_domain.larkdsl` confirms the missing gate.
The CLI certifies exact depth 9. Compilation gives both
`DomainAdminEscalation` and `SystemEscalation` the identical precondition
`DomainController|Windows`; the latter does not require Admin. The compiled
condition proof and an adapted improved-runtime execution reach System directly
from User and omit the Admin action.

Correction after runtime verification: this fixture does **not** prove a numeric
9-to-8 depth collapse. Compilation also changes initially discovered `gateway`
into an executable `Initial.Discovery` action. In the adapted improved runtime,
that added action exactly offsets the skipped Admin action, producing 9 executed
actions. The confirmed defect is semantic path/gate mismatch and false mandatory
reporting; a numeric depth mismatch requires a separate reproduction and is not
claimed from this fixture.

Recommended fix: compile runtime privilege tags/preconditions where the action
model can enforce them, reject unrepresentable source gates, and compare the
runtime action mask against every BFS step and every lower-privilege state.

## P1: the condition solver treats zero-rate vulnerabilities as usable rules

The compiled-artifact condition extractor ignores vulnerability success rates.
It creates reachability rules even for `successRate: 0.0`, compounding the BFS
zero-rate defect and preventing this static layer from catching it.

Recommended fix: exclude zero-probability rules from reachability, report
probabilistic edges explicitly, and add a regression where the only goal path has
rate zero and must be unsolved in every certification layer.

## P1: Probe actions are state-neutral and absent from every BFS path

Probe can be enabled for a discovered target, and compilation gives it a
property-discovery outcome. `_apply()` does not model observed properties, so it
returns the identical state. The BFS explicitly discards identical candidates.

Reproduction: a scenario containing an enabled Probe explored only the initial
state; the result was unsolved with no action path.

Impact: probe steps cannot contribute to minimum depth or mandatory-path
contracts, even though the compiled scenario exposes them as actions.

Recommended fix: add observed properties to `SearchState` and make subsequent
preconditions depend on them, or explicitly define probes as out-of-model and
forbid them in mandatory/depth-bearing paths.

## Related semantic risks still requiring dynamic confirmation

- BFS treats nonzero success rates deterministically; its depth is an optimistic
  semantic-step lower bound, not a dynamic success guarantee.
- The compiler writes only `nodes/*.yaml` and `scenario.sha256`; compatibility
  with the full generated-scenario loading and post-static contract needs an
  end-to-end loader check.

## P0: blocked Connect policies compile conflicting allow and deny rules

The compiler emits an allow pair for every Connect transition without consulting
the policy permission. It then emits explicit block rules separately. A Connect
covered by a block policy is unsolved in BFS but compiles an outgoing allow plus
both incoming allow and deny entries at the same priority.

Reproduction: the block-policy case was valid and BFS-unsolved; the source had
`[(ALLOW, priority 1)]` and the target had both `(ALLOW, 1)` and `(BLOCK, 1)`.

Impact: the static result and runtime result depend on conflicting semantics and
rule-order behavior. In the connected runtime, the first same-port rule wins;
because the compiler appends the allow before the deny, the blocked connection is
actually allowed. The compiled artifact does not encode the policy certified by
BFS.

Recommended fix: resolve policy once before compilation; emit an allow only when
the matching policy permits it and reject contradictory transition/policy
contracts. Add runtime tests for allow, block, missing, and duplicate policies.

## P1: BFS truncation is reported as unsolvability

The search loop stops when the predecessor map exceeds `max_states`, but
`BFSResult` has no exhausted/truncated field. Queue exhaustion and state-cap
exhaustion both return `solved=False`, `minimum_depth=None`.

Reproduction: a normally solvable one-step case returned the ordinary unsolved
shape at caps 0 and 1, with explored-state counts 1 and 2 respectively.

Impact: the generator can request LLM repair or reject legitimate scenarios
because resource exhaustion is presented as a semantic proof of no solution.

Recommended fix: return an explicit completion status such as solved,
exhaustively-unsolved, or truncated; never certify unsolvability from a truncated
search, and expose the cap/status in reports.

## P1: mandatory-bypass reporting checks the wrong transition set

`analyze_paths()` examines only transitions present in one selected shortest
path and does not filter them by `role == MANDATORY`. It therefore misses
mandatory transitions bypassed by that path and can label alternate actions as
"bypassable mandatory."

Reproduction: two parallel depth-one remote exploits were ordered Alternate then
Mandatory. The selected path used `AlternateFirst`; the report returned
`('AlternateFirst',)` and never mentioned `DeclaredMandatory`.

Impact: the CLI's `bypassable_mandatory` summary can be both false-positive and
false-negative. It also does not currently reject compilation when the tuple is
nonempty.

Recommended fix: for every declared mandatory transition, test whether the goal
is solvable when that transition is removed (or formally require it in every
accepted solution). Report only mandatory vulnerability IDs, and make a violated
mandatory contract a compilation error.
