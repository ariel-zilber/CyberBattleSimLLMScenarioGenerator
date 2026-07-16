# Firewall and Credential-Edge Consistency

Status: confirmed by source inspection and a generated-artifact audit.

## Generated evidence

The Pass 10 scenario generated with seed 4242 and `PYTHONHASHSEED=1` was scanned.
For every cross-node `LeakedCredentials` tuple, the audit checked:

- source firewall has an ALLOW outgoing rule for target port and target subnet;
- target firewall has an ALLOW incoming rule for that port and source subnet.

Results:

```text
cross-node credential edges: 272
incomplete firewall pairs:   146
incomplete rate:             53.7%
edges missing outgoing:       92
edges missing incoming:       93
```

Self-target credentials were excluded from these totals.

## Policy/runtime semantic divergence

`open_firewall_for_cred` builds `existing_ports` for each rule list and therefore
deduplicates by port even though serialized rules carry peer subnet. More
critically, CyberBattleSim's current firewall actuator ignores the subnet field
entirely and returns on the first matching port.

On the same 272 non-start edges, only 43 (15.8%) lack a runtime-allowing first
port match in one or both directions. Of the 146 exact-policy failures, 103 are
still dynamically permitted. The dataset therefore has both blocked intended
credential transitions and cross-subnet over-permission/shortcut risk.

The same pattern appears in entry firewall opening: existence is tested by subnet
alone, so one allowed port to the attacker subnet can suppress another necessary
port.

## Not every credential producer opens a path

Generic vulnerability patterns and coverage placement can create credential
outcomes without invoking the shared firewall helper. Even a corrected helper
would therefore need to be applied as a central invariant after all outcome
mutation, rather than opportunistically in selected builders.

## Validator mismatch

The static Phase 2 evaluator and attack-spine graph treat credential leaks as
edges without enforcing the actuator's first-port-match behavior. The newer
condition solver does enforce port+subnet pairs, which is stricter than the
actuator. These components are certifying different connectivity graphs.

## Wildcard metric mismatch

The effective topology calculator explicitly skips wildcard `*`/`any` rules.
The actuator also does not implement wildcard matching: it compares rule port
for exact equality. A generated start-node `*` rule therefore does not authorize
SSH/RDP/etc. at runtime, contrary to the apparent configuration intent.

## Suggested fix

- First decide and document whether subnet is enforceable policy. If yes, fix the
  actuator to evaluate it and deduplicate using `(port, subnet, permission)`; if
  no, remove misleading subnet-scoped certification and explicitly model the
  port-wide connectivity graph.
- After all generation mutations, enumerate every intended credential transition
  and verify both firewall directions against the exact serialized rules.
- Make BFS, static search, condition solver, and runtime use one shared firewall
  decision function, including rule priority/order and wildcard behavior.
- Replay credential actions dynamically for final acceptance.
- Report simulator connectivity and policy-only topology as separate metrics if
  wildcard exclusion is analytically desired.
