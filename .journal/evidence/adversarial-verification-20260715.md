# Adversarial verification evidence — 2026-07-15

This pass was specifically designed to disprove prior findings where possible.

## GoalNormalizer nested policy

Sentinel input used the production nesting:

```text
config.goal_config.num_goals = 1
config.goal_config.selection_strategy = value
config.goal_config.allow_promote = false
config.goal_config.shared_goal_name = GoalClass
```

The caller-style explicit goal count was retained, while the component reported:

```text
num 1
strategy diverse
allow_promote true
shared None
```

This component-reproduces problem 33.

## GoalNormalizer early return

A separate root-level sentinel ensured `shared_goal_name` was recognized, with
one existing goal and target count one. `normalize()` returned immediately and
the goal's properties remained empty rather than receiving `GoalClass`. This
component-reproduces problem 34 independently of the nesting bug.

## Firewall subnet over-permission

Artifact: `/tmp/cbsgen_hashseed_1`

Selected actual credential edge:

```text
source Z1_ServerFarm_SalesWorkstations_2 (10.1.10.0/24)
target InternetEdge_F5LoadBalancers_4 (10.0.1.0/24)
port SSH
credential InternetEdge_F5LoadBalancers_4_SSH
exact source/target subnet rule pair false
```

To isolate firewall behavior, the improved actuator was placed in the state that
Connect checks immediately before firewall evaluation: source owned, target
discovered, credential gathered. The actual `connect_to_remote_machine()` method
then returned `LateralMove` and raised target privilege to LocalUser.

This runtime-reproduces cross-subnet over-permission. It does not prove the
original credential-producing action is executable: an earlier attempt showed
that selected producer was masked. Firewall behavior and end-to-end path
usability must remain separate claims.

## Firewall blocking and static-evaluator disagreement

Selected actual edge:

```text
source HQ_Edge_FortiGateAppliances_6
target InternetEdge_PaloAltoFirewalls_4
port PaloAltoFirewall
source outgoing first-port allow false
target incoming first-port allow true
```

With source owned, target discovered, and the accepted credential gathered, the
improved actuator's real Connect returned no outcome, reward `-10`, and target
privilege remained 0. The edge is dynamically blocked.

The production static evaluator's `_build_attack_edges()` nevertheless included
this exact source→target edge because it consumes credential outcomes without
firewall evaluation. This confirms a component-level static/dynamic graph
disagreement. It does not yet prove the overall scenario's final solvability
verdict differs, since alternate paths may exist.
