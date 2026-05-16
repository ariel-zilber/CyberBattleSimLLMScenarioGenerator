---
name: CBS Config Architecture Decisions
description: Key design rules for CyberBattleSim YAML configs: depth validation, breach_node pattern, constraint relations
type: project
---

## Depth Validation (config_checker.py)

- BFS from "entry services" (sources NOT appearing as any target in attack_flow)
- `depth < 2` = ERROR. `depth == 2` = YELLOW warning. `depth >= 3` = GREEN (ideal)
- Common depth=1 cause: a source-only entry in attack_flow that directly reaches the goal
  - Fix: make that service appear as a target too (add it to another rule's targets list)
- Common depth=2 cause: direct shortcut from an early node to goal skipping intermediates

**Why:** Depth ≥ 3 in attack_flow is the design target. Achieved by chaining service nodes:
  Entry → Intermediate1 → Intermediate2 → Goal (3 hops)

## Breach Node Pattern

For pre-owned entry nodes (representing handoff from another specialist):
```yaml
services:
  SalesWorkstation:
    default_properties: [Windows, breach_node, DomainJoined, ...]
    
solvability_vulnerabilities:
  remote_access:
    - name: Solvability.BreachNode_Entry
      type: REMOTE
      success_rate: 1.0
      match_properties: [Windows, breach_node]
      probability: 1.0
```
Groups: min_count: 1, max_count: 1

## Valid Constraint Relations

- `MUST_HAVE`: source group must have this property
- `MUST_CONNECT`: source can reach target via protocol (creates network path)
- `KNOWS`: owning source reveals target nodes
- `LEAK_KNOWN_CREDENTIALS`: owning source leaks credentials valid for target
- `CLIENT_OF`: source is a client of target service
- `MUST_REACH`: source must be able to reach target

**INVALID**: `MUST_NOT_CONNECT` — not supported, will fail validation.

## LEAK_KNOWN_CREDENTIALS Must Have MUST_CONNECT

The config_checker warns if LEAK_KNOWN_CREDENTIALS exists without a MUST_CONNECT on the same edge. Always pair them:
```yaml
- source: GroupA
  target: GroupB
  relation: MUST_CONNECT
  protocol: HTTPS
- source: GroupA
  target: GroupB
  relation: LEAK_KNOWN_CREDENTIALS
  protocol: HTTPS
```

## Key Design Rules

1. **No `MUST_NOT_CONNECT`** — invalid relation, use topological isolation instead
2. **No AdminWorkstations→DomainControllers cross-domain** — creates depth=2 shortcut
3. **FileServers must NOT directly reach DomainControllers** — forces 3-hop path
4. **Single flat domain** (S-REC-01): Use ONE domain with all groups; use KNOWS+LEAK_KNOWN_CREDENTIALS for credential graph traversal
5. **PHASE2_STRATA** in .env: `small,medium,large` — generates 21 scenarios per config
