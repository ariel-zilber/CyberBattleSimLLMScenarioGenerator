# Microservice Topology Addendum

Inject this addendum alongside `system_prompt_v3.md` **only** when the scenario is microservice-based (multi-tier containerised AWS/cloud topology). Do NOT load for enterprise/Windows/branch scenarios — the rules are irrelevant and add noise.

---

## MICROSERVICE-SPECIFIC DIRECTIVES

### M1 — Hub Node (Cross-Tier Shared Service)

Every microservice config with ≥ 3 tiers MUST include exactly one hub DataTier service reachable from multiple upstream tiers. Typical hubs:
- `RedisServer` (`Misconfigured`, `GoRuntime`) — reachable from both AppTier and WorkerTier
- `ElasticsearchServer` (`Java`) — reachable from AppTier and WorkerTier

Model this with two separate `inter_domain_constraints` entries both pointing to the same DataTier group. Hub node value: 4000–7000. A `Misconfigured` hub creates a cross-tier credential propagation path the DRL agent must discover.

### M2 — Shadow Runtime Paths (Hidden Connections)

In 20–30% of microservice configs, add one `MUST_REACH` constraint between non-adjacent tiers to model undocumented runtime dependencies. Allowed shadow paths:
- WorkerTier → DataTier (MongoDB direct write)
- WebTier → AuthTier (nginx `auth_request`)
- AppTier → WorkerTier reverse (Jenkins → Kafka)

Rules: always use `MUST_REACH` (not `MUST_CONNECT`); always specify a concrete protocol (never `ALL`). This creates a tier-skipping attack option that prevents the agent from learning only the canonical vertical chain.

### M3 — Tier Protocol Constraints

| From → To | Allowed Protocols | Forbidden |
|-----------|-------------------|-----------|
| WebTier → AppTier | `HTTPS`, `REST` | `SMB`, `RDP`, `LDAP` |
| AppTier → DataTier | `PostgreSQL`, `MySQL`, `MongoDB`, `Redis` | `HTTP`, `ALL` |
| AppTier → WorkerTier | `Kafka`, `AMQP` | `ALL` |
| AppTier → AuthTier | `HTTPS`, `OIDC` | `ALL` |
| WorkerTier → DataTier | `MongoDB`, `PostgreSQL` | `ALL` |
