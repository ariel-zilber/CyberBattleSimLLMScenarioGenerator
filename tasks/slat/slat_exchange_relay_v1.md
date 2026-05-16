# S-LAT-S04: Exchange NTLM Coercion
**Agent:** S_Lateral
**File:** `slat_exchange_relay_v1.yaml`
**Tier:** small · ≤50 nodes · 5 train scenarios
**Status:** [ ] not started

Exchange NTLM coercion (PrivExchange / ProxyNotShell) from a pre-owned server, relaying ExchangeServer machine account hash to DomainController via LDAP. Agent must chain coercion → relay → LDAP write.
