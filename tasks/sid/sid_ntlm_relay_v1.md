# S-ID-S03: NTLM Relay Chain
**Agent:** S_Identity
**File:** `sid_ntlm_relay_v1.yaml`
**Tier:** small · ≤50 nodes · 5 train scenarios
**Status:** [ ] not started

PrinterBug coerces machine authentication; agent relays NTLM to LDAP to write AD attributes, then DCSync to DomainController.
