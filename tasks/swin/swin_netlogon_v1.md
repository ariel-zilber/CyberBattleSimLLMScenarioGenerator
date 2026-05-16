# S-WIN-S05: Netlogon Authentication Bypass
**Agent:** S_Windows
**File:** `swin_netlogon_v1.yaml`
**Tier:** small · ≤50 nodes · 5 train scenarios
**Status:** [ ] not started

Netlogon OS authentication bypass (CVE-2022-38023 session key brute-force or CVE-2023-21526 session key leak) against DomainController, followed by kernel privilege escalation and SYSTEM shell. Pure OS-layer attack — no credential relay (S_Lateral owns that path).
