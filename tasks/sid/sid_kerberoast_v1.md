# S-ID-S01: Kerberoasting Chain
**Agent:** S_Identity
**File:** `sid_kerberoast_v1.yaml`
**Tier:** small · ≤50 nodes · 5 train scenarios
**Status:** [ ] not started

SPN-bearing service accounts enable Kerberoasting; agent cracks the TGS offline, uses SilverTicket to reach MSSQL, then DCSync to DomainController.
