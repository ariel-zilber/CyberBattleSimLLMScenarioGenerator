# S-LAT-S01: NTLM Relay Entry
**Agent:** S_Lateral
**File:** `slat_ntlm_relay_v1.yaml`
**Tier:** small · ≤50 nodes · 5 train scenarios
**Status:** [ ] not started

NTLM relay from a breach node in Z2 into a Z1 workstation. S_Lateral fires `Solvability.Mimikatz_LSASS` (LOCAL credential_leak) as step 1 to extract the NTLM hash; then selects the correct relay technique (SMB relay vs LDAP relay) and target node to reach the Z1 entry workstation. Credential store starts empty — no pre-seeded hash.
