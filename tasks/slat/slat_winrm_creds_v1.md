# S-LAT-S02: WinRM Remote Execution
**Agent:** S_Lateral
**File:** `slat_winrm_creds_v1.yaml`
**Tier:** small · ≤50 nodes · 5 train scenarios
**Status:** [ ] not started

WinRM remote execution from a breach workstation. S_Lateral fires `Solvability.Mimikatz_LSASS` (LOCAL credential_leak) as step 1 to extract NTLM hash or Kerberos TGT from the breach node; then selects the correct WinRM technique (hash vs ticket) and executes into AdminWorkstation as terminal goal. Credential store starts empty — no pre-seeded creds.
