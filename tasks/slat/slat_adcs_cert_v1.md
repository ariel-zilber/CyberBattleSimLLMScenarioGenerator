# S-LAT-S05: ADCS Certificate → PAM Auth
**Agent:** S_Lateral
**File:** `slat_adcs_cert_v1.yaml`
**Tier:** small · ≤50 nodes · 5 train scenarios
**Status:** [ ] not started

ADCS ESC1 certificate request from a breach DomainController. S_Lateral first fires `Solvability.LAPS_Password_Read` or `Solvability.Mimikatz_LSASS` (LOCAL credential_leak) to extract an admin credential, then requests an ESC1 certificate, converts it to a Kerberos ticket, and authenticates to CyberArkPAM as terminal goal. Isolates the ADCS → PAM crossing. Credential store starts empty — no pre-seeded creds.
