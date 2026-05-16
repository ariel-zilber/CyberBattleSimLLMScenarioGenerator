# S-LAT-S03: MSSQL xp_cmdshell Lateral Move
**Agent:** S_Lateral
**File:** `slat_mssql_lateral_v1.yaml`
**Tier:** small · ≤50 nodes · 5 train scenarios
**Status:** [ ] not started

MSSQL xp_cmdshell execution using SA or DA credentials on a pre-owned node, pivoting to MSSQLServer as terminal goal. Agent learns to select xp_cmdshell over NTLM relay when database credentials are available.
