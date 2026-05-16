# S-LAT-M01: Multi-Zone Relay Chain
**Agent:** S_Lateral
**File:** `slat_multizone_relay_v1.yaml`
**Tier:** medium · 50–200 nodes · 3 train scenarios
**Status:** [ ] not started

Multi-step lateral movement chain: Z2 perimeter → NTLM relay → Z1 workstation → WinRM → Z1 server → MSSQL xp_cmdshell → Z1 database server (terminal goal). Agent must select different techniques at each hop depending on available credential types and open ports.
