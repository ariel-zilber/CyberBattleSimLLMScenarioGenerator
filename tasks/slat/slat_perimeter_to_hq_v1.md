# S-LAT-L01: Perimeter to HQ Credential Bridge
**Agent:** S_Lateral
**File:** `slat_perimeter_to_hq_v1.yaml`
**Tier:** large · 200–500 nodes · 2 train scenarios
**Status:** [ ] not started

Full Z2 → Z1 crossing scenario. Multiple perimeter nodes carry different credential types (NTLM hashes, Kerberos tickets, plaintext). Patched nodes block some relay paths. Agent must learn to select the correct credential + technique combination for each available target, routing around patched relay paths to reach the first Z1 terminal node.
