# S-LAT-XL01: Enterprise Full Lateral Movement
**Agent:** S_Lateral
**File:** `slat_enterprise_full_v1.yaml`
**Tier:** xl · 500–1000 nodes · 1 train scenario
**Status:** [ ] not started

Enterprise-scale lateral movement across all zones. Multiple active credential stores (NTLM hashes, Kerberos tickets, ADCS certs, cloud IAM tokens). Mixed patch states block different techniques across different network segments. Agent must build a multi-hop relay chain from Z2 perimeter through Z1 VLANs and Server Farm to CyberArkPAM (Z8) as terminal goal. Tests all 8 S_Lateral CVE categories in a single scenario.
