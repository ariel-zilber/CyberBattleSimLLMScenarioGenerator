# Technical Specification: Binary Attacker-Effort Model (Q10)
**Status:** FINAL (Formalized 2026-05-16)

## 1. Overview
DRL agents optimize for `Reward - Cost`. To prevent agents from "spamming" complex protocol abuses (AD techniques) over surgical exploits (CVEs), a tiered cost model is enforced.

## 2. Cost Tiers
| Type | Default Cost | Description |
|------|--------------|-------------|
| **CVE-Backed** | 1.0 | Standard RCE or Local Exploit with a known CVE ID. |
| **AD Technique** | 2.0 | Complex protocol abuse (Mimikatz, DCSync, ShadowCredentials, etc.) |

## 3. Automated Normalization Logic
The `VulnerabilityManager` and `SolvabilityPostProcessor` apply the following check when creating vulnerabilities:
- **Technique Detection:** If `ENABLE_TECHNIQUE_COST_SCALING` is True, any vulnerability without an explicit `exploit_cve` or containing known protocol-abuse keywords is assigned the `DEFAULT_TECHNIQUE_COST` (2.0).
- **CVSS Grounding:** CVE-backed exploits default to 1.0 (or their CVSS-derived value if explicitly defined).

## 4. Configuration
- Flag: `ENABLE_TECHNIQUE_COST_SCALING: bool = True`
- Locations: `VulnerabilityManager.py`, `SolvabilityPostProcessor.py`.
