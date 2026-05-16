# Technical Specification: Identifier Garbage Collection (Q25)
**Status:** FINAL (Formalized 2026-05-16)

## 1. Overview
LLMs frequently hallucinate or over-specify security properties. Unused properties bloat the DRL observation vector and introduce noise into the state space.

## 2. Pruning Logic
The `SolvabilityPostProcessor` performs a **Reverse Dependency Scan**:
1. **Identify Usage:** Scans `services`, `groups`, `solvability_vulnerabilities`, and `start_node` to build a set of "Actually Used" properties.
2. **Flag Orphans:** Identifies properties in `identifiers.base_properties` that are NOT in the used set.
3. **Delete:** Removes orphaned properties from the configuration before the static `02_config_checker.py` runs.

## 3. Mandatory Exceptions
The property `breach_node` is always preserved as it is a fundamental CyberBattleSim anchor.
