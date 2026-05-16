# Technical Specification: Balanced Vulnerability Density (Q9)
**Status:** FINAL (Formalized 2026-05-16)

## 1. Problem Statement
Uniform high-density seeding (e.g., 70%) creates "loud" networks where DRL agents over-fit to a sea of vulnerabilities rather than learning architectural navigation.

## 2. Implementation Logic
- **Global Seeding Ratio:** The default `min_credential_leaking_nodes` ratio is set to **0.5 (50%)**.
- **The "50/50" Balance:** This provides a statistically guaranteed solvability path while leaving 50% of the network "clean," forcing the agent to prioritize targets rather than spamming every node.
- **Deterministic Injection:** If the ratio is not met, the `SolvabilityPostProcessor` injects vulnerabilities until the target is reached, prioritizing entry points and goal-adjacent nodes.

## 3. Configuration
Centralized in `pipeline/constants.py`:
- `DEFAULT_MIN_CREDENTIAL_LEAKING_NODES_RATIO = 0.5`
- `DEFAULT_MAX_CREDENTIAL_LEAKING_NODES_MULTIPLIER = 1.5`
