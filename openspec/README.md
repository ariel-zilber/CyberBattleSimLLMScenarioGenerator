# OpenSpec: CyberBattleSim Scenario Generator Logic
**Project:** LLM-Driven Scenario Generation for DRL Training
**Date:** 2026-05-16

This folder contains the formalized technical specifications for the scenario generation pipeline. These documents serve as the "Source of Truth" for the architecture logic discussed during the design review.

## Reference Specifications

### 1. Generation Core
- [WYSIWYG Scenario Generation](specs/wysiwyg_generation.md) — The 1:1 YAML-to-Graph model.
- [Balanced Vulnerability Density (Q9)](specs/balanced_density.md) — The 50/50 seeding strategy.
- [Binary Attacker-Effort Model (Q10)](specs/cost_normalization.md) — Tiered cost logic for exploits vs techniques.

### 2. Validation & Feasibility
- [Training Feasibility Metric (CSR) (Q27)](specs/training_feasibility_csr.md) — End-to-end probability feedback for the LLM.
- [Identifier Garbage Collection (Q25)](specs/identifier_garbage_collection.md) — Automatic pruning of orphaned state properties.

## Strategic Goal
These specifications ensure that generated data is **architecturally diverse**, **physically solvable**, and **DRL-trainable**, providing a robust foundation for the thesis experiments.
