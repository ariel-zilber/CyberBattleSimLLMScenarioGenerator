# Technical Specification: WYSIWYG Scenario Generation
**Status:** FINAL (Formalized 2026-05-16)

## 1. Overview
The "What You See Is What You Get" (WYSIWYG) model defines a strict 1:1 relationship between the LLM's YAML configuration and the generated CyberBattleSim graph. This eliminates artificial scaling and ensures that architectural intent is preserved.

## 2. Core Principles
- **Absolute Counts:** The `count` or `min_count/max_count` defined in the YAML are respected exactly.
- **Topological Integrity:** The generator does not mathematically expand or "stretch" the network; it only varies the instantiation via random seeds.
- **LLM as Architect:** The responsibility for network sizing (Small, Medium, Large, XL) rests entirely with the LLM.

## 3. Disjoint Seed Partitioning
To ensure evaluation integrity, training and testing datasets use non-overlapping seed ranges:
- **Train Split:** Seeds 1 – 10,000.
- **Test Split:** Seeds 10,001 – 20,000.

## 4. Stratified Manifests
While mathematical stratification is removed, the generator still outputs a `manifest.json` for each dataset, recording the specific YAML version and seed range used to ensure research reproducibility.
