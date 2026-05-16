# Technical Specification: Training Feasibility Metric (CSR) (Q27)
**Status:** FINAL (Formalized 2026-05-16)

## 1. Overview
The "Cumulative Success Rate" (CSR) measures the end-to-end probability of a successful attack path. It serves as the primary "Training Feasibility" signal for the Actor-Critic loop.

## 2. The Formula
For the shortest path $P$ from entry to goal, where $SR_i$ is the success rate of the exploit at hop $i$:
$$CSR = \prod_{i \in P} SR_i$$

## 3. LLM Critic Rubric
The `ScenarioQualityEvaluator` injects CSR results into the LLM prompt with the following status codes:

| CSR Range | Status | LLM Instruction |
|-----------|--------|-----------------|
| **> 25%** | HEALTHY | High convergence potential. |
| **15% - 25%** | WARNING | Potential sparse reward; consider increasing individual SR. |
| **< 10%** | CRITICAL | DRL-impossible due to reward sparsity; repair MANDATORY. |

## 4. DRL Impact
The CSR ensures that the LLM does not design architectures that are "too difficult to learn." It forces a trade-off between path depth and exploit reliability, ensuring the agent sees the "Goal Reward" often enough to converge.
