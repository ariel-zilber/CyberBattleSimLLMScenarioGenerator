# Data Generation Investigation Journal

> **Verification notice (2026-07-15):** The problem index is an audit inventory,
> not a count of proven production bugs. Some entries are source-level risks,
> quality concerns, or findings in the isolated object-generator MVP. Use
> `context/verification-ledger.md` for current evidence strength, withdrawals,
> and production-versus-experimental scope before quoting any finding.

This hidden directory is durable context for investigating the LLM scenario
generation pipeline. It records claims separately from evidence so that a later
session can resume without treating an unverified hypothesis as a fact.

## Layout

- `context/` — architecture, terminology, and pipeline maps.
- `problems/` — confirmed defects, impact, evidence, and suggested fixes.
- `hypotheses/` — plausible issues that still need reproduction.
- `evidence/` — command outputs and compact observations.
- `runs/` — validation-loop summaries.

## Investigation protocol

1. Map the relevant code path before judging generated data.
2. Label every claim as confirmed, likely, or open.
3. Preserve a minimal reproduction or precise source location.
4. Distinguish structural/static validity from dynamic solvability.
5. Distinguish scenario-generation defects from training/metrics defects.
6. Never mark a check as passed when it was skipped, inconclusive, or interrupted.

## Current status

The current filesystem is substantially ahead of `HEAD`: 49 tracked files are
modified and many new generator, solver, test, report, and output artifacts are
untracked. Reviews therefore apply to the working tree unless explicitly marked
as committed-code-only.

See [problems/index.md](problems/index.md) for prioritized findings.
