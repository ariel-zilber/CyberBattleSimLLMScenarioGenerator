# Design Grill — Answers

Fill in responses below. Each section corresponds to a question block in `grill_questions.md`.

---

## Q1 — S_Recon BFS Filtering: Category vs. Type

**Q1a.** In the CBS data model, is there a sub-category field that distinguishes `remote_access` RCEs from `credential_leak` / `discovery` REMOTE entries — or are they all just `VulnerabilityType.REMOTE`?

> 

**Q1b.** If no sub-category exists, filtering for S_Recon must be done by vulnerability name (e.g., `Solvability.*` prefix). Is that the intended mechanism, and where is the naming convention enforced?

> 

**Q1c.** Does the KNOWS constraint appear in the environment's vulnerability dictionary, or is it a graph-level CBS mechanic the BFS never sees? Is that a gap?

> 

---

## Q2 — Action Space Overlap: S_Windows vs S_Identity

**Q2a.** Where exactly is the S_Windows / S_Identity partition defined?

> 

**Q2b.** Is PrintNightmare/SpoolSample classified as S_Windows or S_Identity? What is the decision rule?

> 

**Q2c.** Can an S_Identity config validly contain Windows OS RCEs as intermediate steps, or must all Windows RCEs come from pre-owned handoff nodes?

> 

**Q2d.** When BFS filtering for S_Identity is implemented, what mechanism determines which vulnerabilities are allowed — allowlist, node-property predicate, or something else? Who maintains it?

> 

---

## Q3 — Meta Stage 4 BFS Validity

**Q3a.** What does BFS solvability actually validate for Stage 4 adversarial configs?

> 

**Q3b.** Should Stage 4 configs use `GreedyExplorationAgent` as the solvability test instead of BFS?

> 

**Q3c.** For `meta_stagnation_v1` — is BFS solvability the wrong success criterion? What should the criterion be?

> 

**Q3d.** Is there a risk that adversarial properties (e.g., a decoy on a choke-point) cause Stage 4 configs to fail the BFS gate they're not supposed to fail?

> 

---

## Q4 — Small Config Technique Isolation

**Q4a.** Intent of small configs: train individual sub-skills (curriculum), or independent complete scenarios that emphasize one technique?

> 

**Q4b.** Risk of technique overfitting on small configs — will the agent transfer to medium configs that require choosing between techniques?

> 

**Q4c.** S_Recon small configs also isolate credential-extraction mechanics. Is this intentional curriculum design or a naming side effect?

> 

**Q4d.** S_Network small configs differentiate by topology shape, not CVE technique. Is this a deliberate difference from S_Identity's technique-isolation approach? Why?

> 

---

## Q5 — The `maximum_node_count=100` Hardcoded Cap

**Q5a.** What does `maximum_node_count=100` control in `ImprovedCyberBattleEnv` — observation space cap, actual node truncation, or something else?

> 

**Q5b.** Does BFS run over all nodes regardless of the cap, or does it also only see 100?

> 

**Q5c.** Is the cap set correctly for actual DRL training runs, or is Phase 2 BFS evaluation running in a different observation window than training will use?

> 

---

## Q6 — Scoring Semantics

**Q6a.** Which score do the task README numbers represent — LLM critic quality, BFS difficulty, or a combination?

> 

**Q6b.** Is a high difficulty score good or bad? Is there a target range where the scenario is "hard enough to be interesting, easy enough to be learnable"?

> 

**Q6c.** Is there a target difficulty range per tier (e.g., small=EASY, XL=EXTREME)? Or is difficulty not expected to correlate with tier?

> 
