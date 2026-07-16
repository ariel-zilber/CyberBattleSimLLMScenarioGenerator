# Train/Test Contamination and Diversity

Status: confirmed scope gap; no claim that a particular final dataset is
contaminated without a content-hash audit.

## Current checks

The post-static audit checks train/test numeric ID overlap. IDs are intentionally
drawn from disjoint ranges (train near 1, test near 10001), so this verifies naming
policy rather than content independence.

It also constructs a structural signature from:

- node count and goal count;
- property frequency histogram;
- service frequency histogram;
- vulnerability frequency histogram.

Edge endpoints, node identities, credential targets, firewall rules, outcome
payloads, preconditions, values, and goal types are absent. Two materially
different graphs can collide in this representation; conversely it cannot
quantify near-duplicate causal structure. Matches are warnings, not failures.

## Jaccard is vocabulary overlap, not contamination

The runner builds each scenario's set of vulnerability names and reports pairwise
and cross-split Jaccard similarity. Specialist scenarios are intentionally drawn
from a shared fixed vocabulary, so high overlap is expected and does not prove
sample duplication. Low overlap also does not prove graph independence.

Only scenarios having `run_metrics.json` are included. Node parse exceptions are
silently skipped, including known start-node tag issues. The reported train/test
counts therefore describe the analyzed subset, not necessarily the manifest.

## Suggested fix

- Canonicalize and hash complete semantic scenario content after removing only
  non-semantic serialization order.
- Hard-fail exact cross-split hash duplicates.
- Add graph-isomorphism or stable Weisfeiler-Lehman-style hashes labeled with
  node roles, outcomes, prerequisites, credentials, firewall policy, and goals.
- Report near-duplicate similarity separately from vocabulary coverage.
- Account for every manifest slot and mark skipped parsing as inconclusive.
- Persist seed-family derivation and enforce split-specific seed namespaces after
  deterministic generation is fixed.
