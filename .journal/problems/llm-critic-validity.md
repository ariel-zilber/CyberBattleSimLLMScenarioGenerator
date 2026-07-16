# LLM Critic Validity

Status: confirmed with a direct parser reproduction.

## Default-score acceptance

`_parse_llm_scores` initializes all six LLM dimensions at score 7, grade B, with
no findings. It then overwrites only fields it successfully recognizes. The
caller rejects only an empty response, not a malformed response.

Direct reproduction:

```text
input: "hello"
overall: 7.0
dimensions: all six = 7
top issues: 0

input: "I cannot comply"
overall: 7.0
dimensions: all six = 7
top issues: 0

input: DIMENSION topology_realism / SCORE 9 only
overall: 7.3
dimensions: topology=9, remaining five=7
top issues: 0
```

After parsing, a seventh static dimension is added and the overall score is
recomputed. Depending on that static score and the configured target, garbage or
partial output can satisfy the actor-critic stopping condition.

## Impact

- Backend refusal or conversational prose can be mistaken for a B-grade audit.
- Missing dimensions are invisible in the final report.
- “No critical issues found” can mean “no findings were parsed.”
- Actor repair may stop based on fabricated defaults rather than model judgment.
- Comparing phase scores across runs is invalid when parse completeness differs.

## Suggested fix

Use a strict JSON schema with:

- exactly the six required LLM dimension keys;
- numeric scores in range;
- explicit findings arrays;
- a parser/schema version and backend/model metadata;
- rejection of unknown, missing, duplicate, or malformed dimensions.

If parsing fails, mark the critic `inconclusive` and do not compute or compare an
overall score. Never impute a neutral/pass score for missing model output.

## Secondary reliability issue

The Gemini CLI fallback creates a temporary prompt file but does not use it; it
places the full prompt in a command-line argument. Large configs may exceed OS
argument limits. This should be treated as backend failure, not silently followed
by score parsing from partial output.
