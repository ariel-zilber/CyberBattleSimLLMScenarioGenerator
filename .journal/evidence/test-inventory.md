# Focused Test Inventory

Command:

```text
pytest --collect-only -q tests/test_post_generation_static_audit.py \
  tests/test_specialist_coverage.py tests/condition_solver tests/object_generator
```

Result: 203 tests collected in 0.06 seconds.

Composition:

- 9 post-generation static-audit tests;
- 6 fast specialist catalog/template tests;
- approximately 186 specialist coverage assertions, including one assertion per
  vocabulary slot plus train/test split checks;
- 4 condition-solver tests;
- 18 object-generator/language tests.

The first 15 dots seen during execution correspond exactly to the 9 post-static
tests and 6 fast specialist tests. The next test requests `dataset_coverage`, whose
session fixture recursively reads every `nodes/*.yaml` under the default
`output_specialist_meta_pipeline` until full coverage is found or input is
exhausted. On a large or incomplete dataset this can be slow and silent.

Review implication: compilation passed, 15 initial tests passed, and the remaining
focused suite was not completed. It must not be reported as a full test pass.
