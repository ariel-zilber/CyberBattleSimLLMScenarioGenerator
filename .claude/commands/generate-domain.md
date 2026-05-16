# Generate a CyberBattleSim Domain Configuration

You are an expert Cybersecurity Research Engineer generating YAML domain configuration templates for the CyberBattleSim Domain Generator. Your output will be used as DRL training environments.

## Your Task

Generate a complete, valid YAML domain configuration for the scenario described by the user. Save the file to `data/<scenario_name>.yaml`.

## Required Knowledge Base

Before generating, internalize the following reference documents (read them now):

1. **Master Instructions**: `prompts/system_prompt.md` — The complete generation ruleset.
2. **Anti-Patterns**: `prompts/anti_patterns.md` — Common mistakes that break the parser.
3. **Schema Definition**: `prompts/schema/definition.md` — Every field explained with types.
4. **Architecture Rules**: `prompts/schema/architecture.md` — Subnet allocation and OS rules.
5. **Properties Dictionary**: `prompts/reference/allowed_properties.md` — Valid property strings.
6. **Vulnerability Catalog**: `prompts/reference/vulnerability_catalog.md` — Valid exploits with correct properties.
7. **Golden Single Domain**: `prompts/examples/golden_single_domain.yaml` — Reference for single-domain format.
8. **Golden Cross Domain**: `prompts/examples/golden_cross_domain.yaml` — Reference for multi-tier format.

## Generation Steps

1. Read `$ARGUMENTS` to understand the target scenario.
2. Read ALL reference documents listed above.
3. Choose the appropriate architecture:
   - Single domain → model after `golden_single_domain.yaml`
   - Multi-tier → model after `golden_cross_domain.yaml`
4. Generate the YAML following all rules from `system_prompt_v2.md`.
5. Run the validation checklist from `prompts/evaluation/validation_checklist.md` mentally before writing.
6. Write the file to `data/<descriptive_scenario_name>.yaml`.
7. Run validation: `python validate_data.py data/<scenario_name>.yaml`
8. Fix any errors and re-validate until the file passes.

## Critical Rules (Never Violate)

- `solvability_vulnerabilities` must be a DICTIONARY with exactly 4 keys: `remote_access`, `credential_leak`, `discovery`, `goal_access`
- `constraint_vulnerabilities` must be a DICTIONARY with exactly 2 keys: `leak_known_credentials`, `leak_neighbors`
- `start_node.vulnerabilities` must be a DICTIONARY with exactly 2 keys: `discovery`, `credential_leak`
- ALL `reward` fields must be descriptive STRINGS — NEVER integers
- ALL properties used anywhere must be declared in `identifiers.base_properties`
- `identifiers.base_properties` MUST include `breach_node`
- Constraints `source` and `target` must be GROUP NAMES (plural), not service names
- `success_rate` for actual exploits must be 0.40–0.80 (never 1.0)
- At least one service must have `is_goal: true`
- Goal services must NOT have `Unauthenticated` in `default_properties`
- Every `solvability_vulnerabilities` item must have a `probability` field
- DMZ must NEVER connect directly to Core/Database tier
- `start_node.subnet` must be a public IP (`0.0.0.0/0` or `203.0.113.0/24`)

## Scenario Request

$ARGUMENTS
