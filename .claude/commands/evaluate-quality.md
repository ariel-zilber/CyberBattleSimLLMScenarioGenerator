# Evaluate CyberBattleSim Scenario Quality

Evaluate the realism quality of a generated domain configuration across 5 dimensions and produce an actionable improvement report.

## Your Task

Given a domain config YAML file path (or domain name), run the quality evaluator and produce a structured realism report with specific fixes for each issue found.

## Steps

1. **Resolve the config path** from `$ARGUMENTS`:
   - Full path → use directly
   - Domain name like `active_directory` → look for `data/<name>.yaml`
   - No argument → call `list_configs` MCP tool and ask the user to pick one

2. **Call the MCP tool** `evaluate_scenario_quality` with the resolved path.

3. **Display the formatted report** returned in `formatted_report`.

4. **For each finding with type `critical` or `fail`**, provide a concrete YAML fix:
   - Cross-reference with `prompts/anti_patterns.md` if a `ref` field is present
   - Show the broken YAML snippet and the corrected version
   - Prioritise in order: CRITICAL → FAIL → WARNING

5. **Read the evaluation criteria** from `prompts/evaluation/quality_criteria.md` (via `read_prompt_file`) if you need to explain the scoring logic to the user.

6. **Offer to apply fixes** — ask the user if they want you to edit the config file directly to resolve the issues found.

## Dimensions Evaluated (each 0–10)

| # | Dimension | Key Checks |
|---|-----------|------------|
| 1 | Network Topology Realism | Subnet segmentation, RFC 1918 addresses, OS diversity, node count |
| 2 | Properties & Vulnerabilities Realism | Exploit names, success rates (0.40–0.80), match_properties specificity |
| 3 | Scenario Difficulty | Attack flow depth, goal density, lateral movement requirements |
| 4 | Firewall Rules Realism | Protocol specificity, DMZ isolation, no direct DMZ→Core connections |
| 5 | General Realism | Service naming, asset values, service diversity, attack narrative |

## Output Format

Display the `formatted_report` from the MCP tool, then follow up with this structure:

```
QUALITY EVALUATION: <config_name>
==================================
Overall: <score>/10  Grade: <grade>

DIMENSION BREAKDOWN:
  Network Topology Realism          <score>/10 (<grade>)
  Properties & Vulnerabilities      <score>/10 (<grade>)
  Scenario Difficulty               <score>/10 (<grade>)
  Firewall Rules Realism            <score>/10 (<grade>)
  General Realism                   <score>/10 (<grade>)

CRITICAL ISSUES (fix immediately):
  1. [Dimension]: <issue>
     Fix: <specific YAML change>

WARNINGS (improve realism):
  1. [Dimension]: <issue>
     Suggestion: <improvement>

NEXT STEPS:
  1. <highest priority fix>
  2. <second priority fix>
```

## Arguments

$ARGUMENTS
