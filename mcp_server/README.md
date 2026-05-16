# CyberBattleSim Domain Generator MCP Server

This MCP server exposes the CyberBattleSim Domain Generator as a set of tools
for use with Claude Code or any MCP-compatible client.

## Tools

| Tool | Description |
|------|-------------|
| `generate_template_yaml` | Returns the full prompt package (system prompt + examples + catalogs) for generating a new domain config YAML |
| `run_pipeline` | Runs the full generation + evaluation pipeline on a config file |
| `get_pipeline_summary` | Reads and parses the evaluation results from a completed pipeline run |
| `fix_template` | Applies automatic fixes to a config based on pipeline evaluation results |
| `validate_config` | Fast structural validation of a config YAML (no generation) |
| `list_configs` | Lists all available domain configs and recent pipeline runs |
| `read_prompt_file` | Read any file from the prompts/ reference library |

## The Tract-Style Generation Loop

```
1. generate_template_yaml(scenario_description="...", scenario_name="my_scenario")
   → Returns prompt package to feed to your LLM

2. [LLM generates YAML → save to data/my_scenario.yaml]

3. validate_config(config_path="data/my_scenario.yaml")
   → Quick check before running the full pipeline

4. run_pipeline(config_path="data/my_scenario.yaml", train_count=3, test_count=1)
   → Generates scenarios and evaluates quality
   → Returns run_id and output_dir

5. get_pipeline_summary(output_dir="<output_dir from step 4>")
   → Returns structured analysis with recommendations

6. fix_template(config_path="data/my_scenario.yaml", output_dir="<output_dir>")
   → Applies automatic fixes → returns new_config_path

7. [Repeat from step 3 with new_config_path until all metrics pass]
```

## Installation

```bash
pip install -r mcp_server/requirements.txt
```

## Running

```bash
python mcp_server/domain_generator_mcp.py
```

## Registering with Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "cyberbattlesim": {
      "command": "python",
      "args": ["/absolute/path/to/CyberBattleSimDomainGenerator/mcp_server/domain_generator_mcp.py"]
    }
  }
}
```

## Registering with Claude Code

Add to `.mcp.json` in the repo root:

```json
{
  "mcpServers": {
    "cyberbattlesim": {
      "command": "python",
      "args": ["mcp_server/domain_generator_mcp.py"]
    }
  }
}
```
