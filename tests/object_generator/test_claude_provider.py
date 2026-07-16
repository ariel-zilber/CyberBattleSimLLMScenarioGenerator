import subprocess

import pytest

from pipeline.object_generator.claude_provider import ClaudeProviderError, call_claude_cli
from pipeline.object_generator.cli import main
from pipeline.object_generator.lark_generator import build_lark_prompt


EXAMPLE = "examples/object_generator/perimeter_to_domain.larkdsl"


def test_claude_provider_uses_bounded_noninteractive_command():
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="scenario generated using s_linux {}\n", stderr="")

    response = call_claude_cli("generate", model="sonnet", timeout=17, runner=runner)

    assert response == "scenario generated using s_linux {}"
    command, kwargs = calls[0]
    assert command[:3] == ["claude", "--print", "--no-session-persistence"]
    assert "--strict-mcp-config" in command
    assert kwargs["input"] == "generate"
    assert kwargs["timeout"] == 17
    assert kwargs["check"] is False


def test_claude_provider_reports_nonzero_exit_without_returning_output():
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 2, stdout="", stderr="authentication failed")

    with pytest.raises(ClaudeProviderError, match="authentication failed"):
        call_claude_cli("generate", runner=runner)


def test_generation_prompt_contains_language_and_example():
    prompt = build_lark_prompt("Create a scenario")

    assert "LANGUAGE REFERENCE:" in prompt
    assert "VALID EXAMPLE:" in prompt
    assert "target server at SYSTEM depth 5 to 5" in prompt
    assert "Do not output Markdown or prose" in prompt


def test_cli_generates_validated_artifact_through_claude_provider(tmp_path, monkeypatch):
    source = open(EXAMPLE, encoding="utf-8").read()
    monkeypatch.setattr(
        "pipeline.object_generator.cli.call_claude_cli", lambda prompt, **kwargs: source
    )

    status = main([
        "--request", "Generate the fixture", "--output", str(tmp_path),
        "--claude-timeout", "5",
    ])

    scenario = tmp_path / "object_perimeter_to_domain_0002"
    assert status == 0
    assert (scenario / "nodes" / "dc.yaml").is_file()
    assert (scenario / "identifiers" / "identifiers.yaml").is_file()
