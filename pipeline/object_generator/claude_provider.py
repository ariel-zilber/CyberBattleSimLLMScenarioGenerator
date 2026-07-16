from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence


class ClaudeProviderError(RuntimeError):
    """Raised when Claude CLI cannot return a usable scenario."""


Runner = Callable[..., subprocess.CompletedProcess[str]]


def call_claude_cli(
    prompt: str,
    *,
    model: str = "sonnet",
    timeout: int = 300,
    executable: str = "claude",
    runner: Runner = subprocess.run,
    extra_args: Sequence[str] = (),
) -> str:
    """Generate one DSL response through Claude Code's non-interactive CLI.

    The command is invoked as an argument vector with ``shell=False`` (the
    subprocess default). The prompt is supplied on stdin, so scenario text is
    never interpreted as a shell command.
    """
    command = [
        executable,
        "--print",
        "--no-session-persistence",
        "--disable-slash-commands",
        "--model",
        model,
        "--mcp-config",
        '{"mcpServers":{}}',
        "--strict-mcp-config",
        *extra_args,
    ]
    try:
        result = runner(
            command,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ClaudeProviderError(
            f"Claude CLI executable not found: {executable}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ClaudeProviderError(
            f"Claude CLI exceeded the {timeout}s timeout"
        ) from exc
    except OSError as exc:
        raise ClaudeProviderError(f"Claude CLI could not start: {exc}") from exc

    response = (result.stdout or "").strip()
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no diagnostic output").strip()
        raise ClaudeProviderError(
            f"Claude CLI exited with status {result.returncode}: {detail[:500]}"
        )
    if not response:
        raise ClaudeProviderError("Claude CLI returned an empty response")
    return response
