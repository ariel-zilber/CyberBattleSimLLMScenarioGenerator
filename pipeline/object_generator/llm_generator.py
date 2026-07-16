from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .dsl_parser import DSLParseError, parse_dsl
from .model import ScenarioSpec
from .state_bfs import find_minimum_solution
from .validator import validate


SYSTEM_PROMPT = """You generate compact CyberBattleSim Scenario DSL.
Return exactly one Scenario(...) expression and no executable Python.
Allowed constructors: Scenario, Node, Initial, Goal, Discover, Probe,
RemoteExploit, LeakCredential, Connect, Escalate.
The target must reach the requested privilege at a shortest action depth inside
the requested range. Every credential must be accepted by the named target
service. Escalation is local and must increase privilege.
"""


@dataclass(frozen=True)
class GenerationResult:
    spec: ScenarioSpec
    attempts: int
    feedback: tuple[str, ...]


def generate_with_model(
    request: str,
    call_model: Callable[[str], str],
    max_attempts: int = 3,
) -> GenerationResult:
    """Generate and repair a ScenarioSpec through an injected Claude/API callable."""
    feedback: list[str] = []
    for attempt in range(1, max_attempts + 1):
        prompt = SYSTEM_PROMPT + "\nREQUEST:\n" + request
        if feedback:
            prompt += "\n\nVALIDATION ERRORS FROM THE PREVIOUS ATTEMPT:\n- " + "\n- ".join(feedback)
            prompt += "\nReturn the complete corrected Scenario(...)."
        try:
            spec = parse_dsl(call_model(prompt))
        except (DSLParseError, KeyError, ValueError) as exc:
            feedback = [f"DSL parse failed: {exc}"]
            continue
        result = validate(spec)
        feedback = list(result.errors)
        if feedback:
            continue
        bfs = find_minimum_solution(spec)
        if not bfs.solved:
            feedback = ["No valid action sequence reaches the goal privilege"]
            continue
        if bfs.minimum_depth is None or bfs.minimum_depth < spec.goal.minimum_depth:
            feedback = [
                f"Shortcut detected: shortest depth {bfs.minimum_depth}, "
                f"required at least {spec.goal.minimum_depth}"
            ]
            continue
        if spec.goal.maximum_depth is not None and bfs.minimum_depth > spec.goal.maximum_depth:
            feedback = [
                f"Shortest depth {bfs.minimum_depth} exceeds maximum {spec.goal.maximum_depth}"
            ]
            continue
        return GenerationResult(spec, attempt, tuple(feedback))
    raise ValueError("Scenario generation failed: " + "; ".join(feedback))
