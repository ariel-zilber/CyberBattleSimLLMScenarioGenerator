from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .catalogs import NODE_TEMPLATES, SPECIALISTS, validate_catalogs
from .lark_parser import parse_lark_dsl
from .llm_generator import GenerationResult
from .path_analysis import analyze_paths
from .validator import validate
from .expansion import ExpansionResult, expand_scenario, parse_expansion_dsl
from .model import ScenarioSpec


DSL_REFERENCE = """\
scenario NAME using SPECIALIST[, SPECIALIST...] {
  node NODE: TEMPLATE in ZONE [goal] {
    props PROPERTY[, PROPERTY...]
    service SERVICE [accepts CREDENTIAL[, CREDENTIAL...]]
  }
  initially discover NODE[, NODE...]
  allow ZONE -> ZONE on SERVICE
  block ZONE -> ZONE on SERVICE
  SOURCE -> TARGET: discover VULN by SPECIALIST [requires PRIVILEGE]
  SOURCE -> TARGET: exploit VULN by SPECIALIST grants PRIVILEGE [requires PRIVILEGE] [needs PROPERTY[, PROPERTY...]]
  SOURCE -> TARGET: leak VULN credential CREDENTIAL via SERVICE by SPECIALIST [requires PRIVILEGE]
  SOURCE -> TARGET: connect VULN via SERVICE using CREDENTIAL by SPECIALIST grants PRIVILEGE [requires PRIVILEGE]
  NODE -> NODE: escalate VULN by SPECIALIST from PRIVILEGE to PRIVILEGE [needs PROPERTY[, PROPERTY...]]
  target NODE at PRIVILEGE depth MIN [to MAX] [through ZONE[, ZONE...]]
}

PRIVILEGE is one of NONE, USER, ADMIN, SYSTEM. Names are unquoted identifiers.
Every referenced node, credential, service, zone, and specialist must be declared.
Every credential used by connect must be leaked and accepted by the target service.
"""


DSL_EXAMPLE = """\
scenario example using s_network, s_linux {
  node gateway: linux_gateway in perimeter {
    service SSH accepts server_key
  }
  node server: linux_server in internal goal {
    service SSH accepts server_key
  }
  initially discover gateway
  allow perimeter -> internal on SSH
  start -> gateway: exploit GatewayRCE by s_network grants USER needs Linux
  gateway -> server: discover FindServer by s_linux requires USER
  gateway -> server: leak ServerKey credential server_key via SSH by s_linux requires USER
  gateway -> server: connect ServerSSH via SSH using server_key by s_linux grants USER requires USER
  server -> server: escalate RootEscalation by s_linux from USER to SYSTEM needs Linux
  target server at SYSTEM depth 5 to 5 through perimeter, internal
}
"""


def build_lark_prompt(request: str, feedback: list[str] | None = None) -> str:
    templates = ", ".join(sorted(NODE_TEMPLATES))
    specialists = ", ".join(sorted(SPECIALISTS))
    prompt = f"""Generate exactly one scenario in the CyberBattleSim Lark DSL.
Do not output Markdown or prose.

Static node templates: {templates}
Static specialists: {specialists}

LANGUAGE REFERENCE:
{DSL_REFERENCE}

VALID EXAMPLE:
{DSL_EXAMPLE}

Every transition must use `by specialist`. Define explicit `allow` policies for
each connect path and explicit `block` policies for forbidden cross-zone paths.
The target contract must declare privilege, depth range, and required zone order.

REQUEST:
{request}
"""
    if feedback:
        prompt += "\nVALIDATION ERRORS:\n- " + "\n- ".join(feedback)
        prompt += "\nReturn the complete corrected scenario."
    return prompt


def generate_lark_with_model(
    request: str,
    call_model: Callable[[str], str],
    max_attempts: int = 3,
) -> GenerationResult:
    catalog_errors = validate_catalogs()
    if catalog_errors:
        raise ValueError("Static catalogs are invalid: " + "; ".join(catalog_errors))
    feedback: list[str] = []
    for attempt in range(1, max_attempts + 1):
        try:
            spec = parse_lark_dsl(call_model(build_lark_prompt(request, feedback)))
            validation = validate(spec)
            feedback = list(validation.errors)
            if feedback:
                continue
            analysis = analyze_paths(spec)
            if not analysis.result.solved:
                feedback = ["No gated path reaches the target privilege"]
            elif analysis.result.minimum_depth is None or analysis.result.minimum_depth < spec.goal.minimum_depth:
                feedback = [
                    f"Shortcut: minimum depth {analysis.result.minimum_depth}, "
                    f"required {spec.goal.minimum_depth}"
                ]
            elif spec.goal.maximum_depth is not None and analysis.result.minimum_depth > spec.goal.maximum_depth:
                feedback = [f"Minimum depth {analysis.result.minimum_depth} exceeds {spec.goal.maximum_depth}"]
            elif not analysis.required_zones_present:
                feedback = [f"Minimum path does not cross zones {list(spec.goal.required_zones)} in order"]
            else:
                return GenerationResult(spec, attempt, tuple(feedback))
        except Exception as exc:
            feedback = [f"Parse failed: {exc}"]
    raise ValueError("Lark scenario generation failed: " + "; ".join(feedback))


@dataclass(frozen=True)
class ExpansionGenerationResult:
    expansion: ExpansionResult
    source: str
    attempts: int


def build_expansion_prompt(
    request: str,
    base_source: str,
    feedback: list[str] | None = None,
) -> str:
    templates = ", ".join(sorted(NODE_TEMPLATES))
    specialists = ", ".join(sorted(SPECIALISTS))
    prompt = f"""Generate exactly one expansion in the CyberBattleSim Lark DSL.
Do not output Markdown, prose, or a complete replacement scenario.
Begin with `expansion NAME using ...` and declare only new nodes and additions.
Never redeclare or modify a base node. Declare a new target and full merged depth contract.

Static node templates: {templates}
Static specialists: {specialists}

LANGUAGE REFERENCE:
{DSL_REFERENCE.replace('scenario NAME', 'expansion NAME')}

IMMUTABLE BASE SCENARIO:
{base_source}

EXPANSION REQUEST:
{request}
"""
    if feedback:
        prompt += "\nMERGED VALIDATION ERRORS:\n- " + "\n- ".join(feedback)
        prompt += "\nReturn the complete corrected expansion only."
    return prompt


def generate_expansion_with_model(
    base: ScenarioSpec,
    base_source: str,
    request: str,
    call_model: Callable[[str], str],
    max_attempts: int = 3,
) -> ExpansionGenerationResult:
    feedback: list[str] = []
    for attempt in range(1, max_attempts + 1):
        source = call_model(build_expansion_prompt(request, base_source, feedback))
        try:
            delta = parse_expansion_dsl(source)
            result = expand_scenario(base, delta)
            feedback = list(result.validation.errors)
            if feedback:
                continue
            analysis = analyze_paths(result.spec)
            if not analysis.result.solved:
                feedback = ["No gated path reaches the expanded target privilege"]
            elif analysis.result.minimum_depth is None or analysis.result.minimum_depth < result.spec.goal.minimum_depth:
                feedback = [
                    f"Shortcut: merged minimum depth {analysis.result.minimum_depth}, "
                    f"required {result.spec.goal.minimum_depth}"
                ]
            elif (result.spec.goal.maximum_depth is not None
                  and analysis.result.minimum_depth > result.spec.goal.maximum_depth):
                feedback = [
                    f"Merged minimum depth {analysis.result.minimum_depth} exceeds "
                    f"{result.spec.goal.maximum_depth}"
                ]
            elif not analysis.required_zones_present:
                feedback = [
                    f"Minimum path does not cross zones {list(result.spec.goal.required_zones)} in order"
                ]
            else:
                return ExpansionGenerationResult(result, source, attempt)
        except Exception as exc:
            feedback = [f"Expansion failed: {exc}"]
    raise ValueError("Lark expansion generation failed: " + "; ".join(feedback))
