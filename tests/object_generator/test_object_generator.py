from pathlib import Path

import pytest
import yaml

from pipeline.object_generator.compiler import compile_identifiers, compile_nodes, write_compiled_scenario
from pipeline.object_generator.dsl_parser import DSLParseError, parse_dsl
from pipeline.object_generator.llm_generator import generate_with_model
from pipeline.object_generator.state_bfs import find_minimum_solution
from pipeline.object_generator.validator import validate


EXAMPLE = Path("examples/object_generator/perimeter_to_domain.dsl")


def load_example():
    return parse_dsl(EXAMPLE.read_text(encoding="utf-8"))


def test_example_is_valid_and_has_exact_depth_nine():
    spec = load_example()
    validation = validate(spec)
    bfs = find_minimum_solution(spec)

    assert validation.errors == ()
    assert bfs.solved
    assert bfs.minimum_depth == 9
    assert bfs.actions[-1].vulnerability == "SystemEscalation"


def test_parser_rejects_executable_python():
    with pytest.raises((DSLParseError, SyntaxError)):
        parse_dsl("__import__('os').system('touch /tmp/should-not-exist')")


def test_validator_rejects_credential_not_accepted_by_service():
    source = EXAMPLE.read_text(encoding="utf-8").replace(
        'Connect("app", "dc", "LDAP", "domain_user"',
        'Connect("app", "dc", "LDAP", "wrong_password"',
    )
    result = validate(parse_dsl(source))
    assert any("wrong_password is not accepted" in error for error in result.errors)
    assert any("wrong_password is never" in error for error in result.errors)


def test_validator_rejects_nonlocal_escalation():
    source = EXAMPLE.read_text(encoding="utf-8").replace(
        'Escalate("dc", "dc", "SystemEscalation"',
        'Escalate("app", "dc", "SystemEscalation"',
    )
    result = validate(parse_dsl(source))
    assert any("escalation must stay on the same node" in error for error in result.errors)


def test_shortcut_is_detected_by_minimum_depth():
    source = EXAMPLE.read_text(encoding="utf-8").replace(
        "    ],\n    initial=Initial",
        '        RemoteExploit("start", "dc", "DirectDC", grants="System"),\n'
        "    ],\n    initial=Initial",
    ).replace('discovered=["gateway"]', 'discovered=["gateway", "dc"]')
    spec = parse_dsl(source)
    bfs = find_minimum_solution(spec)
    assert bfs.minimum_depth == 1
    assert bfs.minimum_depth < spec.goal.minimum_depth


def test_compiler_writes_existing_node_yaml_shape(tmp_path):
    spec = load_example()
    scenario_dir = write_compiled_scenario(spec, tmp_path)
    dc = yaml.safe_load((scenario_dir / "nodes" / "dc.yaml").read_text())
    gateway = yaml.safe_load((scenario_dir / "nodes" / "gateway.yaml").read_text())

    assert dc["is_goal"] is True
    assert dc["vulnerabilities"]["SystemEscalation"]["outcome"]["type"] == "privilege_escalation"
    assert gateway["vulnerabilities"]["GatewayRCE"]["outcome"]["type"] == "lateral_move"
    assert (scenario_dir / "scenario.sha256").is_file()
    identifiers = yaml.safe_load(
        (scenario_dir / "identifiers" / "identifiers.yaml").read_text()
    )
    assert "SystemEscalation" in identifiers["local_vulnerabilities"]
    assert "GatewayRCE" in identifiers["remote_vulnerabilities"]
    assert "LDAP" in identifiers["ports"]
    assert yaml.safe_load(
        (scenario_dir / "vulnerability_library" / "vulnerability_library.yaml").read_text()
    ) == {}


def test_identifier_catalog_is_derived_from_compiled_duplicate_names():
    spec = load_example()
    duplicate = spec.transitions[0]
    spec.transitions.append(duplicate)
    nodes = compile_nodes(spec)

    identifiers = compile_identifiers(nodes)

    assert duplicate.vulnerability in identifiers["remote_vulnerabilities"]
    assert f"{duplicate.vulnerability}_{len(spec.transitions) - 1}" in identifiers["remote_vulnerabilities"]


def test_model_feedback_loop_repairs_invalid_first_attempt():
    valid = EXAMPLE.read_text(encoding="utf-8")
    responses = iter(["not a scenario", valid])
    prompts = []

    def model(prompt):
        prompts.append(prompt)
        return next(responses)

    result = generate_with_model("Generate a depth-nine perimeter scenario", model)
    assert result.attempts == 2
    assert "VALIDATION ERRORS" in prompts[1]
