from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from pipeline.object_generator.catalogs import validate_catalogs
from pipeline.object_generator.compiler import write_compiled_scenario
from pipeline.object_generator.dsl_parser import DSLParseError
from pipeline.object_generator.lark_parser import parse_lark_dsl
from pipeline.object_generator.lark_generator import generate_lark_with_model
from pipeline.object_generator.path_analysis import analyze_paths
from pipeline.object_generator.state_bfs import find_minimum_solution
from pipeline.object_generator.validator import validate


EXAMPLE = Path("examples/object_generator/perimeter_to_domain.larkdsl")


def source():
    return EXAMPLE.read_text(encoding="utf-8")


def test_static_catalog_is_self_consistent():
    assert validate_catalogs() == []


def test_lark_example_has_exact_specialist_path_contract():
    spec = parse_lark_dsl(source())
    validation = validate(spec)
    analysis = analyze_paths(spec)

    assert validation.errors == ()
    assert analysis.result.minimum_depth == 9
    assert analysis.required_zones_present
    assert analysis.visited_zones == ("perimeter", "server_farm", "corporate")
    assert analysis.bypassable_mandatory == ()
    assert {a.specialist for a in analysis.result.actions} == {"s_network", "s_linux", "s_identity"}


def test_lark_reports_line_and_column_for_bad_syntax():
    with pytest.raises(DSLParseError, match=r"line \d+, column \d+"):
        parse_lark_dsl(source().replace("grants USER", "gives USER", 1))


def test_unknown_template_is_rejected_statically():
    spec = parse_lark_dsl(source().replace("linux_gateway", "invented_gateway", 1))
    assert any("unknown template invented_gateway" in e for e in validate(spec).errors)


def test_specialist_cannot_use_action_outside_profile():
    spec = parse_lark_dsl(source().replace(
        "escalate SystemEscalation by s_identity",
        "escalate SystemEscalation by s_network",
    ))
    errors = validate(spec).errors
    assert any("escalate is not allowed for s_network" in e for e in errors)


def test_missing_firewall_allow_makes_path_unsolvable():
    spec = parse_lark_dsl(source().replace("allow server_farm -> corporate on LDAP", "block server_farm -> corporate on LDAP"))
    assert not find_minimum_solution(spec).solved


def test_duplicate_firewall_rule_is_rejected():
    text = source().replace(
        "allow perimeter -> server_farm on SSH",
        "allow perimeter -> server_farm on SSH\n  block perimeter -> server_farm on SSH",
    )
    assert any("Ambiguous duplicate firewall policy" in e for e in validate(parse_lark_dsl(text)).errors)


def test_compiler_emits_explicit_block_rule(tmp_path):
    spec = parse_lark_dsl(source())
    scenario = write_compiled_scenario(spec, tmp_path)
    dc = yaml.safe_load((scenario / "nodes" / "dc.yaml").read_text())
    assert any(rule["permission"] == 1 and rule["port"] == "LDAP"
               for rule in dc["firewall"]["incoming"])


def test_restricted_specialist_bfs_cannot_use_other_specialists():
    spec = parse_lark_dsl(source())
    assert not find_minimum_solution(spec, allowed_specialists=frozenset({"s_identity"})).solved
    assert find_minimum_solution(
        spec, allowed_specialists=frozenset({"s_network", "s_linux", "s_identity"})
    ).solved


def test_lark_model_loop_returns_static_validated_scenario():
    result = generate_lark_with_model("Generate the fixture", lambda _prompt: source())
    assert result.attempts == 1
    assert result.spec.goal.minimum_depth == 9
