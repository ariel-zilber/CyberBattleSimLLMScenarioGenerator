from pathlib import Path

import pytest

from pipeline.object_generator.expansion import (
    ExpansionError,
    expand_scenario,
    fingerprint_spec,
    parse_expansion_dsl,
)
from pipeline.object_generator.lark_parser import parse_lark_dsl
from pipeline.object_generator.state_bfs import find_minimum_solution
from pipeline.object_generator.cli import main
from pipeline.object_generator.lark_generator import generate_expansion_with_model


BASE = Path("examples/object_generator/perimeter_to_domain.larkdsl")
EXPANSION = Path("examples/object_generator/perimeter_to_database.expansion.larkdsl")


def load_pair():
    return (
        parse_lark_dsl(BASE.read_text()),
        parse_expansion_dsl(EXPANSION.read_text()),
    )


def test_expansion_preserves_base_and_extends_minimum_path():
    base, delta = load_pair()
    fingerprint = fingerprint_spec(base)

    result = expand_scenario(base, delta)
    bfs = find_minimum_solution(result.spec)

    assert result.validation.errors == ()
    assert fingerprint_spec(base) == fingerprint == result.base_fingerprint
    assert result.added_nodes == ("database",)
    assert result.added_transitions == 4
    assert bfs.solved and bfs.minimum_depth == 13
    assert bfs.actions[-1].vulnerability == "DatabaseRoot"


def test_base_fingerprint_is_independent_of_set_insertion_order():
    first = parse_lark_dsl(BASE.read_text())
    second = parse_lark_dsl(BASE.read_text())
    second.nodes["gateway"].properties = set(reversed(sorted(second.nodes["gateway"].properties)))

    assert fingerprint_spec(first) == fingerprint_spec(second)


def test_expansion_cannot_replace_a_base_node():
    base, delta = load_pair()
    delta.nodes["dc"] = delta.nodes.pop("database")

    with pytest.raises(ExpansionError, match="cannot replace base nodes"):
        expand_scenario(base, delta)


def test_expansion_rejects_non_expansion_header():
    with pytest.raises(ExpansionError, match="must start"):
        parse_expansion_dsl(BASE.read_text())


def test_cli_compiles_expansion_with_provenance(tmp_path):
    status = main([
        "--base", str(BASE), "--expansion", str(EXPANSION), "--output", str(tmp_path),
    ])

    scenario = tmp_path / "object_perimeter_to_database_0001"
    assert status == 0
    assert (scenario / "nodes" / "database.yaml").is_file()
    provenance = (scenario / "expansion_validation.json").read_text()
    assert '"base_preserved": true' in provenance
    assert '"added_transitions": 4' in provenance


def test_claude_generates_only_delta_and_preserves_base(tmp_path, monkeypatch):
    expansion_source = EXPANSION.read_text()
    monkeypatch.setattr(
        "pipeline.object_generator.cli.call_claude_cli",
        lambda prompt, **kwargs: expansion_source,
    )

    status = main([
        "--base", str(BASE), "--request", "Add a protected database target",
        "--output", str(tmp_path),
    ])

    scenario = tmp_path / "object_perimeter_to_database_0001"
    assert status == 0
    assert (scenario / "generated.expansion.larkdsl").read_text() == expansion_source


def test_expansion_generation_repairs_shortcut():
    base, _ = load_pair()
    valid = EXPANSION.read_text()
    shortcut = valid.replace("depth 13 to 13", "depth 14 to 14")
    responses = iter((shortcut, valid))
    prompts = []

    result = generate_expansion_with_model(
        base, BASE.read_text(), "Add database", lambda prompt: (prompts.append(prompt), next(responses))[1]
    )

    assert result.attempts == 2
    assert "MERGED VALIDATION ERRORS" in prompts[1]
