from pathlib import Path
from types import SimpleNamespace

import pytest

from pipeline.object_generator.lark_parser import parse_lark_dsl
from pipeline.object_generator.runtime_verifier import (
    RuntimeVerificationError,
    verify_runtime_solution,
)
from pipeline.object_generator.state_bfs import find_minimum_solution
from pipeline.object_generator.cli import main


EXAMPLE = Path("examples/object_generator/perimeter_to_domain.larkdsl")


class FakeActuator:
    def __init__(self):
        self.calls = []

    def _result(self, *call):
        self.calls.append(call)
        return SimpleNamespace(outcome=SimpleNamespace(), reward=1.0)

    def exploit_local_vulnerability(self, node, vulnerability):
        return self._result("local", node, vulnerability)

    def exploit_remote_vulnerability(self, source, target, vulnerability):
        return self._result("remote", source, target, vulnerability)

    def connect_to_remote_machine(self, source, target, service, credential):
        return self._result("connect", source, target, service, credential)


def test_runtime_replay_counts_bootstrap_separately(monkeypatch):
    spec = parse_lark_dsl(EXAMPLE.read_text())
    bfs = find_minimum_solution(spec)
    actuator = FakeActuator()
    environment = SimpleNamespace(
        get_node=lambda node: SimpleNamespace(privilege_level=3)
    )
    monkeypatch.setattr(
        "pipeline.object_generator.runtime_verifier._load_runtime",
        lambda scenario, root: (environment, actuator),
    )

    result = verify_runtime_solution(spec, Path("unused"), bfs)

    assert result.passed
    assert result.symbolic_depth == result.runtime_depth == 9
    assert result.bootstrap_actions == 1
    assert actuator.calls[0] == ("local", "start", "Initial.Discovery")
    assert actuator.calls[-1] == ("local", "dc", "SystemEscalation")


def test_runtime_replay_rejects_missing_outcome(monkeypatch):
    spec = parse_lark_dsl(EXAMPLE.read_text())
    bfs = find_minimum_solution(spec)
    actuator = FakeActuator()
    environment = SimpleNamespace(get_node=lambda node: SimpleNamespace(privilege_level=3))
    monkeypatch.setattr(
        "pipeline.object_generator.runtime_verifier._load_runtime",
        lambda scenario, root: (environment, actuator),
    )
    actuator.exploit_remote_vulnerability = lambda *args: SimpleNamespace(outcome=None, reward=-1)

    with pytest.raises(RuntimeVerificationError, match="returned no outcome"):
        verify_runtime_solution(spec, Path("unused"), bfs)


def test_cli_persists_runtime_rejection(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pipeline.object_generator.cli.verify_runtime_solution",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeVerificationError("replay mismatch")),
    )

    status = main([
        str(EXAMPLE), "--output", str(tmp_path), "--verify-runtime",
    ])

    assert status == 4
    report = (tmp_path / "object_perimeter_to_domain_0002" / "runtime_validation.json").read_text()
    assert '"runtime_verified": false' in report
    assert "replay mismatch" in report
