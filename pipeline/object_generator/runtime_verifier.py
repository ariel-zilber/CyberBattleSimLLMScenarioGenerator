from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import ActionType, Privilege, ScenarioSpec, Transition
from .state_bfs import BFSResult


class RuntimeVerificationError(RuntimeError):
    """Raised when a compiled scenario diverges from its symbolic solution."""


@dataclass(frozen=True)
class RuntimeStep:
    index: int
    action: str
    source: str
    target: str
    vulnerability: str
    outcome: str
    reward: float


@dataclass(frozen=True)
class RuntimeVerificationResult:
    passed: bool
    symbolic_depth: int
    runtime_depth: int
    bootstrap_actions: int
    target_privilege: int
    steps: tuple[RuntimeStep, ...]


def _load_runtime(scenario_dir: Path, cyberbattle_root: Path | None) -> tuple[Any, Any]:
    if cyberbattle_root is not None:
        root = str(cyberbattle_root.resolve())
        if root not in sys.path:
            sys.path.insert(0, root)
    try:
        from cyberbattle._env.DynamicEnviroment import new_environment
        from cyberbattle.simulation.improved.improved_actions import AgentActions
    except ImportError as exc:
        raise RuntimeVerificationError(
            "CyberBattleSim is not importable; provide --cyberbattle-root or set PYTHONPATH"
        ) from exc
    try:
        environment = new_environment(str(scenario_dir))
        return environment, AgentActions(environment, throws_on_invalid_actions=True)
    except Exception as exc:
        raise RuntimeVerificationError(f"CyberBattleSim failed to load the scenario: {exc}") from exc


def _execute(actuator: Any, transition: Transition) -> Any:
    if transition.action in {ActionType.DISCOVER, ActionType.LEAK_CREDENTIAL, ActionType.ESCALATE}:
        return actuator.exploit_local_vulnerability(transition.source, transition.vulnerability)
    if transition.action == ActionType.REMOTE_EXPLOIT:
        return actuator.exploit_remote_vulnerability(
            transition.source, transition.target, transition.vulnerability
        )
    if transition.action == ActionType.CONNECT:
        return actuator.connect_to_remote_machine(
            transition.source,
            transition.target,
            transition.service,
            transition.credential,
        )
    raise RuntimeVerificationError(f"Runtime replay does not support {transition.action.value}")


def verify_runtime_solution(
    spec: ScenarioSpec,
    scenario_dir: Path,
    bfs: BFSResult,
    *,
    cyberbattle_root: Path | None = None,
) -> RuntimeVerificationResult:
    """Replay the symbolic minimum path against an unmodified CyberBattleSim.

    Declared initial discovery is materialized by the compiler as one local
    bootstrap vulnerability. It is executed before the path and reported
    separately, because it represents initial observation rather than an
    attacker decision in the symbolic depth contract.
    """
    if not bfs.solved or bfs.minimum_depth is None:
        raise RuntimeVerificationError("Cannot replay an unsolved symbolic scenario")
    environment, actuator = _load_runtime(scenario_dir, cyberbattle_root)
    bootstrap_actions = 0
    if spec.initial_state.discovered:
        try:
            bootstrap = actuator.exploit_local_vulnerability("start", "Initial.Discovery")
        except Exception as exc:
            raise RuntimeVerificationError(f"Initial discovery bootstrap failed: {exc}") from exc
        if bootstrap.outcome is None:
            raise RuntimeVerificationError("Initial discovery bootstrap returned no outcome")
        bootstrap_actions = 1

    steps: list[RuntimeStep] = []
    for index, transition in enumerate(bfs.actions, start=1):
        try:
            result = _execute(actuator, transition)
        except Exception as exc:
            raise RuntimeVerificationError(
                f"Runtime step {index}/{bfs.minimum_depth} failed "
                f"({transition.action.value} {transition.vulnerability}): {exc}"
            ) from exc
        if result.outcome is None:
            raise RuntimeVerificationError(
                f"Runtime step {index}/{bfs.minimum_depth} returned no outcome "
                f"({transition.action.value} {transition.vulnerability}, reward={result.reward})"
            )
        steps.append(RuntimeStep(
            index=index,
            action=transition.action.value,
            source=transition.source,
            target=transition.target,
            vulnerability=transition.vulnerability,
            outcome=type(result.outcome).__name__,
            reward=float(result.reward),
        ))

    target_node = environment.get_node(spec.goal.node)
    target_privilege = int(target_node.privilege_level)
    if target_privilege < int(spec.goal.privilege):
        raise RuntimeVerificationError(
            f"Replay ended at privilege {target_privilege}, expected at least {int(spec.goal.privilege)}"
        )
    if len(steps) != bfs.minimum_depth:
        raise RuntimeVerificationError(
            f"Runtime depth {len(steps)} differs from symbolic depth {bfs.minimum_depth}"
        )
    return RuntimeVerificationResult(
        passed=True,
        symbolic_depth=bfs.minimum_depth,
        runtime_depth=len(steps),
        bootstrap_actions=bootstrap_actions,
        target_privilege=target_privilege,
        steps=tuple(steps),
    )
