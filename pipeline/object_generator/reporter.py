from __future__ import annotations

import json
from pathlib import Path

import yaml

from .model import ScenarioSpec
from .state_bfs import BFSResult
from .validator import ValidationResult


def write_reports(
    spec: ScenarioSpec,
    scenario_dir: Path,
    validation: ValidationResult,
    bfs: BFSResult,
) -> None:
    (scenario_dir / "scenario.json").write_text(
        json.dumps(spec.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    result = {
        "valid": validation.valid,
        "errors": list(validation.errors),
        "warnings": list(validation.warnings),
        "solved": bfs.solved,
        "minimum_depth": bfs.minimum_depth,
        "required_minimum_depth": spec.goal.minimum_depth,
        "maximum_depth": spec.goal.maximum_depth,
        "depth_preserved": bool(
            bfs.solved and bfs.minimum_depth is not None
            and bfs.minimum_depth >= spec.goal.minimum_depth
            and (spec.goal.maximum_depth is None or bfs.minimum_depth <= spec.goal.maximum_depth)
        ),
        "explored_states": bfs.explored_states,
        "specialists": list(spec.specialists),
    }
    (scenario_dir / "validation.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    rows = [
        "# Attack Chain", "",
        f"Goal: `{spec.goal.node}` at `{spec.goal.privilege.name}` privilege.", "",
        f"Required minimum depth: **{spec.goal.minimum_depth}**  ",
        f"Computed minimum depth: **{bfs.minimum_depth if bfs.solved else 'UNSOLVED'}**", "",
        "| Step | Specialist | Source | Action | Target | Vulnerability | Produces |",
        "|---:|---|---|---|---|---|---|",
    ]
    for index, action in enumerate(bfs.actions, 1):
        produces = action.grants_privilege.name if action.grants_privilege else (
            action.credential or "visibility"
        )
        rows.append(
            f"| {index} | {action.specialist or '-'} | {action.source} | {action.action.value} | {action.target} | "
            f"{action.vulnerability} | {produces} |"
        )
    (scenario_dir / "attack_chain.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    with (scenario_dir / "scenario.yaml").open("w", encoding="utf-8") as stream:
        yaml.safe_dump(spec.to_dict(), stream, sort_keys=False, allow_unicode=False)
