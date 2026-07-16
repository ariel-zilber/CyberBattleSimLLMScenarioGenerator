from __future__ import annotations

from dataclasses import dataclass, replace

from .model import ScenarioSpec, Transition
from .state_bfs import BFSResult, find_minimum_solution


@dataclass(frozen=True)
class PathAnalysis:
    result: BFSResult
    visited_zones: tuple[str, ...]
    required_zones_present: bool
    bypassable_mandatory: tuple[str, ...]


def analyze_paths(spec: ScenarioSpec) -> PathAnalysis:
    result = find_minimum_solution(spec)
    zones = []
    for action in result.actions:
        node = spec.nodes.get(action.target)
        if node and (not zones or zones[-1] != node.zone):
            zones.append(node.zone)
    required = list(spec.goal.required_zones)
    cursor = 0
    for zone in zones:
        if cursor < len(required) and zone == required[cursor]:
            cursor += 1

    bypassable = []
    for index, transition in enumerate(spec.transitions):
        if transition not in result.actions:
            continue
        candidate = replace(spec, transitions=spec.transitions[:index] + spec.transitions[index + 1:])
        if find_minimum_solution(candidate).solved:
            bypassable.append(transition.vulnerability)
    return PathAnalysis(result, tuple(zones), cursor == len(required), tuple(bypassable))
