from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .model import ActionType, FirewallPermission, Privilege, ScenarioSpec, Transition, TransitionRole


@dataclass(frozen=True)
class SearchState:
    privileges: tuple[tuple[str, int], ...]
    discovered: frozenset[str]
    credentials: frozenset[str]

    def privilege(self, node: str) -> Privilege:
        return Privilege(dict(self.privileges).get(node, Privilege.NONE))


@dataclass(frozen=True)
class BFSResult:
    solved: bool
    minimum_depth: int | None
    actions: tuple[Transition, ...]
    explored_states: int


def _initial(spec: ScenarioSpec) -> SearchState:
    privileges = tuple(sorted((node, int(level)) for node, level in spec.initial_state.privileges))
    return SearchState(privileges, spec.initial_state.discovered, spec.initial_state.credentials)


def firewall_allows(spec: ScenarioSpec, transition: Transition) -> bool:
    if transition.action != ActionType.CONNECT or not spec.firewall_policies:
        return True
    source = spec.nodes.get(transition.source)
    target = spec.nodes.get(transition.target)
    if not source or not target:
        return False
    matching = [p for p in spec.firewall_policies
                if p.source_zone == source.zone and p.target_zone == target.zone
                and p.service == transition.service]
    return len(matching) == 1 and matching[0].permission == FirewallPermission.ALLOW


def _enabled(spec: ScenarioSpec, state: SearchState, transition: Transition) -> bool:
    if transition.role == TransitionRole.BLOCKED:
        return False
    source_level = state.privilege(transition.source)
    if source_level < transition.requires_privilege:
        return False
    if transition.action == ActionType.DISCOVER:
        return source_level > Privilege.NONE
    if transition.action == ActionType.PROBE:
        return transition.target in state.discovered
    if transition.action == ActionType.REMOTE_EXPLOIT:
        return transition.target in state.discovered and source_level > Privilege.NONE
    if transition.action == ActionType.LEAK_CREDENTIAL:
        return source_level > Privilege.NONE
    if transition.action == ActionType.CONNECT:
        return (transition.target in state.discovered
                and transition.credential in state.credentials
                and firewall_allows(spec, transition))
    if transition.action == ActionType.ESCALATE:
        return source_level >= transition.requires_privilege
    return False


def _apply(state: SearchState, transition: Transition) -> SearchState:
    privileges = dict(state.privileges)
    discovered = set(state.discovered)
    credentials = set(state.credentials)
    if transition.action == ActionType.DISCOVER:
        discovered.add(transition.target)
    elif transition.action == ActionType.LEAK_CREDENTIAL and transition.credential:
        credentials.add(transition.credential)
    elif transition.action in {ActionType.REMOTE_EXPLOIT, ActionType.CONNECT, ActionType.ESCALATE}:
        granted = transition.grants_privilege or Privilege.USER
        privileges[transition.target] = max(int(granted), privileges.get(transition.target, 0))
        discovered.add(transition.target)
    return SearchState(tuple(sorted(privileges.items())), frozenset(discovered), frozenset(credentials))


def find_minimum_solution(
    spec: ScenarioSpec,
    max_states: int = 100_000,
    allowed_specialists: frozenset[str] | None = None,
) -> BFSResult:
    start = _initial(spec)
    queue = deque([start])
    predecessor: dict[SearchState, tuple[SearchState, Transition] | None] = {start: None}

    while queue and len(predecessor) <= max_states:
        state = queue.popleft()
        if state.privilege(spec.goal.node) >= spec.goal.privilege:
            actions: list[Transition] = []
            cursor = state
            while predecessor[cursor] is not None:
                previous, action = predecessor[cursor]  # type: ignore[misc]
                actions.append(action)
                cursor = previous
            actions.reverse()
            return BFSResult(True, len(actions), tuple(actions), len(predecessor))
        for transition in spec.transitions:
            if (allowed_specialists is not None
                    and transition.specialist not in allowed_specialists):
                continue
            if not _enabled(spec, state, transition):
                continue
            candidate = _apply(state, transition)
            if candidate == state or candidate in predecessor:
                continue
            predecessor[candidate] = (state, transition)
            queue.append(candidate)
    return BFSResult(False, None, (), len(predecessor))
