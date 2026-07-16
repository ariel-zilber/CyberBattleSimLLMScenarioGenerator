from __future__ import annotations

import ast
from typing import Any

from .model import (
    ActionType, Goal, InitialState, Node, Privilege, ScenarioSpec, Service,
    Transition, TransitionRole,
)


class DSLParseError(ValueError):
    pass


def _literal(node: ast.AST) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [_literal(item) for item in node.elts]
    if isinstance(node, ast.Dict):
        return {_literal(k): _literal(v) for k, v in zip(node.keys, node.values)}
    raise DSLParseError(f"Only literals are allowed, found {type(node).__name__}")


def _call(node: ast.AST, expected: str | None = None) -> tuple[str, list[Any], dict[str, Any]]:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        raise DSLParseError("Expected a constructor call")
    name = node.func.id
    if expected and name != expected:
        raise DSLParseError(f"Expected {expected}(...), found {name}(...)")
    args = [_literal(v) for v in node.args]
    kwargs = {kw.arg: _literal(kw.value) for kw in node.keywords if kw.arg}
    if len(kwargs) != len(node.keywords):
        raise DSLParseError("Dictionary expansion is not allowed")
    return name, args, kwargs


def _privilege(value: str | int | None, default: Privilege = Privilege.NONE) -> Privilege:
    if value is None:
        return default
    if isinstance(value, int):
        return Privilege(value)
    return Privilege[value.upper()]


def parse_dsl(source: str) -> ScenarioSpec:
    """Parse the restricted, Python-looking scenario DSL without executing it."""
    try:
        tree = ast.parse(source.strip(), mode="eval")
    except SyntaxError as exc:
        raise DSLParseError(str(exc)) from exc
    if not isinstance(tree.body, ast.Call) or not isinstance(tree.body.func, ast.Name) or tree.body.func.id != "Scenario":
        raise DSLParseError("Document must be one Scenario(...) expression")
    if tree.body.args:
        raise DSLParseError("Scenario uses keyword arguments only")
    fields = {kw.arg: kw.value for kw in tree.body.keywords if kw.arg}
    if len(fields) != len(tree.body.keywords):
        raise DSLParseError("Dictionary expansion is not allowed")
    unknown = set(fields) - {"name", "nodes", "transitions", "goal", "initial"}
    if unknown:
        raise DSLParseError(f"Unknown Scenario fields: {sorted(unknown)}")
    name = _literal(fields["name"])

    nodes: dict[str, Node] = {}
    node_expr = fields.get("nodes", ast.List(elts=[]))
    if not isinstance(node_expr, (ast.List, ast.Tuple)):
        raise DSLParseError("nodes must be a list")
    for item in node_expr.elts:
        _, args, kw = _call(item, "Node")
        if len(args) < 3:
            raise DSLParseError("Node requires id, template, and zone")
        node_id, template, zone = map(str, args[:3])
        services = {}
        for svc_name, credentials in kw.get("services", {}).items():
            services[str(svc_name)] = Service(str(svc_name), tuple(map(str, credentials)))
        nodes[node_id] = Node(
            node_id, template, zone, set(map(str, kw.get("properties", []))),
            services, bool(kw.get("goal", False)), int(kw.get("value", 100)),
        )

    transitions: list[Transition] = []
    transition_expr = fields.get("transitions", ast.List(elts=[]))
    if not isinstance(transition_expr, (ast.List, ast.Tuple)):
        raise DSLParseError("transitions must be a list")
    action_map = {
        "Discover": ActionType.DISCOVER, "RemoteExploit": ActionType.REMOTE_EXPLOIT,
        "LeakCredential": ActionType.LEAK_CREDENTIAL, "Connect": ActionType.CONNECT,
        "Escalate": ActionType.ESCALATE, "Probe": ActionType.PROBE,
    }
    for index, item in enumerate(transition_expr.elts):
        constructor, args, kw = _call(item)
        if constructor not in action_map or len(args) < 2:
            raise DSLParseError(f"Invalid transition constructor at index {index}: {constructor}")
        source, target = map(str, args[:2])
        vulnerability = str(kw.pop("vulnerability", args[2] if len(args) > 2 else f"{constructor}_{index}"))
        transitions.append(Transition(
            source=source, target=target, action=action_map[constructor], vulnerability=vulnerability,
            requires_privilege=_privilege(kw.pop("requires", None)),
            grants_privilege=_privilege(kw.pop("grants", None)) if "grants" in kw else None,
            service=kw.pop("service", args[2] if constructor == "Connect" and len(args) > 2 else None),
            credential=kw.pop(
                "credential",
                args[2] if constructor == "LeakCredential" and len(args) > 2
                else args[3] if constructor == "Connect" and len(args) > 3 else None,
            ),
            prerequisites=frozenset(map(str, kw.pop("prerequisites", []))),
            success_rate=float(kw.pop("success_rate", 1.0)),
            role=TransitionRole(str(kw.pop("role", "mandatory")).lower()),
        ))
        if kw:
            raise DSLParseError(f"Unknown {constructor} fields: {sorted(kw)}")

    goal_name, goal_args, goal_kw = _call(fields["goal"], "Goal")
    del goal_name
    if not goal_args:
        raise DSLParseError("Goal requires a node")
    goal = Goal(
        str(goal_args[0]), _privilege(goal_args[1] if len(goal_args) > 1 else goal_kw.get("privilege"), Privilege.SYSTEM),
        int(goal_kw.get("minimum_depth", 1)),
        int(goal_kw["maximum_depth"]) if "maximum_depth" in goal_kw else None,
    )
    initial = InitialState()
    if "initial" in fields:
        _, initial_args, initial_kw = _call(fields["initial"], "Initial")
        if initial_args:
            raise DSLParseError("Initial uses keyword arguments only")
        privileges = tuple(
            (str(k), _privilege(v)) for k, v in initial_kw.get("privileges", {"start": "System"}).items()
        )
        initial = InitialState(
            frozenset(map(str, initial_kw.get("discovered", []))),
            frozenset(map(str, initial_kw.get("credentials", []))), privileges,
        )
    return ScenarioSpec(str(name), nodes, transitions, goal, initial)
