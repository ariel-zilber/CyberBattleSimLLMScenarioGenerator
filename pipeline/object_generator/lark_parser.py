from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from lark import Lark, Transformer, UnexpectedInput

from .catalogs import NODE_TEMPLATES
from .dsl_parser import DSLParseError
from .model import (ActionType, FirewallPermission, FirewallPolicy, Goal, InitialState,
                    Node, Privilege, ScenarioSpec, Service, Transition)


GRAMMAR = Path(__file__).with_name("grammar.lark").read_text(encoding="utf-8")
PARSER = Lark(GRAMMAR, parser="lalr", propagate_positions=True)


def _privilege(token) -> Privilege:
    return Privilege[str(token)]


@dataclass(frozen=True)
class _NodeParts:
    node: Node


class _ScenarioTransformer(Transformer):
    def NAME(self, token):
        return str(token)

    def INT(self, token):
        return int(token)

    def PRIVILEGE(self, token):
        return _privilege(token)

    def PERMISSION(self, token):
        return FirewallPermission(str(token))

    def name_list(self, items):
        return list(items)

    def goal_marker(self, _items):
        return True

    def properties(self, items):
        return ("properties", set(items[0]))

    def service(self, items):
        return ("service", items[0], tuple(items[1]) if len(items) > 1 else ())

    def node(self, items):
        node_id, template_name, zone = items[:3]
        rest = items[3:]
        is_goal = bool(rest and rest[0] is True)
        if is_goal:
            rest = rest[1:]
        template = NODE_TEMPLATES.get(template_name)
        properties = set(template.properties) if template else set()
        services = {name: Service(name) for name in template.services} if template else {}
        for item in rest:
            if item[0] == "properties":
                properties.update(item[1])
            else:
                _, name, credentials = item
                services[name] = Service(name, credentials)
        return _NodeParts(Node(node_id, template_name, zone, properties, services, is_goal))

    def initial(self, items):
        return InitialState(discovered=frozenset(items[0]))

    def requires(self, items):
        return ("requires", items[0])

    def prerequisites(self, items):
        return ("prerequisites", frozenset(items[0]))

    @staticmethod
    def _optional(items, key, default):
        return next((value for name, value in items if isinstance((name, value), tuple) and name == key), default)

    def discover(self, items):
        source, target, vuln, specialist, *opts = items
        requires = next((v for k, v in opts if k == "requires"), Privilege.NONE)
        return Transition(source, target, ActionType.DISCOVER, vuln, requires_privilege=requires, specialist=specialist)

    def exploit(self, items):
        source, target, vuln, specialist, grants, *opts = items
        requires = next((v for k, v in opts if k == "requires"), Privilege.NONE)
        prereqs = next((v for k, v in opts if k == "prerequisites"), frozenset())
        return Transition(source, target, ActionType.REMOTE_EXPLOIT, vuln, requires, grants,
                          prerequisites=prereqs, specialist=specialist)

    def leak(self, items):
        source, target, vuln, credential, service, specialist, *opts = items
        requires = next((v for k, v in opts if k == "requires"), Privilege.NONE)
        return Transition(source, target, ActionType.LEAK_CREDENTIAL, vuln, requires,
                          service=service, credential=credential, specialist=specialist)

    def connect(self, items):
        source, target, vuln, service, credential, specialist, grants, *opts = items
        requires = next((v for k, v in opts if k == "requires"), Privilege.NONE)
        return Transition(source, target, ActionType.CONNECT, vuln, requires, grants,
                          service, credential, specialist=specialist)

    def escalate(self, items):
        source, target, vuln, specialist, requires, grants, *opts = items
        prereqs = next((v for k, v in opts if k == "prerequisites"), frozenset())
        return Transition(source, target, ActionType.ESCALATE, vuln, requires, grants,
                          prerequisites=prereqs, specialist=specialist)

    def target(self, items):
        node, privilege, minimum, *rest = items
        maximum = next((x for x in rest if isinstance(x, int)), minimum)
        zones = next((tuple(x) for x in rest if isinstance(x, list)), ())
        return Goal(node, privilege, minimum, maximum, zones)

    def firewall(self, items):
        return FirewallPolicy(items[1], items[2], items[3], items[0])

    def scenario(self, items):
        name, specialists, *statements = items
        nodes = {part.node.id: part.node for part in statements if isinstance(part, _NodeParts)}
        transitions = [part for part in statements if isinstance(part, Transition)]
        policies = tuple(part for part in statements if isinstance(part, FirewallPolicy))
        initial = next((part for part in statements if isinstance(part, InitialState)), InitialState())
        goal = next((part for part in statements if isinstance(part, Goal)), None)
        if goal is None:
            raise DSLParseError("Scenario requires a target declaration")
        return ScenarioSpec(name, nodes, transitions, goal, initial, tuple(specialists), policies)

    def start(self, items):
        return items[0]


def parse_lark_dsl(source: str) -> ScenarioSpec:
    try:
        return _ScenarioTransformer().transform(PARSER.parse(source))
    except UnexpectedInput as exc:
        context = exc.get_context(source).strip()
        raise DSLParseError(f"line {exc.line}, column {exc.column}: {context}") from exc
