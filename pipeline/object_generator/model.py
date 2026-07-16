from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from typing import Any


class Privilege(IntEnum):
    NONE = 0
    USER = 1
    ADMIN = 2
    SYSTEM = 3


class ActionType(str, Enum):
    DISCOVER = "discover"
    REMOTE_EXPLOIT = "remote_exploit"
    LEAK_CREDENTIAL = "leak_credential"
    CONNECT = "connect"
    ESCALATE = "escalate"
    PROBE = "probe"


class TransitionRole(str, Enum):
    MANDATORY = "mandatory"
    ALTERNATE = "alternate"
    DECOY = "decoy"
    BLOCKED = "blocked"


class FirewallPermission(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True)
class Service:
    name: str
    credentials: tuple[str, ...] = ()


@dataclass
class Node:
    id: str
    template: str
    zone: str
    properties: set[str] = field(default_factory=set)
    services: dict[str, Service] = field(default_factory=dict)
    is_goal: bool = False
    value: int = 100


@dataclass(frozen=True)
class Transition:
    source: str
    target: str
    action: ActionType
    vulnerability: str
    requires_privilege: Privilege = Privilege.NONE
    grants_privilege: Privilege | None = None
    service: str | None = None
    credential: str | None = None
    prerequisites: frozenset[str] = frozenset()
    success_rate: float = 1.0
    role: TransitionRole = TransitionRole.MANDATORY
    specialist: str | None = None


@dataclass(frozen=True)
class Goal:
    node: str
    privilege: Privilege = Privilege.SYSTEM
    minimum_depth: int = 1
    maximum_depth: int | None = None
    required_zones: tuple[str, ...] = ()


@dataclass(frozen=True)
class FirewallPolicy:
    source_zone: str
    target_zone: str
    service: str
    permission: FirewallPermission


@dataclass(frozen=True)
class InitialState:
    discovered: frozenset[str] = frozenset()
    credentials: frozenset[str] = frozenset()
    privileges: tuple[tuple[str, Privilege], ...] = (("start", Privilege.SYSTEM),)


@dataclass
class ScenarioSpec:
    name: str
    nodes: dict[str, Node]
    transitions: list[Transition]
    goal: Goal
    initial_state: InitialState = field(default_factory=InitialState)
    specialists: tuple[str, ...] = ()
    firewall_policies: tuple[FirewallPolicy, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        def convert(value: Any) -> Any:
            if isinstance(value, Enum):
                return value.name
            if isinstance(value, (set, frozenset, tuple)):
                return [convert(v) for v in value]
            if isinstance(value, dict):
                return {str(k): convert(v) for k, v in value.items()}
            if isinstance(value, list):
                return [convert(v) for v in value]
            return value

        return convert(asdict(self))
