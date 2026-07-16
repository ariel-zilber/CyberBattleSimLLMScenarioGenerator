from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .lark_parser import parse_lark_dsl
from .model import InitialState, ScenarioSpec
from .validator import ValidationResult, validate


class ExpansionError(ValueError):
    """Raised when an expansion attempts to mutate or invalidate its base."""


@dataclass(frozen=True)
class ExpansionResult:
    spec: ScenarioSpec
    validation: ValidationResult
    base_fingerprint: str
    added_nodes: tuple[str, ...]
    added_transitions: int
    added_firewall_policies: int


_HEADER = re.compile(r"\A\s*expansion\s+([A-Za-z_][A-Za-z0-9_.-]*)\s+using\s+")


def parse_expansion_dsl(source: str) -> ScenarioSpec:
    """Parse the restricted expansion language using the same Lark grammar.

    An expansion deliberately has the same typed statements as a scenario, but
    begins with ``expansion``. It must declare a target contract; that target
    replaces the base goal after the additions are applied.
    """
    if not _HEADER.match(source):
        raise ExpansionError("Expansion must start with `expansion NAME using ...`")
    scenario_source = _HEADER.sub(r"scenario \1 using ", source, count=1)
    return parse_lark_dsl(scenario_source)


def fingerprint_spec(spec: ScenarioSpec) -> str:
    def canonical(value: Any) -> Any:
        if isinstance(value, Enum):
            return value.name
        if dataclasses.is_dataclass(value):
            return {
                field.name: canonical(getattr(value, field.name))
                for field in dataclasses.fields(value)
            }
        if isinstance(value, dict):
            return {str(key): canonical(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
        if isinstance(value, (set, frozenset)):
            converted = [canonical(item) for item in value]
            return sorted(converted, key=lambda item: json.dumps(item, sort_keys=True))
        if isinstance(value, (list, tuple)):
            return [canonical(item) for item in value]
        return value

    payload = json.dumps(canonical(spec), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def expand_scenario(base: ScenarioSpec, expansion: ScenarioSpec) -> ExpansionResult:
    """Apply typed additions to a deep copy and prove the base was untouched."""
    base_validation = validate(base)
    if not base_validation.valid:
        raise ExpansionError("Base scenario is invalid: " + "; ".join(base_validation.errors))
    before = fingerprint_spec(base)
    duplicate_nodes = sorted(set(base.nodes) & set(expansion.nodes))
    if duplicate_nodes:
        raise ExpansionError(f"Expansion cannot replace base nodes: {duplicate_nodes}")

    merged = copy.deepcopy(base)
    merged.name = expansion.name
    merged.nodes.update(copy.deepcopy(expansion.nodes))
    merged.transitions.extend(copy.deepcopy(expansion.transitions))
    merged.firewall_policies = tuple(merged.firewall_policies) + tuple(
        copy.deepcopy(expansion.firewall_policies)
    )
    merged.specialists = tuple(dict.fromkeys((*merged.specialists, *expansion.specialists)))
    merged.goal = copy.deepcopy(expansion.goal)
    merged.initial_state = InitialState(
        discovered=base.initial_state.discovered | expansion.initial_state.discovered,
        credentials=base.initial_state.credentials | expansion.initial_state.credentials,
        privileges=tuple(dict((*base.initial_state.privileges, *expansion.initial_state.privileges)).items()),
    )

    validation = validate(merged)
    after = fingerprint_spec(base)
    if before != after:
        raise ExpansionError("Internal error: expansion mutated the base scenario")
    return ExpansionResult(
        spec=merged,
        validation=validation,
        base_fingerprint=before,
        added_nodes=tuple(sorted(expansion.nodes)),
        added_transitions=len(expansion.transitions),
        added_firewall_policies=len(expansion.firewall_policies),
    )
