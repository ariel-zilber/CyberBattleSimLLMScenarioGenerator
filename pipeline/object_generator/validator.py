from __future__ import annotations

from dataclasses import dataclass

from .model import ActionType, Privilege, ScenarioSpec, TransitionRole
from .catalogs import NODE_TEMPLATES, SPECIALISTS, validate_catalogs
from .model import FirewallPermission


@dataclass(frozen=True)
class ValidationResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.errors


def validate(spec: ScenarioSpec) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []
    errors.extend(f"catalog: {error}" for error in validate_catalogs())
    known = set(spec.nodes) | {"start"}

    for specialist in spec.specialists:
        if specialist not in SPECIALISTS:
            errors.append(f"Unknown scenario specialist: {specialist}")
    for node in spec.nodes.values():
        if node.template not in NODE_TEMPLATES:
            errors.append(f"Node {node.id}: unknown template {node.template}")
    zones = {node.zone for node in spec.nodes.values()}
    policy_keys = set()
    for policy in spec.firewall_policies:
        key = (policy.source_zone, policy.target_zone, policy.service)
        if policy.source_zone not in zones or policy.target_zone not in zones:
            errors.append(f"Firewall policy references unknown zone: {key}")
        if key in policy_keys:
            errors.append(f"Ambiguous duplicate firewall policy: {key}")
        policy_keys.add(key)

    if not spec.nodes:
        errors.append("Scenario has no nodes")
    if spec.goal.node not in spec.nodes:
        errors.append(f"Goal node does not exist: {spec.goal.node}")
    if spec.goal.minimum_depth < 1:
        errors.append("Goal minimum_depth must be at least 1")

    seen: set[tuple] = set()
    leaked_credentials: set[str] = set(spec.initial_state.credentials)
    for index, transition in enumerate(spec.transitions):
        prefix = f"transition[{index}] {transition.vulnerability}"
        if transition.source not in known:
            errors.append(f"{prefix}: unknown source {transition.source}")
        if transition.target not in known:
            errors.append(f"{prefix}: unknown target {transition.target}")
            continue
        key = (transition.source, transition.target, transition.action, transition.vulnerability)
        if key in seen:
            errors.append(f"{prefix}: duplicate transition")
        seen.add(key)
        if not 0.0 <= transition.success_rate <= 1.0:
            errors.append(f"{prefix}: success_rate must be in [0, 1]")
        target = spec.nodes.get(transition.target)
        if spec.specialists and not transition.specialist:
            errors.append(f"{prefix}: no specialist assigned")
        elif transition.specialist:
            profile = SPECIALISTS.get(transition.specialist)
            if profile is None:
                errors.append(f"{prefix}: unknown specialist {transition.specialist}")
            else:
                if transition.specialist not in spec.specialists:
                    errors.append(f"{prefix}: specialist {transition.specialist} is not declared by scenario")
                if transition.action not in profile.actions:
                    errors.append(f"{prefix}: {transition.action.value} is not allowed for {transition.specialist}")
                if transition.service and transition.service not in profile.services:
                    errors.append(f"{prefix}: service {transition.service} is not allowed for {transition.specialist}")
                if (target and transition.action in {ActionType.REMOTE_EXPLOIT, ActionType.CONNECT, ActionType.ESCALATE}
                        and target.template not in profile.target_templates):
                    errors.append(
                        f"{prefix}: {transition.specialist} cannot target template {target.template} "
                        f"with {transition.action.value}"
                    )
        if target and not transition.prerequisites.issubset(target.properties):
            missing = sorted(transition.prerequisites - target.properties)
            errors.append(f"{prefix}: target lacks prerequisites {missing}")

        if transition.action == ActionType.LEAK_CREDENTIAL:
            if not transition.credential:
                errors.append(f"{prefix}: credential leak has no credential")
            else:
                leaked_credentials.add(transition.credential)
            if transition.source == transition.target:
                warnings.append(f"{prefix}: credential points back to its source node")
            if target and transition.service:
                service = target.services.get(transition.service)
                if service is None:
                    errors.append(f"{prefix}: {transition.target} has no {transition.service} service")
                elif transition.credential not in service.credentials:
                    errors.append(
                        f"{prefix}: leaked credential is not accepted by "
                        f"{transition.target}/{transition.service}"
                    )

        elif transition.action == ActionType.CONNECT:
            if not transition.service or not transition.credential:
                errors.append(f"{prefix}: connect requires service and credential")
            elif target:
                service = target.services.get(transition.service)
                if service is None:
                    errors.append(f"{prefix}: {transition.target} has no {transition.service} service")
                elif transition.credential not in service.credentials:
                    errors.append(
                        f"{prefix}: {transition.credential} is not accepted by "
                        f"{transition.target}/{transition.service}"
                    )
            if transition.grants_privilege is None:
                errors.append(f"{prefix}: connect must grant a privilege")

        elif transition.action == ActionType.ESCALATE:
            if transition.source != transition.target:
                errors.append(f"{prefix}: escalation must stay on the same node")
            if transition.grants_privilege is None:
                errors.append(f"{prefix}: escalation must grant a privilege")
            elif transition.grants_privilege <= transition.requires_privilege:
                errors.append(f"{prefix}: escalation must increase privilege")

        elif transition.action == ActionType.REMOTE_EXPLOIT:
            if transition.source == transition.target:
                errors.append(f"{prefix}: remote exploit cannot target its source")
            if transition.grants_privilege is None:
                errors.append(f"{prefix}: remote exploit must grant a privilege")

        elif transition.action in {ActionType.DISCOVER, ActionType.PROBE}:
            if transition.grants_privilege is not None:
                errors.append(f"{prefix}: information action cannot grant privilege")

        if transition.role == TransitionRole.BLOCKED and transition.action == ActionType.ESCALATE:
            warnings.append(f"{prefix}: blocked escalation is unusual")

    for index, transition in enumerate(spec.transitions):
        if transition.action == ActionType.CONNECT and transition.credential not in leaked_credentials:
            errors.append(
                f"transition[{index}] {transition.vulnerability}: credential "
                f"{transition.credential} is never initially available or leaked"
            )

    if spec.goal.node in spec.nodes and not spec.nodes[spec.goal.node].is_goal:
        warnings.append(f"Goal node {spec.goal.node} is not marked goal=True; compiler will mark it")
    missing_zones = set(spec.goal.required_zones) - zones
    if missing_zones:
        errors.append(f"Goal path requires unknown zones: {sorted(missing_zones)}")
    return ValidationResult(tuple(errors), tuple(warnings))
