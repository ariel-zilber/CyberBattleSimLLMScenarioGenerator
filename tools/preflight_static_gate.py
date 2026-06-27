#!/usr/bin/env python3
"""
Preflight static gate for CyberBattleSim LLM-generated scenario configs.

This runs before the expensive pipeline. It combines the existing static
validators with deterministic generation-feasibility checks that catch configs
that are syntactically valid but unlikely to instantiate useful scenarios.

Usage:
  python tools/preflight_static_gate.py data/scenarios/specialists/foo.yaml
  python tools/preflight_static_gate.py data/scenarios/specialists/foo.yaml --strict
  python tools/preflight_static_gate.py data/scenarios/specialists/foo.yaml --json
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
PHASE1_DIR = REPO_ROOT / "pipeline" / "phase1"
AGENTS_DIR = REPO_ROOT / "prompts" / "reference" / "agents"
CATALOG_PATH = REPO_ROOT / "prompts" / "reference" / "vulnerability_catalog.md"

LOCAL_CBS_VOCAB = (
    REPO_ROOT.parent / "CyberBattleSim" / "cyberbattle" / "data" / "global_vocabulary.yaml"
)
FALLBACK_VOCAB = REPO_ROOT / "data" / "global_vocabulary.yaml"

sys.path.insert(0, str(TOOLS_DIR))
sys.path.insert(0, str(PHASE1_DIR))

try:
    import static_validation  # type: ignore
except ImportError as exc:  # pragma: no cover - import failure is reported at runtime
    static_validation = None  # type: ignore[assignment]
    _STATIC_IMPORT_ERROR = exc
else:
    _STATIC_IMPORT_ERROR = None

try:
    import config_checker  # type: ignore
except ImportError as exc:  # pragma: no cover - import failure is reported at runtime
    config_checker = None  # type: ignore[assignment]
    _CONFIG_IMPORT_ERROR = exc
else:
    _CONFIG_IMPORT_ERROR = None


@dataclass(frozen=True)
class Issue:
    severity: str
    check: str
    message: str


@dataclass(frozen=True)
class NodeProfile:
    domain: str
    group: str
    service: str
    min_count: int
    max_count: int
    properties: frozenset[str]

    @property
    def label(self) -> str:
        return f"{self.domain}.{self.group}:{self.service}"


class GateReport:
    def __init__(self) -> None:
        self.issues: list[Issue] = []

    def error(self, check: str, message: str) -> None:
        self.issues.append(Issue("error", check, message))

    def warn(self, check: str, message: str) -> None:
        self.issues.append(Issue("warning", check, message))

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "warning"]


PLACEHOLDER_RE = re.compile(
    r"^\s*(?:null|none|todo|tbd|fixme|placeholder|replace_me|<[^>]+>)\s*$",
    re.IGNORECASE,
)

SPEC_NAMES = {
    "s_network.md": "S_Network",
    "s_linux.md": "S_Linux",
    "s_windows.md": "S_Windows",
    "s_identity.md": "S_Identity",
    "s_lateral.md": "S_Lateral",
}

REQUIRED_SPEC_HEADINGS = (
    "## Role",
    "## Fixed Action Collection",
    "### Local Vulnerabilities",
    "### Remote Vulnerabilities",
    "### Connect Ports",
    "## Observation Context Collection",
    "### Service IDs",
    "### Property IDs",
    "## Generation Rules",
    "## Scenario Intent",
)

FAMILY_PROPERTIES: dict[str, set[str]] = {
    "windows": {
        "Windows", "Win10", "Win2019", "Win2022", "DomainJoined",
        "DomainController", "DomainAdmin", "LocalAdmin", "Workstation",
        "FileServer", "PrintServer", "MailServer", "ExchangeServer",
        "ADCS", "Kerberoastable", "NTLMRelayable", "NoLAPS",
    },
    "identity": {
        "IdentityProvider", "DomainController", "DomainJoined", "ADCS",
        "Kerberoastable", "NTLMRelayable", "DomainAdmin", "LocalAdmin",
        "LDAP", "LDAPS", "Kerberos",
    },
    "linux": {
        "Linux", "Unix", "Ubuntu", "CentOS", "Debian", "Alpine", "RedHat",
        "Kali", "WebServer", "NginxServer", "ApacheServer", "AppServer",
        "DatabaseServer", "MySQLServer", "PostgreSQLServer", "MongoDBServer",
        "RedisServer", "ElasticsearchServer", "NoSQL", "PostgreSQL",
        "DeveloperWorkstation",
    },
    "container": {
        "Container", "Docker", "Kubernetes", "K8sCluster", "Pod",
        "WorkerNode", "EKS", "etcd",
    },
    "cloud": {
        "CloudInstance", "AWS", "EC2", "EKS", "CloudLambda", "CloudRDS",
        "Serverless", "IMDS", "IMDSv1",
    },
    "network": {
        "NetworkDevice", "Router", "Switch", "Firewall", "VPN", "WAF",
        "NGFW", "SSLVPN", "Bastion", "CiscoIOS", "CiscoNXOS",
        "CiscoASA", "CiscoFirepower", "JuniperJunos", "FortiGate",
        "PaloAlto", "PANOS", "GlobalProtect", "F5BIGIP", "LoadBalancer",
        "ReverseProxy", "APIGateway",
    },
}

VULN_FAMILY_PATTERNS: list[tuple[re.Pattern[str], set[str]]] = [
    (
        re.compile(
            r"panos|forti|cisco|nxos|asa|ios|f5|bigip|citrix|juniper|junos|"
            r"netgear|snmp|vlan|networkdevice",
            re.IGNORECASE,
        ),
        {"network"},
    ),
    (
        re.compile(
            r"docker|kubernetes|container|redis|hadoop|bundler|wordpress|"
            r"envvars|aws|vault|kube|mongodb|keycloak|kafka|grafana|airflow|"
            r"concourse|spark|snakeyaml|imagemagick|mysql|java|ghostcms|"
            r"avro|libssh|gogoprotobuf|zlib|openexr|pgdump|elasticsearch|"
            r"nodejs|ssh_privkey",
            re.IGNORECASE,
        ),
        {"linux", "container", "cloud"},
    ),
    (
        re.compile(
            r"adcs|kerberoast|asrep|dcsync|zerologon|ntlm|winrm|wsd|smb|"
            r"rdp|wmi|print|exchange|proxylogon|nolaps|laps|mssql|"
            r"passthehash|shadow|delegation|domain|ldap",
            re.IGNORECASE,
        ),
        {"windows", "identity"},
    ),
]


def dotted(path: Iterable[Any]) -> str:
    return ".".join(str(p) for p in path) or "<root>"


def load_yaml(path: Path, report: GateReport) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        report.error("yaml", f"{path.name}: YAML parse error: {exc}")
        return {}
    if not isinstance(data, dict):
        report.error("yaml", f"{path.name}: YAML root must be a mapping")
        return {}
    return data


def count_range(group: dict[str, Any]) -> tuple[int, int]:
    if "min_count" in group or "max_count" in group:
        lo = int(group.get("min_count", 1))
        hi = int(group.get("max_count", lo))
        return lo, hi
    count = group.get("count", 1)
    if isinstance(count, dict):
        lo = int(count.get("min", 1))
        hi = int(count.get("max", lo))
        return lo, hi
    n = int(count)
    return n, n


def float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def families_for_properties(properties: Iterable[str]) -> set[str]:
    props = set(properties)
    families: set[str] = set()
    for family, markers in FAMILY_PROPERTIES.items():
        if props & markers:
            families.add(family)
    return families


def families_for_vuln_name(name: str) -> set[str]:
    families: set[str] = set()
    for pattern, family_set in VULN_FAMILY_PATTERNS:
        if pattern.search(name):
            families |= family_set
    return families


def service_node_profiles(cfg: dict[str, Any]) -> list[NodeProfile]:
    services = cfg.get("services", {}) or {}
    max_total_nodes = int((cfg.get("config", {}) or {}).get("max_total_nodes", 100))
    profiles: list[NodeProfile] = []

    def props_for(service_name: str, group: dict[str, Any] | None = None) -> frozenset[str]:
        svc = services.get(service_name, {}) or {}
        props = set(svc.get("default_properties", []) or [])
        props.update(svc.get("allowed_os", []) or [])
        if svc.get("port"):
            props.add(str(svc["port"]))
        props.add(service_name)
        if group:
            props.update(group.get("properties", []) or [])
            if group.get("name"):
                props.add(str(group["name"]))
        return frozenset(str(p) for p in props if p is not None)

    for domain in cfg.get("domains", []) or []:
        domain_name = str(domain.get("name", ""))
        for group in domain.get("groups", []) or []:
            service = group.get("service")
            if not service:
                continue
            lo, hi = count_range(group)
            profiles.append(
                NodeProfile(
                    domain=domain_name,
                    group=str(group.get("name", "")),
                    service=str(service),
                    min_count=lo,
                    max_count=hi,
                    properties=props_for(str(service), group),
                )
            )

        for service in domain.get("filler", []) or []:
            profiles.append(
                NodeProfile(
                    domain=domain_name,
                    group="Filler",
                    service=str(service),
                    min_count=0,
                    max_count=max_total_nodes,
                    properties=props_for(str(service)),
                )
            )

    return profiles


def matching_profiles(match_properties: list[str], profiles: list[NodeProfile]) -> list[NodeProfile]:
    wanted = set(match_properties)
    if not wanted:
        return []
    return [p for p in profiles if wanted & set(p.properties)]


def collect_solvability_vulns(cfg: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    result: list[tuple[str, dict[str, Any]]] = []
    solv = cfg.get("solvability_vulnerabilities", {}) or {}
    for category, entries in solv.items():
        if not isinstance(entries, list):
            continue
        for idx, entry in enumerate(entries):
            if isinstance(entry, dict):
                result.append((f"solvability_vulnerabilities.{category}[{idx}]", entry))
    return result


def collect_all_vuln_dicts(obj: Any, path: tuple[Any, ...] = ()) -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    if isinstance(obj, dict):
        name = obj.get("name")
        if isinstance(name, str) and name.startswith("Solvability."):
            found.append((dotted(path), obj))
        for key, value in obj.items():
            found.extend(collect_all_vuln_dicts(value, path + (key,)))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            found.extend(collect_all_vuln_dicts(value, path + (idx,)))
    return found


def check_existing_validators(
    config_path: Path,
    cfg: dict[str, Any],
    report: GateReport,
    vocab_path: Path,
    catalog_path: Path,
) -> None:
    if static_validation is None:
        report.error("existing-static-validation", f"could not import static_validation.py: {_STATIC_IMPORT_ERROR}")
    else:
        if not vocab_path.exists():
            report.error("existing-static-validation", f"vocab not found: {vocab_path}")
        elif not catalog_path.exists():
            report.error("existing-static-validation", f"catalog not found: {catalog_path}")
        else:
            vocab = static_validation.load_global_vocab(vocab_path)
            catalog = static_validation.load_vuln_catalog(catalog_path)
            results = static_validation.validate_file(config_path, vocab, catalog)
            for check_name, issues in results.items():
                for issue in issues:
                    report.error(f"static_validation.{check_name}", issue)

    if config_checker is None:
        report.error("phase1-config-checker", f"could not import config_checker.py: {_CONFIG_IMPORT_ERROR}")
        return

    with contextlib.redirect_stdout(io.StringIO()):
        catalog = config_checker.load_vulnerability_catalog()
        checks = [
            ("Metadata block", config_checker.check_metadata(cfg)),
            ("Config settings", config_checker.check_config_settings(cfg)),
            ("Identifiers completeness", config_checker.check_identifiers(cfg)),
            ("Service / group consistency", config_checker.check_groups(cfg)),
            ("Vulnerability coverage", config_checker.check_vulnerability_coverage(cfg)),
            ("Agent-category allowlist", config_checker.check_agent_category_allowlist(cfg, catalog)),
            ("Constraint soundness", config_checker.check_constraints(cfg)),
            ("Specialist vocab coverage", config_checker.check_specialist_vocab_coverage(cfg)),
        ]
        depth_issues, _depth_report = config_checker.check_attack_flow_depth(cfg)

    error_keywords = [
        "UNREACHABLE", "unsolvable", "not defined", "not in identifiers",
        "is missing", "must be", "breach_node", "incorrect category pairing",
        "vulnerability_catalog.md", "orphaned property", "metadata block",
        "metadata.", "AP-022", "AP-023", "vocab-coverage", "dead in training",
    ]

    for check_name, issues in checks:
        for issue in issues:
            if any(k.lower() in issue.lower() for k in error_keywords):
                report.error(f"config_checker.{check_name}", issue)
            else:
                report.warn(f"config_checker.{check_name}", issue)

    for issue in depth_issues:
        if "UNREACHABLE" in issue or "unsolvable" in issue.lower():
            report.error("config_checker.Attack flow depth", issue)
        else:
            report.warn("config_checker.Attack flow depth", issue)


def check_placeholders(cfg: dict[str, Any], report: GateReport) -> None:
    def walk(obj: Any, path: tuple[Any, ...] = ()) -> None:
        if obj is None:
            report.error("placeholder-cleanup", f"{dotted(path)} is null")
            return
        if isinstance(obj, str):
            if PLACEHOLDER_RE.match(obj):
                report.error("placeholder-cleanup", f"{dotted(path)} contains placeholder value {obj!r}")
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                walk(value, path + (key,))
        elif isinstance(obj, list):
            for idx, value in enumerate(obj):
                walk(value, path + (idx,))

    walk(cfg)


def check_probability_and_rates(
    cfg: dict[str, Any],
    profiles: list[NodeProfile],
    report: GateReport,
    min_success_rate: float,
) -> None:
    for path, vuln in collect_all_vuln_dicts(cfg):
        name = str(vuln.get("name", ""))
        vtype = vuln.get("type")
        if vtype is not None and vtype not in {"LOCAL", "REMOTE"}:
            report.error("vulnerability-parameters", f"{path}.{name}: invalid type {vtype!r}")

        if "success_rate" in vuln:
            rate = float_or_none(vuln.get("success_rate"))
            if rate is None:
                report.error("vulnerability-parameters", f"{path}.{name}: success_rate is not numeric")
            elif not 0.0 <= rate <= 1.0:
                report.error("vulnerability-parameters", f"{path}.{name}: success_rate={rate} outside [0,1]")
            elif rate < min_success_rate:
                report.error(
                    "vulnerability-parameters",
                    f"{path}.{name}: success_rate={rate} below floor {min_success_rate}",
                )

        if "probability" in vuln:
            prob = float_or_none(vuln.get("probability"))
            if prob is None:
                report.error("vulnerability-parameters", f"{path}.{name}: probability is not numeric")
            elif not 0.0 <= prob <= 1.0:
                report.error("vulnerability-parameters", f"{path}.{name}: probability={prob} outside [0,1]")
            elif prob == 0.0:
                report.error("vulnerability-parameters", f"{path}.{name}: probability=0 makes the slot unreachable")

    for path, vuln in collect_solvability_vulns(cfg):
        name = str(vuln.get("name", ""))
        match_props = vuln.get("match_properties", []) or []
        if not isinstance(match_props, list) or not match_props:
            report.error("placement-feasibility", f"{path}.{name}: match_properties is empty")
            continue

        eligible = matching_profiles([str(p) for p in match_props], profiles)
        if not eligible:
            report.error(
                "placement-feasibility",
                f"{path}.{name}: no generated service/group has any match_properties {match_props}",
            )
            continue

        prob = float_or_none(vuln.get("probability", 1.0))
        if prob is None:
            prob = 1.0
        expected_min = sum(p.min_count for p in eligible) * prob
        expected_max = sum(p.max_count for p in eligible) * prob
        if expected_max < 1.0:
            report.warn(
                "placement-feasibility",
                f"{path}.{name}: expected max placements {expected_max:.2f} < 1 "
                f"(eligible={len(eligible)}, probability={prob})",
            )
        elif expected_min < 1.0:
            report.warn(
                "placement-feasibility",
                f"{path}.{name}: may only appear via optional/filler nodes "
                f"(expected min {expected_min:.2f}, max {expected_max:.2f})",
            )


def check_semantic_families(
    cfg: dict[str, Any],
    profiles: list[NodeProfile],
    report: GateReport,
) -> None:
    for path, vuln in collect_solvability_vulns(cfg):
        name = str(vuln.get("name", ""))
        allowed = families_for_vuln_name(name)
        if not allowed:
            continue

        match_props = [str(p) for p in (vuln.get("match_properties", []) or [])]
        match_families = families_for_properties(match_props)
        eligible = matching_profiles(match_props, profiles)
        eligible_families: set[str] = set()
        for profile in eligible:
            eligible_families |= families_for_properties(profile.properties)

        if match_families and not (match_families & allowed):
            report.error(
                "semantic-family",
                f"{path}.{name}: match_properties {match_props} imply "
                f"{sorted(match_families)} but name implies {sorted(allowed)}",
            )
        elif not match_families:
            report.warn(
                "semantic-family",
                f"{path}.{name}: match_properties {match_props} contain no OS/role family marker",
            )

        if eligible_families and not (eligible_families & allowed):
            report.error(
                "semantic-family",
                f"{path}.{name}: eligible generated nodes imply {sorted(eligible_families)} "
                f"but name implies {sorted(allowed)}",
            )


def resolve_reference(reference: str, domain: str, profiles: list[NodeProfile]) -> list[NodeProfile]:
    result = [
        p for p in profiles
        if p.domain == domain and p.group == reference and p.max_count > 0
    ]
    if result:
        return result
    result = [
        p for p in profiles
        if p.domain == domain and p.service == reference and p.max_count > 0
    ]
    if result:
        return result
    return [
        p for p in profiles
        if p.domain == domain and (reference in p.group or reference in p.service)
        and p.max_count > 0
    ]


def check_constraint_resolvability(
    cfg: dict[str, Any],
    profiles: list[NodeProfile],
    report: GateReport,
) -> None:
    for domain in cfg.get("domains", []) or []:
        domain_name = str(domain.get("name", ""))
        for idx, constraint in enumerate(domain.get("constraints", []) or []):
            if not isinstance(constraint, dict):
                continue
            rel = constraint.get("relation")
            source = str(constraint.get("source", ""))
            target = str(constraint.get("target", ""))
            path = f"domains.{domain_name}.constraints[{idx}]"

            source_profiles = resolve_reference(source, domain_name, profiles)
            if not source_profiles:
                report.error("constraint-resolvability", f"{path}: source {source!r} resolves to zero generated nodes")

            if rel in {"MUST_HAVE", "MUST_NOT_HAVE"}:
                continue

            target_profiles = resolve_reference(target, domain_name, profiles)
            if not target_profiles:
                report.error("constraint-resolvability", f"{path}: target {target!r} resolves to zero generated nodes")

    for group_idx, group in enumerate(cfg.get("inter_domain_constraints", []) or []):
        if not isinstance(group, dict):
            continue
        source_domain = str(group.get("source_domain", ""))
        target_domain = str(group.get("target_domain", ""))
        for idx, constraint in enumerate(group.get("constraints", []) or []):
            if not isinstance(constraint, dict):
                continue
            source = str(constraint.get("source", ""))
            target = str(constraint.get("target", ""))
            path = f"inter_domain_constraints[{group_idx}].constraints[{idx}]"
            if not resolve_reference(source, source_domain, profiles):
                report.error(
                    "constraint-resolvability",
                    f"{path}: source {source_domain}.{source} resolves to zero generated nodes",
                )
            if not resolve_reference(target, target_domain, profiles):
                report.error(
                    "constraint-resolvability",
                    f"{path}: target {target_domain}.{target} resolves to zero generated nodes",
                )

    for idx, rule in enumerate(cfg.get("attack_flow", []) or []):
        if not isinstance(rule, dict):
            continue
        source = str(rule.get("source_pattern", ""))
        if source and not any(
            source == p.service or source == p.group or source in p.properties
            for p in profiles
        ):
            report.error("attack-flow-resolvability", f"attack_flow[{idx}].source_pattern {source!r} matches no generated node type")
        for tidx, target in enumerate(rule.get("targets", []) or []):
            target_s = str(target)
            if not any(
                target_s == p.service or target_s == p.group or target_s in p.properties
                for p in profiles
            ):
                report.error("attack-flow-resolvability", f"attack_flow[{idx}].targets[{tidx}] {target_s!r} matches no generated node type")


def check_entry_points(
    cfg: dict[str, Any],
    profiles: list[NodeProfile],
    report: GateReport,
) -> None:
    for idx, entry in enumerate(cfg.get("entry_points", []) or []):
        if not isinstance(entry, dict):
            continue
        domain = str(entry.get("domain", ""))
        node = str(entry.get("node", ""))
        if not node:
            report.error("entry-point-resolvability", f"entry_points[{idx}].node is missing")
            continue
        domain_profiles = [p for p in profiles if not domain or p.domain == domain]
        candidates = [
            p for p in domain_profiles
            if node == p.group or node == p.service or node in p.group or node in p.service
        ]
        if not candidates:
            report.error(
                "entry-point-resolvability",
                f"entry_points[{idx}] {domain + '.' if domain else ''}{node} resolves to zero generated nodes",
            )
            continue

        max_candidates = sum(p.max_count for p in candidates)
        start = cfg.get("start_node", {}) or {}
        min_leaked = int(start.get("min_leaked_nodes", 1))
        if min_leaked > max_candidates:
            report.error(
                "entry-point-resolvability",
                f"start_node.min_leaked_nodes={min_leaked} but entry point has at most {max_candidates} candidate nodes",
            )


def check_concentration(
    cfg: dict[str, Any],
    profiles: list[NodeProfile],
    report: GateReport,
    max_fraction: float,
) -> None:
    vulns = collect_solvability_vulns(cfg)
    if not vulns or not profiles:
        return

    weighted: dict[str, float] = {}
    for _path, vuln in vulns:
        match_props = [str(p) for p in (vuln.get("match_properties", []) or [])]
        eligible = matching_profiles(match_props, profiles)
        if not eligible:
            continue
        weight = 1.0 / len(eligible)
        for profile in eligible:
            weighted[profile.label] = weighted.get(profile.label, 0.0) + weight

    if not weighted:
        return

    top_label, top_score = max(weighted.items(), key=lambda item: item[1])
    frac = top_score / max(len(vulns), 1)
    if frac > max_fraction and len(profiles) > 5:
        report.warn(
            "spatial-concentration",
            f"{top_label} is eligible for {frac:.0%} of solvability slots "
            f"(threshold {max_fraction:.0%}); LLM may be concentrating training signal",
        )


def parse_spec_slots(text: str, heading: str) -> list[str]:
    marker = f"### {heading}"
    start = text.find(marker)
    if start < 0:
        return []
    rest = text[start + len(marker):]
    next_heading = rest.find("\n### ")
    section = rest if next_heading < 0 else rest[:next_heading]
    return re.findall(r"\|\s*\d+\s*\|\s*`([^`]+)`\s*\|", section)


def check_agent_spec_format(report: GateReport) -> None:
    for filename, agent in SPEC_NAMES.items():
        path = AGENTS_DIR / filename
        if not path.exists():
            report.error("agent-spec-format", f"{filename}: missing spec file")
            continue
        text = path.read_text(encoding="utf-8")
        for heading in REQUIRED_SPEC_HEADINGS:
            if heading not in text:
                report.error("agent-spec-format", f"{filename}: missing heading {heading!r}")

        local = parse_spec_slots(text, "Local Vulnerabilities")
        remote = parse_spec_slots(text, "Remote Vulnerabilities")
        ports = parse_spec_slots(text, "Connect Ports")
        total = len(local) + len(remote) + len(ports)
        if total != 50:
            report.error(
                "agent-spec-format",
                f"{filename}: parsed {total} actions for {agent}, expected 50 "
                f"(local={len(local)}, remote={len(remote)}, ports={len(ports)})",
            )
        if not local or not remote or not ports:
            report.error(
                "agent-spec-format",
                f"{filename}: action tables must remain machine-readable "
                "as '| Slot | `Identifier` |' rows",
            )


def run_gate(
    config_path: Path,
    vocab_path: Path,
    catalog_path: Path,
    min_success_rate: float,
    max_concentration_fraction: float,
) -> GateReport:
    report = GateReport()
    cfg = load_yaml(config_path, report)
    if not cfg:
        return report

    check_existing_validators(config_path, cfg, report, vocab_path, catalog_path)
    check_agent_spec_format(report)
    check_placeholders(cfg, report)

    profiles = service_node_profiles(cfg)
    if not profiles:
        report.error("generation-feasibility", "no service/group profiles can be generated from domains")
        return report

    check_probability_and_rates(cfg, profiles, report, min_success_rate)
    check_semantic_families(cfg, profiles, report)
    check_constraint_resolvability(cfg, profiles, report)
    check_entry_points(cfg, profiles, report)
    check_concentration(cfg, profiles, report, max_concentration_fraction)

    return report


def print_human(config_path: Path, report: GateReport, strict: bool) -> None:
    print()
    print("=" * 72)
    print("  PREFLIGHT STATIC GATE")
    print(f"  Config: {config_path}")
    print("=" * 72)

    if report.errors:
        print("\nERRORS")
        for issue in report.errors:
            print(f"  [{issue.check}] {issue.message}")
    else:
        print("\nERRORS")
        print("  none")

    if report.warnings:
        print("\nWARNINGS")
        for issue in report.warnings:
            print(f"  [{issue.check}] {issue.message}")
    else:
        print("\nWARNINGS")
        print("  none")

    passed = not report.errors and (not strict or not report.warnings)
    print()
    print(
        f"SUMMARY: {'PASS' if passed else 'FAIL'} "
        f"({len(report.errors)} error(s), {len(report.warnings)} warning(s)"
        f"{', strict' if strict else ''})"
    )
    print("=" * 72)
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hard preflight gate for LLM-generated CyberBattleSim configs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("config", type=Path, help="Scenario config YAML")
    parser.add_argument(
        "--vocab",
        type=Path,
        default=LOCAL_CBS_VOCAB if LOCAL_CBS_VOCAB.exists() else FALLBACK_VOCAB,
        help="Path to global_vocabulary.yaml",
    )
    parser.add_argument("--catalog", type=Path, default=CATALOG_PATH,
                        help="Path to vulnerability_catalog.md")
    parser.add_argument("--min-success-rate", type=float, default=0.05,
                        help="Minimum usable success_rate for any Solvability.* vuln")
    parser.add_argument("--max-concentration-fraction", type=float, default=0.40,
                        help="Warn when one generated node type can carry more than this fraction of slots")
    parser.add_argument("--strict", action="store_true",
                        help="Treat warnings as failures")
    parser.add_argument("--json", action="store_true",
                        help="Emit machine-readable result")
    args = parser.parse_args()

    if not args.config.exists():
        print(f"ERROR: config not found: {args.config}", file=sys.stderr)
        return 2

    report = run_gate(
        config_path=args.config,
        vocab_path=args.vocab,
        catalog_path=args.catalog,
        min_success_rate=args.min_success_rate,
        max_concentration_fraction=args.max_concentration_fraction,
    )
    passed = not report.errors and (not args.strict or not report.warnings)

    if args.json:
        payload = {
            "config": str(args.config),
            "passed": passed,
            "strict": args.strict,
            "errors": [issue.__dict__ for issue in report.errors],
            "warnings": [issue.__dict__ for issue in report.warnings],
        }
        print(json.dumps(payload, indent=2))
    else:
        print_human(args.config, report, args.strict)

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
