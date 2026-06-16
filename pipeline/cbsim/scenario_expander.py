"""
Scenario Expander
=================
Injects missing GLOBALTECH background zones into a scenario YAML so that every
scenario in the dataset shares the same canonical enterprise topology skeleton.

Active zones (those whose subnets overlap a canonical zone's detect_subnet) are
left untouched.  Missing zones get a disconnected background domain: real node
types, zero vulnerabilities, value=1.  The agent can probe background nodes but
will find nothing to exploit — they are structural noise.

Output written to <source_stem>_expanded.yaml in the same directory.
"""

from __future__ import annotations

import copy
from ipaddress import ip_network, ip_address
from pathlib import Path
from typing import Any

import yaml


_BASE_YAML = Path(__file__).parent.parent.parent / "data" / "canonical_base.yaml"

# Additional subnet ranges that map to Z5 (branch) beyond the canonical /16
_Z5_EXTRA_SUBNETS = [ip_network("10.100.0.0/24")]


def _load_base() -> dict[str, Any]:
    return yaml.safe_load(_BASE_YAML.read_text())["zones"]


def _parse_subnet(subnet_str: str) -> ip_network | None:
    """Return an ip_network or None if the subnet is unparseable / too broad."""
    try:
        net = ip_network(subnet_str, strict=False)
        # Ignore subnets that cover the whole RFC-1918 10.x space —
        # those are flat single-domain configs that already represent everything.
        if net.prefixlen <= 8:
            return None
        return net
    except ValueError:
        return None


def _subnets_overlap(a: ip_network, b: ip_network) -> bool:
    return a.overlaps(b)


def _covered_zones(scenario: dict[str, Any], base: dict[str, Any]) -> set[str]:
    """Return the set of canonical zone IDs already covered by the scenario."""
    covered: set[str] = set()
    domains = scenario.get("domains", [])
    if not domains:
        return covered

    for domain in domains:
        domain_net = _parse_subnet(domain.get("subnet", ""))
        if domain_net is None:
            # Broad flat subnet — counts as covering all zones.
            return set(base.keys())

        for zone_id, zone_def in base.items():
            detect_net = ip_network(zone_def["detect_subnet"], strict=False)

            # Extra branch subnets
            extra = _Z5_EXTRA_SUBNETS if zone_id == "Z5_BranchOffice" else []

            if _subnets_overlap(domain_net, detect_net) or any(
                _subnets_overlap(domain_net, e) for e in extra
            ):
                covered.add(zone_id)

    return covered


def _collect_bg_properties(base: dict[str, Any], missing_zones: set[str]) -> list[str]:
    """Return sorted list of unique properties used by background services."""
    props: set[str] = set()
    for zone_id in missing_zones:
        for svc_def in base[zone_id]["services"].values():
            props.update(svc_def.get("default_properties", []))
    return sorted(props)


def expand(scenario_path: Path, output_path: Path | None = None) -> Path:
    """
    Expand *scenario_path* and write the result to *output_path*.
    If *output_path* is None, writes to <stem>_expanded.yaml in the same dir.
    Returns the path of the written file.
    """
    raw = scenario_path.read_text(encoding="utf-8")
    scenario = yaml.safe_load(raw)
    base = _load_base()

    covered = _covered_zones(scenario, base)
    missing = set(base.keys()) - covered

    if not missing:
        # Nothing to add — write a clean copy with a note in metadata.
        expanded = copy.deepcopy(scenario)
        expanded.setdefault("metadata", {})["bg_expansion"] = "full_coverage_no_zones_added"
        out = output_path or scenario_path.with_stem(scenario_path.stem + "_expanded")
        out.write_text(yaml.dump(expanded, allow_unicode=True, sort_keys=False), encoding="utf-8")
        return out

    expanded = copy.deepcopy(scenario)

    # 1. Inject background services (BG_* prefix avoids name collisions)
    expanded.setdefault("services", {})
    for zone_id in sorted(missing):
        for svc_name, svc_def in base[zone_id]["services"].items():
            if svc_name not in expanded["services"]:
                expanded["services"][svc_name] = copy.deepcopy(svc_def)

    # 2. Inject background domains (disconnected — no inter_domain_constraints)
    expanded.setdefault("domains", [])
    existing_subnets = {d.get("subnet") for d in expanded["domains"]}
    for zone_id in sorted(missing):
        domain_def = copy.deepcopy(base[zone_id]["domain"])
        if domain_def["subnet"] not in existing_subnets:
            expanded["domains"].append(domain_def)
            existing_subnets.add(domain_def["subnet"])

    # 3. Register background properties in identifiers.base_properties
    bg_props = _collect_bg_properties(base, missing)
    base_props: list = expanded.setdefault("identifiers", {}).setdefault("base_properties", [])
    for prop in bg_props:
        if prop not in base_props:
            base_props.append(prop)

    # 4. Record expansion metadata
    expanded.setdefault("metadata", {})["bg_expansion"] = {
        "covered_zones": sorted(covered),
        "added_zones": sorted(missing),
    }

    out = output_path or scenario_path.with_stem(scenario_path.stem + "_expanded")
    out.write_text(yaml.dump(expanded, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return out


def expansion_summary(scenario_path: Path) -> dict[str, Any]:
    """Return coverage info without writing anything — useful for dry runs."""
    scenario = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    base = _load_base()
    covered = _covered_zones(scenario, base)
    missing = set(base.keys()) - covered
    return {
        "scenario": scenario_path.name,
        "covered": sorted(covered),
        "will_add": sorted(missing),
    }
