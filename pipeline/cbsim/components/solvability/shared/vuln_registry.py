"""
Planned-vulnerability registry, shared by SolvabilityPostProcessor and
SolvabilityConstraintProcessor. Plain functions — no class/self state.
"""

from typing import Dict


def collect_planned_vuln_names(config: dict) -> set:
    """Return the set of all vulnerability names declared anywhere in the YAML config.

    Covers: solvability_vulnerabilities, vulnerability_patterns,
    probe_vulnerabilities, constraint_vulnerabilities, start_node.vulnerabilities.
    Any vulnerability injected at runtime must appear here.
    """
    names: set = set()
    for item in config.get('vulnerability_patterns', []):
        if isinstance(item, dict) and item.get('name'):
            names.add(item['name'])
    for item in config.get('probe_vulnerabilities', []):
        if isinstance(item, dict) and item.get('name'):
            names.add(item['name'])
    for group in config.get('solvability_vulnerabilities', {}).values():
        for item in (group if isinstance(group, list) else []):
            if isinstance(item, dict) and item.get('name'):
                names.add(item['name'])
    for vdef in config.get('constraint_vulnerabilities', {}).values():
        if isinstance(vdef, dict) and vdef.get('name'):
            names.add(vdef['name'])
    for vdef in config.get('start_node', {}).get('vulnerabilities', {}).values():
        if isinstance(vdef, dict) and vdef.get('name'):
            names.add(vdef['name'])
    return names


def check_planned(tmpl: Dict, planned_vuln_names: set, label: str, context: str = '') -> bool:
    """Return False and print an error if the template name is not declared
    in the YAML config. Prevents injecting unplanned vulnerabilities that
    would be absent from the CyberBattleSim action space.

    label distinguishes the caller's log prefix ("Solvability" or
    "Constraints") — preserved so existing log output doesn't change.
    """
    name = tmpl.get('name', '') if isinstance(tmpl, dict) else ''
    if not name:
        print(f"[{label}] ERROR: injection template missing 'name'"
              f"{' (' + context + ')' if context else ''} — skipping")
        return False
    if planned_vuln_names and name not in planned_vuln_names:
        print(f"[{label}] ERROR: refusing to inject unplanned vulnerability "
              f"'{name}' — not declared in any YAML config section. "
              f"Add it to solvability_vulnerabilities or vulnerability_patterns.")
        return False
    return True
