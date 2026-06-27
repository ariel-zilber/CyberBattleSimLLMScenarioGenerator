#!/usr/bin/env python3
"""Validate specialist scenario configs against the fixed global vocabulary."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml


LEGACY_PREFIXES = ("Remote.Probe.", "External.", "Local.")
FORBIDDEN_TEXT = {
    "S_Recon",
    "BranchRouter",
    "BranchSDWAN",
    "AWSHTTP",
    "Solvability.ARP_Table_Dump",
    "Solvability.Nmap_Internal",
    "Solvability.CDP_Neighbors",
    "Solvability.CiscoASA_OSPF",
}


def load_vocab(path: Path) -> dict[str, set[str]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        "local": set(data.get("local_vulnerabilities", [])),
        "remote": set(data.get("remote_vulnerabilities", [])),
        "ports": set(data.get("ports", [])),
        "services": set(data.get("service_ids", [])),
        "properties": set(data.get("properties", [])),
    }


def dotted(path: tuple[Any, ...]) -> str:
    return ".".join(str(part) for part in path) or "<root>"


def add(issues: list[str], file_path: Path, path: tuple[Any, ...], kind: str, value: Any) -> None:
    issues.append(f"{file_path}:{dotted(path)}: {kind}: {value}")


def validate_file(file_path: Path, vocab: dict[str, set[str]]) -> list[str]:
    data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    issues: list[str] = []

    local = vocab["local"]
    remote = vocab["remote"]
    all_vulns = local | remote
    ports = vocab["ports"]
    services = vocab["services"]
    # The generator schema allows port labels in property slots, and phase1
    # requires breach_node as the synthetic attacker node marker.
    properties = vocab["properties"] | ports | {"breach_node"}

    def walk(obj: Any, path: tuple[Any, ...] = ()) -> None:
        if isinstance(obj, dict):
            if path == ("services",):
                for service_id in obj:
                    if service_id not in services:
                        add(issues, file_path, path + (service_id,), "unknown service key", service_id)

            for key, value in obj.items():
                key_path = path + (key,)

                if key in {"port", "protocol", "default_entry_port"} and isinstance(value, str):
                    if value not in ports:
                        add(issues, file_path, key_path, "unknown port", value)

                if key in {"standard_ports", "standard_ports_extra", "preferred_entry_ports"} and isinstance(value, list):
                    for idx, item in enumerate(value):
                        if isinstance(item, str) and item not in ports:
                            add(issues, file_path, key_path + (idx,), "unknown port", item)

                if key == "service" and isinstance(value, str) and value not in services:
                    add(issues, file_path, key_path, "unknown service", value)

                if key == "source_pattern" and isinstance(value, str):
                    if value not in services and value not in properties:
                        add(issues, file_path, key_path, "unknown attack-flow label", value)

                if key == "targets" and isinstance(value, list):
                    for idx, item in enumerate(value):
                        if isinstance(item, str) and item not in services and item not in properties:
                            add(issues, file_path, key_path + (idx,), "unknown attack-flow label", item)

                if key in {"default_properties", "properties", "match_properties", "base_properties"} and isinstance(value, list):
                    for idx, item in enumerate(value):
                        if isinstance(item, str) and item not in properties:
                            add(issues, file_path, key_path + (idx,), "unknown property", item)

                if key == "name" and isinstance(value, str):
                    if value.startswith(LEGACY_PREFIXES):
                        add(issues, file_path, key_path, "legacy vulnerability name", value)
                    elif value.startswith("Solvability."):
                        vuln_type = obj.get("type")
                        if vuln_type == "LOCAL" and value not in local:
                            add(issues, file_path, key_path, "not a global local vulnerability", value)
                        elif vuln_type == "REMOTE" and value not in remote:
                            add(issues, file_path, key_path, "not a global remote vulnerability", value)
                        elif vuln_type not in {"LOCAL", "REMOTE"} and value not in all_vulns:
                            add(issues, file_path, key_path, "not a global vulnerability", value)

                if isinstance(value, str):
                    for token in FORBIDDEN_TEXT:
                        if token in value:
                            add(issues, file_path, key_path, "forbidden legacy text", token)

                walk(value, key_path)

        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                walk(item, path + (idx,))

    walk(data)
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vocab",
        type=Path,
        default=Path("/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml"),
        help="Path to global_vocabulary.yaml",
    )
    parser.add_argument("configs", nargs="+", type=Path, help="Config YAML files to validate")
    args = parser.parse_args()

    vocab = load_vocab(args.vocab)
    issues: list[str] = []
    for config in args.configs:
        issues.extend(validate_file(config, vocab))

    if issues:
        print(f"Specialist vocabulary validation failed: {len(issues)} issue(s)")
        for issue in issues:
            print(issue)
        return 1

    print(f"Specialist vocabulary validation passed: {len(args.configs)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
