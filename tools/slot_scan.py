"""
tools/slot_scan.py
===================
Single shared implementation for scanning generated scenario instances for
Solvability.* vulnerability slot names.

Problem #10 from the validation report: two coverage tools disagreed on the
same dataset (one reported e.g. 38/38 slots, another 36/38 for the same
config/scenarios). Root cause: check_dataset_coverage.py's
_instance_observed_slots() parsed each node YAML with yaml.safe_load(), which
raises ConstructorError on nodes/start.yaml (it serializes real Python
objects like ipaddress.IPv4Network via a custom PyYAML tag that safe_load
refuses to construct). The exception was caught by a bare
`except Exception: continue`, silently skipping that entire file — so any
slot that lives ONLY on the start node (e.g. the config's own
start_node.vulnerabilities entries) was invisible to that tool, while
audit_full_coverage_dataset.py's separate regex-based scanner (immune to
this, since it never parses YAML at all) saw it correctly.

Fix: one shared, YAML-parse-independent extractor, used by every coverage
gate. A plain regex over the raw file text can never fail to "parse" —
there is nothing it depends on beyond the literal string "Solvability.X"
appearing in the file, which is true regardless of what custom object tags
surround it.
"""
from __future__ import annotations

import re
from pathlib import Path

SOLVABILITY_RE = re.compile(r"Solvability\.[A-Za-z0-9_]+")


def observed_solvability_slots(scenarios_dir: Path) -> set[str]:
    """Regex-scan every nodes/*.yaml under scenarios_dir for Solvability.*
    vulnerability names. Used identically by every coverage-checking tool so
    they can never disagree due to differing extraction mechanisms."""
    slots: set[str] = set()
    for node_file in scenarios_dir.rglob("nodes/*.yaml"):
        try:
            slots.update(SOLVABILITY_RE.findall(node_file.read_text(encoding="utf-8")))
        except Exception:
            continue
    return slots
