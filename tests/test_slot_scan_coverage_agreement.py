"""Regression test for problem #10 in the validation report: two coverage
tools disagreed on the same dataset (e.g. one reported 38/38 slots, another
36/38).

Root cause: check_dataset_coverage.py's _instance_observed_slots() used
yaml.safe_load() to parse every generated node YAML. nodes/start.yaml
serializes real Python objects (e.g. ipaddress.IPv4Network) via a custom
PyYAML tag that safe_load refuses to construct, raising ConstructorError.
That exception was caught by a bare `except: continue`, silently skipping
the ENTIRE start.yaml file -- so any Solvability.* slot that only ever
appears on the start node was invisible to that tool, while
audit_full_coverage_dataset.py's separate regex-based scanner (which never
parses YAML at all) saw it correctly. Same dataset, two different answers.

Fix: both tools now delegate to tools.slot_scan.observed_solvability_slots,
a single shared, YAML-parse-independent (regex-based) extractor.

Run:
    pytest tests/test_slot_scan_coverage_agreement.py -x -q
"""
from pathlib import Path

from tools.slot_scan import observed_solvability_slots


_UNPARSEABLE_START_YAML = """\
vulnerabilities:
  Solvability.LDAP_Enum:
    type: LOCAL
network_info:
- subnet: !!python/object/apply:ipaddress.IPv4Network
  - 10.0.1.0/24
"""

_NORMAL_NODE_YAML = """\
vulnerabilities:
  Solvability.PanOS_CMDInject:
    type: REMOTE
properties:
- Linux
"""


def test_observed_slots_finds_solvability_names_even_in_unparseable_yaml(tmp_path):
    """The exact bug scenario: a node YAML containing a custom Python object
    tag that yaml.safe_load cannot construct. The shared extractor must
    still find the Solvability.* name in it -- proving it never depends on
    successfully parsing the YAML at all."""
    scenarios_dir = Path(tmp_path) / "scenarios"
    nodes_dir = scenarios_dir / "train" / "CyberBattleSim-test-0001" / "nodes"
    nodes_dir.mkdir(parents=True)

    (nodes_dir / "start.yaml").write_text(_UNPARSEABLE_START_YAML)
    (nodes_dir / "entry.yaml").write_text(_NORMAL_NODE_YAML)

    # Sanity: confirm start.yaml really is unparseable by plain yaml.safe_load,
    # i.e. this test is actually exercising the reported failure mode.
    import yaml
    try:
        yaml.safe_load((nodes_dir / "start.yaml").read_text())
        assert False, "test fixture is not actually unparseable by safe_load -- fix the fixture"
    except yaml.constructor.ConstructorError:
        pass

    observed = observed_solvability_slots(scenarios_dir)

    assert observed == {"Solvability.LDAP_Enum", "Solvability.PanOS_CMDInject"}, (
        f"expected both slots (including the one only on the unparseable "
        f"start.yaml), got {observed}"
    )


def test_check_dataset_coverage_and_audit_tool_use_the_same_extractor():
    """Both coverage tools must import the identical shared function, not
    independent reimplementations that could silently drift apart again."""
    from tools.check_dataset_coverage import observed_solvability_slots as a
    from tools.audit_full_coverage_dataset import observed_solvability_slots as b
    from tools.slot_scan import observed_solvability_slots as shared

    assert a is shared
    assert b is shared
