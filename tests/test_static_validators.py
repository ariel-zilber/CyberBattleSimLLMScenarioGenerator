"""
Unit tests for tools/static_validation.py

Tests cover the pure-Python per-file check functions.
Each check takes (fp: Path, data: dict); we pass a dummy Path for the name.
"""

import pytest
from pathlib import Path

from tools.static_validation import (
    check_breach_node,
    check_remote_entry,
    check_success_rates,
    check_category_spread,
    check_value_monotonicity,
    check_orphan_services,
    check_goal_specialist_coverage,
    load_vuln_catalog,
)

FP = Path("test_scenario.yaml")


# ===========================================================================
# load_vuln_catalog
# ===========================================================================

class TestLoadVulnCatalog:
    def test_parses_category_headers(self, tmp_path):
        md = tmp_path / "catalog.md"
        md.write_text(
            "## Category: `remote_access`\n"
            "| `Solvability.BlueKeep` | 0.6 | Windows |\n"
            "## Category: `credential_leak`\n"
            "| `Solvability.Zerologon` | 0.55 | AD |\n"
        )
        catalog = load_vuln_catalog(md)
        assert "remote_access" in catalog
        assert "Solvability.BlueKeep" in catalog["remote_access"]

    def test_extracts_solvability_names(self, tmp_path):
        md = tmp_path / "catalog.md"
        md.write_text(
            "## Category: `discovery`\n"
            "| `Solvability.LDAP_Enum` | 0.9 | AD |\n"
            "| `Solvability.SMB_Enum` | 0.8 | Windows |\n"
        )
        catalog = load_vuln_catalog(md)
        assert "Solvability.LDAP_Enum" in catalog["discovery"]
        assert "Solvability.SMB_Enum" in catalog["discovery"]

    def test_non_solvability_names_ignored(self, tmp_path):
        md = tmp_path / "catalog.md"
        md.write_text(
            "## Category: `remote_access`\n"
            "Some text with `NotSolvability.Foo` and `Solvability.Real`.\n"
        )
        catalog = load_vuln_catalog(md)
        assert "NotSolvability.Foo" not in catalog.get("remote_access", set())
        assert "Solvability.Real" in catalog["remote_access"]

    def test_empty_file_returns_empty(self, tmp_path):
        md = tmp_path / "empty.md"
        md.write_text("")
        catalog = load_vuln_catalog(md)
        assert catalog == {}


# ===========================================================================
# check_breach_node
# ===========================================================================

class TestCheckBreachNode:
    def test_breach_node_in_service_default_properties(self):
        data = {
            "services": {
                "MyFW": {"default_properties": ["breach_node", "Windows"]}
            }
        }
        assert check_breach_node(FP, data) == []

    def test_breach_node_in_service_base_properties(self):
        data = {
            "services": {
                "Entry": {"base_properties": ["breach_node"]}
            }
        }
        assert check_breach_node(FP, data) == []

    def test_breach_node_in_start_node_properties(self):
        data = {
            "start_node": {"properties": ["breach_node"]}
        }
        assert check_breach_node(FP, data) == []

    def test_missing_breach_node_returns_error(self):
        data = {
            "services": {"Svc": {"default_properties": ["Windows"]}},
            "start_node": {"properties": ["Linux"]},
        }
        issues = check_breach_node(FP, data)
        assert len(issues) == 1
        assert "breach_node" in issues[0]

    def test_empty_data_returns_error(self):
        issues = check_breach_node(FP, {})
        assert len(issues) == 1


# ===========================================================================
# check_remote_entry
# ===========================================================================

class TestCheckRemoteEntry:
    def test_remote_vuln_in_solvability_passes(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"type": "REMOTE", "name": "Solvability.BlueKeep"}]
            }
        }
        assert check_remote_entry(FP, data) == []

    def test_remote_vuln_in_start_node_passes(self):
        data = {
            "start_node": {
                "vulnerabilities": {
                    "disc": {"type": "REMOTE", "name": "Solvability.LDAP_Enum"}
                }
            }
        }
        assert check_remote_entry(FP, data) == []

    def test_only_local_vulns_returns_error(self):
        data = {
            "solvability_vulnerabilities": {
                "credential_leak": [{"type": "LOCAL", "name": "Solvability.Mimikatz"}]
            }
        }
        issues = check_remote_entry(FP, data)
        assert len(issues) == 1
        assert "REMOTE" in issues[0]

    def test_empty_data_returns_error(self):
        issues = check_remote_entry(FP, {})
        assert len(issues) == 1


# ===========================================================================
# check_success_rates
# ===========================================================================

class TestCheckSuccessRates:
    def test_valid_rate_passes(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Solvability.X", "success_rate": 0.7}]
            }
        }
        assert check_success_rates(FP, data) == []

    def test_rate_too_low_returns_error(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Solvability.X", "success_rate": 0.01}]
            }
        }
        issues = check_success_rates(FP, data)
        assert len(issues) == 1
        assert "0.01" in issues[0]

    def test_rate_too_high_returns_error(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Solvability.X", "success_rate": 0.99}]
            }
        }
        issues = check_success_rates(FP, data)
        assert len(issues) == 1

    def test_boundary_low_passes(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Solvability.X", "success_rate": 0.05}]
            }
        }
        assert check_success_rates(FP, data) == []

    def test_boundary_high_passes(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Solvability.X", "success_rate": 0.95}]
            }
        }
        assert check_success_rates(FP, data) == []

    def test_nested_success_rate_caught(self):
        data = {
            "solvability_vulnerabilities": {
                "cat": [{"name": "v1", "success_rate": 1.0}]
            }
        }
        issues = check_success_rates(FP, data)
        assert len(issues) == 1

    def test_multiple_vulns_multiple_errors(self):
        data = {
            "solvability_vulnerabilities": {
                "cat": [
                    {"name": "v1", "success_rate": 0.01},
                    {"name": "v2", "success_rate": 0.99},
                    {"name": "v3", "success_rate": 0.5},
                ]
            }
        }
        issues = check_success_rates(FP, data)
        assert len(issues) == 2


# ===========================================================================
# check_category_spread
# ===========================================================================

class TestCheckCategorySpread:
    def test_two_categories_passes(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "v1"}],
                "credential_leak": [{"name": "v2"}],
            }
        }
        assert check_category_spread(FP, data) == []

    def test_three_categories_passes(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "v1"}],
                "credential_leak": [{"name": "v2"}],
                "discovery": [{"name": "v3"}],
            }
        }
        assert check_category_spread(FP, data) == []

    def test_one_category_returns_error(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "v1"}],
                "credential_leak": [],  # empty
            }
        }
        issues = check_category_spread(FP, data)
        assert len(issues) == 1

    def test_empty_categories_returns_error(self):
        data = {"solvability_vulnerabilities": {}}
        issues = check_category_spread(FP, data)
        assert len(issues) == 1

    def test_all_empty_returns_error(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [],
                "credential_leak": [],
            }
        }
        issues = check_category_spread(FP, data)
        assert len(issues) == 1


# ===========================================================================
# check_value_monotonicity
# ===========================================================================

class TestCheckValueMonotonicity:
    def test_uniform_non_goal_values_warned(self):
        data = {
            "services": {
                "A": {"value": 1, "is_goal": False},
                "B": {"value": 1, "is_goal": False},
                "C": {"value": 1, "is_goal": False},
            }
        }
        issues = check_value_monotonicity(FP, data)
        assert len(issues) == 1

    def test_varied_non_goal_values_pass(self):
        data = {
            "services": {
                "A": {"value": 1, "is_goal": False},
                "B": {"value": 2, "is_goal": False},
                "C": {"value": 3, "is_goal": False},
            }
        }
        assert check_value_monotonicity(FP, data) == []

    def test_goal_services_excluded_from_check(self):
        data = {
            "services": {
                "A": {"value": 5, "is_goal": True},
                "B": {"value": 1, "is_goal": False},
                "C": {"value": 1, "is_goal": False},
            }
        }
        # only 2 non-goal services → need >=3 for warning
        assert check_value_monotonicity(FP, data) == []

    def test_two_non_goal_services_no_warning(self):
        data = {
            "services": {
                "A": {"value": 1, "is_goal": False},
                "B": {"value": 1, "is_goal": False},
            }
        }
        # threshold is >=3
        assert check_value_monotonicity(FP, data) == []


# ===========================================================================
# check_orphan_services
# ===========================================================================

class TestCheckOrphanServices:
    def test_empty_service_config_flagged(self):
        data = {"services": {"EmptySvc": {}}}
        issues = check_orphan_services(FP, data)
        assert len(issues) == 1

    def test_non_empty_service_passes(self):
        data = {
            "services": {
                "GoodSvc": {"value": 1, "default_properties": ["Windows"]}
            }
        }
        assert check_orphan_services(FP, data) == []

    def test_mix_empty_and_non_empty(self):
        data = {
            "services": {
                "Good": {"value": 1},
                "Empty": {},
            }
        }
        issues = check_orphan_services(FP, data)
        assert len(issues) == 1
        assert "Empty" in issues[0]
