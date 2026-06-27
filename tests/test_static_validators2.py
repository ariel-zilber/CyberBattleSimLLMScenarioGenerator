"""
Unit tests for tools/static_validation.py — second batch.

Covers: check_identifiers, check_categories, check_duplicates,
        check_goal_values, load_global_vocab.

Note: tools/static_validation.py has its own check_identifiers that is
SEPARATE from pipeline/phase1/config_checker.py's version.  The key
difference: the static-validation version automatically adds 'breach_node'
to the allowed set (so breach_node always passes), whereas the config-checker
version does NOT.
"""

import pytest
from pathlib import Path

from tools.static_validation import (
    check_identifiers,
    check_categories,
    check_duplicates,
    check_goal_values,
    load_global_vocab,
    load_vuln_catalog,
)

FP = Path("test.yaml")
REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_VOCAB   = REPO_ROOT / "data" / "global_vocabulary.yaml"
_DEFAULT_CATALOG = REPO_ROOT / "prompts" / "reference" / "vulnerability_catalog.md"


# ===========================================================================
# check_identifiers  (tools/static_validation.py version)
# ===========================================================================

class TestStaticCheckIdentifiers:
    """check_identifiers from static_validation.py auto-allows breach_node."""

    def _data(self, declared_props, service_props):
        return {
            "identifiers": {"base_properties": declared_props},
            "services": {"SvcA": {"default_properties": service_props}},
        }

    def test_declared_property_passes(self):
        issues = check_identifiers(FP, self._data(["Windows"], ["Windows"]))
        assert issues == []

    def test_undeclared_property_flagged(self):
        issues = check_identifiers(FP, self._data(["Windows"], ["Invented"]))
        assert any("Invented" in i for i in issues)

    def test_breach_node_always_passes(self):
        """breach_node is auto-allowed — not required in identifiers.base_properties."""
        issues = check_identifiers(FP, self._data([], ["breach_node"]))
        assert issues == []

    def test_standard_port_also_allowed(self):
        data = {
            "identifiers": {
                "base_properties": [],
                "standard_ports": ["RDP"],
            },
            "services": {"SvcA": {"default_properties": ["RDP"]}},
        }
        issues = check_identifiers(FP, data)
        assert issues == []

    def test_empty_services_no_issues(self):
        data = {"identifiers": {"base_properties": ["Windows"]}, "services": {}}
        assert check_identifiers(FP, data) == []

    def test_multiple_props_one_undeclared(self):
        issues = check_identifiers(FP, self._data(["Windows"], ["Windows", "Ghost"]))
        undecl = [i for i in issues if "Ghost" in i]
        assert len(undecl) == 1

    def test_match_properties_key_also_checked(self):
        data = {
            "identifiers": {"base_properties": ["Windows"]},
            "services": {"SvcA": {"match_properties": ["Phantom"]}},
        }
        issues = check_identifiers(FP, data)
        assert any("Phantom" in i for i in issues)

    def test_filepath_name_appears_in_issue(self):
        issues = check_identifiers(Path("myfile.yaml"), self._data([], ["BadProp"]))
        assert any("myfile.yaml" in i for i in issues)


# ===========================================================================
# check_categories
# ===========================================================================

class TestCheckCategories:
    def _minimal_catalog(self):
        return {
            "remote_access":    {"Solvability.BlueKeep"},
            "credential_leak":  {"Solvability.Mimikatz"},
            "lateral_movement": {"Solvability.PassTheHash"},
        }

    def test_correct_category_passes(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Solvability.BlueKeep"}],
            }
        }
        issues = check_categories(FP, data, self._minimal_catalog())
        assert issues == []

    def test_wrong_category_flagged(self):
        """BlueKeep placed in credential_leak (canonical: remote_access)."""
        data = {
            "solvability_vulnerabilities": {
                "credential_leak": [{"name": "Solvability.BlueKeep"}],
            }
        }
        issues = check_categories(FP, data, self._minimal_catalog())
        assert any("BlueKeep" in i for i in issues)

    def test_off_catalog_name_not_flagged_by_categories(self):
        """Off-catalog names are handled by check_vocab, not check_categories."""
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Solvability.Invented"}],
            }
        }
        issues = check_categories(FP, data, self._minimal_catalog())
        assert issues == []

    def test_empty_catalog_skips_all_checks(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Solvability.BlueKeep"}],
            }
        }
        assert check_categories(FP, data, {}) == []

    def test_empty_solvability_section_passes(self):
        assert check_categories(FP, {}, self._minimal_catalog()) == []

    def test_non_solvability_names_skipped(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Generic.Exploit"}],
            }
        }
        assert check_categories(FP, data, self._minimal_catalog()) == []

    def test_filepath_name_in_issue(self):
        data = {
            "solvability_vulnerabilities": {
                "credential_leak": [{"name": "Solvability.BlueKeep"}],
            }
        }
        issues = check_categories(Path("myfile.yaml"), data, self._minimal_catalog())
        assert any("myfile.yaml" in i for i in issues)

    def test_real_catalog_loads_and_runs(self):
        if not _DEFAULT_CATALOG.exists():
            pytest.skip("vulnerability_catalog.md not found")
        catalog = load_vuln_catalog(_DEFAULT_CATALOG)
        # Use a known-wrong pairing: pick a name from remote_access, put in credential_leak
        ra_names = list(catalog.get("remote_access", set()))
        if not ra_names:
            pytest.skip("remote_access category empty in catalog")
        data = {
            "solvability_vulnerabilities": {
                "credential_leak": [{"name": ra_names[0]}],
            }
        }
        issues = check_categories(FP, data, catalog)
        assert any(ra_names[0] in i for i in issues)


# ===========================================================================
# check_duplicates
# ===========================================================================

class TestCheckDuplicates:
    def test_no_duplicates_passes(self):
        data = {
            "services": {"SvcA": {"default_properties": ["Windows", "DomainJoined"]}},
            "identifiers": {"base_properties": ["Windows", "DomainJoined"]},
        }
        assert check_duplicates(FP, data) == []

    def test_duplicate_property_in_service_flagged(self):
        data = {
            "services": {"SvcA": {"default_properties": ["Windows", "Windows"]}},
        }
        issues = check_duplicates(FP, data)
        assert any("Windows" in i for i in issues)

    def test_duplicate_in_identifiers_base_properties_flagged(self):
        data = {
            "identifiers": {"base_properties": ["Linux", "Linux"]},
        }
        issues = check_duplicates(FP, data)
        assert any("Linux" in i for i in issues)

    def test_duplicate_in_standard_ports_flagged(self):
        data = {
            "identifiers": {"standard_ports": ["RDP", "RDP", "SSH"]},
        }
        issues = check_duplicates(FP, data)
        assert any("RDP" in i for i in issues)

    def test_duplicate_technique_name_in_category_flagged(self):
        data = {
            "solvability_vulnerabilities": {
                "remote_access": [
                    {"name": "Solvability.BlueKeep"},
                    {"name": "Solvability.BlueKeep"},
                ],
            }
        }
        issues = check_duplicates(FP, data)
        assert any("BlueKeep" in i for i in issues)

    def test_same_name_in_different_categories_passes(self):
        """Duplicate check is per-category, not cross-category."""
        data = {
            "solvability_vulnerabilities": {
                "remote_access":   [{"name": "Solvability.PassTheHash"}],
                "lateral_movement": [{"name": "Solvability.PassTheHash"}],
            }
        }
        issues = check_duplicates(FP, data)
        assert issues == []

    def test_empty_data_passes(self):
        assert check_duplicates(FP, {}) == []

    def test_non_string_items_in_list_not_flagged(self):
        data = {
            "services": {"SvcA": {"default_properties": [1, 1]}},
        }
        # Non-string items are skipped by the duplicate check
        assert check_duplicates(FP, data) == []

    def test_filepath_in_issue(self):
        data = {
            "services": {"SvcA": {"default_properties": ["Windows", "Windows"]}},
        }
        issues = check_duplicates(Path("myfile.yaml"), data)
        assert any("myfile.yaml" in i for i in issues)


# ===========================================================================
# check_goal_values
# ===========================================================================

class TestCheckGoalValues:
    def test_goal_higher_than_non_goal_passes(self):
        data = {
            "services": {
                "Worker": {"value": 5},
                "Goal": {"value": 100, "is_goal": True},
            }
        }
        assert check_goal_values(FP, data) == []

    def test_goal_value_zero_flagged(self):
        data = {
            "services": {
                "Goal": {"value": 0, "is_goal": True},
            }
        }
        issues = check_goal_values(FP, data)
        assert any("value=0" in i or "zero" in i.lower() for i in issues)

    def test_goal_value_negative_flagged(self):
        data = {
            "services": {
                "Goal": {"value": -5, "is_goal": True},
            }
        }
        issues = check_goal_values(FP, data)
        assert len(issues) >= 1

    def test_goal_value_equal_to_non_goal_flagged(self):
        data = {
            "services": {
                "Worker": {"value": 10},
                "Goal": {"value": 10, "is_goal": True},
            }
        }
        issues = check_goal_values(FP, data)
        assert len(issues) >= 1

    def test_no_services_with_value_passes(self):
        data = {
            "services": {
                "Goal": {"is_goal": True},
            }
        }
        assert check_goal_values(FP, data) == []

    def test_no_goal_services_no_issues(self):
        data = {
            "services": {
                "Worker": {"value": 5},
            }
        }
        assert check_goal_values(FP, data) == []


# ===========================================================================
# load_global_vocab
# ===========================================================================

class TestLoadGlobalVocab:
    @pytest.fixture
    def vocab(self):
        if not _DEFAULT_VOCAB.exists():
            pytest.skip("global_vocabulary.yaml not found")
        return load_global_vocab(_DEFAULT_VOCAB)

    def test_vocab_has_required_keys(self, vocab):
        for key in ("local", "remote", "ports", "services", "properties"):
            assert key in vocab, f"Missing key: {key}"

    def test_breach_node_always_in_properties(self, vocab):
        assert "breach_node" in vocab["properties"]

    def test_ports_subset_of_properties(self, vocab):
        assert vocab["ports"].issubset(vocab["properties"])

    def test_all_values_are_sets(self, vocab):
        for key, val in vocab.items():
            assert isinstance(val, set), f"vocab[{key!r}] should be a set"

    def test_vocab_non_empty(self, vocab):
        for key in ("local", "remote", "services"):
            assert len(vocab[key]) > 0, f"vocab[{key!r}] is empty"
