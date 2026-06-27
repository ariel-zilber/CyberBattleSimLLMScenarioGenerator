"""
Adversarial tests for tools/static_validation.py

Tests that probe boundary conditions, malformed configs, cycle detection,
dead-technique detection, and real-file smoke tests.
"""

import pytest
from pathlib import Path

from tools.static_validation import (
    check_success_rates,
    check_breach_node,
    check_remote_entry,
    check_category_spread,
    check_attack_flow_dag,
    check_dead_techniques,
    check_goal_specialist_coverage,
    check_orphan_services,
    validate_file,
    load_vuln_catalog,
    load_global_vocab,
)

FP = Path("adversarial.yaml")

REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_VOCAB = REPO_ROOT / "data" / "global_vocabulary.yaml"
_DEFAULT_CATALOG = REPO_ROOT / "prompts" / "reference" / "vulnerability_catalog.md"


# ===========================================================================
# check_success_rates: boundary adversarials
# ===========================================================================

class TestSuccessRateBoundaries:
    def test_exactly_0_05_passes(self):
        data = {"solvability_vulnerabilities": {"cat": [{"success_rate": 0.05}]}}
        assert check_success_rates(FP, data) == []

    def test_exactly_0_95_passes(self):
        data = {"solvability_vulnerabilities": {"cat": [{"success_rate": 0.95}]}}
        assert check_success_rates(FP, data) == []

    def test_0_049_fails(self):
        data = {"solvability_vulnerabilities": {"cat": [{"success_rate": 0.049}]}}
        assert len(check_success_rates(FP, data)) == 1

    def test_0_951_fails(self):
        data = {"solvability_vulnerabilities": {"cat": [{"success_rate": 0.951}]}}
        assert len(check_success_rates(FP, data)) == 1

    def test_zero_fails(self):
        data = {"solvability_vulnerabilities": {"cat": [{"success_rate": 0.0}]}}
        assert len(check_success_rates(FP, data)) == 1

    def test_one_exactly_fails(self):
        data = {"solvability_vulnerabilities": {"cat": [{"success_rate": 1.0}]}}
        assert len(check_success_rates(FP, data)) == 1

    def test_none_value_skipped_silently(self):
        """None success_rate is not (int, float) → check skips it, no error."""
        data = {"solvability_vulnerabilities": {"cat": [{"success_rate": None}]}}
        # Documents current behavior: None bypasses the bounds check
        assert check_success_rates(FP, data) == []

    def test_string_value_skipped_silently(self):
        """String success_rate is not (int, float) → skipped silently."""
        data = {"solvability_vulnerabilities": {"cat": [{"success_rate": "0.5"}]}}
        assert check_success_rates(FP, data) == []

    def test_success_rate_in_constraint_vulnerabilities_checked(self):
        data = {"constraint_vulnerabilities": {"c": [{"success_rate": 0.0}]}}
        assert len(check_success_rates(FP, data)) == 1

    def test_success_rate_in_start_node_checked(self):
        data = {"start_node": {"vulnerabilities": {"v": {"success_rate": 1.0}}}}
        assert len(check_success_rates(FP, data)) == 1

    def test_probe_vulnerabilities_section_not_checked(self):
        """probe_vulnerabilities intentionally use 1.0 — excluded from check."""
        data = {"probe_vulnerabilities": {"p": [{"success_rate": 1.0}]}}
        assert check_success_rates(FP, data) == []


# ===========================================================================
# check_attack_flow_dag: cycle detection adversarials
# ===========================================================================

class TestAttackFlowDAG:
    def test_linear_chain_passes(self):
        data = {
            "attack_flow": [
                {"source_pattern": "A", "targets": ["B"]},
                {"source_pattern": "B", "targets": ["C"]},
            ]
        }
        assert check_attack_flow_dag(FP, data) == []

    def test_two_node_cycle_detected(self):
        """A→B and B→A is a cycle."""
        data = {
            "attack_flow": [
                {"source_pattern": "A", "targets": ["B"]},
                {"source_pattern": "B", "targets": ["A"]},
            ]
        }
        issues = check_attack_flow_dag(FP, data)
        assert len(issues) == 1
        assert "cycle" in issues[0].lower()

    def test_three_node_cycle_detected(self):
        data = {
            "attack_flow": [
                {"source_pattern": "A", "targets": ["B"]},
                {"source_pattern": "B", "targets": ["C"]},
                {"source_pattern": "C", "targets": ["A"]},
            ]
        }
        assert len(check_attack_flow_dag(FP, data)) == 1

    def test_self_loop_detected(self):
        data = {
            "attack_flow": [
                {"source_pattern": "A", "targets": ["A"]},
            ]
        }
        assert len(check_attack_flow_dag(FP, data)) == 1

    def test_diamond_no_cycle(self):
        """A→B, A→C, B→D, C→D is a valid DAG."""
        data = {
            "attack_flow": [
                {"source_pattern": "A", "targets": ["B", "C"]},
                {"source_pattern": "B", "targets": ["D"]},
                {"source_pattern": "C", "targets": ["D"]},
            ]
        }
        assert check_attack_flow_dag(FP, data) == []

    def test_empty_attack_flow_passes(self):
        data = {"attack_flow": []}
        assert check_attack_flow_dag(FP, data) == []

    def test_missing_attack_flow_passes(self):
        assert check_attack_flow_dag(FP, {}) == []

    def test_non_list_attack_flow_passes(self):
        """Non-list attack_flow (schema error elsewhere) doesn't crash DAG check."""
        data = {"attack_flow": "not_a_list"}
        assert check_attack_flow_dag(FP, data) == []


# ===========================================================================
# check_dead_techniques: adversarials
# ===========================================================================

class TestDeadTechniques:
    def test_technique_satisfiable_by_matching_service_passes(self):
        data = {
            "services": {
                "WindowsServer": {
                    "default_properties": ["Windows", "DomainJoined", "Unpatched"]
                }
            },
            "solvability_vulnerabilities": {
                "remote_access": [
                    {
                        "name": "Solvability.BlueKeep",
                        "match_properties": ["Windows", "Unpatched"],
                    }
                ]
            },
        }
        assert check_dead_techniques(FP, data) == []

    def test_technique_unsatisfiable_flagged(self):
        """match_properties requires Router AND Windows — impossible combination."""
        data = {
            "services": {
                "Router": {"default_properties": ["Router"]},
                "WindowsBox": {"default_properties": ["Windows"]},
            },
            "solvability_vulnerabilities": {
                "remote_access": [
                    {
                        "name": "Solvability.RouterWin",
                        "match_properties": ["Router", "Windows"],
                    }
                ]
            },
        }
        issues = check_dead_techniques(FP, data)
        assert len(issues) == 1
        assert "dead" in issues[0].lower()

    def test_technique_with_empty_match_properties_skipped(self):
        """No match_properties → no dead-technique check."""
        data = {
            "services": {"A": {"default_properties": ["X"]}},
            "solvability_vulnerabilities": {
                "cat": [{"name": "Solvability.Anything", "match_properties": []}]
            },
        }
        assert check_dead_techniques(FP, data) == []

    def test_no_services_skips_check(self):
        data = {
            "solvability_vulnerabilities": {
                "cat": [{"name": "Solvability.V", "match_properties": ["X"]}]
            }
        }
        assert check_dead_techniques(FP, data) == []

    def test_superset_match_passes(self):
        """Service has MORE properties than required → still satisfiable."""
        data = {
            "services": {
                "RichNode": {
                    "default_properties": ["Windows", "DomainJoined", "Unpatched", "RDP"]
                }
            },
            "solvability_vulnerabilities": {
                "cat": [
                    {
                        "name": "Solvability.V",
                        "match_properties": ["Windows", "Unpatched"],
                    }
                ]
            },
        }
        assert check_dead_techniques(FP, data) == []


# ===========================================================================
# check_goal_specialist_coverage: adversarials
# ===========================================================================

class TestGoalSpecialistCoverage:
    def test_three_distinct_specialists_passes(self):
        data = {
            "metadata": {"intermediate_goals": []},
            "services": {
                "DomainController": {"is_goal": True},    # s_identity
                "AppServer": {"is_goal": True},           # s_linux
                "SalesWorkstation": {"is_goal": True},    # s_windows
            },
        }
        issues = check_goal_specialist_coverage(FP, data)
        # Should have 0 issues for specialist count, but may warn about unmapped
        spec_coverage_issues = [i for i in issues if "3 distinct" in i or "≥ 3" in i]
        assert len(spec_coverage_issues) == 0

    def test_fewer_than_three_goals_flagged(self):
        data = {
            "metadata": {"intermediate_goals": []},
            "services": {
                "DomainController": {"is_goal": True},
                "AppServer": {"is_goal": True},
            },
        }
        issues = check_goal_specialist_coverage(FP, data)
        # Produces 2 violations: pool-size < 3 AND specialist-count < 3
        pool_issues = [i for i in issues if "goal pool" in i.lower()]
        assert len(pool_issues) >= 1

    def test_single_specialist_all_goals_flagged(self):
        """All goals map to s_identity → only 1 specialist covered."""
        data = {
            "metadata": {"intermediate_goals": []},
            "services": {
                "DomainController": {"is_goal": True},
                "ADCS_Server": {"is_goal": True},
                "FileServer": {"is_goal": True},
                "CyberArkPAM": {"is_goal": True},
            },
        }
        issues = check_goal_specialist_coverage(FP, data)
        specialist_issues = [i for i in issues if "specialist" in i.lower()]
        assert len(specialist_issues) >= 1

    def test_unmapped_service_flagged(self):
        data = {
            "metadata": {"intermediate_goals": []},
            "services": {
                "UnknownCustomService": {"is_goal": True},
                "DomainController": {"is_goal": True},
                "AppServer": {"is_goal": True},
            },
        }
        issues = check_goal_specialist_coverage(FP, data)
        unmapped = [i for i in issues if "not in specialist map" in i]
        assert len(unmapped) == 1


# ===========================================================================
# Real YAML file smoke tests
# ===========================================================================

class TestRealFileSmoke:
    """Load actual scenario YAML files and verify static validators don't crash."""

    SCENARIO_DIR = REPO_ROOT / "data" / "scenarios" / "specialists"

    @pytest.fixture
    def scenario_files(self):
        files = list(self.SCENARIO_DIR.glob("*.yaml"))
        if not files:
            pytest.skip("No specialist YAML files found in data/scenarios/specialists/")
        return files[:5]  # smoke-test first 5

    def test_check_success_rates_does_not_crash(self, scenario_files):
        import yaml
        for fp in scenario_files:
            data = yaml.safe_load(fp.read_text()) or {}
            result = check_success_rates(fp, data)
            assert isinstance(result, list), f"crashed on {fp.name}"

    def test_check_breach_node_does_not_crash(self, scenario_files):
        import yaml
        for fp in scenario_files:
            data = yaml.safe_load(fp.read_text()) or {}
            result = check_breach_node(fp, data)
            assert isinstance(result, list), f"crashed on {fp.name}"

    def test_check_attack_flow_dag_does_not_crash(self, scenario_files):
        import yaml
        for fp in scenario_files:
            data = yaml.safe_load(fp.read_text()) or {}
            result = check_attack_flow_dag(fp, data)
            assert isinstance(result, list), f"crashed on {fp.name}"

    def test_check_dead_techniques_does_not_crash(self, scenario_files):
        import yaml
        for fp in scenario_files:
            data = yaml.safe_load(fp.read_text()) or {}
            result = check_dead_techniques(fp, data)
            assert isinstance(result, list), f"crashed on {fp.name}"

    def test_real_files_have_breach_node(self, scenario_files):
        """Every real specialist scenario must have a breach_node entry point."""
        import yaml
        for fp in scenario_files:
            data = yaml.safe_load(fp.read_text()) or {}
            issues = check_breach_node(fp, data)
            assert issues == [], f"{fp.name} missing breach_node: {issues}"

    def test_real_files_have_remote_entry(self, scenario_files):
        """Every real specialist scenario must have at least one REMOTE vuln."""
        import yaml
        for fp in scenario_files:
            data = yaml.safe_load(fp.read_text()) or {}
            issues = check_remote_entry(fp, data)
            assert issues == [], f"{fp.name} missing REMOTE entry: {issues}"

    def test_real_files_attack_flow_is_dag(self, scenario_files):
        """No real specialist scenario should have a cycle in attack_flow."""
        import yaml
        for fp in scenario_files:
            data = yaml.safe_load(fp.read_text()) or {}
            issues = check_attack_flow_dag(fp, data)
            assert issues == [], f"{fp.name} has cycle: {issues}"

    def test_real_files_success_rates_in_bounds(self, scenario_files):
        """All real scenario success_rates must be in [0.05, 0.95]."""
        import yaml
        for fp in scenario_files:
            data = yaml.safe_load(fp.read_text()) or {}
            issues = check_success_rates(fp, data)
            assert issues == [], f"{fp.name}: {issues}"


# ===========================================================================
# Vulnerability catalog integrity
# ===========================================================================

class TestVulnCatalogIntegrity:
    @pytest.fixture
    def catalog(self):
        if not _DEFAULT_CATALOG.exists():
            pytest.skip("vulnerability_catalog.md not found")
        return load_vuln_catalog(_DEFAULT_CATALOG)

    def test_catalog_has_expected_categories(self, catalog):
        expected = {
            "remote_access", "credential_leak", "discovery",
            "goal_access", "lateral_movement",
        }
        missing = expected - set(catalog.keys())
        assert missing == set(), f"Missing categories: {missing}"

    def test_cross_category_names_are_known_multi_tactic_techniques(self, catalog):
        """Some Solvability.* names deliberately appear in multiple categories.

        Multi-tactic techniques (e.g. PassTheHash in credential_leak AND goal_access)
        are intentional — the catalog allows cross-category presence. This test
        verifies the count hasn't grown unexpectedly, documenting current state.
        """
        seen: dict[str, str] = {}
        duplicates = []
        for cat, names in catalog.items():
            for name in names:
                if name in seen:
                    duplicates.append(name)
                else:
                    seen[name] = cat
        # As of the thesis catalog: 14 cross-category entries are intentional.
        # If this number grows significantly, investigate whether new duplicates
        # are intentional multi-tactic entries or accidental copy-paste errors.
        assert len(duplicates) <= 20, (
            f"Unexpected surge in cross-category names ({len(duplicates)}): {duplicates}"
        )

    def test_all_names_have_solvability_prefix(self, catalog):
        for cat, names in catalog.items():
            for name in names:
                assert name.startswith("Solvability."), \
                    f"Unexpected name format in {cat}: {name!r}"

    def test_each_category_nonempty(self, catalog):
        for cat, names in catalog.items():
            assert len(names) > 0, f"Category {cat!r} is empty"
