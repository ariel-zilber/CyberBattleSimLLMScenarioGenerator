"""
Unit tests for pipeline/phase1/config_checker.py

Covers: check_identifiers, check_groups, check_metadata,
        check_agent_category_allowlist, check_constraints, check_config_settings.
"""

import pytest
from pipeline.phase1.config_checker import (
    check_identifiers,
    check_groups,
    check_metadata,
    check_agent_category_allowlist,
    check_constraints,
    check_config_settings,
)


# ===========================================================================
# check_identifiers
# ===========================================================================

class TestCheckIdentifiers:
    def _base(self):
        return {
            "identifiers": {
                "base_properties": ["Windows", "DomainJoined", "Unpatched"],
                "standard_ports": ["RDP", "SMB", "SSH"],
            },
            "services": {},
            "solvability_vulnerabilities": {},
        }

    def test_declared_property_in_service_passes(self):
        # Use all declared base_properties to avoid orphan issues
        cfg = self._base()
        cfg["services"]["WinBox"] = {
            "default_properties": ["Windows", "DomainJoined", "Unpatched"]
        }
        assert check_identifiers(cfg) == []

    def test_undeclared_property_in_service_flagged(self):
        cfg = self._base()
        cfg["services"]["WinBox"] = {"default_properties": ["Windows", "Invented"]}
        issues = check_identifiers(cfg)
        assert any("Invented" in i for i in issues)

    def test_port_label_allowed_as_property(self):
        """Ports from standard_ports are valid in default_properties (no 'not in identifiers' error)."""
        cfg = self._base()
        # Use all base_props to avoid orphan noise; add RDP from standard_ports
        cfg["services"]["Box"] = {
            "default_properties": ["Windows", "DomainJoined", "Unpatched", "RDP"]
        }
        # RDP is in standard_ports → valid_props; no "not in identifiers" error for RDP
        issues = [i for i in check_identifiers(cfg) if "RDP" in i]
        assert issues == []

    def test_breach_node_flagged_if_not_in_identifiers(self):
        """breach_node is exempt from the orphan check but NOT from the undeclared-property check."""
        cfg = self._base()
        cfg["services"]["Entry"] = {"default_properties": ["breach_node"]}
        issues = check_identifiers(cfg)
        # breach_node not in identifiers.base_properties → flagged as undeclared
        assert any("breach_node" in i for i in issues)

    def test_orphaned_property_flagged(self):
        """Property declared in identifiers but never used → orphan."""
        cfg = self._base()
        # Windows is declared but no service uses it
        issues = check_identifiers(cfg)
        # All three declared props are orphaned
        assert any("orphaned" in i for i in issues)

    def test_used_property_not_orphaned(self):
        cfg = self._base()
        cfg["services"]["Box"] = {
            "default_properties": ["Windows", "DomainJoined", "Unpatched"]
        }
        orphan_issues = [i for i in check_identifiers(cfg) if "orphaned" in i]
        assert orphan_issues == []

    def test_match_property_undeclared_flagged(self):
        cfg = self._base()
        cfg["solvability_vulnerabilities"] = {
            "remote_access": [
                {"name": "Solvability.V", "match_properties": ["GhostProp"]}
            ]
        }
        issues = check_identifiers(cfg)
        assert any("GhostProp" in i for i in issues)

    def test_match_property_declared_passes(self):
        cfg = self._base()
        cfg["solvability_vulnerabilities"] = {
            "remote_access": [
                {"name": "Solvability.V", "match_properties": ["Windows"]}
            ]
        }
        cfg["services"]["WinBox"] = {"default_properties": ["Windows"]}
        issues = [i for i in check_identifiers(cfg) if "GhostProp" in i or "match_property" in i]
        assert issues == []


# ===========================================================================
# check_groups
# ===========================================================================

class TestCheckGroups:
    def _base(self):
        return {
            "services": {
                "DomainController": {"is_goal": True},
                "FileServer": {},
            },
            "domains": [],
        }

    def test_group_references_defined_service_passes(self):
        cfg = self._base()
        cfg["domains"] = [{
            "name": "Z1",
            "groups": [{"name": "dc_group", "service": "DomainController"}],
        }]
        assert check_groups(cfg) == []

    def test_group_references_undefined_service_flagged(self):
        cfg = self._base()
        cfg["domains"] = [{
            "name": "Z1",
            "groups": [{"name": "ghost_group", "service": "NonExistentService"}],
        }]
        issues = check_groups(cfg)
        assert any("NonExistentService" in i for i in issues)

    def test_mandatory_service_defined_passes(self):
        cfg = self._base()
        cfg["domains"] = [{
            "name": "Z1",
            "groups": [],
            "mandatory_services": ["DomainController"],
        }]
        assert check_groups(cfg) == []

    def test_mandatory_service_undefined_flagged(self):
        cfg = self._base()
        cfg["domains"] = [{
            "name": "Z1",
            "groups": [],
            "mandatory_services": ["MySQLDatabase"],
        }]
        issues = check_groups(cfg)
        assert any("MySQLDatabase" in i for i in issues)

    def test_empty_domains_passes(self):
        cfg = self._base()
        assert check_groups(cfg) == []


# ===========================================================================
# check_metadata
# ===========================================================================

class TestCheckMetadata:
    def _valid_meta(self):
        return {
            "metadata": {
                "scenario_id": "TEST-001",
                "agent": "S_Windows",
                "zones": ["Z1_ServerFarm"],
                "node_range": [5, 20],
                "terminal_goal": "DomainController",
            },
            "services": {
                "DomainController": {"is_goal": True},
            },
        }

    def test_valid_metadata_passes(self):
        assert check_metadata(self._valid_meta()) == []

    def test_missing_metadata_block_flagged(self):
        issues = check_metadata({})
        assert any("missing" in i.lower() for i in issues)

    def test_missing_scenario_id_flagged(self):
        cfg = self._valid_meta()
        del cfg["metadata"]["scenario_id"]
        assert any("scenario_id" in i for i in check_metadata(cfg))

    def test_missing_agent_flagged(self):
        cfg = self._valid_meta()
        del cfg["metadata"]["agent"]
        assert any("agent" in i for i in check_metadata(cfg))

    def test_unknown_agent_flagged(self):
        cfg = self._valid_meta()
        cfg["metadata"]["agent"] = "S_Unknown"
        assert any("S_Unknown" in i for i in check_metadata(cfg))

    def test_all_known_agents_pass(self):
        for agent in ("S_Network", "S_Linux", "S_Windows", "S_Identity", "S_Lateral", "Meta"):
            cfg = self._valid_meta()
            cfg["metadata"]["agent"] = agent
            issues = [i for i in check_metadata(cfg) if "agent" in i.lower() and "recognised" in i]
            assert issues == [], f"Agent {agent!r} wrongly rejected"

    def test_node_range_wrong_length_flagged(self):
        cfg = self._valid_meta()
        cfg["metadata"]["node_range"] = [5]
        assert any("node_range" in i for i in check_metadata(cfg))

    def test_node_range_not_list_flagged(self):
        cfg = self._valid_meta()
        cfg["metadata"]["node_range"] = "5-20"
        assert any("node_range" in i for i in check_metadata(cfg))

    def test_terminal_goal_references_is_goal_service_passes(self):
        cfg = self._valid_meta()
        assert check_metadata(cfg) == []

    def test_terminal_goal_no_matching_service_flagged(self):
        cfg = self._valid_meta()
        cfg["metadata"]["terminal_goal"] = "NonExistentGoal"
        assert any("NonExistentGoal" in i for i in check_metadata(cfg))

    def test_terminal_goal_list_form_passes(self):
        cfg = self._valid_meta()
        cfg["metadata"]["terminal_goal"] = ["DomainController"]
        assert check_metadata(cfg) == []

    def test_zones_not_list_flagged(self):
        cfg = self._valid_meta()
        cfg["metadata"]["zones"] = "Z1_ServerFarm"
        assert any("zones" in i for i in check_metadata(cfg))

    def test_empty_scenario_id_flagged(self):
        cfg = self._valid_meta()
        cfg["metadata"]["scenario_id"] = ""
        assert any("scenario_id" in i for i in check_metadata(cfg))


# ===========================================================================
# check_agent_category_allowlist
# ===========================================================================

class TestCheckAgentCategoryAllowlist:
    def test_s_network_allowed_categories_pass(self):
        cfg = {
            "metadata": {"agent": "S_Network"},
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Solvability.BlueKeep"}],
                "credential_leak": [{"name": "Solvability.Mimikatz"}],
            },
        }
        issues = check_agent_category_allowlist(cfg)
        assert issues == []

    def test_s_network_lateral_movement_flagged(self):
        cfg = {
            "metadata": {"agent": "S_Network"},
            "solvability_vulnerabilities": {
                "lateral_movement": [{"name": "Solvability.PassTheHash"}],
            },
        }
        issues = check_agent_category_allowlist(cfg)
        assert any("lateral_movement" in i for i in issues)

    def test_s_lateral_goal_access_flagged(self):
        cfg = {
            "metadata": {"agent": "S_Lateral"},
            "solvability_vulnerabilities": {
                "goal_access": [{"name": "Solvability.DCSync"}],
            },
        }
        issues = check_agent_category_allowlist(cfg)
        assert any("goal_access" in i for i in issues)

    def test_meta_all_categories_pass(self):
        cfg = {
            "metadata": {"agent": "Meta"},
            "solvability_vulnerabilities": {
                "remote_access": [{"name": "Solvability.A"}],
                "credential_leak": [{"name": "Solvability.B"}],
                "lateral_movement": [{"name": "Solvability.C"}],
                "discovery": [{"name": "Solvability.D"}],
                "goal_access": [{"name": "Solvability.E"}],
            },
        }
        issues = check_agent_category_allowlist(cfg)
        assert issues == []

    def test_no_agent_in_metadata_skips_category_check(self):
        """Without metadata.agent, category check is skipped."""
        cfg = {
            "metadata": {},
            "solvability_vulnerabilities": {
                "lateral_movement": [{"name": "Solvability.X"}],
            },
        }
        issues = check_agent_category_allowlist(cfg)
        # No category violations without agent
        cat_issues = [i for i in issues if "not permitted" in i]
        assert cat_issues == []

    def test_empty_category_list_skipped(self):
        """Empty category entry doesn't trigger allowlist check."""
        cfg = {
            "metadata": {"agent": "S_Network"},
            "solvability_vulnerabilities": {
                "lateral_movement": [],
            },
        }
        issues = check_agent_category_allowlist(cfg)
        assert issues == []


# ===========================================================================
# check_constraints
# ===========================================================================

class TestCheckConstraints:
    def _base_cfg(self, constraints):
        return {
            "services": {
                "WorkstationA": {},
                "FileServer": {"is_goal": True},
            },
            "domains": [{
                "name": "Z1",
                "groups": [
                    {"name": "wks_grp", "service": "WorkstationA"},
                    {"name": "fs_grp", "service": "FileServer"},
                ],
                "constraints": constraints,
            }],
        }

    def test_leak_with_must_connect_passes(self):
        cfg = self._base_cfg([
            {"source": "wks_grp", "target": "fs_grp", "relation": "MUST_CONNECT"},
            {"source": "wks_grp", "target": "fs_grp", "relation": "LEAK_KNOWN_CREDENTIALS"},
        ])
        assert check_constraints(cfg) == []

    def test_leak_without_must_connect_flagged(self):
        cfg = self._base_cfg([
            {"source": "wks_grp", "target": "fs_grp", "relation": "LEAK_KNOWN_CREDENTIALS"},
        ])
        issues = check_constraints(cfg)
        assert any("LEAK_KNOWN_CREDENTIALS" in i for i in issues)

    def test_must_have_unauthenticated_on_goal_flagged(self):
        cfg = self._base_cfg([
            {
                "source": "fs_grp",
                "target": "fs_grp",
                "relation": "MUST_HAVE",
                "property": "Unauthenticated",
            },
        ])
        issues = check_constraints(cfg)
        assert any("Unauthenticated" in i for i in issues)

    def test_must_have_other_prop_on_goal_passes(self):
        cfg = self._base_cfg([
            {
                "source": "fs_grp",
                "target": "fs_grp",
                "relation": "MUST_HAVE",
                "property": "DomainJoined",
            },
        ])
        assert check_constraints(cfg) == []

    def test_must_connect_without_leak_passes(self):
        cfg = self._base_cfg([
            {"source": "wks_grp", "target": "fs_grp", "relation": "MUST_CONNECT"},
        ])
        assert check_constraints(cfg) == []

    def test_empty_constraints_passes(self):
        assert check_constraints(self._base_cfg([])) == []


# ===========================================================================
# check_config_settings
# ===========================================================================

class TestCheckConfigSettings:
    def _valid_cfg(self):
        return {
            "config": {
                "min_total_nodes": 5,
                "max_total_nodes": 20,
                "goal_config": {"num_goals": 1},
            },
            "services": {
                "DomainController": {"is_goal": True},
            },
            "start_node": {
                "properties": ["breach_node"],
                "leaked_node_coverage": 0.1,
            },
        }

    def test_valid_config_passes(self):
        assert check_config_settings(self._valid_cfg()) == []

    def test_min_nodes_zero_flagged(self):
        cfg = self._valid_cfg()
        cfg["config"]["min_total_nodes"] = 0
        assert any("min_total_nodes" in i for i in check_config_settings(cfg))

    def test_max_less_than_min_flagged(self):
        cfg = self._valid_cfg()
        cfg["config"]["min_total_nodes"] = 20
        cfg["config"]["max_total_nodes"] = 10
        assert any("max_total_nodes" in i for i in check_config_settings(cfg))

    def test_max_equals_min_flagged(self):
        cfg = self._valid_cfg()
        cfg["config"]["min_total_nodes"] = 10
        cfg["config"]["max_total_nodes"] = 10
        assert any("max_total_nodes" in i for i in check_config_settings(cfg))

    def test_very_large_max_warns(self):
        cfg = self._valid_cfg()
        cfg["config"]["max_total_nodes"] = 600
        assert any("600" in i or "large" in i.lower() for i in check_config_settings(cfg))

    def test_num_goals_zero_flagged(self):
        cfg = self._valid_cfg()
        cfg["config"]["goal_config"]["num_goals"] = 0
        assert any("num_goals" in i for i in check_config_settings(cfg))

    def test_num_goals_exceeds_goal_services_flagged(self):
        cfg = self._valid_cfg()
        cfg["config"]["goal_config"]["num_goals"] = 5  # only 1 is_goal service
        assert any("num_goals" in i or "goal_eligible" in i.lower() or "is_goal" in i for i in check_config_settings(cfg))

    def test_missing_start_node_flagged(self):
        cfg = self._valid_cfg()
        del cfg["start_node"]
        assert any("start_node" in i for i in check_config_settings(cfg))

    def test_start_node_missing_breach_node_flagged(self):
        cfg = self._valid_cfg()
        cfg["start_node"]["properties"] = ["Linux"]
        assert any("breach_node" in i for i in check_config_settings(cfg))

    def test_leaked_node_coverage_too_high_flagged(self):
        cfg = self._valid_cfg()
        cfg["start_node"]["leaked_node_coverage"] = 0.7
        assert any("leaked_node_coverage" in i for i in check_config_settings(cfg))

    def test_leaked_node_coverage_exactly_half_passes(self):
        cfg = self._valid_cfg()
        cfg["start_node"]["leaked_node_coverage"] = 0.5
        start_issues = [i for i in check_config_settings(cfg) if "leaked_node_coverage" in i]
        assert start_issues == []
