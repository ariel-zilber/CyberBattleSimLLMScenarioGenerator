#!/usr/bin/env python3
"""
template_validator.py
=====================
Validates CyberBattleSim domain configuration YAML templates against the required
schema, ensuring logical consistency, property references, and structural rules.
"""

import yaml
import argparse
import sys
from pathlib import Path

# Required top-level keys
REQUIRED_SECTIONS = [
    'config', 'identifiers', 'os_management_ports', 'start_node',
    'attack_flow', 'constraint_vulnerabilities', 'probe_vulnerabilities',
    'solvability_vulnerabilities', 'services', 'domains',
    'entry_points', 'solvability_rules'
]

VALID_RELATIONS = {
    'MUST_CONNECT', 'MUST_REACH', 'CLIENT_OF', 
    'LEAK_KNOWN_CREDENTIALS', 'KNOWS', 'MUST_HAVE'
}

class TemplateValidator:
    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.data = {}
        self.errors = []
        self.warnings = []
        
        self.registered_properties = set()
        self.registered_ports = set()
        self.registered_services = set()
        self.registered_groups = set()
        self.all_valid_labels = set() # Combined ports and properties

    def log_error(self, msg: str):
        self.errors.append(f"[ERROR] {msg}")

    def log_warning(self, msg: str):
        self.warnings.append(f"[WARNING] {msg}")

    def load(self) -> bool:
        if not self.filepath.exists():
            self.log_error(f"File not found: {self.filepath}")
            return False
        try:
            with open(self.filepath, 'r') as f:
                self.data = yaml.safe_load(f)
            if not isinstance(self.data, dict):
                self.log_error("YAML root must be a dictionary.")
                return False
            return True
        except yaml.YAMLError as e:
            self.log_error(f"YAML parsing error: {e}")
            return False

    def validate(self):
        if not self.load():
            return False

        self._check_top_level_sections()
        if not self.errors:
            self._validate_identifiers()
            self._validate_services()
            self._validate_domains()
            self._validate_start_node()
            self._validate_attack_flow()
            self._validate_solvability_vulns()

        return len(self.errors) == 0

    def _check_top_level_sections(self):
        for section in REQUIRED_SECTIONS:
            if section not in self.data:
                self.log_error(f"Missing required top-level section: '{section}'")

    def _validate_identifiers(self):
        identifiers = self.data.get('identifiers', {})
        self.registered_ports = set(identifiers.get('standard_ports', []))
        self.registered_properties = set(identifiers.get('base_properties', []))
        
        # Ports can be used as property labels in the engine
        self.all_valid_labels = self.registered_properties.union(self.registered_ports)

        if 'breach_node' not in self.registered_properties:
            self.log_error("'identifiers.base_properties' must contain 'breach_node'.")

        if not self.registered_ports:
            self.log_warning("No 'standard_ports' defined in identifiers.")

    def _validate_services(self):
        services = self.data.get('services', {})
        if not services:
            self.log_error("No services defined.")
            return

        has_goal = False
        for svc_name, svc_data in services.items():
            self.registered_services.add(svc_name)
            
            # Check required service keys
            for key in ['port', 'value', 'allowed_os', 'default_properties', 'is_goal']:
                if key not in svc_data:
                    self.log_error(f"Service '{svc_name}' is missing '{key}'.")

            # Check properties against BOTH base_properties and standard_ports
            props = svc_data.get('default_properties', [])
            for prop in props:
                if prop not in self.all_valid_labels:
                    self.log_error(f"Service '{svc_name}' uses unregistered property '{prop}'. "
                                   f"Add it to identifiers.base_properties or identifiers.standard_ports.")
            
            # Check for goals
            if svc_data.get('is_goal') is True:
                has_goal = True
                if 'Unauthenticated' in props:
                    self.log_warning(f"Service '{svc_name}' is a goal but has 'Unauthenticated' property. This may trivialize the scenario.")

        if not has_goal:
            self.log_error("No service is marked with 'is_goal: true'. At least one goal service is required.")

    def _validate_domains(self):
        domains = self.data.get('domains', [])
        if not isinstance(domains, list) or not domains:
            self.log_error("'domains' must be a non-empty list.")
            return

        for idx, domain in enumerate(domains):
            dom_name = domain.get('name', f"Index_{idx}")
            if 'subnet' not in domain:
                self.log_error(f"Domain '{dom_name}' is missing 'subnet'.")
            
            groups = domain.get('groups', [])
            for group in groups:
                group_name = group.get('name')
                svc = group.get('service')
                if group_name:
                    self.registered_groups.add(group_name)
                
                if svc not in self.registered_services:
                    self.log_error(f"Domain '{dom_name}' group '{group_name}' references undefined service '{svc}'.")

            constraints = domain.get('constraints', [])
            for c in constraints:
                rel = c.get('relation')
                if rel not in VALID_RELATIONS:
                    self.log_error(f"Domain '{dom_name}' has invalid constraint relation '{rel}'. Valid options: {VALID_RELATIONS}")
                
                # Check source/target groups exist
                src = c.get('source')
                tgt = c.get('target')
                if src and src not in self.registered_groups:
                    self.log_error(f"Constraint source '{src}' in domain '{dom_name}' is not a defined group name.")
                if tgt and tgt not in self.registered_groups and rel != 'MUST_HAVE':
                    self.log_error(f"Constraint target '{tgt}' in domain '{dom_name}' is not a defined group name.")

    def _validate_start_node(self):
        start_node = self.data.get('start_node', {})
        if 'breach_node' not in start_node.get('properties', []):
            self.log_error("'start_node.properties' must include 'breach_node'.")
        
        vulns = start_node.get('vulnerabilities', {})
        if 'discovery' not in vulns or 'credential_leak' not in vulns:
            self.log_error("'start_node.vulnerabilities' must contain 'discovery' and 'credential_leak' definitions.")

    def _validate_attack_flow(self):
        flow = self.data.get('attack_flow', [])
        if not flow:
            self.log_warning("No 'attack_flow' defined. Lateral movement validation may fail in simulation.")
            return
            
        for rule in flow:
            src = rule.get('source_pattern')
            tgts = rule.get('targets', [])
            
            if src not in self.registered_services and src not in self.all_valid_labels:
                 self.log_warning(f"attack_flow source_pattern '{src}' does not match any known service or property.")
            
            for tgt in tgts:
                if tgt not in self.registered_services and tgt not in self.all_valid_labels:
                    self.log_warning(f"attack_flow target '{tgt}' does not match any known service or property.")

    def _validate_solvability_vulns(self):
        vulns = self.data.get('solvability_vulnerabilities', {})
        for category, vuln_list in vulns.items():
            if not isinstance(vuln_list, list):
                continue
            for v in vuln_list:
                match_props = v.get('match_properties', [])
                for p in match_props:
                    if p not in self.all_valid_labels:
                        self.log_error(f"Solvability vuln '{v.get('name')}' requires unregistered property '{p}'.")
                
                # Check EPSS probability existence
                if 'probability' not in v:
                    self.log_warning(f"Solvability vuln '{v.get('name')}' is missing 'probability'. Realism requires EPSS-derived probabilities.")

    def print_report(self):
        print(f"\n{'='*60}")
        print(f"Template Validation Report: {self.filepath.name}")
        print(f"{'='*60}")
        
        if not self.errors and not self.warnings:
            print("✅ Template is strictly valid and structurally sound.")
            return

        if self.errors:
            print("\n❌ ERRORS (Must fix):")
            for e in self.errors:
                print(f"  {e}")

        if self.warnings:
            print("\n⚠️  WARNINGS (Review recommended):")
            for w in self.warnings:
                print(f"  {w}")
                
        print(f"\nSummary: {len(self.errors)} Errors, {len(self.warnings)} Warnings.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Validate a CyberBattleSim Domain Generator YAML template.")
    parser.add_argument("template", help="Path to the YAML template file to validate.")
    args = parser.parse_args()

    validator = TemplateValidator(args.template)
    validator.validate()
    validator.print_report()
    
    if validator.errors:
        sys.exit(1)
    else:
        sys.exit(0)