# domain_loader.py
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Any
import yaml

@dataclass
class ServiceProfile:
    """Defines a service's characteristics including goal status"""
    port: Any  # Can be int or str (e.g. 'RDP')
    value: int
    allowed_os: List[str]
    default_properties: List[str]
    is_goal: bool = False  # <--- NEW: Goal property

@dataclass
class DomainTemplate:
    """Represents a single domain with its configuration"""
    name: str
    subnet: str
    os_distribution: Dict[str, float]
    mandatory: List[str]
    filler: Optional[List[str]]
    constraints: List[Dict]
    subnet_assignments: Dict[str, str] = None
    groups: List[Dict] = None

@dataclass
class InterDomainConstraint:
    """Constraints between different domains"""
    source_domain: str
    source: str
    target_domain: str
    target: str
    relation: str
    protocol: Optional[str] = None
    def to_dict(self):
        """Converts the dataclass to a standard dictionary."""
        return asdict(self)

    # --- MAGIC METHODS TO FIX YOUR ERRORS ---
    
    def __getitem__(self, key):
        """Allows access via brackets: constraint['source']"""
        return getattr(self, key)

    def get(self, key, default=None):
        """Allows access via .get(): constraint.get('protocol')"""
        return getattr(self, key, default)
class YamlDomainLoader:
    def __init__(self, yaml_path: str):
        with open(yaml_path, 'r') as f:
            self.data = yaml.safe_load(f)
        
        # Load config
        self.config = self.data.get('config', {})
        
        # --- PARSE SERVICES INTO OBJECTS ---
        raw_services = self.data.get('services', {})
        self.services: Dict[str, ServiceProfile] = {}
        for name, data in raw_services.items():
            self.services[name] = ServiceProfile(
                port=data.get('port'),
                value=data.get('value', 0),
                allowed_os=data.get('allowed_os', []),
                default_properties=data.get('default_properties', []),
                is_goal=data.get('is_goal', False)  # <--- Parse is_goal
            )
        
        # Load vulnerabilities
        self.vulnerabilities = self.data.get('vulnerabilities', [])
        
        # Load global groups (if any)
        self.global_groups = self.data.get('groups', [])
        
        # Load multiple domains
        self.domains: Dict[str, DomainTemplate] = {}
        
        # Check if domains is list (new format)
        domains_data = self.data.get('domains', [])
        for domain_config in domains_data:
            domain_name = domain_config['name']
            
            # Domain-specific groups override global groups
            domain_groups = domain_config.get('groups', self.global_groups)
            
            self.domains[domain_name] = DomainTemplate(
                name=domain_name,
                subnet=domain_config.get('subnet', '10.0.0.0/24'),
                os_distribution=domain_config.get('os_distribution', {}),
                mandatory=domain_config.get('mandatory_services', domain_config.get('mandatory', [])),
                filler=domain_config.get('filler', []),
                constraints=domain_config.get('constraints', []),
                subnet_assignments=domain_config.get('subnet_assignments', {}),
                groups=domain_groups
            )
        
        # Load inter-domain constraints
        self.inter_domain_constraints: List[InterDomainConstraint] = []
        inter_constraints = self.data.get('inter_domain_constraints', [])
        
        for constraint_group in inter_constraints:
            source_domain = constraint_group['source_domain']
            target_domain = constraint_group['target_domain']
            for constraint in constraint_group.get('constraints', []):
                self.inter_domain_constraints.append(
                    InterDomainConstraint(
                        source_domain=source_domain,
                        source=constraint['source'],
                        target_domain=target_domain,
                        target=constraint['target'],
                        relation=constraint['relation'],
                        protocol=constraint.get('protocol')
                    )
                )
        
        # Load network topology
        self.network_topology = self.data.get('network_topology', {})
        
        # Load entry points
        self.entry_points = self.data.get('entry_points', [{}])
    
    def get_domain_template(self, domain_name: str) -> DomainTemplate:
        return self.domains.get(domain_name)
    
    def get_all_domains(self) -> List[str]:
        return list(self.domains.keys())
    
    def get_inter_domain_constraints(self, domain_name: str = None):
        if domain_name:
            return [c for c in self.inter_domain_constraints 
                   if c.source_domain == domain_name or c.target_domain == domain_name]
        return self.inter_domain_constraints