# =============================================================================
# CREDENTIAL BANK SYSTEM
# =============================================================================
# Solves the problem: YAML outcomes reference abstract credentials 
# ("domain_user", "admin") but actual credentials are node-specific
# ("CorporateAD_Workstations_1_RDP")
#
# Solution: Build banks of real credentials grouped by type, then vulnerabilities
# randomly select from appropriate banks
# =============================================================================

from typing import Dict, List
import random

class CredentialBank:
    """
    Manages pools of credentials by type/role.
    Vulnerabilities select randomly from appropriate pools.
    """
    
    def __init__(self, nodes: Dict):
        self.nodes = nodes
        self.banks: Dict[str, List[str]] = {
            'guest': [],
            'user': [],
            'domain_user': [],
            'local_admin': [],
            'admin': [],
            'file_admin': [],
            'backup_admin': [],
            'service_admin': [],
            'domain_admin': [],
            'enterprise_admin': [],
            'krbtgt': []
        }
        
        self._build_banks()
    
    def _build_banks(self):
        """Scan all nodes and categorize their credentials into banks"""
        print("\n[CredentialBank] Building credential banks...")
        
        for node_id, node in self.nodes.items():
            if node_id == 'start':
                continue
            
            # Get node type
            node_group = self._get_attr(node, 'group', '')
            services = self._get_attr(node, 'services', [])
            
            for service in services:
                creds = self._get_attr(service, 'allowedCredentials', [])
                
                for cred in creds:
                    # Categorize based on node type and service
                    self._categorize_credential(cred, node_id, node_group, service.name)
        
        # Print summary
        for bank_type, creds in self.banks.items():
            if creds:
                print(f"  [{bank_type:20}] {len(creds)} credentials")
    
    def _categorize_credential(self, cred: str, node_id: str, node_group: str, service_name: str):
        """Put a credential into appropriate bank(s)"""
        
        # Guest credentials (everyone has these)
        if 'Workstation' in node_group:
            self.banks['guest'].append(cred)
            self.banks['user'].append(cred)
            self.banks['domain_user'].append(cred)
        
        # Workstation local admins
        if 'Workstation' in node_group and service_name == 'RDP':
            self.banks['local_admin'].append(cred)
        
        # File server admins
        if 'FileServer' in node_group:
            self.banks['file_admin'].append(cred)
            self.banks['backup_admin'].append(cred)
            self.banks['admin'].append(cred)
            self.banks['domain_user'].append(cred)
        
        # Domain controller admins
        if 'DomainController' in node_group or 'DC' in node_group:
            self.banks['domain_admin'].append(cred)
            self.banks['enterprise_admin'].append(cred)
            self.banks['service_admin'].append(cred)
            self.banks['admin'].append(cred)
            self.banks['krbtgt'].append(cred)
    
    def select_credentials(self, bank_names: List[str], count: int = None, 
                          probability: float = 1.0) -> List[str]:
        """
        Randomly select credentials from specified banks.
        
        Args:
            bank_names: List of bank types to select from (e.g., ['domain_user', 'admin'])
            count: Number of credentials to select (None = all matching)
            probability: Probability of selecting each credential (0.0-1.0)
        
        Returns:
            List of actual credential IDs
        """
        available = set()
        
        # Collect all credentials from requested banks
        for bank_name in bank_names:
            if bank_name in self.banks:
                available.update(self.banks[bank_name])
        
        if not available:
            return []
        
        # Apply probability filtering
        if probability < 1.0:
            selected = [cred for cred in available if random.random() < probability]
        else:
            selected = list(available)
        
        # Limit count if specified
        if count is not None and len(selected) > count:
            selected = random.sample(selected, count)
        
        return selected
    
    def get_credentials_for_node(self, target_node_id: str) -> List[str]:
        """Get all credentials that work on a specific target node"""
        if target_node_id not in self.nodes:
            return []
        
        target_node = self.nodes[target_node_id]
        all_creds = []
        
        for service in self._get_attr(target_node, 'services', []):
            creds = self._get_attr(service, 'allowedCredentials', [])
            all_creds.extend(creds)
        
        return all_creds
    
    def _get_attr(self, obj, attr, default=None):
        """Safe attribute getter"""
        if isinstance(obj, dict):
            return obj.get(attr, default)
        return getattr(obj, attr, default)


# =============================================================================
# INTEGRATION: Replace YAML Credential References
# =============================================================================

class CredentialResolver:
    """
    Resolves abstract credential names from YAML to actual credentials.
    
    Usage in vulnerability processing:
    
    # YAML says:
    outcome:
      leaked_credentials: ["domain_user", "admin"]
    
    # Resolver converts to:
    outcome = LeakedCredentials(credentials=[
        CachedCredential(node="FileServer_1", port="SMB", 
                        credential="CorporateAD_FileServers_1_SMB"),
        CachedCredential(node="DC_1", port="RDP", 
                        credential="CorporateAD_DomainControllers_1_RDP")
    ])
    """
    
    def __init__(self, credential_bank: CredentialBank, nodes: Dict):
        self.bank = credential_bank
        self.nodes = nodes
    
    def resolve_outcome_credentials(self, abstract_creds: List[str], 
                                   context_node_id: str = None,
                                   max_per_type: int = 3,
                                   probability: float = C.DEFAULT_CREDENTIAL_PROBABILITY) -> List[tuple]:
        """
        Convert abstract credential names to actual CachedCredential tuples.
        
        Args:
            abstract_creds: List like ["domain_user", "admin"]
            context_node_id: Source node (for context)
            max_per_type: Maximum credentials to leak per type
            probability: Chance of selecting each credential
        
        Returns:
            List of (node_id, port, credential_id) tuples
        """
        result = []
        
        for abstract_name in abstract_creds:
            # Select real credentials from this bank
            real_creds = self.bank.select_credentials(
                [abstract_name], 
                count=max_per_type,
                probability=probability
            )
            
            # Map each credential to its node
            for cred in real_creds:
                node_id, port = self._find_node_for_credential(cred)
                if node_id:
                    result.append((node_id, port, cred))
        
        return result
    
    def _find_node_for_credential(self, credential_id: str) -> tuple:
        """Find which node and port a credential belongs to"""
        for node_id, node in self.nodes.items():
            if node_id == 'start':
                continue
            
            for service in self._get_attr(node, 'services', []):
                creds = self._get_attr(service, 'allowedCredentials', [])
                if credential_id in creds:
                    return (node_id, service.name)
        
        return (None, None)
    
    def _get_attr(self, obj, attr, default=None):
        """Safe attribute getter"""
        if isinstance(obj, dict):
            return obj.get(attr, default)
        return getattr(obj, attr, default)


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

"""
# In your vulnerability manager:

from credential_bank import CredentialBank, CredentialResolver

class VulnerabilityManager:
    def __init__(self, ...):
        # After nodes are created:
        self.credential_bank = CredentialBank(self.nodes)
        self.credential_resolver = CredentialResolver(self.credential_bank, self.nodes)
    
    def _convert_outcome(self, outcome_dict, vuln_name):
        leaked_creds_abstract = outcome_dict.get('leaked_credentials', [])
        
        if leaked_creds_abstract:
            # Resolve abstract names to real credentials
            cred_tuples = self.credential_resolver.resolve_outcome_credentials(
                leaked_creds_abstract,
                max_per_type=2,      # Leak at most 2 creds per type
                probability=C.DEFAULT_CREDENTIAL_PROBABILITY      # Balanced chance per credential
            )
            
            # Create proper CachedCredential objects
            from cyberbattle.simulation.vulenrabilites import CachedCredential, LeakedCredentials
            cached_creds = [
                CachedCredential(node=node_id, port=port, credential=cred_id)
                for node_id, port, cred_id in cred_tuples
            ]
            
            return LeakedCredentials(credentials=cached_creds)
"""""