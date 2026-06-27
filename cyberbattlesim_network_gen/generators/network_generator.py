"""Stub NetworkGenerator base class for CyberBattleSimLLMScenarioGenerator."""

from typing import Dict


class NetworkGenerator:
    """Base class — subclasses implement get_nodes(), get_identifiers(), get_vulnerability_library()."""

    def __init__(self, **kwargs):
        pass

    def get_nodes(self) -> Dict:
        raise NotImplementedError

    def get_identifiers(self):
        raise NotImplementedError

    def get_vulnerability_library(self) -> Dict:
        return {}

    def generate(self) -> Dict:
        nodes = self.get_nodes()
        identifiers = self.get_identifiers()
        vuln_lib = self.get_vulnerability_library()
        return {
            "nodes": nodes,
            "identifiers": identifiers,
            "vulnerability_library": vuln_lib,
        }
