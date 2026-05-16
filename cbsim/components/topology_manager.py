from typing import Optional, Dict

try:
    import networkx as nx
    _HAS_NX = True
except ImportError:
    nx = None          # type: ignore[assignment]
    _HAS_NX = False


class TopologyManager:
    """
    Manages the loading and processing of static network topologies
    defined in GML or GraphML formats (Backbone networks).
    """

    def __init__(self, gml_path: Optional[str], config: Optional[Dict] = None):
        """
        Args:
            gml_path: File path to the .gml or .graphml file.
                      Can be None or "None" string if no backbone is used.
            config:   Top-level YAML config dict.  Reads
                      ``backbone_subnet_base`` (default ``"172"``) to control
                      which RFC-1918 range is used for backbone node subnets.
        """
        cfg = config or {}
        self._backbone_base = cfg.get('backbone_subnet_base', '172')
        self.backbone_graph = self._load_backbone(gml_path)
        self.backbone_subnets: Dict[str, str] = {}

        # If a graph was successfully loaded, calculate its subnets immediately
        if self.backbone_graph:
            self._assign_subnets_to_backbone()

    def _load_backbone(self, path: Optional[str]):
        """
        Loads a NetworkX graph from the specified file path.
        Supports .graphml and .gml formats.
        """
        if not path or path == "None":
            return None

        if not _HAS_NX:
            print("Warning: networkx is not installed — GML/GraphML topology loading disabled. "
                  "Pass 'None' as gml_file_path to use synthetic topology.")
            return None

        try:
            if path.endswith('.graphml'):
                return nx.read_graphml(path)
            elif path.endswith('.gml'):
                # 'label="id"' ensures node IDs in GML become the NetworkX node keys
                return nx.read_gml(path, label='id')
            else:
                print(f"Warning: Unsupported topology file format: {path}")
                return None
        except Exception as e:
            print(f"Warning: Could not load backbone graph from {path}: {e}")
            return None

    def _assign_subnets_to_backbone(self):
        """
        Assigns distinct subnets to every node in the backbone graph.
        
        Naming Convention:
          - Subnet Key: "backbone_{node_id}"
          - CIDR: 172.{octet_2}.{octet_3}.0/24
        
        Logic:
          - Maps a linear index to the 2nd and 3rd octets of a 172.x.x.x private range.
          - Ensures up to ~65,000 backbone nodes have unique subnets.
        """
        nodes = list(self.backbone_graph.nodes())
        
        for i, node_id in enumerate(nodes):
            octet_2 = (i // 255) % 255
            octet_3 = i % 255
            subnet_cidr = f"{self._backbone_base}.{octet_2}.{octet_3}.0/24"
            self.backbone_subnets[f"backbone_{node_id}"] = subnet_cidr

    def get_backbone_subnets(self) -> Dict[str, str]:
        """
        Returns the dictionary of calculated subnets.
        Format: {'backbone_nodeID': '172.x.y.0/24', ...}
        """
        return self.backbone_subnets

    def get_graph(self):
        """Returns the raw NetworkX graph object."""
        return self.backbone_graph