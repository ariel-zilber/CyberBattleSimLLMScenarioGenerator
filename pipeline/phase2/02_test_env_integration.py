#!/usr/bin/env python3
"""
tools/test_dynamic_solvability.py
=================================
Validates dynamic solvability by deploying a Swarm of Cooperative Heuristic Agents.
Outputs individual scenario LLM prompts AND aggregates all run metrics (including
deep graph/topology math and firewall-inferred routing edges) into a dataset JSON.

Usage:
------
python3 tools/test_dynamic_solvability.py --data-dir /content/drive/MyDrive/thesis/code/datasets/poc/claude/phase2/active_directory --num-agents 5 --episodes 5
"""

import argparse
import os
import re
import sys
import time
import random
import json
import networkx as nx
from pathlib import Path
from collections import Counter, deque

# Add repo root and pipeline/ to sys.path
REPO_ROOT    = Path(__file__).resolve().parent.parent
_PIPELINE_DIR = Path(__file__).resolve().parent.parent  # pipeline/
sys.path.append(str(REPO_ROOT))
sys.path.insert(0, str(_PIPELINE_DIR))

try:
    from constants import AGENT_CATEGORY_ALLOWLIST as _AGENT_ALLOWLIST  # noqa: E402
except ImportError:
    _AGENT_ALLOWLIST: dict = {}  # type: ignore[assignment]

try:
    from cyberbattle._env.improved.improved_cyberbattle_env import ImprovedCyberBattleEnv
    from cyberbattle.runners.common.loaderenv import new_environment
    from cyberbattle.simulation.vulenrabilites import VulnerabilityType
except ImportError as e:
    print(f"Failed to import cyberbattle modules: {e}")
    sys.exit(1)
import yaml




# --- FIX FOR CYBERBATTLESIM YAML LOADING ---
# CyberBattleSim serializes Python Enums into YAML, but loaderenv.py uses safe_load.
# This monkey-patch forces safe_load to allow custom Python object tags.
yaml.safe_load = yaml.unsafe_load

# Add repo root to sys.path so we can import cyberbattle
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(REPO_ROOT))

class GreedyExplorationAgent:
    """
    Learnability-proxy solver.

    Uses only the same information a DRL agent has access to:
      - owned nodes, discovered-not-owned nodes, credential cache.
    No global node catalogue (unlike BFSPlannerAgent).

    Strategy per step:
      Phase 0 — local exploits on owned nodes (generates credentials / discovers neighbours).
      Phase 1 — remote exploits on discovered-not-owned nodes.
      Phase 2 — credential connects to discovered-not-owned nodes.
    Cursor navigation is handled inline. Each (src, tgt, action) triple is retried
    at most _MAX_RETRIES times then permanently skipped.

    If this agent solves the scenario, a DRL agent with proper exploration can learn
    the same policy.
    """

    _MAX_RETRIES = 8  # high enough to handle SR=0.55 vulnerabilities

    def __init__(self, env: ImprovedCyberBattleEnv):
        self.env = env
        base = env.local_vulnerabilities_count + env.remote_vulnerabilities_count + env.port_count
        self.src_fwd, self.src_bwd = base,     base + 1
        self.tgt_fwd, self.tgt_bwd = base + 2, base + 3
        self._local_range  = range(env.local_vulnerabilities_count)
        self._remote_range = range(env.local_vulnerabilities_count,
                                   env.local_vulnerabilities_count + env.remote_vulnerabilities_count)
        self._port_range   = range(env.local_vulnerabilities_count + env.remote_vulnerabilities_count,
                                   base)
        self._skip:    set  = set()   # permanently exhausted triples
        self._tries:   dict = {}      # triple → attempt count since last state change
        self._seen:    set  = set()   # all triples ever enqueued
        self._queue:   list = []
        self._ptr:     int  = 0
        self._owned_snap: frozenset = frozenset()
        self._disc_snap:  frozenset = frozenset()
        self._creds_snap: int       = -1
        self._nav_pending: bool     = False
        self._last_exec:   tuple    = None
        self._extend_queue()

    def _entries_for(self, owned, disc_not, has_creds):
        """All (src, tgt, action) triples reachable from current state."""
        out = []
        for src in owned:
            for a in self._local_range:
                out.append((src, src, a))
        for src in owned:
            for tgt in disc_not:
                for a in self._remote_range:
                    out.append((src, tgt, a))
        if has_creds:
            for src in owned:
                for tgt in disc_not:
                    for a in self._port_range:
                        out.append((src, tgt, a))
        return out

    def _extend_queue(self):
        """Append only NEW entries (never seen before, not skipped) to the queue."""
        owned     = set(self.env.get_owned_nodes())
        disc_not  = set(self.env.get_discovered_not_owned_nodes())
        has_creds = len(self.env.get_credential_cache()) > 0

        for item in self._entries_for(owned, disc_not, has_creds):
            if item not in self._seen and item not in self._skip:
                self._seen.add(item)
                self._queue.append(item)

        # Reset per-triple retry counts — a state change may make old failures viable
        self._tries.clear()
        self._owned_snap = frozenset(owned)
        self._disc_snap  = frozenset(disc_not)
        self._creds_snap = len(self.env.get_credential_cache())

    def _nav(self, src_id, tgt_id):
        """Return one cursor-move action toward (src_id, tgt_id), or None if aligned."""
        owned  = self.env.get_owned_nodes()
        disc   = self.env.get_owned_nodes() + self.env.get_discovered_not_owned_nodes()

        if self.env.source_node_index != src_id:
            if src_id in owned:
                cur = owned.index(self.env.source_node_index) if self.env.source_node_index in owned else 0
                tgt = owned.index(src_id)
                n   = len(owned)
                return self.src_fwd if (tgt - cur) % n <= (cur - tgt) % n else self.src_bwd

        if src_id != tgt_id and self.env.target_node_index != tgt_id:
            if tgt_id in disc:
                cur = disc.index(self.env.target_node_index) if self.env.target_node_index in disc else 0
                tgt = disc.index(tgt_id)
                n   = len(disc)
                return self.tgt_fwd if (tgt - cur) % n <= (cur - tgt) % n else self.tgt_bwd
        return None

    def sample_action(self) -> int:
        owned    = frozenset(self.env.get_owned_nodes())
        disc     = frozenset(self.env.get_discovered_not_owned_nodes())
        creds    = len(self.env.get_credential_cache())
        changed  = (owned != self._owned_snap or disc != self._disc_snap or creds != self._creds_snap)

        if changed:
            self._extend_queue()
            self._nav_pending = False
            self._last_exec   = None
        elif not self._nav_pending and self._last_exec is not None:
            key = self._last_exec
            self._tries[key] = self._tries.get(key, 0) + 1
            if self._tries[key] >= self._MAX_RETRIES:
                self._skip.add(key)
                self._ptr += 1

        self._nav_pending = False
        self._last_exec   = None

        while self._ptr < len(self._queue):
            src, tgt, a = self._queue[self._ptr]
            if (src, tgt, a) in self._skip:
                self._ptr += 1
                continue
            if src not in owned:
                self._ptr += 1
                continue

            nav = self._nav(src, tgt)
            if nav is not None:
                self._nav_pending = True
                return nav

            src_ok = self.env.source_node_index == src
            tgt_ok = (src == tgt) or (self.env.target_node_index == tgt)
            if not src_ok or not tgt_ok:
                self._ptr += 1
                continue

            self._last_exec = (src, tgt, a)
            return a

        # Queue exhausted — nudge target to expose undiscovered nodes
        return self.tgt_fwd



class BFSPlannerAgent:
    """
    Attack-graph BFS agent for scenario solvability evaluation.

    Builds a complete attack plan by running BFS from the currently owned
    nodes across all node vulnerabilities and port connections, then executes
    each (src, tgt, action) step in shortest-hop order with efficient cursor
    navigation. Replans automatically whenever new nodes are owned or new
    credentials are discovered.

    Advantages over the greedy swarm agent:
      - Directed: targets nodes in BFS hop-distance order rather than random sampling.
      - Goal-first: goal nodes are prioritised within each BFS level.
      - No wasted retries: each action is retried at most _MAX_RETRIES times before
        being permanently skipped.
      - Globally aware: queries the full node catalogue at plan time so every
        reachable attack vector is considered.
    """

    _MAX_RETRIES = 10

    def __init__(self, env: ImprovedCyberBattleEnv,
                 allowed_vuln_names: set | None = None):
        self.env = env
        self._allowed_vuln_names = allowed_vuln_names  # D-P1: restrict BFS to agent's action space
        base = (env.local_vulnerabilities_count
                + env.remote_vulnerabilities_count
                + env.port_count)
        self.src_fwd = base
        self.src_bwd = base + 1
        self.tgt_fwd = base + 2
        self.tgt_bwd = base + 3

        self._plan: list = []         # [(src_id, tgt_id, action_idx), …]
        self._plan_ptr: int = 0       # index of the current step being attempted
        self._skip: set = set()       # steps that hit MAX_RETRIES
        self._retry_counts: dict = {} # (src, tgt, action) → attempt count
        self._last_nav: bool = False  # was the last returned action a cursor-nav?
        self._last_exec: tuple = None # last executed (src, tgt, action)
        self._owned_snapshot: frozenset = frozenset()
        self._creds_snapshot: int = -1

        self._replan()

    # ── Plan generation ───────────────────────────────────────────────────────

    def _replan(self):
        """Rebuild the attack plan from the current environment state."""
        owned = set(self.env.get_owned_nodes())
        creds = self.env.get_credential_cache()
        has_creds = len(creds) > 0

        self._owned_snapshot = frozenset(owned)
        self._creds_snapshot = len(creds)
        self._plan_ptr = 0
        self._skip = set()
        self._retry_counts = {}

        all_nodes = list(self.env.get_nodes())
        goal_ids = {nid for nid, nd in all_nodes if getattr(nd, 'is_goal', False)}
        node_dict = dict(all_nodes)
        base_port = (self.env.local_vulnerabilities_count
                     + self.env.remote_vulnerabilities_count)

        scored = []  # (score, src_id, tgt_id, action_idx)

        _allowed = self._allowed_vuln_names  # None = no filter (D-P1)

        # Phase 0 — local exploits on owned nodes (score 0.0, tried first to
        # generate credentials and properties before lateral movement).
        for src_id in owned:
            nd = node_dict.get(src_id)
            if nd is None:
                continue
            for vuln_id, vuln_data in nd.vulnerabilities.items():
                if _allowed is not None and vuln_id not in _allowed:
                    continue
                if vuln_data.type == VulnerabilityType.LOCAL:
                    idx = self.env.get_vulnerability_index(vuln_id)
                    if idx != -1:
                        scored.append((0.0, src_id, src_id, idx))

        # Phase 1 — BFS lateral movement from every owned node.
        # visited_as_frontier prevents adding the same tgt to the queue twice,
        # but we still record every (src, tgt, action) pair so the agent can
        # try multiple owned sources against the same target.
        visited_as_frontier: set = set(owned)
        queue: deque = deque((nid, 0) for nid in owned)

        while queue:
            src_id, hop = queue.popleft()

            for tgt_id, tgt_data in all_nodes:
                if tgt_id == src_id:
                    continue

                goal_bonus = 0.0 if tgt_id in goal_ids else 1.0

                # Remote vulnerability exploits
                for vuln_id, vuln_data in tgt_data.vulnerabilities.items():
                    if _allowed is not None and vuln_id not in _allowed:
                        continue
                    if vuln_data.type == VulnerabilityType.REMOTE:
                        if tgt_id not in owned:
                            idx = self.env.get_vulnerability_index(vuln_id)
                            if idx != -1:
                                scored.append((hop + goal_bonus, src_id, tgt_id, idx))

                # Port / credential-based connections
                if has_creds:
                    for service in getattr(tgt_data, 'services', []):
                        if tgt_id not in owned:
                            port_idx = self.env.get_port_index(service.name)
                            if port_idx != -1:
                                scored.append((hop + goal_bonus, src_id, tgt_id,
                                               base_port + port_idx))

                # Expand BFS frontier: only add tgt_id once.
                if tgt_id not in visited_as_frontier:
                    has_remote = any(
                        vd.type == VulnerabilityType.REMOTE
                        for _, vd in tgt_data.vulnerabilities.items()
                    )
                    has_services = bool(getattr(tgt_data, 'services', []))
                    if has_remote or (has_creds and has_services):
                        visited_as_frontier.add(tgt_id)
                        queue.append((tgt_id, hop + 1))

        scored.sort(key=lambda x: x[0])
        self._plan = [(s, t, a) for _, s, t, a in scored]

    # ── Cursor navigation ─────────────────────────────────────────────────────

    def _nav_action(self, node_list, current_id, target_id, fwd, bwd):
        """Return the single best cursor-move action toward target_id."""
        if not node_list or target_id not in node_list:
            return None
        try:
            cur = node_list.index(current_id)
        except ValueError:
            cur = 0
        tgt = node_list.index(target_id)
        n = len(node_list)
        return fwd if (tgt - cur) % n <= (cur - tgt) % n else bwd

    def _navigate(self, src_id, tgt_id):
        """
        Return a single navigation action to move the source/target cursors
        toward (src_id, tgt_id), or None when both are already aligned.
        Source cursor is moved first; target only after source is settled.
        """
        if self.env.source_node_index != src_id:
            action = self._nav_action(
                self.env.get_owned_nodes(),
                self.env.source_node_index, src_id,
                self.src_fwd, self.src_bwd,
            )
            if action is not None:
                return action

        # Skip target navigation for local exploits (src == tgt).
        if src_id != tgt_id and self.env.target_node_index != tgt_id:
            tgt_list = (self.env.get_owned_nodes()
                        + self.env.get_discovered_not_owned_nodes())
            action = self._nav_action(
                tgt_list,
                self.env.target_node_index, tgt_id,
                self.tgt_fwd, self.tgt_bwd,
            )
            if action is not None:
                return action

        return None  # both cursors are in position

    # ── Main interface ────────────────────────────────────────────────────────

    def sample_action(self) -> int:
        owned = frozenset(self.env.get_owned_nodes())
        creds = len(self.env.get_credential_cache())
        state_changed = (owned != self._owned_snapshot
                         or creds != self._creds_snapshot)

        if state_changed:
            # A previous action succeeded — rebuild plan from the new state.
            self._replan()
            self._last_nav = False
            self._last_exec = None
        elif not self._last_nav and self._last_exec is not None:
            # Last call was an execution that produced no state change → failure.
            key = self._last_exec
            self._retry_counts[key] = self._retry_counts.get(key, 0) + 1
            if self._retry_counts[key] >= self._MAX_RETRIES:
                self._skip.add(key)
                self._plan_ptr += 1   # advance past the exhausted step

        self._last_nav = False
        self._last_exec = None

        while self._plan_ptr < len(self._plan):
            step = self._plan[self._plan_ptr]
            src_id, tgt_id, action_idx = step

            if step in self._skip:
                self._plan_ptr += 1
                continue

            # For remote / port actions the source must already be owned.
            if src_id != tgt_id and src_id not in owned:
                self._plan_ptr += 1
                continue

            # Navigate cursors toward (src_id, tgt_id).
            nav = self._navigate(src_id, tgt_id)
            if nav is not None:
                self._last_nav = True
                return nav

            # Verify both cursors are actually aligned (node may not be
            # discoverable yet, in which case _navigate silently returns None).
            src_ok = self.env.source_node_index == src_id
            tgt_ok = (src_id == tgt_id) or (self.env.target_node_index == tgt_id)
            if not src_ok or not tgt_ok:
                self._plan_ptr += 1
                continue

            # Execute the planned action (do NOT advance ptr here — we only
            # advance on the next call after detecting failure or on replan).
            self._last_exec = step
            return action_idx

        # Plan exhausted — nudge cursors to expose undiscovered nodes.
        return random.choice([self.src_fwd, self.tgt_fwd])


def get_topology_info(env_obj) -> dict:
    """Extracts deep mathematical graph metrics, inferring routing edges via strict IP/Port firewall matching.

    Always builds G_effective from actual firewall rules (deny-by-default between
    node pairs with no matching rule).  The native env_obj.network can be a
    near-complete graph due to CyberBattleSim's internal edge construction, which
    produces misleadingly high density/diameter values unrelated to scenario design.
    """
    G = env_obj.network
    node_count = G.number_of_nodes()
    edge_count = G.number_of_edges()

    # Always build firewall-based effective graph so density/diameter reflect the
    # actual allow/deny policy rather than the simulator's internal edge set.
    if node_count > 1:
        G_effective = nx.DiGraph()
        for node_id, _ in env_obj.nodes():
            G_effective.add_node(node_id)
            
        nodes_data = dict(env_obj.nodes())
        for src_id, src_data in nodes_data.items():
            for tgt_id, tgt_data in nodes_data.items():
                if src_id == tgt_id:
                    continue
                
                src_ips = [ni.ip_address for ni in getattr(src_data, 'network_info', []) if hasattr(ni, 'ip_address')]
                tgt_ips = [ni.ip_address for ni in getattr(tgt_data, 'network_info', []) if hasattr(ni, 'ip_address')]
                
                tgt_ports = [str(s.name) for s in getattr(tgt_data, 'services', []) if hasattr(s, 'name')]
                if not tgt_ports:
                    tgt_ports = ['*']

                def is_traffic_allowed(rules, remote_ips, target_port):
                    # Deny-by-default: no rules = no access.
                    # Wildcard port rules ('*' / 'any') are skipped — they come from
                    # CyberBattleSim's internal simulator setup, not from the YAML
                    # security design.  Only explicit protocol-named rules count.
                    if not rules:
                        return False

                    sorted_rules = sorted(rules, key=lambda r: getattr(r, 'priority', 1))
                    for rule in sorted_rules:
                        rule_port = str(getattr(rule, 'port', '*')).strip()
                        if rule_port in ('*', 'any'):
                            continue  # skip simulator-internal wildcard rules

                        ip_match = False
                        subnet = getattr(rule, 'subnet', None)
                        if subnet:
                            net_str = getattr(subnet, 'network_str', str(subnet))
                            if net_str in ['0.0.0.0/0', 'any', '*']:
                                ip_match = True
                            else:
                                for ip in remote_ips:
                                    try:
                                        if hasattr(subnet, 'contains') and subnet.contains(ip):
                                            ip_match = True
                                            break
                                    except Exception:
                                        pass
                        else:
                            ip_match = True

                        if ip_match:
                            if rule_port == str(target_port):
                                perm_obj = getattr(rule, 'permission', None)
                                perm_name = getattr(perm_obj, 'name', '').upper()
                                perm_val = getattr(perm_obj, 'value', perm_obj)
                                return (perm_name == 'ALLOW' or perm_val == 0)
                                
                    return False
                    
                tgt_fw = getattr(tgt_data, 'firewall', None)
                tgt_incoming = getattr(tgt_fw, 'incoming', []) if tgt_fw else []
                src_fw = getattr(src_data, 'firewall', None)
                src_outgoing = getattr(src_fw, 'outgoing', []) if src_fw else []
                
                edge_exists = False
                for port in tgt_ports:
                    out_allowed = is_traffic_allowed(src_outgoing, tgt_ips, port)
                    in_allowed = is_traffic_allowed(tgt_incoming, src_ips, port)
                    if out_allowed and in_allowed:
                        edge_exists = True
                        break
                        
                if edge_exists:
                    G_effective.add_edge(src_id, tgt_id)

        G = G_effective
        edge_count = G.number_of_edges()

    density = nx.density(G)
    in_degrees = [d for n, d in G.in_degree()]
    out_degrees = [d for n, d in G.out_degree()]
    avg_in_degree = sum(in_degrees) / node_count if node_count > 0 else 0
    avg_out_degree = sum(out_degrees) / node_count if node_count > 0 else 0
    max_in_degree = max(in_degrees) if in_degrees else 0

    try:
        betweenness = nx.betweenness_centrality(G)
        chokepoint_index = max(betweenness.values()) if betweenness else 0.0
    except Exception:
        chokepoint_index = 0.0

    isolated_subnets = nx.number_weakly_connected_components(G)
    two_way_zones = nx.number_strongly_connected_components(G)

    try:
        undirected_G = G.to_undirected()
        if nx.is_connected(undirected_G):
            diameter = nx.diameter(undirected_G)
        else:
            components = [undirected_G.subgraph(c).copy() for c in nx.connected_components(undirected_G)]
            diameter = max([nx.diameter(c) for c in components])
    except Exception:
        diameter = -1

    total_vulns = 0
    unique_vulns = set()
    total_props = 0
    unique_props = set()
    property_counts = Counter()

    for node_id, node_data in env_obj.nodes():
        if hasattr(node_data, 'vulnerabilities'):
            total_vulns += len(node_data.vulnerabilities)
            unique_vulns.update(node_data.vulnerabilities.keys())
        if hasattr(node_data, 'properties'):
            total_props += len(node_data.properties)
            unique_props.update(node_data.properties)
            for p in node_data.properties:
                property_counts[p] += 1

    return {
        "routing": {
            "node_count": node_count,
            "edge_count": edge_count,
            "density": round(density, 4),
            "avg_in_degree": round(avg_in_degree, 2),
            "avg_out_degree": round(avg_out_degree, 2),
            "max_in_degree": max_in_degree,
            "diameter": diameter,
            "chokepoint_index": round(chokepoint_index, 4),
        },
        "segmentation": {
            "isolated_subnets_count": isolated_subnets,
            "two_way_routing_zones_count": two_way_zones,
        },
        "payloads": {
            "total_vulnerability_instances": total_vulns,
            "unique_vulnerabilities": len(unique_vulns),
            "total_property_instances": total_props,
            "unique_properties": len(unique_props),
            "property_counts": dict(property_counts)
        }
    }


_STRATUM_RE = re.compile(r'/(small|medium|large)/', re.IGNORECASE)


def _compute_firewall_metrics(scenario_dir: Path) -> dict:
    """Compute static firewall metrics from node YAML files."""
    import yaml as _yaml
    nodes_dir = scenario_dir / "nodes"
    if not nodes_dir.is_dir():
        return {}

    total_incoming = 0
    total_outgoing = 0
    allow_count    = 0
    block_count    = 0
    node_count     = 0
    blocked_ports: set = set()
    allowed_ports: set = set()

    for node_file in nodes_dir.glob("*.yaml"):
        try:
            data = _yaml.safe_load(node_file.read_text())
        except Exception:
            continue
        fw = data.get("firewall", {})
        if not fw:
            continue
        node_count += 1
        for rule in fw.get("incoming", []):
            total_incoming += 1
            perm = rule.get("permission", 0)
            port = rule.get("port", "*")
            if perm == 0:   # ALLOW
                allow_count += 1
                allowed_ports.add(port)
            else:           # BLOCK
                block_count += 1
                blocked_ports.add(port)
        for rule in fw.get("outgoing", []):
            total_outgoing += 1
            perm = rule.get("permission", 0)
            port = rule.get("port", "*")
            if perm == 0:
                allow_count += 1
                allowed_ports.add(port)
            else:
                block_count += 1
                blocked_ports.add(port)

    total_rules = total_incoming + total_outgoing
    return {
        "nodes_with_firewall":  node_count,
        "total_incoming_rules": total_incoming,
        "total_outgoing_rules": total_outgoing,
        "total_rules":          total_rules,
        "allow_rules":          allow_count,
        "block_rules":          block_count,
        "avg_rules_per_node":   round(total_rules / max(node_count, 1), 2),
        "firewall_coverage":    round(node_count / max(
            len(list(nodes_dir.glob("*.yaml"))), 1), 3),
        "blocked_ports":        sorted(blocked_ports),
        "allowed_ports":        sorted(allowed_ports),
    }


def _detect_stratum(scenario_dir: Path) -> str:
    """Infer stratum name from the scenario path, or 'unknown'."""
    m = _STRATUM_RE.search(str(scenario_dir))
    return m.group(1).lower() if m else "unknown"


def calculate_difficulty_score(run_metrics: dict) -> dict:
    """Computes a normalized difficulty score (0-10) based on multiple telemetry vectors."""
    # 1. Stochastic Factor (0.0 - 2.5): Resistance to success
    sr = run_metrics["action_stats"]["overall_actions_success_rate"]
    stochastic_score = (1.0 - sr) * 2.5
    
    # 2. Structural Factor (0.0 - 2.5): Network depth vs scale
    diameter = max(1, run_metrics["topology_metrics"]["routing"]["diameter"])
    nodes = max(1, run_metrics["topology_metrics"]["routing"]["node_count"])
    # High diameter relative to node count indicates a deep, tiered (harder) bottlenecked path
    structural_score = min(2.5, (diameter / nodes) * 5.0)
    
    # 3. Efficiency Factor (0.0 - 2.5): Steps required per node
    steps = run_metrics["steps_taken"]
    # If a planner takes many steps per node, it implies high cursor navigation or retry overhead
    efficiency_score = min(2.5, (steps / nodes) / 5.0)
    
    # 4. Stochastic Volatility (0.0 - 2.5): Replay failure rate
    replay_sr = run_metrics.get("replay_verification", {}).get("success_rate", 1.0)
    volatility_score = (1.0 - replay_sr) * 2.5
    
    total_score = round(stochastic_score + structural_score + efficiency_score + volatility_score, 2)
    
    if total_score >= 8.0: rating = "EXTREME"
    elif total_score >= 6.0: rating = "HARD"
    elif total_score >= 4.0: rating = "MODERATE"
    elif total_score >= 2.0: rating = "EASY"
    else: rating = "TRIVIAL"
    
    return {
        "score": total_score,
        "rating": rating,
        "metrics": {
            "stochastic_resistance": round(stochastic_score, 2),
            "topological_depth": round(structural_score, 2),
            "operational_overhead": round(efficiency_score, 2),
            "stochastic_volatility": round(volatility_score, 2)
        }
    }


def generate_llm_quality_prompt(scenario_dir: Path, is_solved: bool, best_stats: dict, episodes_run: int, final_step: int, num_agents: int, topo_info: dict, episode_reward: float, replay_info: dict = None) -> dict:
    """Generates the single-scenario LLM prompt AND returns a JSON dictionary for aggregation."""

    total_goals   = best_stats.get('total_goals', 0)
    achieved_goals = best_stats.get('achieved_goals', 0)
    owned_nodes   = best_stats.get('num_owned_nodes', 0)
    total_nodes   = best_stats.get('total_nodes', 1)
    creds_found   = best_stats.get('unique_credentials_discovered', 0)
    outcomes      = best_stats.get('outcome_counts', {})

    goals_captured_ratio = (achieved_goals / total_goals) if total_goals > 0 else 0.0

    # ── Exploration / coverage metrics (from callbacks.py parity) ──────────
    discovered_nodes      = best_stats.get('num_discovered_nodes', 0)
    not_discovered_nodes  = best_stats.get('num_not_discovered_nodes', 0)
    owned_pct             = round(owned_nodes   / max(total_nodes, 1), 4)
    discovered_pct        = round(discovered_nodes / max(total_nodes, 1), 4)
    creds_in_cache        = best_stats.get('unique_credentials_in_cache', 0)
    creds_disc_pct        = best_stats.get('discovered_credentials_percentage', 0.0)

    # ── Goal timing ──────────────────────────────────────────────────────────
    steps_to_first_goal   = best_stats.get('steps_to_first_goal') or 0
    steps_to_final_goal   = best_stats.get('steps_to_final_goal') or 0

    # ── Action success rates (from callbacks.py parity) ─────────────────────
    action_stats = {
        "local_attacks_success_rate":   round(best_stats.get('local_attacks_success_rate', 0.0), 4),
        "remote_attacks_success_rate":  round(best_stats.get('remote_attacks_success_rate', 0.0), 4),
        "port_connections_success_rate": round(best_stats.get('port_connections_success_rate', 0.0), 4),
        "overall_actions_success_rate": round(best_stats.get('overall_actions_success_rate', 0.0), 4),
        "local_attacks_rate":           round(best_stats.get('local_attacks_rate', 0.0), 4),
        "remote_attacks_rate":          round(best_stats.get('remote_attacks_rate', 0.0), 4),
        "port_connections_rate":        round(best_stats.get('port_connections_rate', 0.0), 4),
        "movements_rate":               round(best_stats.get('movements_rate', 0.0), 4),
    }

    # ── Network structure: tree-likeness ratio ────────────────────────────
    n_nodes   = topo_info.get("routing", {}).get("node_count", 2)
    density   = topo_info.get("routing", {}).get("density", 0.0)
    tree_ratio = round(density * max(n_nodes, 2), 3)  # ≈1 → tree; >>1 → mesh

    run_metrics = {
        "scenario_name":               scenario_dir.name,
        "stratum":                     _detect_stratum(scenario_dir),
        "is_solved":                   is_solved,
        "episodes_required":           episodes_run,
        "steps_taken":                 final_step,
        "steps_to_first_goal":         steps_to_first_goal,
        "steps_to_final_goal":         steps_to_final_goal,
        "goals_captured":              f"{achieved_goals}/{total_goals}",
        "goals_captured_ratio":        round(goals_captured_ratio, 4),
        "nodes_owned":                 owned_nodes,
        "nodes_discovered":            discovered_nodes,
        "nodes_not_discovered":        not_discovered_nodes,
        "owned_percentage":            owned_pct,
        "discovered_percentage":       discovered_pct,
        "credentials_discovered":      creds_found,
        "credentials_in_cache":        creds_in_cache,
        "credentials_discovered_pct":  round(creds_disc_pct, 4),
        "total_reward":                episode_reward,
        "topology_metrics":            topo_info,
        "network_structure": {
            "tree_ratio":   tree_ratio,
            "density":      round(density, 4),
            "diameter":     topo_info.get("routing", {}).get("diameter", 0),
            "node_count":   n_nodes,
            "topology_type": (
                "tree-like" if tree_ratio < 3 else
                "hierarchical" if tree_ratio < 10 else
                "mesh"
            ),
        },
        "action_stats":    action_stats,
        "action_outcomes": outcomes,
        "firewall_metrics": _compute_firewall_metrics(scenario_dir),
        "replay_verification": replay_info or {}
    }

    # Compute difficulty score
    run_metrics["difficulty"] = calculate_difficulty_score(run_metrics)

    with open(scenario_dir / "run_metrics.json", "w") as f:
        json.dump(run_metrics, f, indent=4)

    return run_metrics


def _stratum_summary(all_metrics: list) -> str:
    """Return a Markdown table of solve rates grouped by stratum."""
    groups: dict = {}
    for m in all_metrics:
        s = m.get("stratum", "unknown")
        groups.setdefault(s, []).append(m)
    if all(k == "unknown" for k in groups):
        return ""
    lines = ["| Stratum | Scenarios | Solved | Solve% | Avg Goals Ratio |",
             "|---------|-----------|--------|--------|-----------------|"]
    for s in sorted(groups):
        ms = groups[s]
        n = len(ms)
        solved = sum(1 for m in ms if m["is_solved"])
        avg_ratio = sum(m.get("goals_captured_ratio", 0.0) for m in ms) / n
        lines.append(f"| {s:<7} | {n:>9} | {solved:>6} | {solved/n*100:>5.1f}% | {avg_ratio:>15.3f} |")
    return "\n".join(lines)


def generate_dataset_summary_prompt(data_dir: Path, all_metrics: list):
    """Combines all scenario metrics into a grand summary LLM Prompt."""
    if not all_metrics:
        return

    total_scenarios = len(all_metrics)
    solved_scenarios = len([m for m in all_metrics if m["is_solved"]])
    avg_steps = sum(m["steps_taken"] for m in all_metrics) / total_scenarios
    
    avg_reward = sum(m.get("total_reward", 0.0) for m in all_metrics) / total_scenarios
    total_goals_acc = 0
    for m in all_metrics:
        try:
            total_goals_acc += int(m["goals_captured"].split('/')[1])
        except Exception:
            pass
    avg_goals = total_goals_acc / total_scenarios if total_scenarios else 0
    
    avg_nodes = sum(m["topology_metrics"]["routing"]["node_count"] for m in all_metrics) / total_scenarios
    avg_edges = sum(m["topology_metrics"]["routing"]["edge_count"] for m in all_metrics) / total_scenarios
    avg_density = sum(m["topology_metrics"]["routing"]["density"] for m in all_metrics) / total_scenarios
    avg_diameter = sum(max(0, m["topology_metrics"]["routing"]["diameter"]) for m in all_metrics) / total_scenarios
    avg_max_in = sum(m["topology_metrics"]["routing"]["max_in_degree"] for m in all_metrics) / total_scenarios
    
    avg_isolated = sum(m["topology_metrics"]["segmentation"]["isolated_subnets_count"] for m in all_metrics) / total_scenarios
    avg_zones = sum(m["topology_metrics"]["segmentation"]["two_way_routing_zones_count"] for m in all_metrics) / total_scenarios
    
    avg_vulns = sum(m["topology_metrics"]["payloads"]["unique_vulnerabilities"] for m in all_metrics) / total_scenarios
    avg_props = sum(m["topology_metrics"]["payloads"]["unique_properties"] for m in all_metrics) / total_scenarios
    
    # ── Difficulty Analytics ──────────────────────────────────────────────
    avg_diff_score = sum(m["difficulty"]["score"] for m in all_metrics) / total_scenarios
    diff_ratings = Counter(m["difficulty"]["rating"] for m in all_metrics)
    
    exploration_gaps = [m["difficulty"].get("exploration_gap", {}).get("exploration_gap", 0) for m in all_metrics if "exploration_gap" in m["difficulty"]]
    avg_exploration_gap = sum(exploration_gaps) / len(exploration_gaps) if exploration_gaps else None

    # ── Advanced DRL Metrics ──────────────────────────────────────────────
    avg_chokepoint = sum(m["topology_metrics"]["routing"].get("chokepoint_index", 0.0) for m in all_metrics) / total_scenarios
    avg_cred_chain = sum(m.get("drl_hardness", {}).get("min_cred_harvest_sequence", 0) for m in all_metrics) / total_scenarios
    avg_reward_sparse = sum(m.get("drl_hardness", {}).get("avg_steps_between_rewards", 0.0) for m in all_metrics) / total_scenarios
    avg_snr = sum(m.get("drl_hardness", {}).get("action_signal_to_noise_ratio", 0.0) for m in all_metrics) / total_scenarios

    global_prop_counts = Counter()
    for m in all_metrics:
        global_prop_counts.update(m["topology_metrics"]["payloads"].get("property_counts", {}))
    
    top_props_str = ", ".join([f"{k}: {v}" for k, v in global_prop_counts.most_common(10)])
    
    condensed_metrics = []
    for m in all_metrics:
        r = m["topology_metrics"]["routing"]
        s = m["topology_metrics"]["segmentation"]
        p = m["topology_metrics"]["payloads"]
        d = m["difficulty"]
        
        condensed_metrics.append({
            "name": m["scenario_name"],
            "solved": m["is_solved"],
            "difficulty": f"{d['score']} ({d['rating']})",
            "expl_gap": d.get("exploration_gap", {}).get("exploration_gap", "N/A"),
            "drl_metrics": f"CredChain:{m.get('drl_hardness', {}).get('min_cred_harvest_sequence', 0)} | SNR:{m.get('drl_hardness', {}).get('action_signal_to_noise_ratio', 0.0):.3f}",
            "steps": m["steps_taken"],
            "reward": round(m.get("total_reward", 0.0), 2),
            "goals": m["goals_captured"],
            "routing": f"{r['node_count']} nodes, {r['edge_count']} edges, {r['density']} density, {r['diameter']} diameter",
            "segmentation": f"{s['isolated_subnets_count']} isolated, {s['two_way_routing_zones_count']} zones",
            "payloads": f"{p['unique_vulnerabilities']} vulns, {p['unique_properties']} props",
            "creds": m["credentials_discovered"],
            "top_actions": {k: v for k, v in sorted(m["action_outcomes"].items(), key=lambda item: item[1], reverse=True)[:3] if v > 0}
        })

    stratum_table = _stratum_summary(all_metrics)
    stratum_section = ("### SOLVE RATE BY STRATUM\n" + stratum_table + "\n") if stratum_table else ""

    gap_str = f"- **Avg Exploration Gap**: {avg_exploration_gap:.2f}x (Higher = harder for blind RL agents)\n" if avg_exploration_gap else ""

    prompt = f"""You are an expert AI Red Teamer and Cyber Range Architect.
I have run a solvability test using a BFS attack-graph planner agent across a dataset of {total_scenarios} CyberBattleSim network topologies.

### OVERALL DATASET PERFORMANCE & OBJECTIVES
- **Total Scenarios Tested**: {total_scenarios}
- **Successful Solves**: {solved_scenarios} ({(solved_scenarios/total_scenarios)*100:.1f}%)
- **Average Steps per Run**: {avg_steps:.0f}
- **Average Total Reward**: {avg_reward:.2f}
- **Average Goals per Scenario**: {avg_goals:.1f}
{stratum_section}

### HARDNESS & LEARNABILITY
- **Avg Difficulty Score**: {avg_diff_score:.2f} / 10.0
- **Difficulty Distribution**: {dict(diff_ratings)}
{gap_str}- **Strategic Depth**: ~{avg_cred_chain:.1f} sequential credentials needed | {avg_chokepoint:.3f} Chokepoint Index (max betweenness)
- **DRL Resistance**: ~{avg_reward_sparse:.1f} steps between rewards | {avg_snr:.4f} Signal-to-Noise Ratio

### AVERAGE TOPOLOGY & SEGMENTATION
- **Scale & Routing**: ~{avg_nodes:.0f} Nodes | ~{avg_edges:.0f} Edges | {avg_density:.3f} Density | ~{avg_diameter:.1f} Diameter
- **Connectivity**: ~{avg_max_in:.0f} Max In-Degree (indicates central hubs/bottlenecks)
- **Segmentation**: ~{avg_isolated:.1f} Isolated Subnets | ~{avg_zones:.1f} Two-Way Zones
- **Payloads**: ~{avg_vulns:.0f} Unique Vulns | ~{avg_props:.0f} Unique Properties

### NODE TYPES DISTRIBUTION (Across Dataset)
- **Top Properties/Roles**: {top_props_str}

### CONDENSED SCENARIO METRICS
```json
{json.dumps(condensed_metrics, indent=2)}
```

### ANALYSIS REQUEST
Please analyze the generator's health based on these aggregate results:
1. **Scenario Hardness:** Analyze the Average Difficulty Score and Distribution. Are the generated scenarios too easy (TRIVIAL/EASY) or too punishing (EXTREME)? Does the Exploration Gap indicate that blind RL agents will struggle to find paths?
2. **Topological Realism:** Look at the average diameter, max in-degree, and segmentation metrics. Is the generator creating deep, tiered networks (high diameter), hub-and-spoke models (high max in-degree), or flat meshes? Does this match a realistic enterprise environment?
3. **Network Segmentation Health:** Are there too many isolated subnets (completely unreachable nodes) or too few routing boundaries?
4. **Lateral Movement & Goals:** Cross-reference the discovered `creds` and `top_actions` with the routing density and rewards. Are the agents finding enough credentials to cross edges and reach the goals? Does the reward scale make sense for the difficulty?
5. **Actionable Generator Feedback:** Provide 3 specific rule recommendations for the YAML procedural generator to improve hardness balancing, edge/firewall generation, and node role distribution.
"""
    
    out_file = data_dir / "DATASET_EVALUATION_PROMPT.txt"
    with open(out_file, "w") as f:
        f.write(prompt)

    print("\n" + "="*60)
    print(f" ✓ MASTER DATASET PROMPT SAVED TO: {out_file}")
    print("="*60)

    # ── Send prompt to Claude LLM critic ────────────────────────────────────
    _call_llm_critic(prompt, data_dir)


def _get_env_key(key_name: str) -> str:
    key = os.environ.get(key_name, "")
    if key:
        return key
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{key_name}=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def _call_llm_critic(prompt: str, output_dir: Path) -> None:
    """Send the dataset evaluation prompt to Claude (primary) or Gemini (fallback)."""
    anthropic_key = _get_env_key("ANTHROPIC_API_KEY")
    google_key    = _get_env_key("GOOGLE_API_KEY")
    
    if not anthropic_key and not google_key:
        print("  [WARN] Neither ANTHROPIC_API_KEY nor GOOGLE_API_KEY set — LLM critic step skipped")
        return

    system_msg = (
        "You are an expert AI Red Teamer and Cyber Range Architect evaluating "
        "procedurally generated CyberBattleSim network scenarios for a research thesis. "
        "Be direct, precise, and quantitative. Base your assessment exclusively on "
        "the metrics provided. Do not invent details not present in the data."
    )
    
    critic_text = None
    model_name  = "unknown"

    # 1. Try Claude
    if anthropic_key:
        try:
            import anthropic
            print("\n  Calling Claude LLM critic...")
            client   = anthropic.Anthropic(api_key=anthropic_key)
            response = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2048,
                system=system_msg,
                messages=[{"role": "user", "content": prompt}],
            )
            critic_text = response.content[0].text if response.content else ""
            model_name  = "claude-3-5-sonnet-20241022"
            usage = {
                "input_tokens":  response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
        except Exception as exc:
            print(f"  [WARN] Claude critic API call failed: {exc}")

    # 2. Try Gemini fallback
    if not critic_text and google_key:
        try:
            import google.generativeai as genai
            print("\n  Calling Gemini LLM critic fallback...")
            genai.configure(api_key=google_key)
            model = genai.GenerativeModel(
                model_name="gemini-2.0-flash",
                system_instruction=system_msg
            )
            response = model.generate_content(prompt)
            critic_text = response.text
            model_name  = "gemini-2.0-flash"
            usage = {"input_tokens": 0, "output_tokens": 0} # Usage not easily available in same format
        except Exception as exc:
            print(f"  [WARN] Gemini critic API call failed: {exc}")

    if not critic_text:
        print("  [WARN] Both Claude and Gemini critic attempts failed.")
        return

    result = {
        "model":        model_name,
        "prompt_chars": len(prompt),
        "usage":        usage,
        "critique":     critic_text,
    }

    out_file = output_dir / "llm_critic_response.json"
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    print(f"  ✓ LLM critic response saved: {out_file}")
    if anthropic_key and model_name.startswith("claude"):
        print(f"    Tokens used: {usage['input_tokens']} in / {usage['output_tokens']} out")
    
    # Print a short preview
    preview = critic_text[:300].replace("\n", " ")
    print(f"    Preview: {preview}...")


def test_dynamic_solve(scenario_dir: Path, max_steps: int = 10000, num_agents: int = 1, max_episodes: int = 5, eval_difficulty: bool = False, allowed_vuln_names: set | None = None) -> tuple[bool, dict]:
    """
    Evaluate one scenario directory using the BFSPlannerAgent and optionally the GreedyExplorationAgent.

    Runs up to max_episodes independent episodes.  Each episode gets a fresh
    BFSPlannerAgent that builds an attack plan from the initial owned set and
    executes it systematically.

    If eval_difficulty is True, also runs the GreedyExplorationAgent to measure
    the 'Exploration Gap' — a proxy for how hard the scenario is for an RL agent
    to solve without a global map.
    """
    print(f"\n[{scenario_dir.name}] Testing Dynamic Solvability ({max_episodes} Episodes, BFS Planner)...")
    env_obj = new_environment(str(scenario_dir))

    if not hasattr(env_obj, 'maximum_total_credentials'): env_obj.maximum_total_credentials = 1000
    if not hasattr(env_obj, 'masked_identifiers'): env_obj.masked_identifiers = None

    topo_info = get_topology_info(env_obj)

    from cyberbattle._env.cyberbattle_env import AttackerGoal

    env = ImprovedCyberBattleEnv(
        initial_environment=env_obj,
        maximum_total_credentials=1000,
        maximum_node_count=100,
        maximum_discoverable_credentials_per_action=5000,
        neighborhood_size=30,
        stop_at_goal_reached=False,
        attacker_goal=AttackerGoal(own_atleast=9999, reward=999999),
        verbose=False
    )

    best_stats = None
    best_goals = -1
    best_nodes_owned = -1
    best_step_count = max_steps
    best_reward = -float('inf')
    best_actions: list[int] = []

    any_solved = False
    successful_episodes = 0

    for episode in range(1, max_episodes + 1):
        env.reset()
        agent = BFSPlannerAgent(env, allowed_vuln_names=allowed_vuln_names)
        episode_reward = 0.0
        episode_actions: list[int] = []

        for step in range(1, max_steps + 1):
            action = agent.sample_action()
            obs, reward, done, info = env.step(action)
            episode_actions.append(action)
            episode_reward += reward

            if info.get('goal_owned_this_step'):
                stats = env.get_statistics()
                if stats.get('achieved_goals', 0) >= stats.get('total_goals', 1):
                    any_solved = True
                    successful_episodes += 1
                    break

        stats = env.get_statistics()
        achieved = stats.get('achieved_goals', 0)
        owned = stats.get('num_owned_nodes', 0)

        is_better = False
        if best_stats is None:
            is_better = True
        elif achieved > best_goals:
            is_better = True
        elif achieved == best_goals:
            if owned > best_nodes_owned:
                is_better = True
            elif owned == best_nodes_owned and episode_reward > best_reward:
                is_better = True

        if is_better:
            best_goals = achieved
            best_nodes_owned = owned
            best_stats = stats
            best_reward = episode_reward
            best_step_count = step
            best_actions = episode_actions[:]

    # --- Difficulty Evaluation (Greedy Agent) ---
    greedy_info = {}
    if eval_difficulty:
        print(f"  [Difficulty] Evaluating Exploration Hardness ({max_episodes} Greedy Episodes) ...")
        greedy_solves = 0
        greedy_steps_list = []
        for ep in range(1, max_episodes + 1):
            env.reset()
            g_agent = GreedyExplorationAgent(env)
            g_solved = False
            for step in range(1, max_steps + 1):
                action = g_agent.sample_action()
                obs, reward, done, info = env.step(action)
                if info.get('goal_owned_this_step'):
                    st = env.get_statistics()
                    if st.get('achieved_goals', 0) >= st.get('total_goals', 1):
                        g_solved = True
                        greedy_solves += 1
                        greedy_steps_list.append(step)
                        break
            if not g_solved:
                greedy_steps_list.append(max_steps)
        
        avg_greedy_steps = sum(greedy_steps_list) / len(greedy_steps_list)
        exploration_gap = avg_greedy_steps / best_step_count if best_step_count > 0 else 0
        greedy_info = {
            "greedy_solve_rate": greedy_solves / max_episodes,
            "avg_greedy_steps": avg_greedy_steps,
            "exploration_gap": round(exploration_gap, 2),
            "exploration_hardness": "HIGH" if exploration_gap > 10 else "MODERATE" if exploration_gap > 3 else "LOW"
        }
        print(f"  [Difficulty] Exploration Gap: {exploration_gap:.2f}x ({greedy_info['exploration_hardness']})")

    # Pass everything to prompt generator
    run_metrics = generate_llm_quality_prompt(scenario_dir, any_solved, best_stats, max_episodes, best_step_count, num_agents, topo_info, best_reward)
    if eval_difficulty:
        run_metrics["difficulty"]["exploration_gap"] = greedy_info

    if any_solved:
        print(f"  \033[92m✓ SOLVED in {successful_episodes}/{max_episodes} episodes. (Best Reward: {best_reward:.2f} in {best_step_count} steps)\033[0m")
    else:
        print(f"  \033[91m✗ FAILED to solve after {max_episodes} episodes. (Best Reward: {best_reward:.2f})\033[0m")

    # ── Replay verification ───────────────────────────────────────────────────
    # Replays the best BFS action sequence on a fresh env using only the standard
    # step() interface — no planning, no global knowledge.
    # Success proves BFS didn't exploit any privilege unavailable to a real agent.
    replay_trials   = 5
    replay_success  = 0
    replay_steps_list: list[int] = []
    full_trajectory: list[dict]  = []   # recorded from the FIRST replay trial

    # Helper: decode property_array using env.properties list
    def _decode_properties(prop_arr, prop_names):
        return [prop_names[i] for i, v in enumerate(prop_arr) if v and i < len(prop_names)]

    # Helper: decode listening_services_array → running port names
    def _decode_services(svc_arr, port_names):
        result = []
        for i, entry in enumerate(svc_arr):
            if i >= len(port_names):
                break
            running = entry[0] if isinstance(entry, (tuple, list)) else 0
            if running:
                result.append(port_names[i])
        return result

    # Helper: decode vulnerabilities_array → used vuln IDs
    def _decode_vulns_used(vuln_arr, vuln_names):
        result = []
        for i, entry in enumerate(vuln_arr):
            if i >= len(vuln_names):
                break
            used = entry[3] if isinstance(entry, (tuple, list)) and len(entry) >= 4 else 0
            if used:
                result.append(vuln_names[i])
        return result

    # Helper: safe int conversion for numpy scalars / arrays
    def _to_int(v):
        try:
            if hasattr(v, '__len__'):
                return int(v[0])
            return int(v)
        except Exception:
            return 0

    prop_names  = list(env.properties)
    port_names  = list(env.ports)
    vuln_names  = list(env.local_vulnerabilities) + list(env.remote_vulnerabilities)

    print(f"  [Replay] Replaying {len(best_actions)}-step BFS sequence × {replay_trials} trials ...")
    for trial in range(replay_trials):
        env.reset()
        goal_reached  = False
        trial_traj: list[dict] = []

        for step, action in enumerate(best_actions, 1):
            src_before  = env.source_node_index
            tgt_before  = env.target_node_index
            src_name    = env.index_to_node_name.get(src_before, str(src_before))
            tgt_name    = env.index_to_node_name.get(tgt_before, str(tgt_before))
            action_name = env.get_action_name(action)

            obs, reward, done, info = env.step(action)

            outcome     = info.get('outcome')
            outcome_str = type(outcome).__name__ if outcome is not None else "None"
            is_goal     = info.get('goal_owned_this_step', False)
            new_goals   = info.get('new_goal_nodes', [])
            owned_now   = len(env.get_owned_nodes())
            disc_now    = len(env.get_discovered_nodes())
            creds_now   = len(env.get_credential_cache())

            # ── Observation-derived fields ────────────────────────────────────
            src_obs = env.current_observation.get('source_node', {})
            tgt_obs = env.current_observation.get('target_node', {})
            gbl_obs = env.current_observation.get('global_features', {})

            src_priv     = _to_int(src_obs.get('privilege_level', 0))
            tgt_priv     = _to_int(tgt_obs.get('privilege_level', 0))
            src_status   = _to_int(src_obs.get('status', 0))
            tgt_status   = _to_int(tgt_obs.get('status', 0))
            src_props    = _decode_properties(src_obs.get('property_array', []), prop_names)
            tgt_props    = _decode_properties(tgt_obs.get('property_array', []), prop_names)
            tgt_services = _decode_services(tgt_obs.get('listening_services_array', []), port_names)
            src_vulns_used = _decode_vulns_used(src_obs.get('vulnerabilities_array', []), vuln_names)

            # ── Global-feature events (set per-step by env) ───────────────────
            lateral_move  = _to_int(gbl_obs.get('lateral_move', 0))
            escalation    = _to_int(gbl_obs.get('escalation', 0))
            probe_result  = _to_int(gbl_obs.get('probe_result', 0))
            customer_data = _to_int(gbl_obs.get('customer_data_found', 0))
            disc_creds_gbl = _to_int(gbl_obs.get('number_discovered_credentials', 0))

            # ── Outcome details: newly discovered nodes / credentials ─────────
            new_nodes_disc  = [env.index_to_node_name.get(n, str(n))
                               for n in (getattr(outcome, 'new_nodes', None) or [])]
            raw_new_creds   = getattr(outcome, 'new_credentials', None) or []
            new_creds_leaked = []
            for entry in raw_new_creds:
                try:
                    # new_credentials is a list of (idx, CachedCredential) tuples
                    cred_obj = entry[1] if isinstance(entry, (tuple, list)) else entry
                    cred_id  = getattr(cred_obj, 'credential', str(cred_obj))
                    cred_node = env.index_to_node_name.get(
                        getattr(cred_obj, 'node', -1), str(getattr(cred_obj, 'node', '?'))
                    )
                    new_creds_leaked.append(f"{cred_id}@{cred_node}")
                except Exception:
                    pass

            row = {
                # Navigation
                "step":              step,
                "src":               src_name,
                "tgt":               tgt_name,
                "action":            action_name,
                # Action result
                "outcome":           outcome_str,
                "reward":            round(float(reward), 2),
                "done":              done,
                "network_avail":     round(float(info.get('network_availability', 1.0)), 3),
                # Environment counters
                "owned":             owned_now,
                "discovered":        disc_now,
                "creds":             creds_now,
                # Node-level observation
                "src_priv":          src_priv,
                "tgt_priv":          tgt_priv,
                "src_status":        src_status,
                "tgt_status":        tgt_status,
                "src_properties":    src_props,
                "tgt_properties":    tgt_props,
                "tgt_services":      tgt_services,
                "src_vulns_used":    src_vulns_used,
                # Global-feature events
                "lateral_move":      lateral_move,
                "escalation":        escalation,
                "probe_result":      probe_result,
                "customer_data":     customer_data,
                "disc_creds_global": disc_creds_gbl,
                # Outcome discoveries
                "new_nodes":         new_nodes_disc,
                "new_creds":         new_creds_leaked,
                # Goal
                "goal":              [env.index_to_node_name.get(g, str(g)) for g in new_goals] if is_goal else [],
            }
            trial_traj.append(row)

            if is_goal:
                stats = env.get_statistics()
                if stats.get('achieved_goals', 0) >= stats.get('total_goals', 1):
                    goal_reached = True
                    replay_steps_list.append(step)
                    break

        status = f"\033[92msolved @ step {replay_steps_list[-1]}\033[0m" if goal_reached else "\033[91mfailed\033[0m"
        print(f"    trial {trial + 1}/{replay_trials}: {status}")
        if goal_reached:
            replay_success += 1
        if trial == 0:
            full_trajectory = trial_traj   # save first trial for printing

    replay_rate = replay_success / replay_trials
    run_metrics["replay_verification"] = {
        "bfs_sequence_length": len(best_actions),
        "trials":              replay_trials,
        "success_count":       replay_success,
        "success_rate":        round(replay_rate, 4),
        "avg_steps":           round(sum(replay_steps_list) / len(replay_steps_list), 1) if replay_steps_list else None,
    }

    if replay_success == replay_trials:
        print(f"  [Replay] \033[92m✓ ALL {replay_trials} trials succeeded — BFS solution is valid for a real agent\033[0m")
    elif replay_success > 0:
        print(f"  [Replay] \033[93m⚠ {replay_success}/{replay_trials} trials succeeded — stochastic exploits cause some failures\033[0m")
    else:
        print(f"  [Replay] \033[91m✗ ALL trials failed — BFS solution may not transfer to a real agent\033[0m")

    # ── Advanced DRL Metrics ──────────────────────────────────────────────────
    if full_trajectory:
        min_cred_harvest_sequence = sum(1 for r in full_trajectory if len(r.get("new_creds", [])) > 0)
        
        positive_reward_steps = [r["step"] for r in full_trajectory if r.get("reward", 0) > 0]
        avg_steps_between_rewards = 0.0
        if len(positive_reward_steps) > 1:
            intervals = [positive_reward_steps[i] - positive_reward_steps[i-1] for i in range(1, len(positive_reward_steps))]
            avg_steps_between_rewards = sum(intervals) / len(intervals)
        elif len(positive_reward_steps) == 1:
            avg_steps_between_rewards = positive_reward_steps[0]

        signal_actions = sum(1 for r in full_trajectory if r.get("reward", 0) > 0 or r.get("new_nodes") or r.get("new_creds") or r.get("lateral_move") or r.get("escalation"))
        noise_actions = len(full_trajectory) - signal_actions
        action_signal_to_noise_ratio = signal_actions / max(noise_actions, 1)

        run_metrics["drl_hardness"] = {
            "min_cred_harvest_sequence": min_cred_harvest_sequence,
            "avg_steps_between_rewards": round(avg_steps_between_rewards, 2),
            "action_signal_to_noise_ratio": round(action_signal_to_noise_ratio, 4)
        }
    else:
        run_metrics["drl_hardness"] = {
            "min_cred_harvest_sequence": 0,
            "avg_steps_between_rewards": 0.0,
            "action_signal_to_noise_ratio": 0.0
        }

    # ── Save full trajectory (trial 1) to JSON ────────────────────────────────
    if full_trajectory:
        traj_path = scenario_dir / "replay_trajectory.json"
        with open(traj_path, "w") as _tf:
            json.dump(full_trajectory, _tf, indent=2)
        print(f"  [Replay] Trajectory saved → {traj_path}")

    # ── Print full trajectory (trial 1) ──────────────────────────────────────
    if full_trajectory:
        print()
        print("  ── Full Replay Trajectory (trial 1) " + "─" * 64)
        hdr = (f"  {'step':>4}  {'src':<28} {'tgt':<28} {'action':<38} "
               f"{'outcome':<20} {'rwd':>6}  D  {'own/dis/crd':<11}  "
               f"{'sp':>2}/{'tp':>2}  events")
        print(hdr)
        print("  " + "─" * (len(hdr) - 2))
        for r in full_trajectory:
            goal_flag = "  ★ " + ", ".join(r["goal"]) if r["goal"] else ""

            # Compact event flags
            events = []
            if r["lateral_move"]:  events.append("LM")
            if r["escalation"]:    events.append("ESC")
            if r["probe_result"]:  events.append(f"PRB{r['probe_result']}")
            if r["customer_data"]: events.append("CD")
            ev_str = ",".join(events) if events else ""

            owndisc = f"{r['owned']}/{r['discovered']}/{r['creds']}"
            priv    = f"{r['src_priv']:>2}/{r['tgt_priv']:>2}"

            print(
                f"  {r['step']:>4}  "
                f"{r['src']:<28} "
                f"{r['tgt']:<28} "
                f"{str(r['action']):<38} "
                f"{r['outcome']:<20} "
                f"{r['reward']:>6.1f}  "
                f"{'D' if r['done'] else ' '}  "
                f"{owndisc:<11}  "
                f"{priv}  "
                f"{ev_str:<12}"
                f"{goal_flag}"
            )

            # Detail line: show discoveries when something interesting happened
            detail = []
            if r["new_nodes"]:       detail.append(f"new_nodes:{r['new_nodes']}")
            if r["new_creds"]:       detail.append(f"new_creds:{r['new_creds']}")
            if r["tgt_properties"]:  detail.append(f"tgt_props:{r['tgt_properties']}")
            if r["src_vulns_used"]:  detail.append(f"src_vulns_used:{r['src_vulns_used']}")
            if r["tgt_services"]:    detail.append(f"tgt_svcs:{r['tgt_services']}")
            if detail:
                print(f"         {'  '.join(detail)}")

        print("  " + "─" * (len(hdr) - 2))

    with open(scenario_dir / "run_metrics.json", "w") as f:
        json.dump(run_metrics, f, indent=4)

    return any_solved, run_metrics


def main():
    parser = argparse.ArgumentParser(description="Test dynamic solvability of generated scenarios and output LLM prompts.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scenario", type=str, help="Path to a single generated scenario directory")
    group.add_argument("--data-dir", type=str, help="Path to a root directory containing multiple scenarios")
    parser.add_argument("--steps", type=int, default=10000, help="Maximum steps per episode")
    parser.add_argument("--num-agents", type=int, default=5, help="Number of cooperative agents in the swarm")
    parser.add_argument("--episodes", type=int, default=5, help="Number of times to retry the scenario before failing completely")
    parser.add_argument("--eval-difficulty", action="store_true", help="Run additional greedy exploration trials to measure learning gap")
    parser.add_argument("--agent-type", type=str, default=None,
                        help="Agent type for BFS action-space filtering (D-P1), e.g. S_Windows")
    parser.add_argument("--config", type=str, default=None,
                        help="Path to domain config YAML (required with --agent-type)")

    args = parser.parse_args()

    # ── D-P1: Build allowed_vuln_names from config + agent allowlist ──────────
    allowed_vuln_names: set | None = None
    if args.agent_type and _AGENT_ALLOWLIST:
        permitted_cats = set(_AGENT_ALLOWLIST.get(args.agent_type, []))
        if permitted_cats and args.config:
            try:
                import yaml as _yaml
                cfg = _yaml.safe_load(open(args.config).read()) or {}
                solv = cfg.get("solvability_vulnerabilities", {})
                allowed_vuln_names = set()
                for cat, entries in solv.items():
                    if cat in permitted_cats and isinstance(entries, list):
                        for entry in entries:
                            name = entry.get("name") if isinstance(entry, dict) else None
                            if name:
                                allowed_vuln_names.add(name)
                if allowed_vuln_names:
                    print(f"  [D-P1] BFS restricted to {len(allowed_vuln_names)} vulns "
                          f"for agent '{args.agent_type}' "
                          f"(categories: {sorted(permitted_cats)})")
                else:
                    print(f"  [D-P1] WARNING: no vulns found for agent '{args.agent_type}' "
                          f"in config — BFS will run unrestricted")
                    allowed_vuln_names = None
            except Exception as exc:
                print(f"  [D-P1] WARNING: could not build allowlist from config: {exc}")

    scenarios_to_test = []

    if args.scenario:
        scenarios_to_test.append(Path(args.scenario))
    elif args.data_dir:
        root_path = Path(args.data_dir)
        for p in root_path.rglob("nodes"):
            if p.is_dir():
                scenarios_to_test.append(p.parent)

    success_count = 0
    all_metrics = []
    
    for scenario_path in scenarios_to_test:
        solved, metrics = test_dynamic_solve(
            scenario_path,
            max_steps=args.steps,
            num_agents=args.num_agents,
            max_episodes=args.episodes,
            eval_difficulty=args.eval_difficulty,
            allowed_vuln_names=allowed_vuln_names,
        )
        all_metrics.append(metrics)
        if solved:
            success_count += 1

    if args.data_dir:
        generate_dataset_summary_prompt(Path(args.data_dir), all_metrics)
    elif args.scenario:
        generate_dataset_summary_prompt(Path(args.scenario).parent, all_metrics)

    print("\n" + "="*50)
    print(f"Dynamic Solvability Check Complete: {success_count}/{len(scenarios_to_test)} Scenarios Solved.")
    print("="*50)
    sys.exit(0 if success_count == len(scenarios_to_test) else 1)


if __name__ == "__main__":
    main()