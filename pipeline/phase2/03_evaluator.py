#!/usr/bin/env python3
"""
tools/phase2_evaluator.py
============================
Compute structural quality metrics (§3.1), cross-scenario fairness metrics
(§3.3), and comprehensive attack path metrics (§3.4) on generated
CyberBattleSim scenarios.

Usage
-----
# Evaluate a single scenario directory
python3 tools/phase2_evaluator.py --scenario generated_data/active_directory/CyberBattleSim-v0-1

# Evaluate an entire domain directory
python3 tools/phase2_evaluator.py --data-dir generated_data/active_directory

# Evaluate ALL domains, produce full report
python3 tools/phase2_evaluator.py --data-dir generated_data/ --out report.json

# Only print failures (solvable=False or min_depth<2)
python3 tools/phase2_evaluator.py --data-dir generated_data/ --reject-only

# Skip attack-path annotation (faster for large datasets)
python3 tools/phase2_evaluator.py --data-dir generated_data/ --no-attack-paths
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml


# ---------------------------------------------------------------------------
# Custom YAML loader that tolerates Python-specific object tags
# (node files serialise NetworkInterfaces etc. with !!python/object/apply:...)
# ---------------------------------------------------------------------------

def _make_tolerant_loader():
    """Return a YAML Loader subclass that ignores unknown Python tags."""
    class _TolerantLoader(yaml.SafeLoader):
        pass

    def _ignore_unknown(loader, tag_suffix, node):
        """Return a plain string for any unrecognised tag."""
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_mapping(node, deep=True)

    _TolerantLoader.add_multi_constructor("", _ignore_unknown)
    return _TolerantLoader

_TOLERANT_LOADER = _make_tolerant_loader()


def _load_yaml_tolerant(path) -> dict:
    with open(path) as f:
        return yaml.load(f, Loader=_TOLERANT_LOADER) or {}


# ---------------------------------------------------------------------------
# YAML Loading helpers
# ---------------------------------------------------------------------------

def _load_nodes(scenario_dir: Path) -> Optional[Dict[str, dict]]:
    """Load all node YAML files from <scenario_dir>/nodes/. Returns dict keyed by node_id."""
    nodes_dir = scenario_dir / "nodes"
    if not nodes_dir.is_dir():
        return None
    nodes = {}
    for f in nodes_dir.glob("*.yaml"):
        try:
            nodes[f.stem] = _load_yaml_tolerant(f)
        except Exception as exc:
            print(f"  [evaluator] warning: could not parse {f.name}: {exc}", file=sys.stderr)
    return nodes if nodes else None


# ---------------------------------------------------------------------------
# Reachability / BFS
# ---------------------------------------------------------------------------

def _build_attack_edges(nodes: Dict[str, dict]) -> Dict[str, Set[str]]:
    """
    Build a directed reachability graph over the node dict.

    An edge A→B exists if, from node A, an attacker can reach/own node B in
    one exploit step, via one of:
      - A leaks credentials usable on B's service (lateral move)
      - A discovers B (LeakedNodesId) AND B has at least one REMOTE vulnerability
    """
    # Step 1: collect what each node leaks
    creds_from: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)  # node → {(target_node, cred_str)}
    discovers_from: Dict[str, Set[str]] = defaultdict(set)           # node → {target_node}

    for node_id, node in nodes.items():
        for vuln in node.get("vulnerabilities", {}).values():
            outcome = vuln.get("outcome") or {}
            otype = outcome.get("type", "")
            kwargs = outcome.get("kwargs", {})

            if otype == "leaked_credentials":
                for cred_entry in kwargs.get("credentials", []):
                    ck = cred_entry.get("kwargs", {})
                    tgt = ck.get("node", "")
                    cred = ck.get("credential", "")
                    if tgt and cred:
                        creds_from[node_id].add((tgt, cred))

            elif otype == "leaked_nodes_id":
                for n in kwargs.get("nodes", []):
                    if n:
                        discovers_from[node_id].add(n)

    # Step 2: which nodes have REMOTE vulns?
    has_remote: Set[str] = set()
    for node_id, node in nodes.items():
        for vuln in node.get("vulnerabilities", {}).values():
            if vuln.get("type") == 3:  # REMOTE (VulnerabilityType.REMOTE = 3)
                has_remote.add(node_id)
                break

    # Step 3: which credential strings are accepted by which services?
    cred_to_node: Dict[str, str] = {}  # cred_str → node_id (the node that owns this service)
    for node_id, node in nodes.items():
        for svc in node.get("services", []):
            for cred in svc.get("allowedCredentials", []):
                if cred not in cred_to_node:
                    cred_to_node[cred] = node_id

    # Step 4: build adjacency
    adj: Dict[str, Set[str]] = defaultdict(set)
    for src_id in nodes:
        # Via leaked credentials
        for tgt_node, cred in creds_from.get(src_id, set()):
            if tgt_node in nodes:
                adj[src_id].add(tgt_node)
        # Via discovery + remote exploit
        for tgt_node in discovers_from.get(src_id, set()):
            if tgt_node in nodes and tgt_node in has_remote:
                adj[src_id].add(tgt_node)

    return dict(adj)


def _compute_owned(nodes: Dict[str, dict]) -> Set[str]:
    """
    Simulate full attack reachability via BFS over the credential/discovery
    graph. Returns the set of node_ids the attacker can own starting from 'start'.
    """
    if "start" not in nodes:
        return set()

    owned: Set[str] = {"start"}
    discovered: Set[str] = {"start"}
    credentials: Set[str] = set()   # credential strings we hold

    changed = True
    while changed:
        changed = False

        # Run LOCAL vulns on owned nodes
        for node_id in list(owned):
            for vuln in nodes[node_id].get("vulnerabilities", {}).items():
                vuln_data = vuln[1]
                if vuln_data.get("type") != 2:   # LOCAL (VulnerabilityType.LOCAL = 2)
                    continue
                outcome = vuln_data.get("outcome") or {}
                otype = outcome.get("type", "")
                kwargs = outcome.get("kwargs", {})

                if otype == "leaked_credentials":
                    for cred_entry in kwargs.get("credentials", []):
                        cred_str = cred_entry.get("kwargs", {}).get("credential", "")
                        if cred_str and cred_str not in credentials:
                            credentials.add(cred_str)
                            changed = True

                elif otype == "leaked_nodes_id":
                    for n in kwargs.get("nodes", []):
                        if n and n not in discovered:
                            discovered.add(n)
                            changed = True

        # Try REMOTE vulns: owned nodes can attack discovered nodes
        for tgt_id in list(discovered):
            if tgt_id in owned:
                continue
            for vuln_data in nodes.get(tgt_id, {}).get("vulnerabilities", {}).values():
                if vuln_data.get("type") != 3:   # REMOTE (VulnerabilityType.REMOTE = 3)
                    continue
                outcome = vuln_data.get("outcome") or {}
                otype = outcome.get("type", "")
                if otype in ("lateral_move", "privilege_escalation",
                             "leaked_credentials", "leaked_nodes_id", "customer_data"):
                    if tgt_id not in owned:
                        owned.add(tgt_id)
                        changed = True
                        break

        # Lateral move via credential match
        for node_id in list(discovered):
            if node_id in owned:
                continue
            for svc in nodes.get(node_id, {}).get("services", []):
                allowed = set(svc.get("allowedCredentials", []))
                if credentials & allowed:
                    if node_id not in owned:
                        owned.add(node_id)
                        changed = True

    return owned


def _bfs_depth(adj: Dict[str, Set[str]], start: str, target: str) -> int:
    """BFS shortest path length. Returns len if reachable, else -1."""
    if target == start:
        return 0
    visited = {start}
    queue: deque = deque([(start, 0)])
    while queue:
        node, depth = queue.popleft()
        for nbr in adj.get(node, set()):
            if nbr == target:
                return depth + 1
            if nbr not in visited:
                visited.add(nbr)
                queue.append((nbr, depth + 1))
    return -1


# ---------------------------------------------------------------------------
# Attack Path Metrics (§3.4) — per-node reachability + per-goal action plans
# ---------------------------------------------------------------------------

# CBS action type labels
AT_REMOTE_EXPLOIT  = "REMOTE_EXPLOIT"    # exploit REMOTE vuln from owned src
AT_CREDENTIAL_USE  = "CREDENTIAL_USE"    # port-connect with stolen credentials
AT_LOCAL_CRED_LEAK = "LOCAL_CRED_LEAK"   # LOCAL vuln → LeakedCredentials
AT_LOCAL_DISCOVERY = "LOCAL_DISCOVERY"   # LOCAL vuln → LeakedNodesId
AT_LOCAL_PRIVESC   = "LOCAL_PRIVESC"     # LOCAL vuln → PrivilegeEscalation
AT_LOCAL_DUMP      = "LOCAL_DUMP"        # LOCAL vuln → data exfil / dump


def _vuln_rate(vuln: dict) -> float:
    """Robustly extract success_rate from any YAML-deserialised vuln dict.

    CyberBattleSim serialises Rates as a Python object; the tolerant YAML
    loader may return it as a dict, plain float, or repr string.
    Unknown format → 1.0 (optimistic, flags as lower-bound on difficulty).
    """
    rates = vuln.get("rates")
    if isinstance(rates, dict):
        for k in ("successRate", "success_rate"):
            v = rates.get(k)
            if v is not None:
                try:
                    return min(float(v), 1.0)
                except (TypeError, ValueError):
                    pass
    elif isinstance(rates, (int, float)):
        return min(float(rates), 1.0)
    elif isinstance(rates, str):
        m = re.search(r"([\d.]+)", rates)
        if m:
            try:
                return min(float(m.group(1)), 1.0)
            except ValueError:
                pass
    for k in ("success_rate", "successRate"):
        v = vuln.get(k)
        if v is not None:
            try:
                return min(float(v), 1.0)
            except (TypeError, ValueError):
                pass
    return 1.0


def _vuln_cost(vuln: dict) -> float:
    try:
        return float(vuln.get("cost", 1.0))
    except (TypeError, ValueError):
        return 1.0


def _classify_vuln(vtype: int, otype: str) -> str:
    if vtype == 3:                        # REMOTE
        return AT_REMOTE_EXPLOIT
    if otype == "leaked_nodes_id":
        return AT_LOCAL_DISCOVERY
    if otype == "privilege_escalation":
        return AT_LOCAL_PRIVESC
    if otype in ("customer_data", "data_exfil"):
        return AT_LOCAL_DUMP
    return AT_LOCAL_CRED_LEAK            # leaked_credentials (LOCAL)


def _build_enriched_graph(nodes: Dict[str, dict]) -> dict:
    """
    Analyse every node's vulnerabilities and produce an annotated attack
    graph where each directed edge carries a list of possible action sequences.

    adj_meta[src][tgt] — list of edge option dicts::

        {
          "via":              "credential" | "remote_exploit",
          "actions":          [action_dict, ...],
          "edge_probability": float,   # ∏ success_rates for this option
          "edge_cost":        float,   # Σ costs for this option
        }

    Each action_dict has keys:
        action_type, source_node, target_node, vuln_name,
        success_rate, cost, outcome_type
    """
    remote_by:  Dict[str, List[dict]] = defaultdict(list)
    cred_leak:  Dict[str, List[dict]] = defaultdict(list)  # LOCAL → credentials
    discovery:  Dict[str, List[dict]] = defaultdict(list)  # LOCAL → nodes
    privesc:    Dict[str, List[dict]] = defaultdict(list)
    dump_vulns: Dict[str, List[dict]] = defaultdict(list)

    for nid, node in nodes.items():
        for vname, vuln in node.get("vulnerabilities", {}).items():
            if not isinstance(vuln, dict):
                continue
            vtype   = vuln.get("type", 0)
            outcome = vuln.get("outcome") or {}
            if not isinstance(outcome, dict):
                continue
            otype  = outcome.get("type", "")
            kwargs = outcome.get("kwargs", {}) or {}
            rate   = _vuln_rate(vuln)
            cost   = _vuln_cost(vuln)
            base   = {
                "vuln_name":    vname,
                "action_type":  _classify_vuln(vtype, otype),
                "success_rate": rate,
                "cost":         cost,
                "outcome_type": otype,
            }

            if vtype == 3:   # REMOTE
                remote_by[nid].append(base)

            elif vtype == 2:  # LOCAL
                if otype == "leaked_credentials":
                    tgts: Set[str] = set()
                    for ce in kwargs.get("credentials", []):
                        if not isinstance(ce, dict):
                            continue
                        ck = ce.get("kwargs", {}) or {}
                        tgt = ck.get("node", "")
                        if tgt and tgt in nodes and tgt != nid:
                            tgts.add(tgt)
                    if tgts:
                        cred_leak[nid].append({**base, "targets": sorted(tgts)})

                elif otype == "leaked_nodes_id":
                    disc = [n for n in kwargs.get("nodes", [])
                            if n in nodes and n != nid]
                    if disc:
                        discovery[nid].append({**base, "discovers": disc})

                elif otype == "privilege_escalation":
                    privesc[nid].append(base)

                else:   # customer_data, dump, etc.
                    dump_vulns[nid].append(base)

    def _act(atype, src, tgt, vname, rate, cost, otype):
        return {
            "action_type":  atype,
            "source_node":  src,
            "target_node":  tgt,
            "vuln_name":    vname,
            "success_rate": rate,
            "cost":         cost,
            "outcome_type": otype,
        }

    adj_meta: Dict[str, Dict[str, List[dict]]] = defaultdict(lambda: defaultdict(list))

    for src in nodes:
        # ── Credential-leak → credential-use edges ──────────────────────────
        for cl in cred_leak.get(src, []):
            for tgt in cl["targets"]:
                a1 = _act(AT_LOCAL_CRED_LEAK, src, src,
                          cl["vuln_name"], cl["success_rate"], cl["cost"],
                          cl["outcome_type"])
                a2 = _act(AT_CREDENTIAL_USE,  src, tgt,
                          f"connect:{tgt}", 1.0, 1.0, "lateral_move")
                p = cl["success_rate"]       # credential use is deterministic
                c = cl["cost"] + 1.0
                adj_meta[src][tgt].append({
                    "via":              "credential",
                    "actions":          [a1, a2],
                    "edge_probability": round(p, 6),
                    "edge_cost":        round(c, 2),
                })

        # ── Discovery → REMOTE-exploit edges ────────────────────────────────
        for disc in discovery.get(src, []):
            for tgt in disc["discovers"]:
                for rv in remote_by.get(tgt, []):
                    a1 = _act(AT_LOCAL_DISCOVERY, src, src,
                              disc["vuln_name"], disc["success_rate"],
                              disc["cost"],       disc["outcome_type"])
                    a2 = _act(AT_REMOTE_EXPLOIT,  src, tgt,
                              rv["vuln_name"],  rv["success_rate"],
                              rv["cost"],        rv["outcome_type"])
                    p = disc["success_rate"] * rv["success_rate"]
                    c = disc["cost"] + rv["cost"]
                    adj_meta[src][tgt].append({
                        "via":              "remote_exploit",
                        "actions":          [a1, a2],
                        "edge_probability": round(p, 6),
                        "edge_cost":        round(c, 2),
                    })

    adj_plain = {src: dict(tgts) for src, tgts in adj_meta.items()}

    node_local: Dict[str, List[dict]] = {}
    for nid in nodes:
        loc = (cred_leak.get(nid, []) + discovery.get(nid, [])
               + privesc.get(nid, []) + dump_vulns.get(nid, []))
        if loc:
            node_local[nid] = loc

    return {
        "adj_meta":   adj_plain,
        "node_local": node_local,
        "privesc_by": dict(privesc),
        "dump_by":    dict(dump_vulns),
    }


def _best_edge_option(opts: List[dict]) -> dict:
    """Pick the edge option with the highest edge_probability."""
    if not opts:
        return {}
    return max(opts, key=lambda o: o.get("edge_probability", 0.0))


def _find_hop_path(
    adj_meta: Dict[str, Dict[str, List[dict]]],
    start:  str,
    target: str,
) -> Optional[List[str]]:
    """BFS on hop-level graph. Returns node-ID path list, or None."""
    if target == start:
        return [start]
    pred: Dict[str, Optional[str]] = {start: None}
    queue: deque = deque([start])
    while queue:
        cur = queue.popleft()
        for nbr in adj_meta.get(cur, {}):
            if nbr not in pred:
                pred[nbr] = cur
                if nbr == target:
                    path: List[str] = []
                    n: Optional[str] = target
                    while n is not None:
                        path.append(n)
                        n = pred[n]
                    path.reverse()
                    return path
                queue.append(nbr)
    return None


def _annotate_path(
    path:     List[str],
    adj_meta: Dict[str, Dict[str, List[dict]]],
    enriched: dict,
) -> dict:
    """
    Convert a hop-level node path into a fully annotated CBS action plan.

    For each edge (src→tgt) the best available option (by probability) is
    selected.  Post-compromise actions (privesc + dump) are appended for
    the goal node.

    Returns a dict with all per-goal attack path metrics.
    """
    if not path or len(path) < 2:
        return {}

    privesc_by = enriched.get("privesc_by", {})
    dump_by    = enriched.get("dump_by", {})

    actions: List[dict] = []

    for i in range(len(path) - 1):
        src, tgt = path[i], path[i + 1]
        opts = adj_meta.get(src, {}).get(tgt, [])
        best = _best_edge_option(opts)
        actions.extend(best.get("actions", []))

        # After landing on an intermediate node the attacker must escalate
        # privileges before they can run LOCAL credential-leak / discovery
        # actions on it.  Add the cheapest privesc available (if any).
        is_intermediate = (i < len(path) - 2)
        if is_intermediate:
            pvs = privesc_by.get(tgt, [])
            if pvs:
                # pick the highest-probability privesc available on this node
                best_pv = max(pvs, key=lambda p: p.get("success_rate", 0.0))
                actions.append({
                    "action_type":  AT_LOCAL_PRIVESC,
                    "source_node":  tgt,
                    "target_node":  tgt,
                    "vuln_name":    best_pv["vuln_name"],
                    "success_rate": best_pv["success_rate"],
                    "cost":         best_pv["cost"],
                    "outcome_type": best_pv["outcome_type"],
                })

    # Post-compromise on the goal node (privilege escalation + credential dump)
    goal = path[-1]
    for pv in privesc_by.get(goal, []):
        actions.append({
            "action_type":  AT_LOCAL_PRIVESC,
            "source_node":  goal,
            "target_node":  goal,
            "vuln_name":    pv["vuln_name"],
            "success_rate": pv["success_rate"],
            "cost":         pv["cost"],
            "outcome_type": pv["outcome_type"],
        })
    for dv in dump_by.get(goal, []):
        actions.append({
            "action_type":  AT_LOCAL_DUMP,
            "source_node":  goal,
            "target_node":  goal,
            "vuln_name":    dv["vuln_name"],
            "success_rate": dv["success_rate"],
            "cost":         dv["cost"],
            "outcome_type": dv["outcome_type"],
        })

    # Aggregate metrics
    success_prob = 1.0
    for a in actions:
        success_prob *= a.get("success_rate", 1.0)
    success_prob = round(success_prob, 6)

    type_counts:    Dict[str, int] = {}
    outcome_counts: Dict[str, int] = {}
    total_cost = 0.0
    for a in actions:
        at = a["action_type"]
        type_counts[at]    = type_counts.get(at, 0) + 1
        ot = a["outcome_type"]
        outcome_counts[ot] = outcome_counts.get(ot, 0) + 1
        total_cost += a.get("cost", 1.0)

    intermediate = path[1:-1]

    return {
        "path":                path,
        "intermediate_nodes":  intermediate,
        "total_hops":          len(path) - 1,
        # how many nodes the attacker must own before the goal (excl. start + goal)
        "min_nodes_to_own":    len(intermediate),
        "actions":             actions,
        "total_actions":       len(actions),
        "action_type_counts":  type_counts,
        "action_outcomes":     outcome_counts,
        "success_probability": success_prob,
        # expected number of independent attempts before one full run succeeds
        "expected_attempts":   round(1.0 / success_prob, 2) if success_prob > 0 else None,
        "total_cost":          round(total_cost, 2),
    }


# ---------------------------------------------------------------------------
# Elite BFS Solver Metrics (§3.5)
# ---------------------------------------------------------------------------

from pipeline import constants as C

_STEALTH_DETECTION_THRESHOLD = C.STEALTH_DETECTION_THRESHOLD   # default; override per-call


def _count_shortest_paths(
    adj: Dict[str, Set[str]],
    start: str,
    target: str,
) -> int:
    """
    Count the number of distinct shortest paths from *start* to *target*
    using BFS dynamic programming.

    A path is "distinct" if the sequence of node IDs differs.  Returns 0 if
    *target* is unreachable.
    """
    if start == target:
        return 1

    dist: Dict[str, int] = {start: 0}
    path_count: Dict[str, int] = {start: 1}
    queue: deque = deque([start])

    while queue:
        node = queue.popleft()
        for nbr in adj.get(node, set()):
            if nbr not in dist:
                dist[nbr] = dist[node] + 1
                path_count[nbr] = path_count[node]
                queue.append(nbr)
            elif dist[nbr] == dist[node] + 1:
                # Same-depth neighbour — accumulate path counts
                path_count[nbr] = path_count.get(nbr, 0) + path_count[node]

    return path_count.get(target, 0)


def _compute_visibility_index(
    path: List[str],
    adj_meta: Dict[str, Dict[str, List[dict]]],
) -> float:
    """
    Compute the Visibility Index for a hop-level node path.

    VI = cred_edges / (cred_edges + disc_edges)

    Each edge on the path is classified from the *best option*:
      - "credential"     → attacker used a leaked credential   (lower fog)
      - "remote_exploit" → attacker needed to discover first   (higher fog)

    Returns 0.5 when the path has no classifiable edges (neutral).
    Returns a value in [0.0, 1.0]:  1.0 = pure credential chain (no fog of war),
                                    0.0 = pure discovery chain (maximum fog).
    """
    if len(path) < 2:
        return 0.5

    cred_count = 0
    disc_count = 0
    for i in range(len(path) - 1):
        src, tgt = path[i], path[i + 1]
        opts = adj_meta.get(src, {}).get(tgt, [])
        best = _best_edge_option(opts)
        if best.get("via") == "credential":
            cred_count += 1
        elif best.get("via") == "remote_exploit":
            disc_count += 1

    total = cred_count + disc_count
    if total == 0:
        return 0.5
    return round(cred_count / total, 4)


def _find_choke_points(
    hop_adj:  Dict[str, Set[str]],
    all_node_ids: Set[str],
    start:  str,
    goal:   str,
    max_nodes: int = 400,
) -> List[str]:
    """
    Identify articulation / choke-point nodes: intermediate nodes whose
    removal disconnects *start* from *goal*.

    Uses an O(|V| × BFS) exhaustive check.  Skips graphs with more than
    *max_nodes* nodes to bound runtime on XL scenarios.

    Returns the list of choke-point node IDs (excluding start and goal).
    """
    if len(all_node_ids) > max_nodes:
        return []   # skip for XL topologies

    # Verify goal is reachable without any removal
    if _bfs_depth(hop_adj, start, goal) < 0:
        return []

    candidates = [n for n in all_node_ids if n not in (start, goal)]
    choke_points: List[str] = []

    for v in candidates:
        # Build adjacency without v
        reduced: Dict[str, Set[str]] = {
            s: {t for t in tgts if t != v}
            for s, tgts in hop_adj.items()
            if s != v
        }
        if _bfs_depth(reduced, start, goal) < 0:
            choke_points.append(v)

    return choke_points


def _compute_stealth_margin(
    path_annotation: dict,
    detection_threshold: float = _STEALTH_DETECTION_THRESHOLD,
) -> dict:
    """
    Compute the Stealth Margin: how much noise headroom remains before a
    simulated detection system would trigger.

    stealth_margin       = detection_threshold − total_path_cost
    is_stealthy          = stealth_margin > 0
    stealth_ratio        = total_path_cost / detection_threshold
    stealthiest_action   = the action with the lowest individual cost

    A negative stealth_margin indicates the optimal path would generate
    enough noise to cross the detection threshold.
    """
    total_cost = path_annotation.get("total_cost", 0.0)
    actions    = path_annotation.get("actions", [])

    margin = round(detection_threshold - total_cost, 4)

    stealthiest = None
    if actions:
        stealthiest_action = min(actions, key=lambda a: a.get("cost", 1.0))
        stealthiest = {
            "action_type":  stealthiest_action.get("action_type"),
            "vuln_name":    stealthiest_action.get("vuln_name"),
            "cost":         stealthiest_action.get("cost"),
        }

    return {
        "detection_threshold": detection_threshold,
        "total_path_cost":     round(total_cost, 4),
        "stealth_margin":      margin,
        "is_stealthy":         margin > 0,
        "stealth_ratio":       round(total_cost / detection_threshold, 4) if detection_threshold > 0 else None,
        "stealthiest_action":  stealthiest,
    }


def compute_attack_path_metrics(nodes: Dict[str, dict]) -> dict:
    """
    Compute comprehensive attack path metrics for every node and goal.

    Returned structure::

        {
          "per_node": {
            node_id: {
              "reachable":           bool,
              "min_hops_from_start": int | None,  # None = unreachable
            }
          },
          "per_goal": {
            goal_id: {
              "reachable": False
              # -- OR --
              "reachable":           True,
              "path":                [node_id, ...],
              "intermediate_nodes":  [node_id, ...],
              "total_hops":          int,
              "min_nodes_to_own":    int,
              "actions":             [action_dict, ...],
              "total_actions":       int,
              "action_type_counts":  {action_type: count},
              "action_outcomes":     {outcome_type: count},
              "success_probability": float,     # ∏ success_rates
              "expected_attempts":   float,     # 1 / success_probability
              "total_cost":          float,
            }
          },
          "summary": {aggregate statistics across all goals},
        }

    action_type values: REMOTE_EXPLOIT, CREDENTIAL_USE, LOCAL_CRED_LEAK,
                        LOCAL_DISCOVERY, LOCAL_PRIVESC, LOCAL_DUMP
    outcome_type values: lateral_move, leaked_credentials, leaked_nodes_id,
                         privilege_escalation, customer_data, …
    """
    if "start" not in nodes:
        return {}

    non_start = {k: v for k, v in nodes.items() if k != "start"}
    if not non_start:
        return {}

    goal_ids = [k for k, v in non_start.items() if v.get("is_goal", False)]

    enriched = _build_enriched_graph(nodes)
    adj_meta  = enriched["adj_meta"]

    # Hop-level adjacency (set of neighbour IDs) for _bfs_depth reuse
    hop_adj: Dict[str, Set[str]] = {
        src: set(tgts.keys()) for src, tgts in adj_meta.items()
    }

    # ── Per-node reachability ────────────────────────────────────────────────
    per_node: Dict[str, dict] = {}
    for nid in non_start:
        d = _bfs_depth(hop_adj, "start", nid)
        per_node[nid] = {
            "reachable":           d >= 0,
            "min_hops_from_start": d if d >= 0 else None,
        }

    # ── Per-goal full path analysis ──────────────────────────────────────────
    all_node_ids = set(non_start.keys())
    per_goal: Dict[str, dict] = {}
    for gid in goal_ids:
        path = _find_hop_path(adj_meta, "start", gid)
        if path is None:
            per_goal[gid] = {"reachable": False}
        else:
            per_goal[gid] = {"reachable": True, **_annotate_path(path, adj_meta, enriched)}
            # Elite BFS metrics
            per_goal[gid]["path_redundancy_factor"] = _count_shortest_paths(hop_adj, "start", gid)
            per_goal[gid]["visibility_index"]       = _compute_visibility_index(path, adj_meta)
            choke_pts = _find_choke_points(hop_adj, all_node_ids, "start", gid)
            per_goal[gid]["choke_points"]           = choke_pts
            per_goal[gid]["choke_point_count"]      = len(choke_pts)
            per_goal[gid]["stealth_margin"]         = _compute_stealth_margin(per_goal[gid])

    # ── Summary ──────────────────────────────────────────────────────────────
    reachable_g    = [m for m in per_goal.values() if m.get("reachable")]
    total_reachable = sum(1 for m in per_node.values() if m["reachable"])

    summary: dict = {
        "num_goals":             len(goal_ids),
        "reachable_goals":       len(reachable_g),
        "total_reachable_nodes": total_reachable,
        "total_nodes":           len(non_start),
        "reachability_ratio":    round(total_reachable / len(non_start), 3) if non_start else 0.0,
    }

    if reachable_g:
        hops    = [m["total_hops"]          for m in reachable_g]
        probs   = [m["success_probability"] for m in reachable_g]
        acts    = [m["total_actions"]        for m in reachable_g]
        costs   = [m["total_cost"]           for m in reachable_g]
        min_own = [m["min_nodes_to_own"]    for m in reachable_g]

        summary.update({
            "avg_hops_to_goal":        round(sum(hops)    / len(hops),    2),
            "min_hops_to_goal":        min(hops),
            "max_hops_to_goal":        max(hops),
            "avg_min_nodes_to_own":    round(sum(min_own) / len(min_own), 2),
            "avg_success_probability": round(sum(probs)   / len(probs),   4),
            "min_success_probability": round(min(probs),                  4),
            "max_success_probability": round(max(probs),                  4),
            "avg_actions_to_goal":     round(sum(acts)    / len(acts),    1),
            "avg_total_cost":          round(sum(costs)   / len(costs),   2),
        })

        # Global action-type and outcome-type distribution across all goal paths
        global_types:    Dict[str, int] = {}
        global_outcomes: Dict[str, int] = {}
        for m in reachable_g:
            for k, v in m.get("action_type_counts", {}).items():
                global_types[k]    = global_types.get(k, 0)    + v
            for k, v in m.get("action_outcomes", {}).items():
                global_outcomes[k] = global_outcomes.get(k, 0) + v

        summary["global_action_type_counts"] = global_types
        summary["global_action_outcomes"]    = global_outcomes
        if global_types:
            summary["dominant_action_type"] = max(global_types, key=global_types.get)

        # ── Elite BFS metric aggregates ──────────────────────────────────────
        prfs    = [m["path_redundancy_factor"] for m in reachable_g if "path_redundancy_factor" in m]
        vis     = [m["visibility_index"]        for m in reachable_g if "visibility_index"        in m]
        cp_cts  = [m["choke_point_count"]       for m in reachable_g if "choke_point_count"       in m]
        margins = [m["stealth_margin"]["stealth_margin"]
                   for m in reachable_g
                   if "stealth_margin" in m and isinstance(m["stealth_margin"], dict)]

        # Union of all choke-point node IDs across goals (global bottlenecks)
        global_choke: List[str] = []
        seen_choke: Set[str] = set()
        for m in reachable_g:
            for cp in m.get("choke_points", []):
                if cp not in seen_choke:
                    seen_choke.add(cp)
                    global_choke.append(cp)

        if prfs:
            summary["avg_path_redundancy_factor"] = round(sum(prfs) / len(prfs), 2)
            summary["max_path_redundancy_factor"] = max(prfs)
        if vis:
            summary["avg_visibility_index"]       = round(sum(vis) / len(vis), 4)
        if cp_cts:
            summary["avg_choke_point_count"]      = round(sum(cp_cts) / len(cp_cts), 2)
            summary["global_choke_points"]        = global_choke
        if margins:
            summary["avg_stealth_margin"]         = round(sum(margins) / len(margins), 4)
            summary["scenarios_stealthy"]         = sum(1 for mg in margins if mg > 0)
            summary["scenarios_detected"]         = sum(1 for mg in margins if mg <= 0)

    return {"per_node": per_node, "per_goal": per_goal, "summary": summary}


# ---------------------------------------------------------------------------
# Core metrics (§3.1)
# ---------------------------------------------------------------------------

def evaluate_scenario(scenario_dir: Path, include_attack_paths: bool = True) -> Optional[dict]:
    """Compute all structural metrics for a single scenario directory.

    Args:
        scenario_dir: path to the generated scenario directory.
        include_attack_paths: when True (default) compute §3.4 attack path
            metrics.  Set to False for a faster run on large datasets.
    """
    nodes = _load_nodes(scenario_dir)
    if not nodes:
        return None

    non_start = {k: v for k, v in nodes.items() if k != "start"}
    if not non_start:
        return None

    goal_nodes = [k for k, v in non_start.items() if v.get("is_goal", False)]

    # 1. Reachability / solvability
    owned = _compute_owned(nodes)
    solvable = all(g in owned for g in goal_nodes) if goal_nodes else False

    # 2. Credential chain coverage
    cred_leak_count = 0
    for node in non_start.values():
        for vuln in node.get("vulnerabilities", {}).values():
            outcome = vuln.get("outcome") or {}
            if outcome.get("type") == "leaked_credentials":
                cred_leak_count += 1
                break
    cred_ratio = cred_leak_count / len(non_start)

    # 3. Discovery coverage
    discovered_by_any: Set[str] = set()
    for node in non_start.values():
        for vuln in node.get("vulnerabilities", {}).values():
            outcome = vuln.get("outcome") or {}
            if outcome.get("type") == "leaked_nodes_id":
                discovered_by_any.update(outcome.get("kwargs", {}).get("nodes", []))
    discovery_ratio = len(discovered_by_any & set(non_start)) / len(non_start)

    # 4. Attack path depth (hop-level)
    adj = _build_attack_edges(nodes)
    depths = {}
    for g in goal_nodes:
        d = _bfs_depth(adj, "start", g)
        depths[g] = d if d >= 0 else 999   # 999 = unreachable

    min_depth = min(depths.values(), default=0)
    max_depth = max(depths.values(), default=0)
    mean_depth = round(sum(depths.values()) / len(depths), 2) if depths else 0.0

    # 5. Remote-exploitable goal nodes
    has_remote_goal_count = 0
    for g in goal_nodes:
        for vuln in nodes.get(g, {}).get("vulnerabilities", {}).values():
            if vuln.get("type") == 3:  # REMOTE
                has_remote_goal_count += 1
                break

    # 6. Goal ratio
    goal_ratio = len(goal_nodes) / len(non_start) if non_start else 0.0

    # 7. Vulnerability density
    total_vulns = sum(len(n.get("vulnerabilities", {})) for n in non_start.values())
    unique_vuln_names: Set[str] = set()
    for n in nodes.values():
        unique_vuln_names.update(n.get("vulnerabilities", {}).keys())

    result = {
        "scenario":                str(scenario_dir),
        "solvable":                solvable,
        "num_nodes":               len(non_start),
        "num_goals":               len(goal_nodes),
        "goal_ratio":              round(goal_ratio, 4),
        "cred_chain_ratio":        round(cred_ratio, 3),
        "discovery_ratio":         round(discovery_ratio, 3),
        "min_goal_depth":          min_depth,
        "max_goal_depth":          max_depth,
        "mean_goal_depth":         mean_depth,
        "remote_exploitable_goals": has_remote_goal_count,
        "goal_depths":             {k: v for k, v in depths.items()},
        "total_vulnerability_instances": total_vulns,
        "unique_vulnerability_names":    len(unique_vuln_names),
    }

    # 8. Attack path metrics (§3.4) — full per-node + per-goal analysis
    if include_attack_paths:
        result["attack_path_metrics"] = compute_attack_path_metrics(nodes)

    return result


# ---------------------------------------------------------------------------
# Fairness metrics (§3.3)
# ---------------------------------------------------------------------------

def _gini(values: List[float]) -> float:
    """Compute Gini coefficient for a list of non-negative values."""
    if not values or sum(values) == 0:
        return 0.0
    n = len(values)
    s = sorted(values)
    cumsum = 0.0
    for i, v in enumerate(s, 1):
        cumsum += v * (2 * i - n - 1)
    return cumsum / (n * sum(s))


def _cv(values: List[float]) -> float:
    """Coefficient of variation: std / mean."""
    if not values or sum(values) == 0:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return round((var ** 0.5) / mean, 3)


def compute_fairness_metrics(all_results: List[dict]) -> dict:
    """Aggregate cross-domain fairness metrics (§3.3)."""
    by_domain: Dict[str, List[dict]] = defaultdict(list)
    for r in all_results:
        # Infer domain from path: generated_data/<domain>/...
        parts = Path(r["scenario"]).parts
        domain = parts[-3] if len(parts) >= 3 else parts[-2] if len(parts) >= 2 else "unknown"
        by_domain[domain].append(r)

    mean_depth: Dict[str, float] = {}
    mean_cred: Dict[str, float] = {}
    solvability_rate: Dict[str, float] = {}

    for domain, items in by_domain.items():
        depths = [i["mean_goal_depth"] for i in items]
        creds  = [i["cred_chain_ratio"] for i in items]
        solved = [1 if i["solvable"] else 0 for i in items]
        mean_depth[domain]       = round(sum(depths) / len(depths), 3) if depths else 0.0
        mean_cred[domain]        = round(sum(creds)  / len(creds),  3) if creds  else 0.0
        solvability_rate[domain] = round(sum(solved)  / len(solved), 3) if solved else 0.0

    depth_values = list(mean_depth.values())
    return {
        "domains_evaluated":        len(by_domain),
        "mean_depth_per_domain":    mean_depth,
        "mean_cred_ratio_per_domain": mean_cred,
        "solvability_per_domain":   solvability_rate,
        "difficulty_gini":          round(_gini(depth_values), 3),
        "cv_mean_depth":            _cv(depth_values),
    }


# ---------------------------------------------------------------------------
# Thresholds + rejection logic (§3.2)
# ---------------------------------------------------------------------------

THRESHOLDS = {
    "min_solvable":         True,
    "min_cred_chain_ratio": 0.55,
    "min_discovery_ratio":  0.70,
    "min_goal_depth":       2,
    "min_mean_depth":       2.5,
    "max_goal_ratio":       0.15,
    "min_remote_goals":     1,
}


def _check_thresholds(r: dict) -> List[str]:
    """Returns list of violation strings; empty = passes all thresholds."""
    violations = []
    if not r["solvable"]:
        violations.append("solvable=False")
    if r["cred_chain_ratio"] < THRESHOLDS["min_cred_chain_ratio"]:
        violations.append(
            f"cred_chain_ratio={r['cred_chain_ratio']:.3f} < {THRESHOLDS['min_cred_chain_ratio']}"
        )
    if r["discovery_ratio"] < THRESHOLDS["min_discovery_ratio"]:
        violations.append(
            f"discovery_ratio={r['discovery_ratio']:.3f} < {THRESHOLDS['min_discovery_ratio']}"
        )
    if r["min_goal_depth"] < THRESHOLDS["min_goal_depth"] and r["num_goals"] > 0:
        violations.append(
            f"min_goal_depth={r['min_goal_depth']} < {THRESHOLDS['min_goal_depth']}"
        )
    if r["mean_goal_depth"] < THRESHOLDS["min_mean_depth"] and r["num_goals"] > 0:
        violations.append(
            f"mean_goal_depth={r['mean_goal_depth']:.2f} < {THRESHOLDS['min_mean_depth']}"
        )
    if r["goal_ratio"] > THRESHOLDS["max_goal_ratio"]:
        violations.append(
            f"goal_ratio={r['goal_ratio']:.4f} > {THRESHOLDS['max_goal_ratio']}"
        )
    if r["remote_exploitable_goals"] < THRESHOLDS["min_remote_goals"] and r["num_goals"] > 0:
        violations.append(
            f"remote_exploitable_goals={r['remote_exploitable_goals']} < {THRESHOLDS['min_remote_goals']}"
        )
    return violations


# ---------------------------------------------------------------------------
# Scanning helpers
# ---------------------------------------------------------------------------

def _discover_scenario_dirs(root: Path) -> List[Path]:
    """Recursively find all directories that contain a 'nodes/' subdirectory."""
    result = []
    for p in sorted(root.rglob("nodes")):
        if p.is_dir():
            result.append(p.parent)
    return result


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------

COLORS = {
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "red":    "\033[91m",
    "blue":   "\033[94m",
    "cyan":   "\033[96m",
    "end":    "\033[0m",
}


def _c(text: str, color: str) -> str:
    return f"{COLORS[color]}{text}{COLORS['end']}"


def _print_scenario_row(r: dict, violations: List[str]):
    name = Path(r["scenario"]).name[:40].ljust(40)
    solvable = _c("✓", "green") if r["solvable"] else _c("✗", "red")
    status = _c("PASS", "green") if not violations else _c("FAIL", "red")
    print(
        f"  {solvable} {name}  "
        f"nodes={r['num_nodes']:3d}  goals={r['num_goals']:2d}  "
        f"cred={r['cred_chain_ratio']:.2f}  disc={r['discovery_ratio']:.2f}  "
        f"depth={r['min_goal_depth']}/{r['mean_goal_depth']:.1f}  {status}"
    )
    for v in violations:
        print(f"       {_c('→', 'yellow')} {v}")
    ap = r.get("attack_path_metrics", {}).get("summary", {})
    if ap:
        rg   = ap.get("reachable_goals", "?")
        ng   = ap.get("num_goals", "?")
        hops = ap.get("avg_hops_to_goal", "?")
        prob = ap.get("avg_success_probability", "?")
        acts = ap.get("avg_actions_to_goal", "?")
        dom  = ap.get("dominant_action_type", "?")
        print(
            f"       {_c('↳', 'blue')} attack paths: "
            f"{rg}/{ng} goals reachable  "
            f"avg_hops={hops}  avg_actions={acts}  "
            f"avg_p_success={prob:.3f}  dominant={dom}"
            if isinstance(prob, float) else
            f"       {_c('↳', 'blue')} attack paths: {rg}/{ng} goals reachable"
        )
        # Elite BFS metrics line
        prf = ap.get("avg_path_redundancy_factor")
        vi  = ap.get("avg_visibility_index")
        cp  = ap.get("avg_choke_point_count")
        sm  = ap.get("avg_stealth_margin")
        gcps = len(ap.get("global_choke_points", []))
        elite_parts = []
        if prf is not None:
            elite_parts.append(f"PRF={prf:.1f}")
        if vi is not None:
            elite_parts.append(f"VI={vi:.3f}")
        if cp is not None:
            elite_parts.append(f"choke_pts={gcps}")
        if sm is not None:
            stealthy = ap.get("scenarios_stealthy", 0)
            total_g  = ap.get("reachable_goals", 1)
            elite_parts.append(f"stealth_margin={sm:.2f}({stealthy}/{total_g} stealthy)")
        if elite_parts:
            print(f"       {_c('↳', 'cyan')} elite: " + "  ".join(elite_parts))


def _print_fairness(fm: dict):
    print()
    print(_c("═" * 70, "blue"))
    print(_c(" CROSS-DOMAIN FAIRNESS METRICS (§3.3)", "blue"))
    print(_c("═" * 70, "blue"))
    print(f"  Domains evaluated : {fm['domains_evaluated']}")
    print(f"  Difficulty Gini   : {fm['difficulty_gini']:.3f}  (target < 0.15)")
    print(f"  CV mean depth     : {fm['cv_mean_depth']:.3f}  (target < 0.25)")
    print()
    print(f"  {'Domain':<35} {'Mean depth':>10} {'Cred ratio':>10} {'Solvable':>8}")
    print(f"  {'-'*35} {'-'*10} {'-'*10} {'-'*8}")
    for domain in sorted(fm["mean_depth_per_domain"]):
        depth  = fm["mean_depth_per_domain"][domain]
        cred   = fm["mean_cred_ratio_per_domain"][domain]
        srate  = fm["solvability_per_domain"][domain]
        color = "green" if srate >= 0.99 else ("yellow" if srate >= 0.90 else "red")
        print(
            f"  {domain:<35} {depth:>10.2f} {cred:>10.3f} "
            f"{_c(f'{srate:.1%}', color):>8}"
        )
    gini_color = "green" if fm["difficulty_gini"] < 0.15 else ("yellow" if fm["difficulty_gini"] < 0.25 else "red")
    gini_val = f"{fm['difficulty_gini']:.3f}"
    print(f"\n  Gini verdict: {_c(gini_val, gini_color)}", end="")
    if fm["difficulty_gini"] < 0.15:
        print(_c("  ✓ Balanced (publishable)", "green"))
    elif fm["difficulty_gini"] < 0.25:
        print(_c("  ⚠ Borderline", "yellow"))
    else:
        print(_c("  ✗ Unbalanced — some domain dominates", "red"))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate structural quality of generated CyberBattleSim scenarios (§3.1 + §3.3 + §3.4)"
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--scenario", metavar="DIR",
                     help="Evaluate a single scenario directory")
    src.add_argument("--data-dir", metavar="DIR",
                     help="Evaluate all scenarios under this directory tree")
    parser.add_argument("--out", metavar="FILE",
                        help="Write full results JSON to this file")
    parser.add_argument("--reject-only", action="store_true",
                        help="Only print scenarios that fail thresholds")
    parser.add_argument("--no-fairness", action="store_true",
                        help="Skip fairness / Gini report (faster for single domain)")
    parser.add_argument("--no-attack-paths", action="store_true",
                        help="Skip §3.4 attack path annotation (faster for large datasets)")
    parser.add_argument("--detection-threshold", type=float, default=None,
                        metavar="FLOAT",
                        help="Override default stealth detection threshold (default: 10.0)")
    args = parser.parse_args()

    if args.detection_threshold is not None:
        global _STEALTH_DETECTION_THRESHOLD
        _STEALTH_DETECTION_THRESHOLD = args.detection_threshold

    # Collect scenario directories
    if args.scenario:
        dirs = [Path(args.scenario)]
    else:
        root = Path(args.data_dir)
        if not root.is_dir():
            print(f"Error: {root} is not a directory", file=sys.stderr)
            sys.exit(1)
        # Check if the root itself is a scenario dir
        if (root / "nodes").is_dir():
            dirs = [root]
        else:
            dirs = _discover_scenario_dirs(root)

    if not dirs:
        print("No scenario directories found.", file=sys.stderr)
        sys.exit(1)

    print(_c(f"\nEvaluating {len(dirs)} scenario(s)...\n", "blue"))

    include_attack_paths = not args.no_attack_paths

    all_results = []
    total_pass = 0
    total_fail = 0
    total_skip = 0

    for d in dirs:
        r = evaluate_scenario(d, include_attack_paths=include_attack_paths)
        if r is None:
            total_skip += 1
            continue

        violations = _check_thresholds(r)
        r["violations"] = violations
        r["passes"] = len(violations) == 0
        all_results.append(r)

        if violations:
            total_fail += 1
        else:
            total_pass += 1

        if not args.reject_only or violations:
            _print_scenario_row(r, violations)

    # Summary line
    print()
    print(_c("─" * 70, "blue"))
    print(
        f"  Total: {len(all_results)} evaluated  |  "
        f"{_c(str(total_pass) + ' PASS', 'green')}  |  "
        f"{_c(str(total_fail) + ' FAIL', 'red' if total_fail else 'green')}  |  "
        f"{total_skip} skipped"
    )

    # Fairness report
    if not args.no_fairness and len(all_results) > 1:
        fm = compute_fairness_metrics(all_results)
        _print_fairness(fm)
        if args.out:
            for r in all_results:
                r["fairness"] = fm   # attach to first record for JSON output
    elif len(all_results) > 1 and not args.no_fairness:
        fm = compute_fairness_metrics(all_results)

    # JSON output
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "scenarios": all_results,
        }
        if not args.no_fairness and len(all_results) > 1:
            payload["fairness"] = fm
        with open(out_path, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"\n  {_c('→', 'blue')} Report written to {out_path}")

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
