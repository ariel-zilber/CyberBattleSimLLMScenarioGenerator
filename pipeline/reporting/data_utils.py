import json
import re
import shutil
import yaml
from pathlib import Path

OUTCOME_KEYS = [
    "LeakedCredentials", "LeakedNodesId", "LateralMove",
    "PrivilegeEscalation", "AdminEscalation", "SystemEscalation",
    "ProbeSucceeded", "ExploitFailed",
]

OUTCOME_SHORT = {
    "LeakedCredentials":   "CredLeak",
    "LeakedNodesId":       "NodeDisc",
    "LateralMove":         "Lateral",
    "PrivilegeEscalation": "PrivEsc",
    "AdminEscalation":     "AdminEsc",
    "SystemEscalation":    "SysEsc",
    "ProbeSucceeded":      "ProbeOK",
    "ExploitFailed":       "ExploitFail",
}

OUTCOME_COLORS = {
    "LeakedCredentials":   "#e74c3c",
    "LeakedNodesId":       "#3498db",
    "LateralMove":         "#2ecc71",
    "PrivilegeEscalation": "#9b59b6",
    "AdminEscalation":     "#8e44ad",
    "SystemEscalation":    "#6c3483",
    "ProbeSucceeded":      "#f39c12",
    "ExploitFailed":       "#95a5a6",
}


def find_config(scenario_dir: Path, configs_roots: list) -> "Path | None":
    name = scenario_dir.name
    base = re.sub(r"_v\d+$", "", name)
    for root in configs_roots:
        for stem in (name, base, f"{base}_v1"):
            for ext in (".yaml", ".yml"):
                c = root / (stem + ext)
                if c.exists():
                    return c
    return None


def collect_run_metrics(scenario_dir: Path) -> list:
    return [json.loads(p.read_text()) for p in sorted(scenario_dir.rglob("run_metrics.json"))]


def aggregate_metrics(metrics: list) -> dict:
    if not metrics:
        return {}
    solved = [m for m in metrics if m.get("is_solved")]
    n = len(metrics)
    def _t(m, k): return m.get("topology_metrics", {}).get("routing", {}).get(k, 0)

    # Aggregate action outcomes
    outcome_totals: dict = {k: 0 for k in OUTCOME_KEYS}
    for m in metrics:
        for k in OUTCOME_KEYS:
            outcome_totals[k] += m.get("action_outcomes", {}).get(k, 0)

    # Tree-likeness: for a tree density approx 1/n; fully connected density = 1
    # tree_ratio > 1 means denser than a tree -> more mesh-like
    avg_nodes = sum(_t(m, "node_count") for m in metrics) / n
    avg_density = sum(_t(m, "density") for m in metrics) / n
    tree_ratio = round(avg_density * max(avg_nodes, 2), 2)  # > 2 = mesh-like

    return {
        "total":           n,
        "solved":          len(solved),
        "solve_rate":      round(len(solved) / n, 3),
        "mean_steps":      round(sum(m.get("steps_taken", 0) for m in solved) / max(len(solved), 1)),
        "mean_reward":     round(sum(m.get("total_reward",  0) for m in metrics) / n, 1),
        "mean_nodes":      round(sum(m.get("nodes_owned",   0) for m in metrics) / n, 1),
        "mean_creds":      round(sum(m.get("credentials_discovered", 0) for m in metrics) / n, 1),
        "mean_density":    round(avg_density, 4),
        "mean_diameter":   round(sum(_t(m, "diameter")   for m in metrics) / n, 1),
        "mean_node_count": round(avg_nodes, 1),
        "tree_ratio":      tree_ratio,
        "outcome_totals":  outcome_totals,
    }


def merge_progression(raw_lines: list) -> list:
    """Join wrapped continuation lines and strip leading step numbers/labels."""
    step_re = re.compile(r"^\d+[\.\)]\s+")          # "1. " or "1) "
    label_re = re.compile(r"^\w[\w\s]{0,15}:\s+")   # "Entry:   " / "Harvest: "
    steps, current = [], None
    for line in raw_lines:
        if step_re.match(line):
            if current is not None:
                steps.append(current)
            # strip number prefix, then optional label prefix
            text = step_re.sub("", line).strip()
            text = label_re.sub("", text).strip()
            current = text
        else:
            if current is not None:
                current = current + " " + line.strip()
    if current:
        steps.append(current)
    return steps if steps else raw_lines


def extract_yaml_description(config_path: Path) -> dict:
    lines   = config_path.read_text(encoding="utf-8").splitlines()
    result  = {"overview": "", "progression": [], "name": config_path.stem}
    section = None
    buf: list = []
    for line in lines:
        stripped = line.strip().lstrip("#").strip()
        if "SCENARIO OVERVIEW" in line:
            section = "overview";     buf = []; continue
        if "ATTACKER PROGRESSION" in line:
            if section == "overview":
                result["overview"] = " ".join(buf).strip()
            section = "progression";  buf = []; continue
        if "DESIGN DECISIONS" in line or "NETWORK ARCHITECTURE" in line \
                or "FIREWALL RULES" in line \
                or (line.startswith("config:") and section):
            if section == "overview":
                result["overview"] = " ".join(buf).strip()
            elif section == "progression":
                result["progression"] = merge_progression([l for l in buf if l])
            section = None
            if line.startswith("config:"):
                break
            continue
        if section and stripped and not stripped.startswith("="):
            buf.append(stripped)
    if section == "progression" and buf:
        result["progression"] = merge_progression([l for l in buf if l])
    if not result["overview"]:
        for line in lines[:10]:
            s = line.strip().lstrip("#").strip()
            if s and not s.startswith("=") and len(s) > 20:
                result["overview"] = s;  break
    return result


def extract_diversity_metrics(config_path: Path) -> dict:
    try:
        cfg = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    groups, n_connect, n_leak = [], 0, 0
    n_domains = len(cfg.get("domains", []))
    for domain in cfg.get("domains", []):
        groups += domain.get("groups", [])
        for c in domain.get("constraints", []):
            rel = c.get("relation", "").upper()
            if rel in ("MUST_CONNECT", "MUST_REACH", "CLIENT_OF"):  n_connect += 1
            if rel in ("LEAK_KNOWN_CREDENTIALS", "CLIENT_OF"):       n_leak    += 1
    for idc in cfg.get("inter_domain_constraints", []):
        for c in idc.get("constraints", []):
            rel = c.get("relation", "").upper()
            if rel in ("MUST_CONNECT", "MUST_REACH", "CLIENT_OF"):  n_connect += 1
            if rel in ("LEAK_KNOWN_CREDENTIALS", "CLIENT_OF"):       n_leak    += 1
    services = cfg.get("services", {})
    os_types, roles = set(), set()
    for svc in services.values():
        for p in svc.get("default_properties", []):
            if p in {"Windows", "Linux", "MacOS"}:              os_types.add(p)
            if p in {"Workstation", "FileServer", "AppServer",
                     "DomainController", "WebServer", "DatabaseServer",
                     "LegacyWorkstation", "ModernWorkstation"}:  roles.add(p)
    return {
        "n_service_types": len(services),
        "n_groups":        len(groups),
        "n_domains":       n_domains,
        "n_must_connect":  n_connect,
        "n_cred_paths":    n_leak,
        "os_types":        sorted(os_types),
        "node_roles":      sorted(roles),
        "goal_services":   [n for n, s in services.items() if s.get("is_goal")],
        "group_summary":   [{"name": g.get("name","?"), "service": g.get("service","?"),
                             "min": g.get("min_count",0), "max": g.get("max_count",0)}
                            for g in groups],
        "heterogeneous_os": len(os_types) > 1,
    }


def find_topology_png(scenario_dir: Path) -> "Path | None":
    # Prefer subnet_topology.png from the first available scenario instance
    for split in ("train", "test"):
        for pat in ("graphs/subnet_topology.png", "graphs/compact_subnet_topology.png"):
            for p in sorted((scenario_dir / split).rglob(pat)):
                if p.exists() and p.stat().st_size > 0:
                    return p
    # Fallback: any non-empty PNG in scenario_graphs/
    sg = scenario_dir / "scenario_graphs"
    if sg.is_dir():
        pngs = [p for p in sorted(sg.glob("*.png")) if p.stat().st_size > 0]
        if pngs:
            return pngs[0]
    return None


def find_scenario_graph_pngs(scenario_dir: Path) -> dict:
    """Return {key: Path} for attack_paths, network_graph, compact_subnet, subnet_topology
    from the first available scenario instance directory."""
    wanted = [
        ("attack_paths.png",            "attack_paths"),
        ("network_graph.png",           "network_graph"),
        ("compact_subnet_topology.png", "compact_subnet"),
        ("subnet_topology.png",         "subnet_topology"),
    ]
    result: dict = {}
    for split in ("train", "test"):
        split_dir = scenario_dir / split
        if not split_dir.is_dir():
            continue
        # Walk into strata dirs then instance dirs
        for graphs_dir in sorted(split_dir.rglob("graphs")):
            for fname, key in wanted:
                if key in result:
                    continue
                p = graphs_dir / fname
                if p.exists() and p.stat().st_size > 0:
                    result[key] = p
        if result:
            break
    return result


def copy_png_capped(src: Path, dst: Path, max_width: int = 2400) -> None:
    """Copy src PNG to dst, downscaling width to max_width if larger.

    Also caps height so the rendered size (at 72 DPI) stays under pdflatex's
    16383pt hard limit — images wider than ~16383px at 72 DPI cause a fatal
    'Dimension too large' error.
    """
    try:
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = None  # allow large images; we resize them
        img = Image.open(src)
        # pdflatex limit: 16383pt at 72 DPI ≈ 16383px; cap conservatively at 8000px
        pdf_limit = 8000
        target_w = min(max_width, pdf_limit)
        if img.width > target_w:
            ratio    = target_w / img.width
            new_size = (target_w, max(1, int(img.height * ratio)))
            img      = img.resize(new_size, Image.LANCZOS)
            img.save(dst, dpi=(72, 72))
        else:
            shutil.copy(src, dst)
    except Exception:
        shutil.copy(src, dst)


def collect_scenario_stats(scenario_dir: Path) -> dict:
    """Aggregate run_metrics.json across all strata and splits."""
    import statistics as _stats_mod

    node_counts, edge_counts, densities, diameter_vals = [], [], [], []
    avg_degree_vals, max_degree_vals = [], []
    vuln_inst, prop_inst = [], []
    unique_vulns_counts, unique_props_counts = [], []
    vuln_per_node: list = []
    strata_counts: dict = {}
    all_prop_counts: dict = {}

    for jf in scenario_dir.rglob("run_metrics.json"):
        try:
            data = json.loads(jf.read_text())
        except Exception:
            continue
        topo    = data.get("topology_metrics", {})
        routing = topo.get("routing", {})
        payloads = topo.get("payloads", {})

        # strata from path (e.g. .../train/small/...)
        parts = jf.parts
        for p in parts:
            if p in ("small", "medium", "large"):
                strata_counts[p] = strata_counts.get(p, 0) + 1
                break

        nc = routing.get("node_count")
        if nc is not None:
            node_counts.append(nc)
        ec = routing.get("edge_count")
        if ec is not None:
            edge_counts.append(ec)
        d = routing.get("density")
        if d is not None:
            densities.append(d)
        diam = routing.get("diameter")
        if diam is not None:
            diameter_vals.append(diam)
        avg_deg = routing.get("avg_in_degree")
        if avg_deg is not None:
            avg_degree_vals.append(avg_deg)
        max_deg = routing.get("max_in_degree")
        if max_deg is not None:
            max_degree_vals.append(max_deg)
        vi = payloads.get("total_vulnerability_instances")
        if vi is not None:
            vuln_inst.append(vi)
            if nc and nc > 0:
                vuln_per_node.append(round(vi / nc, 3))
        pi = payloads.get("total_property_instances")
        if pi is not None:
            prop_inst.append(pi)
        uv = payloads.get("unique_vulnerabilities")
        unique_vulns_counts.append(uv if isinstance(uv, int) else len(uv) if isinstance(uv, list) else 0)
        pc = payloads.get("property_counts", {})
        unique_props_counts.append(len(pc))
        for p_name, cnt in pc.items():
            all_prop_counts[p_name] = all_prop_counts.get(p_name, 0) + cnt

    def _stat(vals):
        if not vals:
            return {"min": "---", "max": "---", "mean": "---", "stdev": "---", "median": "---", "raw": []}
        raw_floats = [float(v) for v in vals]
        return {
            "min":    round(min(raw_floats), 2),
            "max":    round(max(raw_floats), 2),
            "mean":   round(_stats_mod.mean(raw_floats), 2),
            "stdev":  round(_stats_mod.stdev(raw_floats), 2) if len(raw_floats) > 1 else 0.0,
            "median": round(_stats_mod.median(raw_floats), 2),
            "raw":    raw_floats,
        }

    top_props = sorted(all_prop_counts.items(), key=lambda x: -x[1])[:8]

    return {
        "n_samples":      len(node_counts),
        "nodes":          _stat(node_counts),
        "edges":          _stat(edge_counts),
        "density":        _stat(densities),
        "diameter":       _stat(diameter_vals),
        "avg_degree":     _stat(avg_degree_vals),
        "max_degree":     _stat(max_degree_vals),
        "vuln_inst":      _stat(vuln_inst),
        "prop_inst":      _stat(prop_inst),
        "unique_vulns":   _stat(unique_vulns_counts),
        "unique_props":   _stat(unique_props_counts),
        "vuln_per_node":  _stat(vuln_per_node),
        "strata":         strata_counts,
        "top_props":      top_props,
    }


def collect_attack_path_stats(scenario_dir: Path) -> dict:
    """
    Run scenario_evaluator.evaluate_scenario on every generated scenario instance
    under scenario_dir and aggregate the attack_path_metrics into per-config statistics.
    Only the first MAX_AP_INSTANCES instances are evaluated (to keep runtime reasonable).
    """
    import statistics as _st_mod

    # Lazy import so the main module doesn't fail if scenario_evaluator is absent
    try:
        from scenario_evaluator import evaluate_scenario as _eval_scen
    except ImportError:
        return {}

    MAX_AP_INSTANCES = 30   # cap: evaluate up to this many instances per config

    hops_vals:    list = []
    acts_vals:    list = []
    probs_vals:   list = []
    own_vals:     list = []
    cost_vals:    list = []
    # Elite metrics
    redundancy_vals: list = []
    visibility_vals: list = []
    chokepoint_vals: list = []
    stealth_vals:    list = []

    global_types: dict = {}
    global_outs:  dict = {}
    global_choke_nodes: set = set()
    global_choke_types: dict = {}  # group_name -> total_count_across_instances
    per_goal_examples: list = []
    n_samples          = 0
    n_reach_goals      = 0
    n_total_goals      = 0
    n_stealthy_instances = 0

    for nodes_dir in sorted(scenario_dir.rglob("nodes")):
        if not nodes_dir.is_dir():
            continue
        if n_samples >= MAX_AP_INSTANCES:
            break
        inst_dir = nodes_dir.parent
        try:
            result = _eval_scen(inst_dir, include_attack_paths=True)
        except Exception:
            continue
        if not result:
            continue

        apm = result.get("attack_path_metrics", {})
        if not apm:
            continue

        n_samples     += 1
        summary        = apm.get("summary", {})
        n_total_goals  += summary.get("num_goals", 0)
        n_reach_goals  += summary.get("reachable_goals", 0)

        v = summary.get("avg_hops_to_goal")
        if v is not None:
            hops_vals.append(float(v))
        v = summary.get("avg_actions_to_goal")
        if v is not None:
            acts_vals.append(float(v))
        v = summary.get("avg_success_probability")
        if v is not None:
            probs_vals.append(float(v))
        v = summary.get("avg_min_nodes_to_own")
        if v is not None:
            own_vals.append(float(v))
        v = summary.get("avg_total_cost")
        if v is not None:
            cost_vals.append(float(v))

        # Elite metrics extraction
        v = summary.get("avg_path_redundancy_factor")
        if v is not None:
            redundancy_vals.append(float(v))
        v = summary.get("avg_visibility_index")
        if v is not None:
            visibility_vals.append(float(v))
        v = summary.get("avg_choke_point_count")
        if v is not None:
            chokepoint_vals.append(float(v))
        v = summary.get("avg_stealth_margin")
        if v is not None:
            stealth_vals.append(float(v))

        n_stealthy_instances += summary.get("scenarios_stealthy", 0)
        choke_nodes = summary.get("global_choke_points", [])
        global_choke_nodes.update(choke_nodes)

        # Aggregate choke point types by extracting group name from node ID (group_name_idx)
        for nid in choke_nodes:
            match = re.match(r'^(.+)_(\d+)$', nid)
            group_name = match.group(1) if match else nid
            global_choke_types[group_name] = global_choke_types.get(group_name, 0) + 1

        for k, cnt in summary.get("global_action_type_counts", {}).items():
            global_types[k] = global_types.get(k, 0) + cnt
        for k, cnt in summary.get("global_action_outcomes", {}).items():
            global_outs[k] = global_outs.get(k, 0) + cnt

        # Collect one representative set of per-goal examples
        if n_samples == 1:
            for gid, gm in list(apm.get("per_goal", {}).items())[:4]:
                if gm.get("reachable"):
                    per_goal_examples.append({"goal": gid, **gm})

    def _stat(vals):
        if not vals:
            return {"mean": None, "min": None, "max": None, "stdev": None}
        return {
            "mean":  round(sum(vals) / len(vals), 3),
            "min":   round(min(vals), 3),
            "max":   round(max(vals), 3),
            "stdev": round(_st_mod.stdev(vals), 3) if len(vals) > 1 else 0.0,
        }

    total_acts = sum(global_types.values()) or 1
    total_outs = sum(global_outs.values())  or 1
    action_dist  = {k: round(v / total_acts, 3) for k, v in sorted(global_types.items())}
    outcome_dist = {k: round(v / total_outs, 3) for k, v in sorted(global_outs.items())}
    dominant     = max(global_types, key=global_types.get) if global_types else "---"

    return {
        "n_samples":            n_samples,
        "reachable_ratio":      round(n_reach_goals / max(n_total_goals, 1), 3),
        "avg_hops":             _stat(hops_vals),
        "avg_actions":          _stat(acts_vals),
        "avg_success_prob":     _stat(probs_vals),
        "avg_min_nodes_to_own": _stat(own_vals),
        "avg_cost":             _stat(cost_vals),
        "avg_path_redundancy":  _stat(redundancy_vals),
        "avg_visibility":       _stat(visibility_vals),
        "avg_chokepoints":      _stat(chokepoint_vals),
        "avg_stealth":          _stat(stealth_vals),
        "stealthy_count":       n_stealthy_instances,
        "global_choke_points":  sorted(list(global_choke_nodes)),
        "choke_type_distribution": global_choke_types,
        "action_type_dist":     action_dist,
        "outcome_dist":         outcome_dist,
        "dominant_action_type": dominant,
        "per_goal_examples":    per_goal_examples,
    }


def stats_table(stats: dict) -> str:
    """Generate a LaTeX tabular block with graph statistics."""
    from .latex_base import e as _e

    if not stats or stats.get("n_samples", 0) == 0:
        return ""

    n      = stats["n_samples"]
    strata = stats["strata"]
    strata_str = ", ".join(
        f"{k}: {v}" for k, v in sorted(strata.items(),
                                        key=lambda x: ("small","medium","large").index(x[0])
                                        if x[0] in ("small","medium","large") else 99)
    ) or "---"

    def _row(label, s, fmt="{}", unit=""):
        if s.get("min") == "---":
            return rf"\small {_e(label)} & --- & --- & --- & --- & --- {_e(unit)} \\"
        mn  = fmt.format(s["min"])
        mx  = fmt.format(s["max"])
        avg = fmt.format(s["mean"])
        sd  = fmt.format(s["stdev"])
        med = fmt.format(s["median"])
        return rf"\small {_e(label)} & {mn} & {mx} & {avg} & {sd} & {med} {_e(unit)} \\"

    rows = "\n".join([
        _row("Node count",        stats["nodes"],        "{}"),
        _row("Edge count",        stats["edges"],        "{}"),
        _row("Graph density",     stats["density"],      "{:.3f}"),
        _row("Diameter",          stats["diameter"],     "{}"),
        _row("Avg degree",        stats["avg_degree"],   "{:.1f}"),
        _row("Max degree",        stats["max_degree"],   "{}"),
        _row("Vuln instances",    stats["vuln_inst"],    "{}"),
        _row("Prop instances",    stats["prop_inst"],    "{}"),
        _row("Unique vulns",      stats["unique_vulns"], "{}"),
        _row("Unique properties", stats["unique_props"], "{}"),
        _row("Vulns per node",    stats["vuln_per_node"],"  {:.2f}"),
    ])

    # Top properties sidebar
    top = list(stats["top_props"][:6])
    while len(top) < 6:
        top.append(("", ""))
    top_rows = "\n".join(
        (rf"\small {_e(p)} & \small {c} \\" if p else r" & \\")
        for p, c in top
    )

    return rf"""\smallskip
\noindent\textbf{{Graph Statistics}} ({n} scenarios, strata: {_e(strata_str)})\par\smallskip
\noindent
{{\setlength{{\tabcolsep}}{{4pt}}
\begin{{tabular}}{{lrrrrr@{{\hspace{{1.2cm}}}}lr}}
\toprule
\textbf{{Metric}} & \textbf{{Min}} & \textbf{{Max}} & \textbf{{Mean}} & \textbf{{SD}} & \textbf{{Median}} &
\textbf{{Top Property}} & \textbf{{N}} \\
\midrule
{rows}
\cmidrule{{7-8}}
 & & & & & & {top_rows}
\bottomrule
\end{{tabular}}
}}
"""
