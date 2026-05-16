#!/usr/bin/env python3
"""
tools/phase2_human_report.py
=============================
Generate a human-readable Phase 2 report: EDA plots (saved as PNG) and a
plain-text summary. Intended for human readers — NOT fed into LLM context.

All figures are saved to:
    <out-dir>/figures/<plot_name>.png

A summary text is saved to:
    <out-dir>/human_report.txt

Usage
-----
python3 tools/phase2_human_report.py \\
    --scenarios-dir phase2_output/enterprise_ad_3tier_v1 \\
    --out-dir phase2_output/enterprise_ad_3tier_v1/human_report

python3 tools/phase2_human_report.py \\
    --scenarios-dir phase2_output/enterprise_ad_3tier_v1 \\
    --out-dir phase2_output/enterprise_ad_3tier_v1/human_report \\
    --split train   # only analyse train/ sub-tree
"""

import argparse
import json
import sys
import textwrap
from datetime import datetime
from pathlib import Path

import yaml
import networkx as nx

# Use non-interactive Agg backend BEFORE importing anything that touches pyplot
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.patches as mpatches

# Setup path
TOOLS_DIR    = Path(__file__).resolve().parent        # pipeline/reporting/
REPO_ROOT    = TOOLS_DIR.parent.parent                # project root

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline.reporting.analysis.domain_analysis import DomainAnalysis  # noqa: E402
import pipeline.reporting.analysis.cbs_eda_graphs as _graphs            # noqa: E402
import pipeline.reporting.cve_scenario_graphs as _cve_graphs   # noqa: E402


# ── Patch _save_or_show so every plot_* call saves a PNG instead of showing ──

_FIGURES_DIR: Path = Path(".")  # set before calling any plot_* function

def _save_to_file(fig, name="plot"):
    _FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out = _FIGURES_DIR / f"{name}.png"
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return out

_graphs._save_or_show = _save_to_file


# ── Plot suites: (file_key, section_title, fn) ───────────────────────────────
# Single-analyzer plots — called as fn(analyzer)
_PLOT_SUITES = [
    ("node_graphs",          "Node Analysis",          _graphs.plot_node_graphs),
    ("scenario_graphs",      "Scenario Overview",      _graphs.plot_scenario_graphs),
    ("security_graphs",      "Security Analysis",      _graphs.plot_security_graphs),
    ("properties_graphs",    "Properties Analysis",    _graphs.plot_properties_graphs),
    ("services_graphs",      "Services Analysis",      _graphs.plot_services_graphs),
    ("vuln_rates_graphs",    "Vulnerability Rates",    _graphs.plot_vuln_rates_graphs),
    ("firewall_graphs",      "Firewall Analysis",      _graphs.plot_firewall_graphs),
    ("complexity_dashboard", "Complexity Dashboard",   _graphs.plot_complexity_dashboard),
    ("data_quality",         "Data Quality",           _graphs.plot_data_quality),
    ("diversity",            "Diversity Analysis",     _graphs.plot_diversity),
    ("class_balance",        "Class Balance",          _graphs.plot_class_balance),
    ("attack_surface",       "Attack Surface",         _graphs.plot_attack_surface_detail),
    ("reward_signal",        "Reward Signal",          _graphs.plot_reward_signal),
]

# Multi-analyzer plots — called as fn([analyzer, ...]) or fn([...], global_ids)
_MULTI_PLOT_SUITES = [
    ("cross_domain",          "Cross-Domain Comparison",           _graphs.plot_cross_domain,          False),
    ("statistical_comparison","Statistical Comparison",            _graphs.plot_statistical_comparison, False),
    ("cross_domain_coverage", "Cross-Domain Identifier Coverage",  _graphs.plot_cross_domain_coverage,  True),
]


# ── Per-scenario network topology graph ──────────────────────────────────────

# Property → node colour mapping (order matters: first match wins)
_PROP_COLORS = [
    ("breach_node",      "#10b981"),  # green  – start node
    ("DomainController", "#6a0dad"),  # purple
    ("DatabaseServer",   "#8B4513"),  # brown
    ("FileServer",       "#e67e22"),  # orange
    ("WebServer",        "#0097a7"),  # teal
    ("Workstation",      "#90caf9"),  # light-blue
]
_DEFAULT_NODE_COLOR = "#aaaaaa"

_EDGE_COLORS = {
    "credential_leak": "#e65100",
    "discovery":       "#1565c0",
}


def _node_color(properties: list) -> str:
    for prop, color in _PROP_COLORS:
        if prop in properties:
            return color
    return _DEFAULT_NODE_COLOR


def _short_label(name: str) -> str:
    """Return a readable short label: last two underscore-separated tokens."""
    parts = name.split("_")
    return "_".join(parts[-2:]) if len(parts) >= 2 else name


def _generate_scenario_graph(scenario_dir: Path, out_path: Path) -> "Path | None":
    """Build and save a network topology PNG for one scenario."""
    nodes_dir = scenario_dir / "nodes"
    if not nodes_dir.is_dir():
        return None

    G = nx.DiGraph()
    meta: dict = {}  # node_name -> {color, is_goal, subnet, label}

    for yf in sorted(nodes_dir.glob("*.yaml")):
        node_name = yf.stem
        try:
            data = yaml.safe_load(yf.read_text())
        except Exception:
            continue

        props     = data.get("properties") or []
        is_goal   = bool(data.get("is_goal", False))
        net_info  = data.get("network_info") or []
        subnet    = net_info[0]["subnet"]["network"] if net_info else "unknown"

        meta[node_name] = {
            "color":   _node_color(props),
            "is_goal": is_goal,
            "subnet":  subnet,
            "label":   _short_label(node_name),
        }
        G.add_node(node_name, **meta[node_name])

        # Edges: credential leaks → lateral movement paths
        for vuln_data in (data.get("vulnerabilities") or {}).values():
            outcome = vuln_data.get("outcome") or {}
            otype   = outcome.get("type", "")
            kwargs  = outcome.get("kwargs") or {}
            if otype == "leaked_credentials":
                for cred in kwargs.get("credentials") or []:
                    target = (cred.get("kwargs") or {}).get("node")
                    if target and target != node_name:
                        G.add_edge(node_name, target, etype="credential_leak")
            elif otype == "leaked_nodes_id":
                for target in kwargs.get("nodes") or []:
                    if target and target != node_name:
                        G.add_edge(node_name, target, etype="discovery")

    if not G.nodes:
        return None

    # ── Layout: group nodes by subnet, arrange groups in rows ────────────────
    subnet_groups: dict = {}
    for n, d in G.nodes(data=True):
        subnet_groups.setdefault(d["subnet"], []).append(n)

    pos: dict = {}
    subnets = sorted(subnet_groups)
    row_gap  = 3.0
    col_gap  = 1.8
    for row_idx, subnet in enumerate(subnets):
        nodes_in_group = subnet_groups[subnet]
        n_cols = max(1, len(nodes_in_group))
        for col_idx, node in enumerate(nodes_in_group):
            x = col_idx * col_gap - (n_cols - 1) * col_gap / 2
            y = -row_idx * row_gap
            pos[node] = (x, y)

    # ── Draw ─────────────────────────────────────────────────────────────────
    fig_w  = max(12, len(G.nodes) * 0.45)
    fig_h  = max(6, len(subnet_groups) * row_gap * 0.9)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h), facecolor="#1a1a2e")
    ax.set_facecolor("#1a1a2e")
    ax.axis("off")

    node_colors  = [G.nodes[n]["color"] for n in G.nodes]
    node_sizes   = [600 if G.nodes[n]["is_goal"] else 200 for n in G.nodes]
    node_labels  = {n: G.nodes[n]["label"] for n in G.nodes}
    edge_colors  = [_EDGE_COLORS.get(G.edges[e].get("etype", ""), "#888888") for e in G.edges]

    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors,
                           node_size=node_sizes, alpha=0.92)
    nx.draw_networkx_labels(G, pos, labels=node_labels, ax=ax,
                            font_size=5, font_color="white")
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color=edge_colors,
                           arrows=True, arrowsize=10, width=0.8,
                           connectionstyle="arc3,rad=0.1", alpha=0.75)

    # Subnet labels on the left margin
    for row_idx, subnet in enumerate(subnets):
        y = -row_idx * row_gap
        ax.text(-fig_w * 0.52, y, subnet, color="#aaaaaa",
                fontsize=6, va="center", ha="right")

    # Legend
    legend_items = [
        mpatches.Patch(color=c, label=p) for p, c in _PROP_COLORS
    ] + [
        mpatches.Patch(color=_EDGE_COLORS["credential_leak"], label="Credential leak"),
        mpatches.Patch(color=_EDGE_COLORS["discovery"],       label="Discovery"),
    ]
    ax.legend(handles=legend_items, loc="upper right",
              fontsize=6, framealpha=0.3, facecolor="#333355",
              labelcolor="white", edgecolor="#555577")

    # Metrics strip
    run_mf = scenario_dir / "run_metrics.json"
    if run_mf.exists():
        try:
            rm = json.loads(run_mf.read_text())
            solved = "✓ SOLVED" if rm.get("is_solved") else "✗ UNSOLVED"
            strip  = (f"{solved}  |  steps={rm.get('steps_taken','?')}"
                      f"  |  reward={rm.get('total_reward','?')}"
                      f"  |  goals={rm.get('goals_captured','?')}")
            fig.text(0.5, 0.01, strip, ha="center", fontsize=7,
                     color="#cccccc", style="italic")
        except Exception:
            pass

    ax.set_title(scenario_dir.name, color="white", fontsize=9, pad=8)
    plt.tight_layout(rect=[0, 0.03, 1, 1])

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=130, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return out_path


def _generate_all_scenario_graphs(scenario_dirs: list, graphs_dir: Path) -> list:
    """Generate a topology PNG for every scenario; return list of saved paths."""
    graphs_dir.mkdir(parents=True, exist_ok=True)
    saved = []
    for sd in scenario_dirs:
        out = graphs_dir / f"{sd.name}.png"
        result = _generate_scenario_graph(sd, out)
        if result:
            print(f"  Scenario graph: {out.name}")
            saved.append(result)
        else:
            print(f"  [WARN] Could not generate graph for {sd.name}")
    return saved


# ── SVG graph generation via generate_scenario_graph.py ─────────────────────

_SVG_NAMES = {
    "network_graph.svg":          "Network Architecture",
    "attack_paths.svg":           "Attack Paths",
    "subnet_topology.svg":        "Subnet Topology",
    "compact_subnet_topology.svg":"Compact Subnet Topology",
}


def _svg_to_png(svg_path: Path, png_path: Path) -> "Path | None":
    try:
        import cairosvg
        # Try progressively smaller scales until it renders within cairo's size limit
        for scale in (1.5, 1.0, 0.75, 0.5):
            try:
                cairosvg.svg2png(url=str(svg_path), write_to=str(png_path), scale=scale)
                return png_path
            except Exception:
                continue
        print(f"  [WARN] SVG→PNG failed for {svg_path.name}: all scales exceeded cairo limit")
        return None
    except ImportError:
        print(f"  [WARN] cairosvg not available — skipping {svg_path.name}")
        return None


def _generate_svg_graphs_for_scenario(scenario_dir: Path) -> "list[tuple[str,Path]]":
    """Run process_scenario(), convert SVGs to PNG, return (title, png_path) list."""
    try:
        from pipeline.reporting.scenario_graph import process_scenario
    except ImportError as exc:
        print(f"  [WARN] generate_scenario_graph not importable: {exc}")
        return []

    try:
        svg_paths = process_scenario(scenario_dir)
    except Exception as exc:
        print(f"  [WARN] process_scenario failed for {scenario_dir.name}: {exc}")
        return []

    result = []
    for svg_path in svg_paths:
        if not isinstance(svg_path, Path) or not svg_path.exists():
            continue
        title = _SVG_NAMES.get(svg_path.name, svg_path.stem.replace("_", " ").title())
        png_path = svg_path.with_suffix(".png")
        converted = _svg_to_png(svg_path, png_path)
        if converted:
            result.append((title, converted))
    return result


def _find_scenario_dirs(root: Path):
    """Walk root and return all dirs that contain a nodes/ subdir."""
    return sorted(p.parent for p in root.rglob("nodes") if p.is_dir())


def _load_run_metrics(scenario_dirs):
    metrics = []
    for sd in scenario_dirs:
        mf = sd / "run_metrics.json"
        if mf.exists():
            try:
                metrics.append(json.loads(mf.read_text()))
            except Exception:
                pass
    return metrics


def _fmt(v, decimals=2):
    if isinstance(v, float):
        return f"{v:.{decimals}f}"
    return str(v)


def _build_eda_section(analyzer: DomainAnalysis, figures_dir: Path,
                       saved_plots: list) -> str:
    ds   = analyzer.domain_summary
    now  = datetime.now().strftime("%Y-%m-%d %H:%M")
    sep2 = "─" * 66

    lines = [
        "",
        "╔══════════════════════════════════════════════════════════════════╗",
        "  EDA ANALYSIS  (human review — not fed to LLM)",
        f"  Generated: {now}",
        "╚══════════════════════════════════════════════════════════════════╝",
        "",
        "TOPOLOGY",
        sep2,
        f"  Total nodes               : {ds.get('Total Nodes', '?')}",
        f"  Nodes/scenario            : {_fmt(ds.get('Nodes per Scenario (Mean)', 0))}"
        f"  (std={_fmt(ds.get('Nodes per Scenario (Std)', 0))}"
        f", min={int(ds.get('Nodes per Scenario (Min)', 0))}"
        f", max={int(ds.get('Nodes per Scenario (Max)', 0))})",
        f"  Unique subnets            : {ds.get('Total Unique Subnets', '?')}",
        f"  Avg interfaces per node   : {_fmt(ds.get('Avg Interfaces per Node', 0))}",
        f"  Avg privilege level       : {_fmt(ds.get('Average Privilege Level', 0))}",
        "",
        "VULNERABILITY PROFILE",
        sep2,
        f"  Local vulns               : {ds.get('Total Local Vulnerabilities', '?')}",
        f"  Remote vulns              : {ds.get('Total Remote Vulnerabilities', '?')}",
        f"  Local:Remote ratio        : {_fmt(ds.get('Local vs Remote Vulnerability Ratio', 0))}",
        f"  Weighted exposure score   : {_fmt(ds.get('Weighted Vulnerability Exposure Score', 0))}",
        f"  Avg exploit success rate  : {_fmt(ds.get('Avg Exploit Success Rate', 0))}",
        f"  Domain stealth score      : {_fmt(ds.get('Domain Stealth Score (0=stealthy)', 0))}",
        f"  Attack surface index      : {_fmt(ds.get('Attack Surface Index (0–1)', 0))}",
        "",
        "NODE CONFIGURATION",
        sep2,
        f"  Nodes with agent (%)      : {_fmt(ds.get('Nodes with Agent Installed (%)', 0))}%",
        f"  Goal nodes (%)            : {_fmt(ds.get('Goal Nodes (%)', 0))}%",
        f"  Reimagable nodes (%)      : {_fmt(ds.get('Reimagable Nodes (%)', 0))}%",
        f"  Avg node value            : {_fmt(ds.get('Node Value (Mean)', 0))}",
        f"  Avg services per node     : {_fmt(ds.get('Avg Services per Node', 0))}",
        f"  Duplicate props removed   : {ds.get('Total Duplicate Properties Removed', '?')}",
        "",
        "FIREWALL",
        sep2,
        f"  Total rules               : {ds.get('Total Firewall Rules', '?')}",
        f"  Allow rate (%)            : {_fmt(ds.get('FW Allow Rate (%)', 0))}%",
        f"  Asymmetry (inbound bias)  : {_fmt(ds.get('Firewall Asymmetry (Inbound Bias)', 0))}",
        "",
        "DATA QUALITY",
        sep2,
        f"  Incomplete nodes (%)      : {_fmt(ds.get('Incomplete Nodes (%)', 0))}%",
        f"  Avg null rate (%)         : {_fmt(ds.get('DQ: Avg Null Rate (%)', 0))}%",
        f"  Value skewness            : {_fmt(ds.get('DQ: Value Skewness', 0))}",
        "",
        "DATASET DIVERSITY",
        sep2,
        f"  Diversity index (0=same)  : {_fmt(ds.get('Diversity: Index (0=identical,1=unique)', 0))}",
        f"  Avg Jaccard similarity    : {_fmt(ds.get('Diversity: Avg Jaccard Similarity', 0))}",
        f"  Vocabulary size           : {ds.get('Diversity: Vocabulary Size', '?')}",
        f"  Duplicate scenarios (%)   : {_fmt(ds.get('Diversity: Duplicate Scenarios (%)', 0))}%",
        "",
        "RL REWARD SIGNAL",
        sep2,
        f"  Static solvability (%)    : {_fmt(ds.get('Solvability Rate (%)', 0))}%",
        f"  Reward density            : {_fmt(ds.get('Reward Density (total value / nodes)', 0))}",
        f"  Reachable value (%)       : {_fmt(ds.get('Reachable Value (%)', 0))}%",
        f"  Goal isolation score      : {_fmt(ds.get('Goal Isolation Score (0-1)', 0))}",
        "",
        "FIGURES",
        sep2,
    ]

    for p in saved_plots:
        lines.append(f"  {p.relative_to(figures_dir.parent)}")

    lines.append("")
    return "\n".join(lines)


def _append_eda_to_report(report_path: Path, eda_section: str):
    existing = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    # Strip any previously appended EDA sections so we never duplicate them
    eda_marker = "\n╔══════════════════════════════════════════════════════════════════╗\n  EDA ANALYSIS"
    cut = existing.find(eda_marker)
    base = existing[:cut] if cut != -1 else existing
    report_path.write_text(base + eda_section, encoding="utf-8")


def _parse_phase1_report(text: str) -> dict:
    """Extract structured data from phase1_report.txt."""
    import re
    data: dict = {
        "scenario": "", "final_score": "", "grade": "", "iterations": "",
        "iteration_history": [], "dimension_scores": [],
        "resolved_issues": [], "remaining_issues": [], "verdict": "",
        "findings_by_dim": {}, "top_issues": [],
    }

    # Header fields
    m = re.search(r"Scenario\s*:\s*(.+)", text)
    if m: data["scenario"] = m.group(1).strip()
    m = re.search(r"Final Score:\s*([\d.]+/\d+)\s*\((\w+)\)", text)
    if m: data["final_score"], data["grade"] = m.group(1), m.group(2)
    m = re.search(r"Iterations:\s*(\d+)", text)
    if m: data["iterations"] = m.group(1)

    # Iteration history: "Iter N:  X/10 (G) ✓/✗  ... errors, ... issues"
    for m in re.finditer(
        r"Iter\s+(\d+):\s+([\d.]+/\d+)\s+\((\w+)\s*\)\s*([✓✗])\s*(?:PASS\s*)?"
        r"(\d+)\s+validation\s+error.*?(\d+)\s+critical",
        text,
    ):
        data["iteration_history"].append({
            "iter": m.group(1), "score": m.group(2), "grade": m.group(3),
            "passed": m.group(4) == "✓",
            "validation_errors": m.group(5), "critical_issues": m.group(6),
        })

    # Dimension scores: "  Name   X/10  [bars]"
    for m in re.finditer(r"^\s{2}(.+?)\s{2,}(\d+/\d+)\s+\[", text, re.MULTILINE):
        data["dimension_scores"].append({"dimension": m.group(1).strip(), "score": m.group(2)})

    # Always try to re-evaluate for findings; also fix all-zero scores.
    m_cfg = re.search(r"Path:\s*(.+\.yaml)", text)
    if m_cfg:
        cfg_path = Path(m_cfg.group(1).strip())
        full = _reevaluate_full_quality(cfg_path)
        if full:
            all_zero = data["dimension_scores"] and all(
                s["score"].startswith("0/") for s in data["dimension_scores"]
            )
            if all_zero or not data["dimension_scores"]:
                data["dimension_scores"] = full["scores"]
            data["findings_by_dim"] = full["findings_by_dim"]
            data["top_issues"]       = full["top_issues"]

    # Resolved issues
    for m in re.finditer(r"^\s+✓\s+(.+)$", text, re.MULTILINE):
        data["resolved_issues"].append(m.group(1).strip())

    # Remaining issues
    for m in re.finditer(r"^\s+[⚠⚠]\s+(.+)$", text, re.MULTILINE):
        data["remaining_issues"].append(m.group(1).strip())

    # Verdict
    m = re.search(r"VERDICT:\s*(.+)", text)
    if m: data["verdict"] = m.group(1).strip()

    return data


def _reevaluate_full_quality(config_path: Path) -> "dict | None":
    """Re-evaluate a config file and return full quality result including findings."""
    if not config_path.exists():
        print(f"  [WARN] Phase 1 config not found for re-evaluation: {config_path}")
        return None
    try:
        import yaml as _yaml
        sys.path.insert(0, str(TOOLS_DIR))
        from quality_evaluator import ScenarioQualityEvaluator
        cfg = _yaml.safe_load(config_path.read_text())
        result = ScenarioQualityEvaluator(cfg, config_name=config_path.stem).evaluate()
        _dim_labels = {
            "topology_realism":      "Network Topology Realism",
            "vulnerability_realism": "Properties & Vulnerabilities Realism",
            "scenario_difficulty":   "Scenario Difficulty",
            "firewall_realism":      "Firewall Rules Realism",
            "general_realism":       "General Realism",
            "cve_grounding":         "CVE Grounding",
        }
        dims = result.get("dimensions", {})
        scores = []
        findings_by_dim = {}
        for key, label in _dim_labels.items():
            raw = dims.get(key, {})
            val = int(raw["score"]) if isinstance(raw, dict) else int(raw)
            scores.append({"dimension": label, "score": f"{val}/10"})
            findings_by_dim[label] = raw.get("findings", []) if isinstance(raw, dict) else []
        print(f"  Re-evaluated quality from {config_path.name}")
        return {
            "scores": scores,
            "findings_by_dim": findings_by_dim,
            "top_issues": result.get("top_issues", []),
        }
    except Exception as exc:
        print(f"  [WARN] Could not re-evaluate quality: {exc}")
        return None


def _reevaluate_dimension_scores(config_path: Path) -> "list | None":
    """Re-evaluate a config file to get per-dimension scores (legacy wrapper)."""
    result = _reevaluate_full_quality(config_path)
    return result["scores"] if result else None


def _phase1_report_to_html(data: dict) -> str:
    """Render parsed phase1 data as HTML tables."""
    import html as _html

    def _score_color(score_str: str) -> str:
        try:
            val = float(score_str.split("/")[0])
            if val >= 8: return "#2e7d32"
            if val >= 7: return "#1565c0"
            if val >= 5: return "#e65100"
            return "#b71c1c"
        except Exception:
            return "#333"

    grade_color = _score_color(data["final_score"])

    rows_iter = "".join(
        f'<tr>'
        f'<td>Iter {r["iter"]}</td>'
        f'<td style="font-weight:bold;color:{_score_color(r["score"])}">{_html.escape(r["score"])}</td>'
        f'<td>{_html.escape(r["grade"])}</td>'
        f'<td style="color:{"#2e7d32" if r["passed"] else "#b71c1c"}">'
        f'{"✓ PASS" if r["passed"] else "✗ FAIL"}</td>'
        f'<td>{r["validation_errors"]}</td>'
        f'<td>{r["critical_issues"]}</td>'
        f'</tr>'
        for r in data["iteration_history"]
    )

    rows_dim = "".join(
        f'<tr>'
        f'<td>{_html.escape(r["dimension"])}</td>'
        f'<td style="font-weight:bold;color:{_score_color(r["score"])}">{_html.escape(r["score"])}</td>'
        f'</tr>'
        for r in data["dimension_scores"]
    )

    _sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}
    _sev_color = {"critical": "#b71c1c", "high": "#e65100", "medium": "#f9a825",
                  "low": "#2e7d32", "info": "#1565c0"}

    def _finding_row(finding: dict) -> str:
        sev   = finding.get("type", "").lower()
        color = _sev_color.get(sev, "#333")
        icon  = _sev_icon.get(sev, "•")
        msg   = _html.escape(finding.get("message", ""))
        ref_part = ""
        if finding.get("ref"):
            ref_part = '<br/><small style="color:#888">[&rarr; ' + _html.escape(finding["ref"]) + "]</small>"
        ded_part = ""
        if finding.get("deduction", 0) > 0:
            ded_part = '<small style="color:#c62828"> (-' + str(finding["deduction"]) + " pts)</small>"
        return (
            f'<tr>'
            f'<td style="color:{color}">{icon}</td>'
            f'<td>{msg}{ref_part}{ded_part}</td>'
            f'</tr>'
        )

    findings_html = ""
    if data.get("findings_by_dim"):
        dim_sections = []
        for dim_name, findings in data["findings_by_dim"].items():
            if not findings:
                continue
            rows = "".join(_finding_row(f) for f in findings)
            dim_sections.append(
                f'<tr><td colspan="2" style="background:#f5f5f5;font-weight:bold;padding:4px 6px">'
                f'{_html.escape(dim_name)}</td></tr>'
                + rows
            )
        if dim_sections:
            findings_html = (
                '<h2>Detailed Findings per Dimension</h2>'
                '<table><tr><th style="width:30px"></th><th>Finding</th></tr>'
                + "".join(dim_sections)
                + '</table>'
            )

    top_issues_html = ""
    if data.get("top_issues"):
        rows_top = "".join(
            f'<tr>'
            f'<td style="color:{_sev_color.get(i.get("severity","").lower(),"#333")}">'
            f'{_html.escape(i.get("severity",""))}</td>'
            f'<td>{_html.escape(i.get("dimension",""))}</td>'
            f'<td>{_html.escape(i.get("message",""))}</td>'
            f'</tr>'
            for i in data["top_issues"]
        )
        top_issues_html = (
            '<h2>Top Quality Issues</h2>'
            '<table><tr><th>Severity</th><th>Dimension</th><th>Issue</th></tr>'
            + rows_top + '</table>'
        )

    rows_resolved = "".join(
        f'<tr><td style="color:#2e7d32">✓</td><td>{_html.escape(i)}</td></tr>'
        for i in data["resolved_issues"]
    ) or '<tr><td colspan="2" style="color:#888">—</td></tr>'

    rows_remaining = "".join(
        f'<tr><td style="color:#e65100">⚠</td><td>{_html.escape(i)}</td></tr>'
        for i in data["remaining_issues"]
    ) or '<tr><td colspan="2" style="color:#888">—</td></tr>'

    verdict_color = "#2e7d32" if "✓" in data.get("verdict", "") else "#b71c1c"

    return f"""
<h1>Phase 1 — LLM Quality Evaluation</h1>

<table>
  <tr>
    <th>Scenario</th>
    <th>Final Score</th>
    <th>Grade</th>
    <th>Iterations</th>
  </tr>
  <tr>
    <td>{_html.escape(data["scenario"])}</td>
    <td style="font-weight:bold;color:{grade_color}">{_html.escape(data["final_score"])}</td>
    <td style="font-weight:bold;color:{grade_color}">{_html.escape(data["grade"])}</td>
    <td>{_html.escape(data["iterations"])}</td>
  </tr>
</table>

<h2>Iteration History</h2>
<table>
  <tr>
    <th>Iteration</th><th>Score</th><th>Grade</th><th>Result</th>
    <th>Validation Errors</th><th>Critical Issues</th>
  </tr>
  {rows_iter}
</table>

<h2>Dimension Scores</h2>
<table>
  <tr><th>Dimension</th><th>Score</th></tr>
  {rows_dim}
</table>

{findings_html}

{top_issues_html}

<h2>Issues</h2>
<table>
  <tr><th colspan="2">Resolved</th></tr>
  {rows_resolved}
</table>
<table>
  <tr><th colspan="2">Remaining (manual review)</th></tr>
  {rows_remaining}
</table>

<p style="font-weight:bold;color:{verdict_color};border:1px solid {verdict_color};
          padding:6px;margin-top:10px;">
  {_html.escape(data.get("verdict",""))}
</p>
"""


def _parse_phase2_report(text: str) -> dict:
    """Extract structured data from phase2_report.txt (first block only)."""
    import re

    # Take only the first block — everything before the first EDA section
    eda_cut = text.find("\n╔")
    block = text[:eda_cut] if eda_cut != -1 else text

    def _kv(pattern, src=block, flags=0):
        m = re.search(pattern, src, flags)
        return m.group(1).strip() if m else ""

    d: dict = {
        "scenario":    _kv(r"PHASE 2 REPORT:\s*(.+)"),
        "p1_quality":  _kv(r"Phase 1 Quality\s*:\s*(.+)"),
        "config":      _kv(r"Config Used\s*:\s*(.+)"),
        # generation
        "strata":      _kv(r"Strata\s*:\s*(.+)"),
        "train":       _kv(r"Train scenarios\s*:\s*(\d+)"),
        "test":        _kv(r"Test scenarios\s*:\s*(\d+)"),
        "total":       _kv(r"Total\s*:\s*(\d+)"),
        "gen_status":  _kv(r"Status\s*:\s*(\w+)"),
        # runtime
        "tested":      _kv(r"Scenarios tested\s*:\s*(.+)"),
        "solved":      _kv(r"Solved\s*:\s*(.+)"),
        "mean_steps":  _kv(r"Mean steps\s*:\s*(.+)"),
        "mean_reward": _kv(r"Mean reward\s*:\s*(.+)"),
        "mean_nodes":  _kv(r"Mean nodes owned\s*:\s*(.+)"),
        "mean_creds":  _kv(r"Mean creds found\s*:\s*(.+)"),
        "topo_nodes":  _kv(r"Node count\s*:\s*(.+)"),
        "topo_density":_kv(r"Graph density\s*:\s*(.+)"),
        "topo_diam":   _kv(r"Diameter\s*:\s*(.+)"),
        "verdict":     _kv(r"VERDICT:\s*(.+)"),
    }

    # EDA metrics — take the LAST EDA block
    eda_blocks = list(re.finditer(
        r"EDA ANALYSIS.*?Generated: (.+?)\n(.*?)(?=╔|$)", text, re.DOTALL))
    eda_src = eda_blocks[-1].group(0) if eda_blocks else text

    def _eda(pattern):
        m = re.search(pattern, eda_src)
        return m.group(1).strip() if m else ""

    d["eda"] = {
        "Topology": [
            ("Total nodes",            _eda(r"Total nodes\s*:\s*(.+)")),
            ("Nodes/scenario",         _eda(r"Nodes/scenario\s*:\s*(.+)")),
            ("Unique subnets",         _eda(r"Unique subnets\s*:\s*(.+)")),
            ("Avg interfaces/node",    _eda(r"Avg interfaces per node\s*:\s*(.+)")),
            ("Avg privilege level",    _eda(r"Avg privilege level\s*:\s*(.+)")),
        ],
        "Vulnerability Profile": [
            ("Local vulns",            _eda(r"Local vulns\s*:\s*(.+)")),
            ("Remote vulns",           _eda(r"Remote vulns\s*:\s*(.+)")),
            ("Local:Remote ratio",     _eda(r"Local:Remote ratio\s*:\s*(.+)")),
            ("Weighted exposure",      _eda(r"Weighted exposure score\s*:\s*(.+)")),
            ("Avg exploit success",    _eda(r"Avg exploit success rate\s*:\s*(.+)")),
            ("Domain stealth score",   _eda(r"Domain stealth score\s*:\s*(.+)")),
            ("Attack surface index",   _eda(r"Attack surface index\s*:\s*(.+)")),
        ],
        "Node Configuration": [
            ("Nodes with agent (%)",   _eda(r"Nodes with agent \(%\)\s*:\s*(.+)")),
            ("Goal nodes (%)",         _eda(r"Goal nodes \(%\)\s*:\s*(.+)")),
            ("Reimagable nodes (%)",   _eda(r"Reimagable nodes \(%\)\s*:\s*(.+)")),
            ("Avg node value",         _eda(r"Avg node value\s*:\s*(.+)")),
            ("Avg services/node",      _eda(r"Avg services per node\s*:\s*(.+)")),
            ("Duplicate props removed",_eda(r"Duplicate props removed\s*:\s*(.+)")),
        ],
        "Firewall": [
            ("Total rules",            _eda(r"Total rules\s*:\s*(.+)")),
            ("Allow rate (%)",         _eda(r"Allow rate \(%\)\s*:\s*(.+)")),
            ("Asymmetry (inbound)",    _eda(r"Asymmetry \(inbound bias\)\s*:\s*(.+)")),
        ],
        "Data Quality": [
            ("Incomplete nodes (%)",   _eda(r"Incomplete nodes \(%\)\s*:\s*(.+)")),
            ("Avg null rate (%)",      _eda(r"Avg null rate \(%\)\s*:\s*(.+)")),
            ("Value skewness",         _eda(r"Value skewness\s*:\s*(.+)")),
        ],
        "Dataset Diversity": [
            ("Diversity index",        _eda(r"Diversity index \(0=same\)\s*:\s*(.+)")),
            ("Avg Jaccard similarity", _eda(r"Avg Jaccard similarity\s*:\s*(.+)")),
            ("Vocabulary size",        _eda(r"Vocabulary size\s*:\s*(.+)")),
            ("Duplicate scenarios (%)",_eda(r"Duplicate scenarios \(%\)\s*:\s*(.+)")),
        ],
        "RL Reward Signal": [
            ("Static solvability (%)", _eda(r"Static solvability \(%\)\s*:\s*(.+)")),
            ("Reward density",         _eda(r"Reward density\s*:\s*(.+)")),
            ("Reachable value (%)",    _eda(r"Reachable value \(%\)\s*:\s*(.+)")),
            ("Goal isolation score",   _eda(r"Goal isolation score\s*:\s*(.+)")),
        ],
    }
    return d


def _phase2_report_to_html(d: dict) -> str:
    import html as _h

    def _tbl(rows, headers=("Metric", "Value")):
        th = "".join(f"<th>{_h.escape(c)}</th>" for c in headers)
        body = "".join(
            f"<tr><td>{_h.escape(str(k))}</td><td>{_h.escape(str(v))}</td></tr>"
            for k, v in rows if v
        )
        return f"<table><tr>{th}</tr>{body}</table>"

    # Verdict colour
    verdict = d.get("verdict", "")
    v_color = "#2e7d32" if "✓" in verdict else "#b71c1c"

    # Status colour
    status = d.get("gen_status", "")
    s_color = "#2e7d32" if status.upper() == "SUCCESS" else "#b71c1c"

    # Solved colour
    solved = d.get("solved", "")
    solved_pct = 0.0
    try:
        import re
        m = re.search(r"\((\d+\.?\d*)%\)", solved)
        solved_pct = float(m.group(1)) if m else 0.0
    except Exception:
        pass
    sol_color = "#2e7d32" if solved_pct >= 50 else "#b71c1c"

    eda_tables = ""
    for section, rows in d.get("eda", {}).items():
        if any(v for _, v in rows):
            eda_tables += f"<h2>{_h.escape(section)}</h2>" + _tbl(rows)

    return f"""
<h1>Phase 2 — Quality Report</h1>

<h2>Summary</h2>
{_tbl([
    ("Scenario",        d.get("scenario",   "")),
    ("Phase 1 Quality", d.get("p1_quality", "")),
    ("Config",          d.get("config",     "")),
])}

<h2>Scenario Generation</h2>
{_tbl([
    ("Strata",           d.get("strata", "")),
    ("Train scenarios",  d.get("train",  "")),
    ("Test scenarios",   d.get("test",   "")),
    ("Total",            d.get("total",  "")),
    ("Status",
     f'<span style="font-weight:bold;color:{s_color}">{_h.escape(status)}</span>'),
])}

<h2>Runtime Evaluation</h2>
{_tbl([
    ("Scenarios tested", d.get("tested",      "")),
    ("Solved",
     f'<span style="font-weight:bold;color:{sol_color}">{_h.escape(solved)}</span>'),
    ("Mean steps",       d.get("mean_steps",  "")),
    ("Mean reward",      d.get("mean_reward", "")),
    ("Mean nodes owned", d.get("mean_nodes",  "")),
    ("Mean creds found", d.get("mean_creds",  "")),
])}

<h2>Average Topology</h2>
{_tbl([
    ("Node count",    d.get("topo_nodes",   "")),
    ("Graph density", d.get("topo_density", "")),
    ("Diameter",      d.get("topo_diam",    "")),
])}

{eda_tables}

<p style="font-weight:bold;color:{v_color};border:1px solid {v_color};padding:6px;margin-top:10px;">
  {_h.escape(verdict)}
</p>
"""


def _embed_png(path: Path, caption: str = "", caption_style: str = "") -> str:
    import base64
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    cap = f'<p class="fig-caption" style="{caption_style}">{caption}</p>' if caption else ""
    return f'<div class="figure">{cap}<img src="data:image/png;base64,{b64}" /></div>\n'


_PDF_CSS = """
  @page { size: a4 landscape; margin: 1.2cm; }
  body { font-family: Helvetica, Arial, sans-serif; font-size: 11px; line-height: 1.4; }
  pre  { font-family: Courier, monospace; font-size: 9px; white-space: pre-wrap;
         background: #f8f8f8; border: 1px solid #ddd; padding: 8px; }
  h1   { font-size: 16px; color: #222; border-bottom: 2px solid #555;
         padding-bottom: 4px; margin-top: 20px; }
  h2   { font-size: 13px; color: #333; margin-top: 14px; margin-bottom: 4px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 12px; font-size: 10px; }
  th   { background: #e8e8e8; border: 1px solid #bbb; padding: 5px 8px; text-align: left; }
  td   { border: 1px solid #ccc; padding: 4px 8px; }
  tr:nth-child(even) td { background: #f9f9f9; }
  .page-break { page-break-before: always; }
  .figure     { page-break-inside: avoid; margin: 12px 0; text-align: center; }
  .fig-caption { font-weight: bold; font-size: 10px; margin-bottom: 4px; color: #444; }
  img { max-width: 100%; }
  /* TOC */
  .toc-box { border: 1px solid #ccc; background: #fafafa; padding: 14px 20px;
             margin-bottom: 20px; page-break-inside: avoid; }
  .toc-title { font-size: 15px; font-weight: bold; color: #333;
               border-bottom: 1px solid #bbb; margin-bottom: 10px; padding-bottom: 4px; }
  .toc-h1 { font-size: 11px; margin: 5px 0 2px 0; font-weight: bold; color: #222; }
  .toc-h2 { font-size: 10px; margin: 2px 0 2px 16px; color: #555; }
  .toc-h1 a, .toc-h2 a { color: inherit; text-decoration: none; }
"""


def _build_toc_html(entries: "list[tuple[int,str,str]]") -> str:
    """
    Build a TOC HTML block.
    entries: list of (level, anchor_id, display_title)  level 1=h1, 2=h2
    """
    if not entries:
        return ""
    rows = ""
    for level, anchor, title in entries:
        cls = "toc-h1" if level == 1 else "toc-h2"
        rows += f'<div class="{cls}"><a href="#{anchor}">{title}</a></div>\n'
    return f'<div class="toc-box"><div class="toc-title">Table of Contents</div>\n{rows}</div>\n'


def _slug(text: str) -> str:
    """Convert a display string to a safe anchor id."""
    import re
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _generate_per_scenario_pdfs(
    scenario_dirs: list,
    scenario_svg_graphs: dict,
    scenario_graphs_dir: Path,
) -> int:
    """
    Generate one PDF per scenario directory: metrics header + topology graphs.
    PDF is saved as <scenario_dir>/report.pdf.
    Returns the number of PDFs successfully written.
    """
    try:
        import base64
        import html as _html
        from xhtml2pdf import pisa
    except ImportError:
        print("  [WARN] xhtml2pdf not available — skipping per-scenario PDFs")
        return 0

    written = 0
    for sd in scenario_dirs:
        # ── metrics header ──────────────────────────────────────────────────
        metrics: dict = {}
        mf = sd / "run_metrics.json"
        if mf.exists():
            try:
                metrics = json.loads(mf.read_text())
            except Exception:
                pass

        solved_str = "SOLVED" if metrics.get("is_solved") else "NOT SOLVED"
        solved_color = "#2a7a2a" if metrics.get("is_solved") else "#b02020"
        rows_html = "".join(
            f"<tr><th>{_html.escape(str(k))}</th>"
            f"<td>{_html.escape(str(v))}</td></tr>"
            for k, v in metrics.items()
            if k not in ("topology_metrics",)
        )
        topo = metrics.get("topology_metrics", {}).get("routing", {})
        topo_rows = "".join(
            f"<tr><th>{_html.escape(str(k))}</th>"
            f"<td>{_html.escape(str(v))}</td></tr>"
            for k, v in topo.items()
        )

        # ── build TOC entries ───────────────────────────────────────────────
        toc_entries: list = [(1, "metrics", "Runtime Metrics")]
        if topo_rows:
            toc_entries.append((2, "topology", "Topology"))
        overview_png = scenario_graphs_dir / f"{sd.name}.png"
        if overview_png.exists():
            toc_entries.append((1, "overview", "Network Overview"))
        for title, png_path in (scenario_svg_graphs.get(sd.name) or []):
            if png_path.exists():
                toc_entries.append((1, _slug(title), title))

        toc_html = _build_toc_html(toc_entries)

        topo_section = (
            '<a name="topology"></a><h2>Topology</h2><table>' + topo_rows + "</table>"
            if topo_rows else ""
        )
        metrics_html = (
            '<a name="metrics"></a>'
            f'<h1>{_html.escape(sd.name)}</h1>'
            f'<p style="font-size:14px;font-weight:bold;color:{solved_color}">{solved_str}</p>'
            f'{toc_html}'
            '<h2>Runtime Metrics</h2>'
            f'<table>{rows_html}</table>'
            f'{topo_section}'
        )

        # ── topology PNG (from scenario_graphs_dir/<name>.png) ─────────────
        graphs_html = ""
        if overview_png.exists():
            b64 = base64.b64encode(overview_png.read_bytes()).decode("ascii")
            graphs_html += (
                '<div class="page-break"></div>'
                '<a name="overview"></a><h1>Network Overview</h1>'
                f'<div class="figure"><img src="data:image/png;base64,{b64}" /></div>\n'
            )

        # ── per-scenario SVG→PNG graphs ─────────────────────────────────────
        for title, png_path in (scenario_svg_graphs.get(sd.name) or []):
            if png_path.exists():
                anchor = _slug(title)
                b64 = base64.b64encode(png_path.read_bytes()).decode("ascii")
                graphs_html += (
                    f'<div class="page-break"></div>'
                    f'<a name="{anchor}"></a>'
                    f'<h1>{_html.escape(title)}</h1>'
                    f'<div class="figure"><img src="data:image/png;base64,{b64}" /></div>\n'
                )

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/><style>{_PDF_CSS}</style></head>
<body>{metrics_html}{graphs_html}</body></html>"""

        pdf_path = sd / "report.pdf"
        try:
            with open(pdf_path, "wb") as f:
                status = pisa.CreatePDF(html, dest=f)
            if not status.err:
                print(f"  Per-scenario PDF: {sd.name}/report.pdf")
                written += 1
            else:
                print(f"  [WARN] PDF errors for {sd.name}")
        except Exception as exc:
            print(f"  [WARN] PDF write failed for {sd.name}: {exc}")

    return written


def _llm_critic_to_html(critic_json_path: Path) -> str:
    """Render llm_critic_response.json as an HTML section for the PDF."""
    import html as _html
    if not critic_json_path.exists():
        return ""
    try:
        data = json.loads(critic_json_path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    critique = data.get("critique", "")
    if not critique:
        return ""

    model   = data.get("model", "unknown")
    usage   = data.get("usage", {})
    in_tok  = usage.get("input_tokens", "?")
    out_tok = usage.get("output_tokens", "?")

    # Convert markdown-style headings and bullets to simple HTML
    import re as _re
    lines_out = []
    for line in critique.splitlines():
        line_esc = _html.escape(line)
        # ### heading
        m = _re.match(r'^#{1,3}\s+(.*)', line_esc)
        if m:
            lines_out.append(f"<h3 style='color:#1a237e;margin-top:10px'>{m.group(1)}</h3>")
            continue
        # bullet
        if _re.match(r'^\s*[-*]\s+', line_esc):
            txt = _re.sub(r'^\s*[-*]\s+', '', line_esc)
            # bold **text**
            txt = _re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', txt)
            lines_out.append(f"<li style='margin:3px 0'>{txt}</li>")
            continue
        # numbered list
        if _re.match(r'^\s*\d+\.\s+', line_esc):
            txt = _re.sub(r'^\s*\d+\.\s+', '', line_esc)
            txt = _re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', txt)
            lines_out.append(f"<li style='margin:3px 0'>{txt}</li>")
            continue
        # plain line
        plain = _re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', line_esc)
        lines_out.append(f"<p style='margin:3px 0'>{plain}</p>" if plain.strip() else "<br/>")

    body_html = "\n".join(lines_out)

    return f"""
<div class="page-break"></div>
<a name="llm-critic"></a>
<h1 style="color:#0d47a1">LLM Critic Evaluation</h1>
<p style="color:#555;font-size:10px">
  Model: <strong>{_html.escape(model)}</strong> &nbsp;|&nbsp;
  Tokens: {in_tok} in / {out_tok} out
</p>
<div style="background:#f8f9fa;border-left:4px solid #1565c0;padding:10px 14px;font-size:11px;line-height:1.6">
{body_html}
</div>
"""


def _generate_pdf(report_path: Path, figures_dir: Path, saved_plots: list,
                  phase1_report_path: "Path | None" = None,
                  scenario_graphs: "list | None" = None,
                  scenario_svg_graphs: "dict | None" = None) -> "Path | None":
    """Convert phase2_report.txt + Phase 1 LLM scoring + embedded PNGs into a single PDF."""
    try:
        import base64  # noqa: F401 (imported in _embed_png)
        import html as _html
        from xhtml2pdf import pisa
    except ImportError:
        print("  [WARN] xhtml2pdf not available — skipping PDF generation")
        return None

    report_text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    p2_data = _parse_phase2_report(report_text)
    phase2_tables = _phase2_report_to_html(p2_data)

    phase1_section = ""
    has_phase1 = bool(phase1_report_path and phase1_report_path.exists())
    if has_phase1:
        p1_text = phase1_report_path.read_text(encoding="utf-8")
        p1_data = _parse_phase1_report(p1_text)
        phase1_section = (
            '<div class="page-break"></div><a name="phase1-quality"></a>'
            + _phase1_report_to_html(p1_data)
        )

    # ── LLM critic section (llm_critic_response.json next to phase2_report.txt) ──
    critic_json = report_path.parent / "llm_critic_response.json"
    llm_critic_section = _llm_critic_to_html(critic_json)
    has_critic = bool(llm_critic_section)

    # ── collect TOC entries ─────────────────────────────────────────────────
    toc_entries: list = [(1, "phase2-results", "Phase 2 Results")]
    if has_phase1:
        toc_entries.append((1, "phase1-quality", "Phase 1 Quality Score"))
    if has_critic:
        toc_entries.append((1, "llm-critic", "LLM Critic Evaluation"))

    eda_section_titles_seen: list = []
    for section_title, p in (saved_plots or []):
        if p.exists() and section_title not in eda_section_titles_seen:
            eda_section_titles_seen.append(section_title)
            toc_entries.append((1, _slug(section_title), section_title))

    if scenario_graphs:
        toc_entries.append((1, "scenario-overview", "Per-Scenario Network Topology"))

    if scenario_svg_graphs:
        for scenario_name, graph_list in scenario_svg_graphs.items():
            if graph_list:
                toc_entries.append((1, _slug(f"scenario-{scenario_name}"),
                                    f"Scenario: {scenario_name}"))
                for graph_title, png_path in graph_list:
                    if png_path.exists():
                        toc_entries.append((2, _slug(f"{scenario_name}-{graph_title}"),
                                            graph_title))

    toc_html = _build_toc_html(toc_entries)

    # ── wrap phase2 summary with anchor + TOC ──────────────────────────────
    phase2_with_anchor = (
        '<a name="phase2-results"></a>\n' + phase2_tables + "\n" + toc_html
    )

    # Build one HTML section per (title, path) pair, with page break between sections
    eda_sections_html = ""
    current_section   = None
    for section_title, p in (saved_plots or []):
        if not p.exists():
            continue
        if section_title != current_section:
            anchor = _slug(section_title)
            eda_sections_html += (
                f'<div class="page-break"></div>'
                f'<a name="{anchor}"></a>'
                f'<h1>{_html.escape(section_title)}</h1>\n'
            )
            current_section = section_title
        eda_sections_html += _embed_png(p)

    scenario_graphs_html = ""
    if scenario_graphs:
        scenario_graphs_html = (
            '<div class="page-break"></div>'
            '<a name="scenario-overview"></a>'
            '<h1>Per-Scenario Network Topology</h1>\n'
        )
        for p in scenario_graphs:
            if p.exists():
                scenario_graphs_html += _embed_png(
                    p, p.stem, caption_style="font-size:9px;color:#555;"
                )

    svg_graphs_html = ""
    if scenario_svg_graphs:
        for scenario_name, graph_list in scenario_svg_graphs.items():
            if not graph_list:
                continue
            sc_anchor = _slug(f"scenario-{scenario_name}")
            svg_graphs_html += (
                f'<div class="page-break"></div>'
                f'<a name="{sc_anchor}"></a>'
                f'<h1>Scenario: {_html.escape(scenario_name)}</h1>\n'
            )
            current_svg_section = None
            for graph_title, png_path in graph_list:
                if graph_title != current_svg_section:
                    g_anchor = _slug(f"{scenario_name}-{graph_title}")
                    svg_graphs_html += (
                        f'<a name="{g_anchor}"></a>'
                        f'<h2>{_html.escape(graph_title)}</h2>\n'
                    )
                    current_svg_section = graph_title
                if png_path.exists():
                    svg_graphs_html += _embed_png(png_path)

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"/><style>{_PDF_CSS}</style></head>
<body>
{phase2_with_anchor}
{phase1_section}
{llm_critic_section}
{eda_sections_html}
{scenario_graphs_html}
{svg_graphs_html}
</body>
</html>"""

    pdf_path = report_path.with_suffix(".pdf")
    with open(pdf_path, "wb") as f:
        status = pisa.CreatePDF(html, dest=f)

    if status.err:
        print(f"  [WARN] PDF generation had errors — output may be incomplete: {pdf_path}")
    else:
        print(f"  PDF saved: {pdf_path}")
    return pdf_path


def main():
    parser = argparse.ArgumentParser(description="Append EDA analysis to phase2_report.txt")
    parser.add_argument("--scenarios-dir", required=True,
                        help="Root dir of generated scenarios (phase2_output/<domain>)")
    parser.add_argument("--append-to", required=True,
                        help="Path to phase2_report.txt to append the EDA section to")
    parser.add_argument("--figures-dir", default="",
                        help="Where to save PNG figures (default: <report_dir>/figures)")
    parser.add_argument("--split", choices=["train", "test", "all"], default="all",
                        help="Which split to analyse (default: all)")
    parser.add_argument("--phase1-report", default="",
                        help="Path to phase1_report.txt to include as LLM scoring section in PDF")
    parser.add_argument("--config", default="",
                        help="Path to Phase 1 domain config YAML for CVE grounding graphs")
    args = parser.parse_args()

    scenarios_root    = Path(args.scenarios_dir)
    report_path       = Path(args.append_to)
    figures_dir       = Path(args.figures_dir) if args.figures_dir \
                        else report_path.parent / "figures"
    phase1_report_path = Path(args.phase1_report) if args.phase1_report else None

    if not scenarios_root.is_dir():
        print(f"ERROR: scenarios-dir not found: {scenarios_root}")
        sys.exit(1)

    if args.split == "all":
        analysis_root = scenarios_root
    else:
        analysis_root = scenarios_root / args.split
        if not analysis_root.is_dir():
            print(f"ERROR: split dir not found: {analysis_root}")
            sys.exit(1)

    scenario_dirs = _find_scenario_dirs(analysis_root)
    if not scenario_dirs:
        print(f"ERROR: no scenario dirs (with nodes/) found under {analysis_root}")
        sys.exit(1)

    print(f"Found {len(scenario_dirs)} scenarios under {analysis_root}")

    # ── Load global identifiers from first available scenario ────────────────
    global_ids: dict = {}
    id_candidates = sorted(analysis_root.rglob("identifiers/identifiers.yaml"))
    if id_candidates:
        try:
            global_ids = yaml.safe_load(id_candidates[0].read_text()) or {}
            print(f"  Loaded global identifiers from {id_candidates[0]}")
        except Exception as exc:
            print(f"  [WARN] Could not load identifiers: {exc}")

    # ── Run DomainAnalysis ───────────────────────────────────────────────────
    analyzer = DomainAnalysis(str(analysis_root))
    analyzer.run_full_analysis()

    # ── Generate and save all plots ──────────────────────────────────────────
    import pipeline.reporting.analysis.cbs_eda_graphs as _g

    def _save_to_file_final(fig, name="plot"):
        figures_dir.mkdir(parents=True, exist_ok=True)
        out = figures_dir / f"{name}.png"
        plt.tight_layout(rect=[0, 0, 1, 0.95])
        fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        print(f"  Saved: {out.name}")
        return out

    _g._save_or_show = _save_to_file_final

    # saved_plots: list of (section_title, Path)
    saved_plots: list = []
    for key, section_title, fn in _PLOT_SUITES:
        try:
            fn(analyzer)
            p = figures_dir / f"{key}.png"
            if p.exists():
                saved_plots.append((section_title, p))
        except Exception as exc:
            print(f"  [WARN] {key} failed: {exc}")

    # ── Global identifier coverage ───────────────────────────────────────────
    if global_ids:
        try:
            _g.plot_global_coverage(analyzer, global_ids)
            p = figures_dir / "global_coverage.png"
            if p.exists():
                saved_plots.append(("Global Identifier Coverage", p))
        except Exception as exc:
            print(f"  [WARN] global_coverage failed: {exc}")

    # ── Multi-analyzer plots (train vs test split comparison) ────────────────
    train_root = scenarios_root / "train"
    test_root  = scenarios_root / "test"
    if train_root.is_dir() and test_root.is_dir():
        print("  Building train/test split analyzers for cross-domain plots...")
        train_an = DomainAnalysis(str(train_root))
        train_an.run_full_analysis()
        test_an  = DomainAnalysis(str(test_root))
        test_an.run_full_analysis()
        analyzers = [train_an, test_an]

        for key, section_title, fn, needs_global in _MULTI_PLOT_SUITES:
            try:
                fn(analyzers, global_ids) if needs_global else fn(analyzers)
                p = figures_dir / f"{key}.png"
                if p.exists():
                    saved_plots.append((section_title, p))
            except Exception as exc:
                print(f"  [WARN] {key} failed: {exc}")

    # ── Generate per-scenario topology graphs (networkx/matplotlib) ──────────
    graphs_dir      = figures_dir.parent / "scenario_graphs"
    scenario_graphs = _generate_all_scenario_graphs(scenario_dirs, graphs_dir)
    print(f"Scenario graphs: {len(scenario_graphs)}")

    # ── Generate per-scenario SVG graphs (network_graph, attack_paths, etc.) ─
    print("Generating SVG architecture graphs per scenario...")
    scenario_svg_graphs: dict = {}
    for sd in scenario_dirs:
        graphs = _generate_svg_graphs_for_scenario(sd)
        if graphs:
            scenario_svg_graphs[sd.name] = graphs
            print(f"  {sd.name}: {len(graphs)} graph(s)")
    print(f"SVG graphs generated for {len(scenario_svg_graphs)} scenarios")

    # ── CVE grounding graphs (generated from the Phase 1 YAML config) ────────
    cve_plots_saved = 0
    if args.config:
        config_p = Path(args.config)
        if config_p.exists():
            print(f"\nGenerating CVE grounding graphs from: {config_p.name}")
            try:
                import yaml as _yaml
                from quality_evaluator import ScenarioQualityEvaluator
                cfg = _yaml.safe_load(config_p.read_text(encoding="utf-8"))
                eval_result = ScenarioQualityEvaluator(
                    cfg, config_name=config_p.stem
                ).evaluate()
                cve_out_dir = figures_dir / "cve_grounding"
                cve_paths = _cve_graphs.generate_cve_graphs(
                    eval_result, cve_out_dir, prefix=config_p.stem
                )
                for name, p in cve_paths.items():
                    if p.exists():
                        saved_plots.append(("CVE Grounding Analysis", p))
                        cve_plots_saved += 1
                        print(f"  CVE graph: {p.name}")
                cve_dim = eval_result.get("dimensions", {}).get("cve_grounding", {})
                print(f"  CVE grounding score: {cve_dim.get('score', 0)}/10 "
                      f"({cve_dim.get('grade', '?')})")
            except Exception as exc:
                print(f"  [WARN] CVE graph generation failed: {exc}")
        else:
            print(f"  [WARN] --config file not found: {config_p}")

    # ── Append EDA section to phase2_report.txt ──────────────────────────────
    plot_paths = [p for _, p in saved_plots]
    eda_section = _build_eda_section(analyzer, figures_dir, plot_paths)
    _append_eda_to_report(report_path, eda_section)
    print(f"\nEDA section appended to: {report_path}")
    print(f"Figures dir : {figures_dir}")
    print(f"Plots saved : {len(saved_plots)}")

    # ── Generate combined PDF ─────────────────────────────────────────────────
    pdf_path = _generate_pdf(report_path, figures_dir, saved_plots,
                             phase1_report_path, scenario_graphs, scenario_svg_graphs)

    # ── Generate per-scenario PDFs ────────────────────────────────────────────
    print("\nGenerating per-scenario PDFs...")
    per_scenario_graphs_dir = figures_dir.parent / "scenario_graphs"
    per_scenario_pdfs = _generate_per_scenario_pdfs(
        scenario_dirs, scenario_svg_graphs, per_scenario_graphs_dir
    )
    print(f"Per-scenario PDFs: {per_scenario_pdfs}/{len(scenario_dirs)}")

    runtime_metrics = _load_run_metrics(_find_scenario_dirs(scenarios_root))

    summary = {
        "report_path":           str(report_path),
        "pdf_path":              str(pdf_path) if pdf_path else None,
        "per_scenario_pdfs":     per_scenario_pdfs,
        "figures_dir":           str(figures_dir),
        "plots_saved":           len(saved_plots),
        "cve_plots_saved":       cve_plots_saved,
        "plot_names":            [p.name for _, p in saved_plots],
        "scenario_graphs":       len(scenario_graphs),
        "scenarios_analysed":    len(scenario_dirs),
        "solve_rate":            len([m for m in runtime_metrics if m.get("is_solved")])
                                 / max(len(runtime_metrics), 1),
        "status":                "success",
    }
    print("\n__SUMMARY_JSON__")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
