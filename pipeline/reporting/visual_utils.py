import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
from .latex_base import DIM_SHORT
from .data_utils import OUTCOME_KEYS, OUTCOME_SHORT

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


def save_quality_bars(dim_scores: dict, out_path: Path) -> None:
    labels, scores, colors = [], [], []
    grade_colors = {"A+": "#1a7a1a", "A": "#2ecc71", "B": "#f39c12",
                    "C": "#e67e22", "D": "#e74c3c", "F": "#c0392b"}
    for key, short in DIM_SHORT.items():
        info = dim_scores.get(key, {})
        s    = info.get("score", 0)
        g    = info.get("grade", "F")
        labels.append(short)
        scores.append(s)
        colors.append(grade_colors.get(g, "#c0392b"))

    fig, ax = plt.subplots(figsize=(6, 2.8))
    y_pos = range(len(labels))
    bars  = ax.barh(list(y_pos), scores, color=colors, height=0.55, edgecolor="white")
    ax.set_xlim(0, 10)
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Score (0-10)", fontsize=8)
    ax.set_title("Quality Dimensions", fontsize=9, fontweight="bold")
    ax.axvline(7, color="#bbb", linestyle="--", linewidth=0.8)
    for bar, s in zip(bars, scores):
        ax.text(min(bar.get_width() + 0.15, 9.7),
                bar.get_y() + bar.get_height() / 2,
                f"{s:.0f}", va="center", fontsize=7.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_summary_bars(entries: list, out_path: Path) -> None:
    names = [e["short_name"] for e in entries]
    p1    = [e.get("p1_score", 0) for e in entries]
    sr    = [e["agg"].get("solve_rate", 0) * 10 for e in entries]
    x, w  = np.arange(len(names)), 0.35

    fig, ax = plt.subplots(figsize=(max(5, len(names) * 2), 3.2))
    b1 = ax.bar(x - w/2, p1, w, label="Phase 1 Quality (0-10)", color="#3498db", edgecolor="white")
    b2 = ax.bar(x + w/2, sr,  w, label="Solve Rate x10",         color="#2ecc71", edgecolor="white")
    ax.set_xticks(list(x))
    ax.set_xticklabels(names, fontsize=8, rotation=15, ha="right")
    ax.set_ylim(0, 11)
    ax.axhline(7, color="#bbb", linestyle="--", linewidth=0.8)
    ax.set_ylabel("Score", fontsize=8)
    ax.set_title("Phase 1 Quality vs Runtime Solve Rate", fontsize=9)
    ax.legend(fontsize=7.5)
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    for bar in list(b1) + list(b2):
        v = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, v + 0.1,
                f"{v:.1f}", ha="center", fontsize=6.5)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_solve_donut(agg: dict, out_path: Path) -> None:
    sr = agg.get("solve_rate", 0)
    color = ("#1a7a1a" if sr >= 0.9 else "#2ecc71" if sr >= 0.7
             else "#f39c12" if sr >= 0.5 else "#c0392b")
    fig, ax = plt.subplots(figsize=(2.2, 2.2))
    ax.pie([sr, 1 - sr], colors=[color, "#e0e0e0"],
           startangle=90, counterclock=False,
           wedgeprops={"width": 0.45, "edgecolor": "white"})
    ax.text(0, 0.08, f"{sr*100:.0f}\\%", ha="center", va="center",
            fontsize=14, fontweight="bold", color=color)
    ax.text(0, -0.22, f"{agg.get('solved','?')}/{agg.get('total','?')}",
            ha="center", va="center", fontsize=8, color="#555")
    ax.set_title("Solve Rate", fontsize=8, fontweight="bold", pad=3)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_prop_heatmap(entry_names: list, short_names: list,
                      sorted_items: list, per_scenario: dict,
                      kind: str, out_path: Path) -> None:
    """Heatmap: rows=items, cols=scenarios, blue=present."""
    matrix = np.zeros((len(sorted_items), len(entry_names)))
    for j, en in enumerate(entry_names):
        bag = per_scenario.get(en, {}).get(kind, set() if kind == "props" else {})
        for i, item in enumerate(sorted_items):
            matrix[i, j] = 1 if item in bag else 0

    n_rows, n_cols = matrix.shape
    fig_h = max(4, n_rows * 0.25)
    fig_w = max(5, n_cols * 1.1)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    im = ax.imshow(matrix, aspect="auto", cmap="Blues", vmin=0, vmax=1,
                   interpolation="nearest")
    ax.set_xticks(range(n_cols))
    ax.set_xticklabels(short_names, rotation=40, ha="right", fontsize=7)
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels(sorted_items, fontsize=5.5)
    ax.set_title(f"{'Property' if kind == 'props' else 'Vulnerability'} Coverage Heatmap",
                 fontsize=9, fontweight="bold")
    fig.colorbar(im, ax=ax, shrink=0.4, label="Present")
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_jaccard_heatmap(entry_names: list, short_names: list,
                         per_scenario: dict, kind: str, out_path: Path) -> None:
    """Jaccard similarity matrix heatmap between all scenario pairs."""
    n = len(entry_names)
    matrix = np.zeros((n, n))
    for i, a in enumerate(entry_names):
        bag_a = set(per_scenario.get(a, {}).get(kind, set() if kind == "props" else {}).keys()
                    if kind == "vulns" else per_scenario.get(a, {}).get(kind, set()))
        for j, b in enumerate(entry_names):
            bag_b = set(per_scenario.get(b, {}).get(kind, set() if kind == "props" else {}).keys()
                        if kind == "vulns" else per_scenario.get(b, {}).get(kind, set()))
            union = bag_a | bag_b
            matrix[i, j] = len(bag_a & bag_b) / len(union) if union else 1.0

    fig, ax = plt.subplots(figsize=(max(4, n * 0.9), max(3.5, n * 0.9)))
    im = ax.imshow(matrix, cmap="YlOrRd", vmin=0, vmax=1)
    ax.set_xticks(range(n)); ax.set_yticks(range(n))
    ax.set_xticklabels(short_names, rotation=40, ha="right", fontsize=7)
    ax.set_yticklabels(short_names, fontsize=7)
    for i in range(n):
        for j in range(n):
            ax.text(j, i, f"{matrix[i,j]:.2f}", ha="center", va="center", fontsize=6,
                    color="white" if matrix[i, j] > 0.6 else "black")
    ax.set_title(f"Jaccard Similarity - {'Properties' if kind == 'props' else 'Vulnerabilities'}",
                 fontsize=9, fontweight="bold")
    fig.colorbar(im, ax=ax, shrink=0.6)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_outcome_chart(entries: list, out_path: Path) -> None:
    """Stacked bar chart of aggregated action outcomes per domain."""
    names   = [e["short_name"] for e in entries]
    totals  = [e["agg"].get("outcome_totals", {}) for e in entries]
    if not any(totals):
        return

    active_keys = [k for k in OUTCOME_KEYS
                   if any(t.get(k, 0) > 0 for t in totals)]
    if not active_keys:
        return

    x       = np.arange(len(names))
    bottoms = np.zeros(len(names))
    fig, ax = plt.subplots(figsize=(max(5, len(names) * 1.6), 3.5))

    for key in active_keys:
        vals  = np.array([t.get(key, 0) for t in totals], dtype=float)
        color = OUTCOME_COLORS.get(key, "#ccc")
        ax.bar(x, vals, bottom=bottoms, label=OUTCOME_SHORT.get(key, key),
               color=color, edgecolor="white", width=0.6)
        bottoms += vals

    ax.set_xticks(list(x))
    ax.set_xticklabels(names, fontsize=8, rotation=15, ha="right")
    ax.set_ylabel("Total outcome events", fontsize=8)
    ax.set_title("Aggregated Vulnerability Outcome Distribution per Domain", fontsize=9)
    ax.legend(fontsize=7, loc="upper right", ncol=2)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_topology_radar(entries: list, out_path: Path) -> None:
    """Radar chart comparing network topology features across domains."""
    feats  = ["Density x10", "Diameter", "Tree Ratio/10", "Nodes/10", "Avg Degree/10"]
    n_feat = len(feats)

    angles = [i * 2 * np.pi / n_feat for i in range(n_feat)]
    angles += angles[:1]

    fig, ax = plt.subplots(subplot_kw=dict(polar=True), figsize=(4, 4))
    colors  = plt.cm.tab10(np.linspace(0, 1, len(entries)))

    for entry, color in zip(entries, colors):
        agg = entry["agg"]
        vals = [
            min(agg.get("mean_density", 0) * 10, 10),
            min(agg.get("mean_diameter", 0), 10),
            min(agg.get("tree_ratio", 0) / 10, 10),
            min(agg.get("mean_node_count", 0) / 10, 10),
            min(agg.get("mean_density", 0) * agg.get("mean_node_count", 0) / 10, 10),
        ]
        vals += vals[:1]
        ax.plot(angles, vals, color=color, linewidth=1.5, label=entry["short_name"])
        ax.fill(angles, vals, color=color, alpha=0.1)

    ax.set_thetagrids(np.degrees(angles[:-1]), feats, fontsize=7)
    ax.set_ylim(0, 10)
    ax.set_title("Network Structure Comparison", fontsize=9, pad=12)
    ax.legend(loc="upper right", bbox_to_anchor=(1.4, 1.1), fontsize=7)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_graph_boxplots(entries: list, out_path: Path) -> None:
    """3-panel box plots: node count, edge count, avg degree --- one box per domain."""
    metrics_cfg = [
        ("nodes",      "Node Count",   "# nodes"),
        ("edges",      "Edge Count",   "# edges"),
        ("avg_degree", "Avg Degree",   "degree"),
    ]
    domains = [e["short_name"] for e in entries]
    fig, axes = plt.subplots(1, 3, figsize=(10, 4))
    colors = plt.cm.Set2(np.linspace(0, 1, len(entries)))

    for ax, (key, title, ylabel) in zip(axes, metrics_cfg):
        data_per_domain = []
        for entry in entries:
            raw = entry.get("sample_stats", {}).get(key, {}).get("raw", [])
            data_per_domain.append(raw if raw else [0])
        bp = ax.boxplot(data_per_domain, patch_artist=True, widths=0.5,
                        medianprops=dict(color="black", linewidth=1.5))
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
        ax.set_xticks(list(range(1, len(domains) + 1)))
        ax.set_xticklabels(domains, fontsize=7, rotation=20, ha="right")
        ax.set_ylabel(ylabel, fontsize=8)
        ax.set_title(title, fontsize=9)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

    fig.suptitle("Graph Structure Distribution per Domain", fontsize=10, y=1.01)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_payload_boxplots(entries: list, out_path: Path) -> None:
    """Box plots for vuln instances, property instances, unique vulns, unique props."""
    metrics_cfg = [
        ("vuln_inst",    "Vuln Instances",    "count"),
        ("prop_inst",    "Prop Instances",    "count"),
        ("unique_vulns", "Unique Vulns",      "count"),
        ("unique_props", "Unique Properties", "count"),
    ]
    domains = [e["short_name"] for e in entries]
    fig, axes = plt.subplots(1, 4, figsize=(12, 4))
    colors = plt.cm.Pastel1(np.linspace(0, 1, len(entries)))

    for ax, (key, title, ylabel) in zip(axes, metrics_cfg):
        data_per_domain = []
        for entry in entries:
            raw = entry.get("sample_stats", {}).get(key, {}).get("raw", [])
            data_per_domain.append(raw if raw else [0])
        bp = ax.boxplot(data_per_domain, patch_artist=True, widths=0.5,
                        medianprops=dict(color="black", linewidth=1.5))
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.8)
        ax.set_xticks(list(range(1, len(domains) + 1)))
        ax.set_xticklabels(domains, fontsize=7, rotation=20, ha="right")
        ax.set_ylabel(ylabel, fontsize=8)
        ax.set_title(title, fontsize=9)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

    fig.suptitle("Payload (Vulnerability & Property) Distribution per Domain", fontsize=10, y=1.01)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_nodes_edges_scatter(entries: list, out_path: Path) -> None:
    """Scatter: node count vs edge count for every scenario, colored by domain."""
    fig, ax = plt.subplots(figsize=(6, 4))
    colors = plt.cm.tab10(np.linspace(0, 1, len(entries)))

    for entry, color in zip(entries, colors):
        ss = entry.get("sample_stats", {})
        node_raw = ss.get("nodes", {}).get("raw", [])
        edge_raw = ss.get("edges", {}).get("raw", [])
        uv_raw   = ss.get("unique_vulns", {}).get("raw", [])
        n = min(len(node_raw), len(edge_raw))
        if n == 0:
            continue
        sizes = [max(uv_raw[i], 1) * 15 if i < len(uv_raw) else 30 for i in range(n)]
        ax.scatter(node_raw[:n], edge_raw[:n], s=sizes,
                   color=color, alpha=0.75, edgecolors="white", linewidth=0.5,
                   label=entry["short_name"])

    ax.set_xlabel("Node count", fontsize=9)
    ax.set_ylabel("Edge count", fontsize=9)
    ax.set_title("Node Count vs Edge Count\n(size proportional to unique vulnerabilities)", fontsize=9)
    ax.legend(fontsize=7, loc="upper left")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_degree_dist_chart(entries: list, out_path: Path) -> None:
    """Grouped bar: avg degree and max degree per domain."""
    names    = [e["short_name"] for e in entries]
    avg_degs = [e.get("sample_stats", {}).get("avg_degree", {}).get("mean", 0) for e in entries]
    max_degs = [e.get("sample_stats", {}).get("max_degree", {}).get("mean", 0) for e in entries]

    x     = np.arange(len(names))
    width = 0.35
    fig, ax = plt.subplots(figsize=(max(5, len(names) * 1.4), 3.5))

    ax.bar(x - width / 2, avg_degs, width, label="Avg degree", color="#5c85d6", alpha=0.8)
    ax.bar(x + width / 2, max_degs, width, label="Max degree", color="#e07b54", alpha=0.8)

    ax.set_xticks(list(x))
    ax.set_xticklabels(names, fontsize=8, rotation=15, ha="right")
    ax.set_ylabel("Degree", fontsize=8)
    ax.set_title("Degree Distribution (mean over scenarios)", fontsize=9)
    ax.legend(fontsize=8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_chokepoint_heatmap(entries: list, out_path: Path) -> None:
    """Heatmap showing service types that act as choke points across different domains."""
    all_groups = sorted({
        g for entry in entries
        for g in entry.get("attack_path_stats", {}).get("choke_type_distribution", {})
    })
    if not all_groups:
        return

    names  = [e["short_name"] for e in entries]
    matrix = np.zeros((len(all_groups), len(entries)))

    for j, entry in enumerate(entries):
        dist   = entry.get("attack_path_stats", {}).get("choke_type_distribution", {})
        n_samp = entry.get("attack_path_stats", {}).get("n_samples", 1)
        for i, group in enumerate(all_groups):
            matrix[i, j] = dist.get(group, 0) / max(n_samp, 1)

    fig, ax = plt.subplots(figsize=(max(5, len(entries) * 0.9), max(4, len(all_groups) * 0.3)))
    im = ax.imshow(matrix, aspect="auto", cmap="Reds", vmin=0, vmax=1)

    ax.set_xticks(range(len(entries)))
    ax.set_xticklabels(names, rotation=35, ha="right", fontsize=7)
    ax.set_yticks(range(len(all_groups)))
    ax.set_yticklabels(all_groups, fontsize=7)
    ax.set_title("Service Type Choke Point Frequency", fontsize=9, fontweight="bold")
    fig.colorbar(im, ax=ax, label="Choke Frequency (0-1)")

    for i in range(len(all_groups)):
        for j in range(len(entries)):
            val = matrix[i, j]
            if val > 0:
                ax.text(j, i, f"{val:.1f}", ha="center", va="center",
                        fontsize=6, color="white" if val > 0.6 else "black")

    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_attack_path_figure(entries: list, out_path: Path) -> None:
    """Grouped bar chart: per-scenario avg hops, avg actions (÷2), avg success probability (×10)."""
    names = [e["short_name"] for e in entries]
    ap    = [e.get("attack_path_stats", {}) for e in entries]

    def _m(d, key):
        v = d.get(key, {}).get("mean") if isinstance(d.get(key), dict) else None
        return v if v is not None else 0.0

    hops  = [_m(d, "avg_hops")              for d in ap]
    acts  = [_m(d, "avg_actions") / 2       for d in ap]   # /2 so bars are comparable
    probs = [_m(d, "avg_success_prob") * 10 for d in ap]   # *10 -> 0-10 scale

    x = np.arange(len(names))
    w = 0.26
    fig, ax = plt.subplots(figsize=(max(6, len(names) * 2.2), 3.4))
    b1 = ax.bar(x - w,   hops,  w, label="Avg hops to goal",          color="#3498db", edgecolor="white")
    b2 = ax.bar(x,       acts,  w, label="Avg actions / 2",            color="#e67e22", edgecolor="white")
    b3 = ax.bar(x + w,   probs, w, label="Avg P_success x 10",        color="#2ecc71", edgecolor="white")
    ax.set_xticks(list(x))
    ax.set_xticklabels(names, fontsize=8, rotation=20, ha="right")
    ax.set_ylabel("Value (normalised)", fontsize=8)
    ax.set_title("Attack Path Metrics per Scenario Config", fontsize=9, fontweight="bold")
    ax.axhline(5, color="#bbb", linestyle="--", linewidth=0.7)
    ax.legend(fontsize=7, loc="upper right")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    for bar in list(b1) + list(b2) + list(b3):
        h = bar.get_height()
        if h > 0.2:
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.08,
                    f"{h:.1f}", ha="center", fontsize=6)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_action_type_figure(entries: list, out_path: Path) -> None:
    """Stacked horizontal bar: action-type fraction breakdown per scenario."""
    TYPE_COLORS = {
        "REMOTE_EXPLOIT":  "#e74c3c",
        "CREDENTIAL_USE":  "#3498db",
        "LOCAL_CRED_LEAK": "#f39c12",
        "LOCAL_DISCOVERY": "#2ecc71",
        "LOCAL_PRIVESC":   "#9b59b6",
        "LOCAL_DUMP":      "#1abc9c",
    }
    TYPE_SHORT = {
        "REMOTE_EXPLOIT":  "RemExploit",
        "CREDENTIAL_USE":  "CredUse",
        "LOCAL_CRED_LEAK": "CredLeak",
        "LOCAL_DISCOVERY": "Discovery",
        "LOCAL_PRIVESC":   "PrivEsc",
        "LOCAL_DUMP":      "Dump",
    }

    all_types = sorted({
        k for entry in entries
        for k in entry.get("attack_path_stats", {}).get("action_type_dist", {})
    })
    if not all_types:
        return

    names = [e["short_name"] for e in entries]
    data  = {t: [entry.get("attack_path_stats", {}).get("action_type_dist", {}).get(t, 0.0)
                 for entry in entries]
             for t in all_types}

    fig, ax = plt.subplots(figsize=(max(6, len(names) * 1.6), max(3, len(entries) * 0.55)))
    left = np.zeros(len(names))
    for atype in all_types:
        vals = np.array(data[atype])
        ax.barh(names, vals, left=left, color=TYPE_COLORS.get(atype, "#999"),
                label=TYPE_SHORT.get(atype, atype), height=0.55)
        for i, (v, l) in enumerate(zip(vals, left)):
            if v > 0.06:
                ax.text(l + v / 2, i, f"{v:.2f}", ha="center", va="center",
                        fontsize=6, color="white")
        left += vals

    ax.set_xlim(0, 1.0)
    ax.set_xlabel("Fraction of actions", fontsize=8)
    ax.set_title("Attack Action-Type Composition per Scenario", fontsize=9, fontweight="bold")
    ax.legend(fontsize=6.5, bbox_to_anchor=(1.01, 1), loc="upper left")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def save_strategic_metrics_figure(entries: list, out_path: Path) -> None:
    """Grouped bar chart for elite strategic metrics: Redundancy, Visibility Index, Choke Point Count, Stealth Margin."""
    names = [e["short_name"] for e in entries]
    ap    = [e.get("attack_path_stats", {}) for e in entries]

    def _m(d, key):
        v = d.get(key, {}).get("mean") if isinstance(d.get(key), dict) else None
        return v if v is not None else 0.0

    redundancy = [_m(d, "avg_path_redundancy")    for d in ap]
    visibility = [_m(d, "avg_visibility") * 10    for d in ap]  # Scale 0-1 to 0-10
    choke      = [_m(d, "avg_chokepoints")         for d in ap]
    stealth    = [_m(d, "avg_stealth")             for d in ap]

    x = np.arange(len(names))
    w = 0.2
    fig, ax = plt.subplots(figsize=(max(6, len(names) * 2.2), 3.4))
    b1 = ax.bar(x - 1.5*w, redundancy, w, label="Path Redundancy",        color="#9b59b6", edgecolor="white")
    b2 = ax.bar(x - 0.5*w, visibility, w, label="Visibility Index (x10)", color="#3498db", edgecolor="white")
    b3 = ax.bar(x + 0.5*w, choke,      w, label="Choke Point Count",      color="#e74c3c", edgecolor="white")
    b4 = ax.bar(x + 1.5*w, stealth,    w, label="Stealth Margin",         color="#2ecc71", edgecolor="white")

    ax.set_xticks(list(x))
    ax.set_xticklabels(names, fontsize=8, rotation=20, ha="right")
    ax.set_ylabel("Value", fontsize=8)
    ax.set_title("Strategic Complexity Metrics per Scenario Config", fontsize=9, fontweight="bold")
    ax.legend(fontsize=7, loc="upper right")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    for bars in [b1, b2, b3, b4]:
        for bar in bars:
            h = bar.get_height()
            if h != 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + 0.05,
                        f"{h:.1f}", ha="center", fontsize=6)

    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)
