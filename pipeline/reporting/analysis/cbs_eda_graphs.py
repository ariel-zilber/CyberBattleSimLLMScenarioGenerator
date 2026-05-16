"""
CyberBattleSim EDA - Comprehensive Visualization Suite
=======================================================
Drop-in visualization module for DomainAnalysis output.

Usage (in your notebook):
    from cbs_eda_graphs import plot_all, plot_node_graphs, plot_scenario_graphs,
                               plot_security_graphs, plot_properties_graphs,
                               plot_services_graphs, plot_vuln_rates_graphs,
                               plot_firewall_graphs, plot_complexity_dashboard,
                               plot_cross_domain

    # Single domain — all suites
    plot_all(analyzer)

    # Cross-domain comparison (pass list of DomainAnalysis objects)
    plot_cross_domain([analyzer_cloud, analyzer_scada, analyzer_proxy])
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as mtick
from matplotlib.gridspec import GridSpec
import seaborn as sns
from collections import Counter
import warnings
warnings.filterwarnings("ignore")

# ── Palette ───────────────────────────────────────────────────────────────────
PALETTE = ["#4C72B0","#DD8452","#55A868","#C44E52","#8172B2",
           "#937860","#DA8BC3","#8C8C8C","#CCB974","#64B5CD"]
BG      = "#0F1117"
CARD    = "#1A1D27"
TEXT    = "#E8EAF0"
SUBTEXT = "#8B8FA8"
ACCENT  = "#4C72B0"


# ── Shared helpers ────────────────────────────────────────────────────────────
def _style():
    plt.rcParams.update({
        "figure.facecolor":  BG,
        "axes.facecolor":    CARD,
        "axes.edgecolor":    "#2A2D3A",
        "axes.labelcolor":   TEXT,
        "axes.titlecolor":   TEXT,
        "xtick.color":       SUBTEXT,
        "ytick.color":       SUBTEXT,
        "text.color":        TEXT,
        "grid.color":        "#2A2D3A",
        "grid.linestyle":    "--",
        "grid.alpha":        0.6,
        "legend.facecolor":  CARD,
        "legend.edgecolor":  "#2A2D3A",
        "legend.labelcolor": TEXT,
        "font.family":       "monospace",
        "axes.spines.top":   False,
        "axes.spines.right": False,
    })


def _fig_title(fig, title, subtitle=""):
    fig.text(0.5, 0.98, title, ha="center", va="top",
             fontsize=16, fontweight="bold", color=TEXT)
    if subtitle:
        fig.text(0.5, 0.96, subtitle, ha="center", va="top",
                 fontsize=10, color=SUBTEXT)


def _empty(ax, msg="No data available"):
    ax.text(0.5, 0.5, msg, ha="center", va="center",
            transform=ax.transAxes, color=SUBTEXT, fontsize=10)
    ax.set_xticks([]); ax.set_yticks([])


def _bar_labels(ax, bars, fmt="{:.1f}", offset_frac=0.01):
    """Annotate bars with their values."""
    ylim = ax.get_ylim()[1]
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2,
                h + ylim * offset_frac,
                fmt.format(h), ha="center", fontsize=8, color=TEXT)


def _save_or_show(fig, name=""):
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.show()


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 – NODE-LEVEL GRAPHS
# ═══════════════════════════════════════════════════════════════════════════════

def plot_node_graphs(analyzer):
    """6 graphs focused on individual node attributes."""
    _style()
    df     = analyzer.get_node_dataframe()
    domain = analyzer.domain_name

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"NODE-LEVEL ANALYSIS  ·  {domain.upper()}",
               f"{len(df):,} nodes across {df['scenario'].nunique():,} scenarios")
    axes = axes.flatten()

    # 1 – Value histogram
    ax = axes[0]
    vals = df["value"].dropna()
    ax.hist(vals, bins=40, color=PALETTE[0], edgecolor=BG, alpha=0.9)
    ax.axvline(vals.mean(),   color=PALETTE[1], lw=2, ls="--", label=f"Mean={vals.mean():.1f}")
    ax.axvline(np.median(vals), color=PALETTE[2], lw=2, ls=":",  label=f"Median={np.median(vals):.1f}")
    ax.set_title("Node Value Distribution"); ax.set_xlabel("Value"); ax.set_ylabel("Count")
    ax.legend(); ax.grid(True, axis="y")

    # 2 – Privilege Level bar
    ax = axes[1]
    priv_counts = df["privilege_level"].value_counts().sort_index()
    bars = ax.bar(priv_counts.index.astype(str), priv_counts.values,
                  color=[PALETTE[i % len(PALETTE)] for i in range(len(priv_counts))],
                  edgecolor=BG)
    _bar_labels(ax, bars, fmt="{:.0f}")
    ax.set_title("Privilege Level Distribution"); ax.set_xlabel("Privilege Level"); ax.set_ylabel("Node Count")
    ax.grid(True, axis="y")

    # 3 – Boolean flags
    ax = axes[2]
    flags     = ["agent_installed", "reimagable", "is_goal"]
    flag_pct  = [(df[f].sum() / len(df)) * 100 for f in flags]
    bars = ax.barh(flags, flag_pct, color=PALETTE[:3], edgecolor=BG)
    for bar, val in zip(bars, flag_pct):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                f"{val:.1f}%", va="center", fontsize=9, color=TEXT)
    ax.set_xlim(0, 105)
    ax.set_title("Node Boolean Flags (% True)"); ax.set_xlabel("Percentage (%)")
    ax.grid(True, axis="x")

    # 4 – Local vs Remote vulnerabilities per node
    ax = axes[3]
    vuln_data = df[["local_vulnerabilities", "remote_vulnerabilities"]].copy()
    vuln_data = vuln_data[(vuln_data > 0).any(axis=1)]
    if not vuln_data.empty:
        bins = np.arange(0, vuln_data.max().max() + 2) - 0.5
        ax.hist(vuln_data["local_vulnerabilities"],  bins=bins, alpha=0.75, label="Local",  color=PALETTE[3])
        ax.hist(vuln_data["remote_vulnerabilities"], bins=bins, alpha=0.75, label="Remote", color=PALETTE[0])
        ax.legend(); ax.set_title("Vuln Count per Node (nodes with ≥1 vuln)")
        ax.set_xlabel("Vulnerabilities per Node"); ax.set_ylabel("Count")
        ax.grid(True, axis="y")
    else:
        _empty(ax, "No vulnerability data"); ax.set_title("Vulnerability Distribution")

    # 5 – SLA Weight distribution
    ax = axes[4]
    sla_nonzero = df["sla_weight"].dropna()
    sla_nonzero = sla_nonzero[sla_nonzero > 0]
    if not sla_nonzero.empty:
        ax.hist(sla_nonzero, bins=30, color=PALETTE[4], edgecolor=BG)
        ax.axvline(sla_nonzero.mean(), color=PALETTE[1], lw=2, ls="--",
                   label=f"Mean={sla_nonzero.mean():.3f}")
        ax.legend()
    ax.set_title("SLA Weight Distribution (non-zero)"); ax.set_xlabel("SLA Weight"); ax.set_ylabel("Count")
    ax.grid(True, axis="y")

    # 6 – Node Value vs Total Vulnerabilities scatter (coloured by privilege)
    ax = axes[5]
    sample = df.sample(min(2000, len(df)), random_state=42)
    sc = ax.scatter(sample["value"], sample["total_vulnerabilities"],
                    alpha=0.4, s=20, c=sample["privilege_level"],
                    cmap="viridis", edgecolors="none")
    plt.colorbar(sc, ax=ax, label="Privilege Level")
    ax.set_title("Node Value vs Total Vulnerabilities")
    ax.set_xlabel("Node Value"); ax.set_ylabel("Total Vulnerabilities")
    ax.grid(True)

    _save_or_show(fig, "node_graphs")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 – SCENARIO-LEVEL GRAPHS
# ═══════════════════════════════════════════════════════════════════════════════

def plot_scenario_graphs(analyzer):
    """6 graphs focused on per-scenario statistics."""
    _style()
    df_sc  = analyzer.get_scenario_dataframe()
    domain = analyzer.domain_name

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"SCENARIO-LEVEL ANALYSIS  ·  {domain.upper()}",
               f"{len(df_sc):,} scenarios")
    axes = axes.flatten()

    # 1 – Node count distribution
    ax = axes[0]
    ax.hist(df_sc["num_nodes"], bins=30, color=PALETTE[0], edgecolor=BG)
    ax.axvline(df_sc["num_nodes"].mean(), color=PALETTE[1], lw=2, ls="--",
               label=f"Mean={df_sc['num_nodes'].mean():.1f}")
    ax.set_title("Nodes per Scenario"); ax.set_xlabel("Node Count"); ax.set_ylabel("# Scenarios")
    ax.legend(); ax.grid(True, axis="y")

    # 2 – Avg node value distribution
    ax = axes[1]
    ax.hist(df_sc["avg_node_value"], bins=30, color=PALETTE[2], edgecolor=BG)
    ax.axvline(df_sc["avg_node_value"].mean(), color=PALETTE[1], lw=2, ls="--",
               label=f"Mean={df_sc['avg_node_value'].mean():.2f}")
    ax.set_title("Avg Node Value per Scenario"); ax.set_xlabel("Avg Value"); ax.set_ylabel("# Scenarios")
    ax.legend(); ax.grid(True, axis="y")

    # 3 – Local vs Remote vulnerabilities scatter
    ax = axes[2]
    ax.scatter(df_sc["total_local_vulns"], df_sc["total_remote_vulns"],
               alpha=0.4, s=15, color=PALETTE[3], edgecolors="none")
    ax.set_title("Local vs Remote Vulns per Scenario")
    ax.set_xlabel("Total Local Vulnerabilities"); ax.set_ylabel("Total Remote Vulnerabilities")
    ax.grid(True)

    # 4 – Firewall rules distribution
    ax = axes[3]
    ax.hist(df_sc["firewall_incoming_rules"], bins=30, alpha=0.75, label="Incoming", color=PALETTE[0])
    ax.hist(df_sc["firewall_outgoing_rules"], bins=30, alpha=0.75, label="Outgoing", color=PALETTE[1])
    ax.set_title("Firewall Rules per Scenario"); ax.set_xlabel("Rule Count"); ax.set_ylabel("# Scenarios")
    ax.legend(); ax.grid(True, axis="y")

    # 5 – Identifier counts
    ax = axes[4]
    id_cols = [c for c in ["properties","ports","local_vulnerabilities","remote_vulnerabilities"]
               if c in df_sc.columns]
    if id_cols:
        id_means = df_sc[id_cols].mean()
        bars = ax.bar(id_means.index, id_means.values,
                      color=[PALETTE[i % len(PALETTE)] for i in range(len(id_cols))],
                      edgecolor=BG)
        _bar_labels(ax, bars)
        ax.set_title("Avg Identifier Counts per Scenario"); ax.set_ylabel("Mean Count")
        ax.grid(True, axis="y")
    else:
        _empty(ax, "No identifier data")

    # 6 – Node count vs total vulnerabilities
    ax = axes[5]
    total_vulns = df_sc["total_local_vulns"] + df_sc["total_remote_vulns"]
    ax.scatter(df_sc["num_nodes"], total_vulns, alpha=0.35, s=15,
               color=PALETTE[4], edgecolors="none")
    z = np.polyfit(df_sc["num_nodes"], total_vulns, 1)
    x_line = np.linspace(df_sc["num_nodes"].min(), df_sc["num_nodes"].max(), 100)
    ax.plot(x_line, np.poly1d(z)(x_line), color=PALETTE[1], lw=2, ls="--", label="Trend")
    ax.set_title("Node Count vs Total Vulnerabilities")
    ax.set_xlabel("# Nodes"); ax.set_ylabel("Total Vulnerabilities")
    ax.legend(); ax.grid(True)

    _save_or_show(fig, "scenario_graphs")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 – TOPOLOGY & SECURITY DEEP-DIVE
# ═══════════════════════════════════════════════════════════════════════════════

def plot_security_graphs(analyzer):
    """6 graphs focused on security posture and topology."""
    _style()
    df     = analyzer.get_node_dataframe()
    df_sc  = analyzer.get_scenario_dataframe()
    domain = analyzer.domain_name

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"SECURITY & TOPOLOGY DEEP-DIVE  ·  {domain.upper()}")
    axes = axes.flatten()

    # 1 – Local vs Remote stacked bar (top 20 scenarios by size)
    ax = axes[0]
    top20 = df_sc.nlargest(20, "num_nodes")[
        ["scenario_name","total_local_vulns","total_remote_vulns"]
    ].set_index("scenario_name")
    top20.plot(kind="bar", stacked=True, ax=ax,
               color=[PALETTE[3], PALETTE[0]], edgecolor=BG)
    ax.set_title("Local vs Remote Vulns (Top 20 Scenarios by Size)")
    ax.set_xlabel(""); ax.set_ylabel("Vulnerabilities")
    ax.tick_params(axis="x", labelsize=6, rotation=45)
    ax.legend(["Local","Remote"]); ax.grid(True, axis="y")

    # 2 – Avg vulns heatmap: privilege × is_goal
    ax = axes[1]
    pivot = df.pivot_table(values="total_vulnerabilities",
                           index="privilege_level", columns="is_goal",
                           aggfunc="mean", fill_value=0)
    pivot.columns = ["Non-Goal","Goal"]
    sns.heatmap(pivot, ax=ax, cmap="YlOrRd", annot=True, fmt=".2f",
                linewidths=0.5, linecolor=BG, cbar_kws={"label":"Avg Vulns"})
    ax.set_title("Avg Vulns · Privilege Level × Is-Goal")
    ax.set_xlabel("Is Goal Node"); ax.set_ylabel("Privilege Level")

    # 3 – CDF of node values by is_goal
    ax = axes[2]
    for label, grp in df.groupby("is_goal"):
        vals = grp["value"].sort_values()
        cdf  = np.arange(1, len(vals)+1) / len(vals)
        ax.plot(vals, cdf, lw=2, label=f"Goal={label}",
                color=PALETTE[0] if not label else PALETTE[3])
    ax.set_title("CDF of Node Values (Goal vs Non-Goal)")
    ax.set_xlabel("Node Value"); ax.set_ylabel("Cumulative Probability")
    ax.legend(); ax.grid(True)

    # 4 – Firewall rules vs vulnerabilities
    ax = axes[3]
    fw_total   = df_sc["firewall_incoming_rules"] + df_sc["firewall_outgoing_rules"]
    vuln_total = df_sc["total_local_vulns"]        + df_sc["total_remote_vulns"]
    ax.scatter(fw_total, vuln_total, alpha=0.3, s=15, color=PALETTE[2], edgecolors="none")
    ax.set_title("Firewall Rules vs Total Vulnerabilities")
    ax.set_xlabel("Total Firewall Rules"); ax.set_ylabel("Total Vulnerabilities")
    ax.grid(True)

    # 5 – Privilege Level by agent install status
    ax = axes[4]
    agent_groups = [df[df["agent_installed"]==v]["privilege_level"].values
                    for v in [False, True]]
    ax.boxplot(agent_groups, labels=["No Agent","Agent Installed"],
               patch_artist=True, notch=True,
               boxprops=dict(facecolor=PALETTE[0], alpha=0.7),
               medianprops=dict(color=PALETTE[1], lw=2))
    ax.set_title("Privilege Level by Agent Install Status")
    ax.set_ylabel("Privilege Level"); ax.grid(True, axis="y")

    # 6 – SLA weight by reimagability
    ax = axes[5]
    for reimag, color, label in [(True, PALETTE[2],"Reimagable"), (False, PALETTE[3],"Not Reimagable")]:
        sla = df[df["reimagable"]==reimag]["sla_weight"]
        ax.hist(sla[sla > 0], bins=25, alpha=0.7, color=color, label=label, edgecolor=BG)
    ax.set_title("SLA Weight (non-zero) by Reimagability")
    ax.set_xlabel("SLA Weight"); ax.set_ylabel("Count")
    ax.legend(); ax.grid(True, axis="y")

    _save_or_show(fig, "security_graphs")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 – PROPERTIES & IDENTIFIERS
# ═══════════════════════════════════════════════════════════════════════════════

def plot_properties_graphs(analyzer):
    """4 graphs on node properties and identifier richness."""
    _style()
    df    = analyzer.get_node_dataframe()
    df_sc = analyzer.get_scenario_dataframe()
    domain = analyzer.domain_name

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"PROPERTIES & IDENTIFIERS  ·  {domain.upper()}")
    axes = axes.flatten()

    # 1 – Top 15 node properties (deduped)
    ax = axes[0]
    all_props = [p for sublist in df["properties"].dropna() for p in sublist]
    if all_props:
        prop_counts = Counter(all_props).most_common(15)
        labels, vals = zip(*prop_counts)
        colors = [PALETTE[i % len(PALETTE)] for i in range(len(labels))]
        ax.barh(labels[::-1], vals[::-1], color=colors[::-1], edgecolor=BG)
        ax.set_title("Top 15 Most Common Node Properties (deduped)")
        ax.set_xlabel("Occurrence Count"); ax.grid(True, axis="x")
    else:
        _empty(ax, "No property data"); ax.set_title("Node Properties")

    # 2 – Properties per node histogram + duplicate count annotation
    ax = axes[1]
    prop_len = df["num_properties"] if "num_properties" in df.columns else \
               df["properties"].apply(lambda x: len(x) if isinstance(x, list) else 0)
    ax.hist(prop_len, bins=range(0, int(prop_len.max())+2), color=PALETTE[1], edgecolor=BG, align="left")
    ax.set_title("Properties per Node (after deduplication)")
    ax.set_xlabel("# Properties"); ax.set_ylabel("# Nodes")
    ax.grid(True, axis="y")
    if "num_duplicate_properties" in df.columns:
        total_dupes = int(df["num_duplicate_properties"].sum())
        ax.text(0.97, 0.97, f"Dupes removed: {total_dupes:,}",
                ha="right", va="top", transform=ax.transAxes,
                fontsize=8, color=SUBTEXT)

    # 3 – Identifier richness boxplot
    ax = axes[2]
    id_cols = [c for c in ["properties","ports","local_vulnerabilities","remote_vulnerabilities"]
               if c in df_sc.columns]
    if id_cols:
        ax.boxplot([df_sc[c].dropna() for c in id_cols],
                   labels=id_cols, patch_artist=True,
                   boxprops=dict(facecolor=PALETTE[0], alpha=0.6),
                   medianprops=dict(color=PALETTE[1], lw=2))
        ax.set_title("Identifier Count Distribution per Scenario")
        ax.set_ylabel("Count"); ax.grid(True, axis="y")
        ax.tick_params(axis="x", rotation=20)
    else:
        _empty(ax, "No identifier data")

    # 4 – Avg properties per node vs total vulnerabilities
    ax = axes[3]
    prop_len_sc = df.groupby("scenario")["num_properties"].mean().reset_index()
    prop_len_sc.columns = ["scenario_name", "avg_props"]
    merged = df_sc.merge(prop_len_sc, on="scenario_name", how="left")
    if not merged.empty:
        total_vulns = merged["total_local_vulns"] + merged["total_remote_vulns"]
        ax.scatter(merged["avg_props"], total_vulns,
                   alpha=0.4, s=15, color=PALETTE[4], edgecolors="none")
        ax.set_title("Avg Properties/Node vs Total Vulnerabilities")
        ax.set_xlabel("Avg Properties per Node"); ax.set_ylabel("Total Vulnerabilities")
        ax.grid(True)
    else:
        _empty(ax)

    _save_or_show(fig, "properties_graphs")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 – SERVICES & NETWORK  (NEW)
# ═══════════════════════════════════════════════════════════════════════════════

def plot_services_graphs(analyzer):
    """6 graphs covering services, running state, image types, and network topology."""
    _style()
    df    = analyzer.get_node_dataframe()
    df_sc = analyzer.get_scenario_dataframe()
    domain = analyzer.domain_name

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"SERVICES & NETWORK  ·  {domain.upper()}")
    axes = axes.flatten()

    # 1 – Services per node histogram
    ax = axes[0]
    if "num_services" in df.columns:
        svc = df["num_services"].dropna()
        bins = range(0, int(svc.max())+2)
        ax.hist(svc, bins=bins, color=PALETTE[0], edgecolor=BG, align="left")
        ax.axvline(svc.mean(), color=PALETTE[1], lw=2, ls="--",
                   label=f"Mean={svc.mean():.2f}")
        ax.legend(); ax.set_title("Services per Node")
        ax.set_xlabel("# Services"); ax.set_ylabel("# Nodes")
        ax.grid(True, axis="y")
    else:
        _empty(ax, "No service data"); ax.set_title("Services per Node")

    # 2 – Running vs total services per node (stacked bar by bucket)
    ax = axes[1]
    if "num_services" in df.columns and "num_running_services" in df.columns:
        df_svc = df[df["num_services"] > 0].copy()
        if not df_svc.empty:
            df_svc["stopped"] = df_svc["num_services"] - df_svc["num_running_services"]
            totals  = df_svc.groupby("num_services")[["num_running_services","stopped"]].sum()
            totals.plot(kind="bar", stacked=True, ax=ax,
                        color=[PALETTE[2], PALETTE[3]], edgecolor=BG)
            ax.set_title("Running vs Stopped Services (by service count group)")
            ax.set_xlabel("# Services on Node"); ax.set_ylabel("Cumulative Count")
            ax.legend(["Running","Stopped"]); ax.grid(True, axis="y")
            ax.tick_params(axis="x", rotation=0)
        else:
            _empty(ax, "No nodes with services")
    else:
        _empty(ax, "No service data"); ax.set_title("Running vs Stopped Services")

    # 3 – Top 10 service types
    ax = axes[2]
    if "service_names" in df.columns:
        all_svcs = [s for sublist in df["service_names"].dropna() for s in sublist]
        if all_svcs:
            svc_counts = Counter(all_svcs).most_common(10)
            labels, vals = zip(*svc_counts)
            bars = ax.barh(labels[::-1], vals[::-1],
                           color=[PALETTE[i % len(PALETTE)] for i in range(len(labels))],
                           edgecolor=BG)
            ax.set_title("Top 10 Service Types"); ax.set_xlabel("Occurrence Count")
            ax.grid(True, axis="x")
        else:
            _empty(ax, "No service names found"); ax.set_title("Top Service Types")
    else:
        _empty(ax, "No service data"); ax.set_title("Top Service Types")

    # 4 – Image type distribution
    ax = axes[3]
    if "image" in df.columns:
        img_counts = df["image"].value_counts()
        if not img_counts.empty:
            colors = [PALETTE[i % len(PALETTE)] for i in range(len(img_counts))]
            bars = ax.bar(img_counts.index, img_counts.values, color=colors, edgecolor=BG)
            _bar_labels(ax, bars, fmt="{:.0f}")
            ax.set_title("Node Image Type Distribution")
            ax.set_xlabel("Image Type"); ax.set_ylabel("Node Count")
            ax.tick_params(axis="x", rotation=20); ax.grid(True, axis="y")
        else:
            _empty(ax, "No image data"); ax.set_title("Image Distribution")
    else:
        _empty(ax, "No image data"); ax.set_title("Image Distribution")

    # 5 – Service credentials per node
    ax = axes[4]
    if "num_service_credentials" in df.columns:
        creds = df["num_service_credentials"].dropna()
        ax.hist(creds, bins=range(0, int(creds.max())+2), color=PALETTE[4], edgecolor=BG, align="left")
        ax.axvline(creds.mean(), color=PALETTE[1], lw=2, ls="--",
                   label=f"Mean={creds.mean():.2f}")
        ax.set_title("Service Credentials per Node")
        ax.set_xlabel("# Allowed Credentials"); ax.set_ylabel("# Nodes")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "No credential data"); ax.set_title("Service Credentials per Node")

    # 6 – Unique subnets per scenario
    ax = axes[5]
    if "unique_subnets" in df_sc.columns:
        ax.hist(df_sc["unique_subnets"].dropna(), bins=20, color=PALETTE[5], edgecolor=BG)
        ax.axvline(df_sc["unique_subnets"].mean(), color=PALETTE[1], lw=2, ls="--",
                   label=f"Mean={df_sc['unique_subnets'].mean():.1f}")
        ax.set_title("Unique Subnets per Scenario")
        ax.set_xlabel("# Unique Subnets"); ax.set_ylabel("# Scenarios")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "No subnet data"); ax.set_title("Unique Subnets per Scenario")

    _save_or_show(fig, "services_graphs")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 – VULNERABILITY RATES & OUTCOMES  (NEW)
# ═══════════════════════════════════════════════════════════════════════════════

def plot_vuln_rates_graphs(analyzer):
    """6 graphs on exploit rates, detection rates, costs, and leakage outcomes."""
    _style()
    df    = analyzer.get_node_dataframe()
    df_sc = analyzer.get_scenario_dataframe()
    domain = analyzer.domain_name

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"VULNERABILITY RATES & OUTCOMES  ·  {domain.upper()}")
    axes = axes.flatten()

    # 1 – Exploit success rate distribution
    ax = axes[0]
    if "avg_success_rate" in df.columns:
        sr = df["avg_success_rate"].dropna()
        ax.hist(sr, bins=30, color=PALETTE[3], edgecolor=BG, alpha=0.9)
        ax.axvline(sr.mean(), color=PALETTE[1], lw=2, ls="--", label=f"Mean={sr.mean():.3f}")
        ax.set_title("Avg Exploit Success Rate per Node")
        ax.set_xlabel("Success Rate (0–1)"); ax.set_ylabel("# Nodes")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "No success rate data"); ax.set_title("Exploit Success Rate")

    # 2 – Detection rates: probing vs exploit
    ax = axes[1]
    has_pdr = "avg_probing_detect_rate" in df.columns
    has_edr = "avg_exploit_detect_rate" in df.columns
    if has_pdr or has_edr:
        if has_pdr:
            pdr = df["avg_probing_detect_rate"].dropna()
            ax.hist(pdr, bins=30, alpha=0.75, color=PALETTE[0], label="Probing Detection", edgecolor=BG)
        if has_edr:
            edr = df["avg_exploit_detect_rate"].dropna()
            ax.hist(edr, bins=30, alpha=0.75, color=PALETTE[2], label="Exploit Detection", edgecolor=BG)
        ax.set_title("Detection Rate Distributions per Node")
        ax.set_xlabel("Detection Rate (0–1)"); ax.set_ylabel("# Nodes")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "No detection rate data")

    # 3 – Success rate vs node value scatter
    ax = axes[2]
    if "avg_success_rate" in df.columns:
        sample = df[["value","avg_success_rate","remote_vulnerabilities"]].dropna()
        sample = sample.sample(min(2000, len(sample)), random_state=42)
        sc = ax.scatter(sample["value"], sample["avg_success_rate"],
                        alpha=0.4, s=20, c=sample["remote_vulnerabilities"],
                        cmap="plasma", edgecolors="none")
        plt.colorbar(sc, ax=ax, label="Remote Vulns")
        ax.set_title("Node Value vs Avg Success Rate")
        ax.set_xlabel("Node Value"); ax.set_ylabel("Avg Success Rate")
        ax.grid(True)
    else:
        _empty(ax, "No success rate data")

    # 4 – Vulnerability cost distribution
    ax = axes[3]
    if "total_vuln_cost" in df.columns:
        cost = df["total_vuln_cost"].dropna()
        cost = cost[cost > 0]
        if not cost.empty:
            ax.hist(cost, bins=30, color=PALETTE[5], edgecolor=BG)
            ax.axvline(cost.mean(), color=PALETTE[1], lw=2, ls="--",
                       label=f"Mean={cost.mean():.2f}")
            ax.legend()
        ax.set_title("Total Vulnerability Cost per Node (non-zero)")
        ax.set_xlabel("Total Cost"); ax.set_ylabel("# Nodes")
        ax.grid(True, axis="y")
    else:
        _empty(ax, "No cost data"); ax.set_title("Vulnerability Cost")

    # 5 – Outcome type breakdown (domain-wide stacked bar per scenario, top 20)
    ax = axes[4]
    outcome_cols = [c for c in ["total_outcome_probe","total_outcome_creds","total_outcome_nodes"]
                    if c in df_sc.columns]
    if outcome_cols:
        top20 = df_sc.nlargest(20, "num_nodes")[["scenario_name"] + outcome_cols].set_index("scenario_name")
        top20.columns = ["Probe","Cred Leak","Node Leak"]
        top20.plot(kind="bar", stacked=True, ax=ax,
                   color=[PALETTE[0], PALETTE[3], PALETTE[2]], edgecolor=BG)
        ax.set_title("Vulnerability Outcome Types (Top 20 Scenarios)")
        ax.set_xlabel(""); ax.set_ylabel("# Outcomes")
        ax.tick_params(axis="x", labelsize=6, rotation=45)
        ax.legend(fontsize=8); ax.grid(True, axis="y")
    else:
        _empty(ax, "No outcome data"); ax.set_title("Vulnerability Outcomes")

    # 6 – Credential & node leakage per scenario
    ax = axes[5]
    has_creds = "total_creds_leaked" in df_sc.columns
    has_nodes = "total_nodes_leaked" in df_sc.columns
    if has_creds or has_nodes:
        if has_creds:
            ax.hist(df_sc["total_creds_leaked"], bins=30, alpha=0.75,
                    color=PALETTE[1], label="Credentials Leaked", edgecolor=BG)
        if has_nodes:
            ax.hist(df_sc["total_nodes_leaked"], bins=30, alpha=0.75,
                    color=PALETTE[4], label="Node IDs Leaked", edgecolor=BG)
        ax.set_title("Leakage per Scenario")
        ax.set_xlabel("Count Leaked"); ax.set_ylabel("# Scenarios")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "No leakage data"); ax.set_title("Leakage per Scenario")

    _save_or_show(fig, "vuln_rates_graphs")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 – FIREWALL PERMISSIONS & COVERAGE  (NEW)
# ═══════════════════════════════════════════════════════════════════════════════

def plot_firewall_graphs(analyzer):
    """6 graphs on firewall rule permissions, priorities, asymmetry, and coverage gaps."""
    _style()
    df    = analyzer.get_node_dataframe()
    df_sc = analyzer.get_scenario_dataframe()
    domain = analyzer.domain_name

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"FIREWALL PERMISSIONS & COVERAGE  ·  {domain.upper()}")
    axes = axes.flatten()

    # 1 – Allow vs Deny breakdown (incoming)
    ax = axes[0]
    fw_allow_deny_cols = {
        "fw_in_allow": "In Allow", "fw_in_deny": "In Deny",
        "fw_out_allow": "Out Allow","fw_out_deny": "Out Deny",
    }
    present = {k: v for k, v in fw_allow_deny_cols.items() if k in df_sc.columns}
    if present:
        totals = {v: df_sc[k].sum() for k, v in present.items()}
        colors = [PALETTE[2], PALETTE[3], PALETTE[0], PALETTE[1]][:len(totals)]
        bars = ax.bar(list(totals.keys()), list(totals.values()), color=colors, edgecolor=BG)
        _bar_labels(ax, bars, fmt="{:.0f}")
        ax.set_title("Firewall Permission Breakdown (Domain Total)")
        ax.set_ylabel("Rule Count"); ax.grid(True, axis="y")
    else:
        _empty(ax, "No permission data"); ax.set_title("Firewall Permissions")

    # 2 – Firewall allow rate per scenario histogram
    ax = axes[1]
    if all(c in df_sc.columns for c in ["fw_in_allow","fw_in_deny","fw_out_allow","fw_out_deny"]):
        total_allow = df_sc["fw_in_allow"] + df_sc["fw_out_allow"]
        total_rules = (df_sc["firewall_incoming_rules"] + df_sc["firewall_outgoing_rules"]).replace(0, np.nan)
        allow_rate  = (total_allow / total_rules * 100).dropna()
        ax.hist(allow_rate, bins=30, color=PALETTE[2], edgecolor=BG)
        ax.axvline(allow_rate.mean(), color=PALETTE[1], lw=2, ls="--",
                   label=f"Mean={allow_rate.mean():.1f}%")
        ax.set_title("Firewall Allow Rate per Scenario (%)")
        ax.set_xlabel("Allow Rate (%)"); ax.set_ylabel("# Scenarios")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "Insufficient data"); ax.set_title("FW Allow Rate")

    # 3 – Firewall coverage: nodes with no rules (incoming / outgoing / any)
    ax = axes[2]
    if "firewall_incoming" in df.columns and "firewall_outgoing" in df.columns:
        n = len(df)
        no_in  = (df["firewall_incoming"] == 0).sum()
        no_out = (df["firewall_outgoing"] == 0).sum()
        no_any = ((df["firewall_incoming"] == 0) & (df["firewall_outgoing"] == 0)).sum()
        labels = ["No Incoming\nRules","No Outgoing\nRules","No Rules\nAt All"]
        vals   = [(no_in/n)*100, (no_out/n)*100, (no_any/n)*100]
        colors = [PALETTE[1], PALETTE[3], PALETTE[5]]
        bars   = ax.bar(labels, vals, color=colors, edgecolor=BG)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() + 0.5, f"{v:.1f}%",
                    ha="center", fontsize=9, color=TEXT)
        ax.set_title("Nodes with Firewall Coverage Gaps (%)")
        ax.set_ylabel("% of Nodes"); ax.set_ylim(0, max(vals)*1.2 + 5)
        ax.grid(True, axis="y")
    else:
        _empty(ax, "No firewall data"); ax.set_title("Firewall Coverage Gaps")

    # 4 – Firewall asymmetry per scenario (inbound – outbound) / total
    ax = axes[4]
    if "firewall_incoming_rules" in df_sc.columns and "firewall_outgoing_rules" in df_sc.columns:
        total_fw = (df_sc["firewall_incoming_rules"] + df_sc["firewall_outgoing_rules"]).replace(0, np.nan)
        asym = ((df_sc["firewall_incoming_rules"] - df_sc["firewall_outgoing_rules"]) / total_fw).dropna()
        ax.hist(asym, bins=30, color=PALETTE[0], edgecolor=BG)
        ax.axvline(0, color=PALETTE[1], lw=2, ls="--", label="Balanced")
        ax.axvline(asym.mean(), color=PALETTE[3], lw=2, ls=":", label=f"Mean={asym.mean():.3f}")
        ax.set_title("Firewall Asymmetry per Scenario\n(+= more inbound, -= more outbound)")
        ax.set_xlabel("Asymmetry Ratio"); ax.set_ylabel("# Scenarios")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "No firewall data"); ax.set_title("Firewall Asymmetry")

    # 5 – Avg FW priority per node (violin)
    ax = axes[3]
    if "fw_avg_priority" in df.columns:
        prio = df["fw_avg_priority"].dropna()
        if not prio.empty:
            ax.violinplot([prio], positions=[0], showmedians=True,
                          bw_method=0.3)
            ax.set_xticks([0]); ax.set_xticklabels(["Avg FW Priority"])
            ax.set_title("Firewall Rule Priority Distribution")
            ax.set_ylabel("Priority Value"); ax.grid(True, axis="y")
        else:
            _empty(ax, "No priority data"); ax.set_title("FW Priority")
    else:
        _empty(ax, "No priority data"); ax.set_title("FW Priority")

    # 6 – Incoming vs Outgoing rules per node scatter
    ax = axes[5]
    if "firewall_incoming" in df.columns and "firewall_outgoing" in df.columns:
        sample = df[["firewall_incoming","firewall_outgoing","value"]].dropna()
        sample = sample.sample(min(2000, len(sample)), random_state=42)
        sc = ax.scatter(sample["firewall_incoming"], sample["firewall_outgoing"],
                        alpha=0.4, s=20, c=sample["value"],
                        cmap="viridis", edgecolors="none")
        plt.colorbar(sc, ax=ax, label="Node Value")
        lim = max(sample["firewall_incoming"].max(), sample["firewall_outgoing"].max()) + 1
        ax.plot([0, lim], [0, lim], color=SUBTEXT, lw=1, ls="--", label="y=x")
        ax.set_title("Incoming vs Outgoing FW Rules per Node")
        ax.set_xlabel("Incoming Rules"); ax.set_ylabel("Outgoing Rules")
        ax.legend(); ax.grid(True)
    else:
        _empty(ax, "No firewall data"); ax.set_title("Incoming vs Outgoing Rules")

    _save_or_show(fig, "firewall_graphs")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 – SCENARIO COMPLEXITY DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

def plot_complexity_dashboard(analyzer):
    """Dense dashboard of scenario complexity with updated metrics."""
    _style()
    df_sc  = analyzer.get_scenario_dataframe()
    domain = analyzer.domain_name

    fig = plt.figure(figsize=(18, 12))
    fig.patch.set_facecolor(BG)
    gs = GridSpec(3, 4, figure=fig, hspace=0.45, wspace=0.35)
    _fig_title(fig, f"COMPLEXITY DASHBOARD  ·  {domain.upper()}",
               f"{len(df_sc):,} scenarios")

    # Build composite complexity score
    df = df_sc.copy()
    complexity_inputs = {
        "num_nodes":               0.25,
        "total_local_vulns":       0.15,
        "total_remote_vulns":      0.20,
        "firewall_incoming_rules": 0.10,
        "firewall_outgoing_rules": 0.10,
        "total_services":          0.10,   # NEW
        "total_creds_leaked":      0.10,   # NEW
    }
    df["complexity"] = 0.0
    for col, weight in complexity_inputs.items():
        if col in df.columns:
            mn, mx = df[col].min(), df[col].max()
            df["complexity"] += ((df[col] - mn) / (mx - mn + 1e-9)) * weight

    # 1 – Complexity score histogram
    ax1 = fig.add_subplot(gs[0, :2])
    ax1.hist(df["complexity"], bins=40, color=PALETTE[0], edgecolor=BG)
    ax1.axvline(df["complexity"].mean(), color=PALETTE[1], lw=2, ls="--",
                label=f"Mean={df['complexity'].mean():.3f}")
    ax1.set_title("Composite Complexity Score Distribution"); ax1.set_xlabel("Score")
    ax1.legend(); ax1.grid(True, axis="y")

    # 2 – Nodes vs complexity
    ax2 = fig.add_subplot(gs[0, 2:])
    ax2.scatter(df["num_nodes"], df["complexity"], alpha=0.3, s=10,
                color=PALETTE[2], edgecolors="none")
    ax2.set_title("Num Nodes vs Complexity")
    ax2.set_xlabel("# Nodes"); ax2.set_ylabel("Complexity")
    ax2.grid(True)

    # 3–6 – KDE plots for key metrics (row 2)
    metrics = [
        ("num_nodes",               "Nodes per Scenario",      PALETTE[0]),
        ("avg_node_value",          "Avg Node Value",           PALETTE[1]),
        ("avg_success_rate",        "Avg Exploit Success Rate", PALETTE[3]),   # NEW
        ("total_creds_leaked",      "Credentials Leaked",       PALETTE[4]),   # NEW
    ]
    for col_idx, (metric, title, color) in enumerate(metrics):
        ax = fig.add_subplot(gs[1, col_idx])
        if metric not in df.columns:
            _empty(ax, f"No {metric}"); ax.set_title(title, fontsize=8)
            continue
        data = df[metric].dropna()
        ax.hist(data, bins=25, color=color, edgecolor=BG, alpha=0.85, density=True)
        try:
            from scipy.stats import gaussian_kde
            kde = gaussian_kde(data)
            x_range = np.linspace(data.min(), data.max(), 200)
            ax.plot(x_range, kde(x_range), color="white", lw=1.5)
        except Exception:
            pass
        ax.set_title(title, fontsize=8); ax.set_ylabel("Density", fontsize=7)
        ax.tick_params(labelsize=7); ax.grid(True, axis="y")

    # 7 – Correlation heatmap (bottom row, full width) — extended with new cols
    ax_heat = fig.add_subplot(gs[2, :])
    corr_cols = [
        "num_nodes","avg_node_value","total_local_vulns","total_remote_vulns",
        "firewall_incoming_rules","firewall_outgoing_rules",
        "total_services","avg_success_rate","total_creds_leaked","complexity",
    ]
    corr_cols = [c for c in corr_cols if c in df.columns]
    corr = df[corr_cols].corr()
    sns.heatmap(corr, ax=ax_heat, cmap="coolwarm", center=0,
                annot=True, fmt=".2f", linewidths=0.5, linecolor=BG,
                cbar_kws={"shrink": 0.6})
    ax_heat.set_title("Scenario Metric Correlation Matrix", fontsize=10)
    ax_heat.tick_params(axis="x", rotation=30, labelsize=7)
    ax_heat.tick_params(axis="y", rotation=0,  labelsize=7)

    _save_or_show(fig, "complexity_dashboard")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 – CROSS-DOMAIN COMPARISON
# ═══════════════════════════════════════════════════════════════════════════════

def plot_cross_domain(analyzers):
    """
    Compare multiple domains side by side.
    Pass a list of DomainAnalysis objects (already processed).
    """
    _style()

    summaries = []
    for a in analyzers:
        s = a.domain_summary
        if not s:
            a.process_domain()
            s = a.domain_summary
        summaries.append(s)

    df_sum  = pd.DataFrame(summaries).set_index("Domain Name")
    domains = df_sum.index.tolist()
    colors  = [PALETTE[i % len(PALETTE)] for i in range(len(domains))]

    fig, axes = plt.subplots(3, 4, figsize=(22, 15))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, "CROSS-DOMAIN COMPARISON", " · ".join(domains))
    axes = axes.flatten()

    def _bar(ax, metric, title, ylabel="", pct=False):
        if metric not in df_sum.columns:
            _empty(ax, f"'{metric}' not found"); ax.set_title(title); return
        vals = df_sum[metric].astype(float)
        bars = ax.bar(domains, vals, color=colors, edgecolor=BG)
        suffix = "%" if pct else ""
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() * 1.01,
                    f"{bar.get_height():.1f}{suffix}",
                    ha="center", fontsize=8, color=TEXT)
        ax.set_title(title); ax.set_ylabel(ylabel or metric)
        ax.tick_params(axis="x", rotation=20); ax.grid(True, axis="y")

    # Row 1 – topology
    _bar(axes[0],  "Nodes per Scenario (Mean)",          "Avg Nodes / Scenario",         "Nodes")
    _bar(axes[1],  "Node Value (Mean)",                   "Mean Node Value",               "Value")
    _bar(axes[2],  "Nodes with Agent Installed (%)",      "Agent Coverage",                "%",  pct=True)
    _bar(axes[3],  "Goal Nodes (%)",                      "Goal Nodes",                    "%",  pct=True)

    # Row 2 – vulnerabilities
    ax = axes[4]  # stacked local + remote
    loc_col = "Total Local Vulnerabilities"
    rem_col = "Total Remote Vulnerabilities"
    if loc_col in df_sum.columns and rem_col in df_sum.columns:
        loc_v = df_sum[loc_col].astype(float)
        rem_v = df_sum[rem_col].astype(float)
        ax.bar(domains, loc_v, color=PALETTE[3], edgecolor=BG, label="Local")
        ax.bar(domains, rem_v, bottom=loc_v, color=PALETTE[0], edgecolor=BG, label="Remote")
        ax.set_title("Total Vulnerabilities by Type"); ax.set_ylabel("Count")
        ax.tick_params(axis="x", rotation=20); ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(axes[4], "No vuln data"); axes[4].set_title("Vulnerabilities")

    _bar(axes[5],  "Avg Exploit Success Rate",            "Avg Exploit Success Rate",      "Rate (0–1)")
    _bar(axes[6],  "Avg Probing Detection Rate",          "Avg Probing Detection Rate",    "Rate (0–1)")
    _bar(axes[7],  "Domain Stealth Score (0=stealthy)",   "Domain Stealth Score",          "Score")

    # Row 3 – services, firewall, risk, leakage
    _bar(axes[8],  "Avg Services per Node",               "Avg Services / Node",           "Services")
    _bar(axes[9],  "FW Allow Rate (%)",                   "Firewall Allow Rate",           "%",  pct=True)
    _bar(axes[10], "Attack Surface Index (0–1)",          "Attack Surface Index",          "Index (0–1)")
    _bar(axes[11], "Total Credentials Leaked",            "Total Credentials Leaked",      "Count")

    _save_or_show(fig, "cross_domain")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 11 – DATA QUALITY
# ═══════════════════════════════════════════════════════════════════════════════

def plot_data_quality(analyzer):
    """6 graphs on null rates, outliers, and distribution shape."""
    _style()
    dq     = getattr(analyzer, 'data_quality', None)
    df     = analyzer.get_node_dataframe()
    domain = analyzer.domain_name
    if dq is None:
        analyzer.analyze_data_quality()
        dq = analyzer.data_quality

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"DATA QUALITY  ·  {domain.upper()}")
    axes = axes.flatten()

    # 1 – Null rate per field
    ax = axes[0]
    null_rates = dq.get('Null Rate per Field (%)', {})
    if null_rates:
        labels = list(null_rates.keys())
        vals   = [null_rates[k] for k in labels]
        colors = [PALETTE[3] if v > 0 else PALETTE[2] for v in vals]
        ax.barh(labels[::-1], vals[::-1], color=colors[::-1], edgecolor=BG)
        ax.axvline(0, color=SUBTEXT, lw=1)
        ax.set_title("Null / Missing Rate per Field (%)")
        ax.set_xlabel("Missing (%)"); ax.grid(True, axis="x")
    else:
        _empty(ax, "No null rate data"); ax.set_title("Null Rates")

    # 2 – Outlier % per field
    ax = axes[1]
    out_data = dq.get('Outliers by Field', {})
    if out_data:
        out_labels = list(out_data.keys())
        out_pcts   = [out_data[k]['pct'] for k in out_labels]
        bars = ax.bar(out_labels, out_pcts,
                      color=[PALETTE[i % len(PALETTE)] for i in range(len(out_labels))],
                      edgecolor=BG)
        _bar_labels(ax, bars, fmt="{:.1f}")
        ax.set_title("Outlier Rate per Field (IQR 1.5×)")
        ax.set_ylabel("% Outliers"); ax.grid(True, axis="y")
        ax.tick_params(axis="x", rotation=25)
    else:
        _empty(ax, "No outlier data"); ax.set_title("Outliers")

    # 3 – Node value Q-Q plot
    ax = axes[2]
    from scipy import stats as sp_stats
    vals = df['value'].dropna()
    if len(vals) > 4:
        (osm, osr), (slope, intercept, r) = sp_stats.probplot(vals)
        ax.scatter(osm, osr, alpha=0.3, s=10, color=PALETTE[0], edgecolors='none')
        ax.plot(osm, slope * np.array(osm) + intercept,
                color=PALETTE[1], lw=2, ls='--', label=f'R²={r**2:.3f}')
        ax.set_title("Q-Q Plot: Node Value vs Normal")
        ax.set_xlabel("Theoretical Quantiles"); ax.set_ylabel("Sample Quantiles")
        ax.legend(); ax.grid(True)
    else:
        _empty(ax, "Insufficient data"); ax.set_title("Q-Q Plot")

    # 4 – Skewness & kurtosis bar chart
    ax = axes[3]
    shape = dq.get('Shape Stats', {})
    if shape:
        metrics = list(shape.keys())
        skews   = [shape[m]['skewness']  for m in metrics]
        kurts   = [shape[m]['kurtosis']  for m in metrics]
        x       = np.arange(len(metrics))
        w       = 0.35
        ax.bar(x - w/2, skews, w, label='Skewness', color=PALETTE[0], edgecolor=BG)
        ax.bar(x + w/2, kurts, w, label='Kurtosis', color=PALETTE[1], edgecolor=BG)
        ax.axhline(0, color=SUBTEXT, lw=1, ls='--')
        ax.set_xticks(x); ax.set_xticklabels(metrics, rotation=15)
        ax.set_title("Skewness & Kurtosis per Field")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "No shape data"); ax.set_title("Distribution Shape")

    # 5 – Normality test results table
    ax = axes[4]
    norm = dq.get('Normality Tests (Shapiro-Wilk)', {})
    if norm:
        cols_n   = list(norm.keys())
        p_vals   = [norm[c]['p_value']  for c in cols_n]
        is_norm  = [norm[c]['normal']   for c in cols_n]
        bar_cols = [PALETTE[2] if n else PALETTE[3] for n in is_norm]
        bars = ax.bar(cols_n, p_vals, color=bar_cols, edgecolor=BG)
        ax.axhline(0.05, color=PALETTE[1], lw=2, ls='--', label='p=0.05')
        for bar, pv in zip(bars, p_vals):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() + 0.001,
                    f"{pv:.4f}", ha='center', fontsize=8, color=TEXT)
        ax.set_title("Shapiro-Wilk Normality Test p-values\n(green=normal, red=non-normal)")
        ax.set_ylabel("p-value"); ax.legend(); ax.grid(True, axis="y")
        ax.tick_params(axis="x", rotation=15)
    else:
        _empty(ax, "No normality data"); ax.set_title("Normality Tests")

    # 6 – SLA weight zero vs non-zero pie
    ax = axes[5]
    if 'sla_weight' in df.columns:
        zero_sla = (df['sla_weight'] == 0).sum()
        nonz_sla = len(df) - zero_sla
        ax.pie([zero_sla, nonz_sla],
               labels=[f'Zero SLA\n({zero_sla})', f'Non-zero SLA\n({nonz_sla})'],
               colors=[PALETTE[3], PALETTE[2]],
               autopct='%1.1f%%', startangle=90,
               textprops={'color': TEXT, 'fontsize': 9},
               wedgeprops={'edgecolor': BG, 'linewidth': 1.5})
        ax.set_title("SLA Weight: Zero vs Non-Zero Nodes")
    else:
        _empty(ax, "No SLA data"); ax.set_title("SLA Coverage")

    _save_or_show(fig, "data_quality")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 12 – SCENARIO DIVERSITY
# ═══════════════════════════════════════════════════════════════════════════════

def plot_diversity(analyzer):
    """6 graphs on scenario diversity, Jaccard similarity, and vocabulary coverage."""
    _style()
    div    = getattr(analyzer, 'diversity', None)
    domain = analyzer.domain_name
    if div is None:
        analyzer.analyze_diversity()
        div = analyzer.diversity

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"SCENARIO DIVERSITY  ·  {domain.upper()}",
               f"Diversity Index: {div['Scenario Diversity Index (0-1)']:.3f}  ·  "
               f"Avg Jaccard: {div['Avg Pairwise Jaccard Similarity']:.3f}")
    axes = axes.flatten()

    scenarios  = div['Scenario Names']
    sim_matrix = div['Jaccard Similarity Matrix']
    n_scen     = len(scenarios)

    # 1 – Jaccard similarity heatmap (sample up to 40 scenarios for readability)
    ax = axes[0]
    MAX_DISPLAY = 40
    if n_scen > MAX_DISPLAY:
        idx   = np.linspace(0, n_scen-1, MAX_DISPLAY, dtype=int)
        sm    = sim_matrix[np.ix_(idx, idx)]
        slbls = [scenarios[i][:12] for i in idx]
    else:
        sm    = sim_matrix
        slbls = [s[:12] for s in scenarios]
    show_annot = n_scen <= 20
    sns.heatmap(sm, ax=ax, cmap='YlOrRd', vmin=0, vmax=1,
                annot=show_annot, fmt='.2f' if show_annot else '',
                xticklabels=slbls, yticklabels=slbls,
                linewidths=0 if n_scen > 20 else 0.3,
                cbar_kws={'label': 'Jaccard Similarity'})
    ax.set_title("Pairwise Jaccard Similarity Heatmap")
    ax.tick_params(axis='x', labelsize=5, rotation=45)
    ax.tick_params(axis='y', labelsize=5, rotation=0)

    # 2 – Distribution of pairwise similarities (off-diagonal)
    ax = axes[1]
    mask = ~np.eye(n_scen, dtype=bool)
    off_diag = sim_matrix[mask]
    ax.hist(off_diag, bins=40, color=PALETTE[0], edgecolor=BG, alpha=0.9)
    ax.axvline(off_diag.mean(), color=PALETTE[1], lw=2, ls='--',
               label=f"Mean={off_diag.mean():.3f}")
    ax.axvline(np.median(off_diag), color=PALETTE[2], lw=2, ls=':',
               label=f"Median={np.median(off_diag):.3f}")
    ax.set_title("Distribution of Pairwise Jaccard Similarities")
    ax.set_xlabel("Jaccard Similarity"); ax.set_ylabel("Pair Count")
    ax.legend(); ax.grid(True, axis="y")

    # 3 – Vocabulary coverage per scenario histogram
    ax = axes[2]
    vc = np.array(div['Vocabulary Coverage per Scenario']) * 100
    ax.hist(vc, bins=30, color=PALETTE[2], edgecolor=BG)
    ax.axvline(vc.mean(), color=PALETTE[1], lw=2, ls='--',
               label=f"Mean={vc.mean():.1f}%")
    ax.set_title("Vocabulary Coverage per Scenario\n(% of domain vocab used)")
    ax.set_xlabel("Coverage (%)"); ax.set_ylabel("# Scenarios")
    ax.legend(); ax.grid(True, axis="y")

    # 4 – Near-duplicate detection: # scenarios with similarity > 0.9
    ax = axes[3]
    thresholds = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95]
    pair_counts = []
    for t in thresholds:
        pairs = int(np.sum(sim_matrix[mask] > t) / 2)
        pair_counts.append(pairs)
    ax.bar([str(t) for t in thresholds], pair_counts,
           color=[PALETTE[i % len(PALETTE)] for i in range(len(thresholds))],
           edgecolor=BG)
    ax.set_title("Near-Duplicate Scenario Pairs by Similarity Threshold")
    ax.set_xlabel("Jaccard Threshold"); ax.set_ylabel("# Pairs")
    ax.grid(True, axis="y")

    # 5 – Scenario size vs vocabulary coverage scatter
    ax = axes[4]
    df_scen = analyzer.get_scenario_dataframe()
    if len(df_scen) == len(vc):
        ax.scatter(df_scen['num_nodes'], vc,
                   alpha=0.5, s=15, color=PALETTE[4], edgecolors='none')
        ax.set_title("Scenario Size vs Vocabulary Coverage")
        ax.set_xlabel("# Nodes"); ax.set_ylabel("Vocab Coverage (%)")
        ax.grid(True)
    else:
        _empty(ax, "Size mismatch"); ax.set_title("Size vs Coverage")

    # 6 – Fingerprint uniqueness summary
    ax = axes[5]
    unique_fp = div['Unique Scenario Fingerprints']
    dup_fp    = div['Duplicate Scenario Fingerprints']
    ax.pie([unique_fp, dup_fp],
           labels=[f'Unique\n({unique_fp})', f'Duplicate\n({dup_fp})'],
           colors=[PALETTE[2], PALETTE[3]],
           autopct='%1.1f%%', startangle=140,
           textprops={'color': TEXT, 'fontsize': 10},
           wedgeprops={'edgecolor': BG, 'linewidth': 1.5})
    ax.set_title("Scenario Fingerprint Uniqueness\n(node count + property set)")

    _save_or_show(fig, "diversity")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 13 – CLASS BALANCE & REPRESENTATION
# ═══════════════════════════════════════════════════════════════════════════════

def plot_class_balance(analyzer):
    """6 graphs on goal prevalence, Gini, vulnerability balance, and degenerate scenarios."""
    _style()
    cb     = getattr(analyzer, 'class_balance', None)
    df     = analyzer.get_node_dataframe()
    df_sc  = analyzer.get_scenario_dataframe()
    domain = analyzer.domain_name
    if cb is None:
        analyzer.analyze_class_balance()
        cb = analyzer.class_balance

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"CLASS BALANCE & REPRESENTATION  ·  {domain.upper()}")
    axes = axes.flatten()

    # 1 – Goal prevalence distribution across scenarios
    ax = axes[0]
    goal_pct = df_sc['goal_pct'] if 'goal_pct' in df_sc.columns else \
               (df_sc['nodes_is_goal'] / df_sc['num_nodes'].replace(0,1) * 100)
    ax.hist(goal_pct, bins=30, color=PALETTE[0], edgecolor=BG)
    ax.axvline(goal_pct.mean(), color=PALETTE[1], lw=2, ls='--',
               label=f"Mean={goal_pct.mean():.2f}%")
    ax.set_title("Goal Node Prevalence per Scenario (%)")
    ax.set_xlabel("Goal Nodes (%)"); ax.set_ylabel("# Scenarios")
    ax.legend(); ax.grid(True, axis="y")

    # 2 – Lorenz curve for property frequency (Gini visualisation)
    ax = axes[1]
    from collections import Counter as _Counter
    all_props  = [p for sub in df['properties'].dropna() for p in sub]
    prop_freqs = np.array(sorted(_Counter(all_props).values(), ), dtype=float)
    if len(prop_freqs) > 0:
        prop_freqs /= prop_freqs.sum()
        cum = np.cumsum(np.sort(prop_freqs))
        x   = np.linspace(0, 1, len(cum))
        ax.plot(x, cum, color=PALETTE[0], lw=2, label='Lorenz curve')
        ax.plot([0,1],[0,1], color=SUBTEXT, lw=1, ls='--', label='Perfect equality')
        ax.fill_between(x, x, cum, alpha=0.2, color=PALETTE[0])
        gini = cb.get('Property Frequency Gini', 0)
        ax.text(0.05, 0.85, f"Gini = {gini:.3f}", transform=ax.transAxes,
                fontsize=11, color=PALETTE[0], fontfamily='monospace')
        ax.set_title("Lorenz Curve — Property Frequency\n(Gini: 0=uniform, 1=concentrated)")
        ax.set_xlabel("Cumulative Properties"); ax.set_ylabel("Cumulative Frequency")
        ax.legend(); ax.grid(True)
    else:
        _empty(ax, "No property data"); ax.set_title("Lorenz Curve")

    # 3 – Local:Remote vuln ratio distribution
    ax = axes[2]
    ratio = df_sc['local_to_remote_vuln_ratio'].dropna()
    if not ratio.empty:
        ax.hist(ratio[ratio.between(0,10)], bins=30, color=PALETTE[3], edgecolor=BG)
        ax.axvline(1.0, color=PALETTE[1], lw=2, ls='--', label='1:1 balanced')
        ax.axvline(ratio.mean(), color=PALETTE[2], lw=2, ls=':',
                   label=f"Mean={ratio.mean():.2f}")
        ax.set_title("Local:Remote Vulnerability Ratio per Scenario")
        ax.set_xlabel("Local / Remote Ratio"); ax.set_ylabel("# Scenarios")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "No ratio data"); ax.set_title("Vuln Balance")

    # 4 – Value concentration: top-N% share bar
    ax = axes[4]
    vals_sorted = df['value'].sort_values(ascending=False).reset_index(drop=True)
    total_val   = vals_sorted.sum()
    if total_val > 0:
        pct_nodes  = [1, 5, 10, 25, 50]
        val_shares = []
        for p in pct_nodes:
            cut = max(int(len(vals_sorted) * p / 100), 1)
            val_shares.append(vals_sorted.iloc[:cut].sum() / total_val * 100)
        bars = ax.bar([f"Top {p}%" for p in pct_nodes], val_shares,
                      color=[PALETTE[i % len(PALETTE)] for i in range(len(pct_nodes))],
                      edgecolor=BG)
        _bar_labels(ax, bars, fmt="{:.1f}")
        ax.set_title("Value Concentration\n(top-N% of nodes hold X% of total value)")
        ax.set_ylabel("% of Total Value"); ax.grid(True, axis="y")
    else:
        _empty(ax, "No value data"); ax.set_title("Value Concentration")

    # 5 – Degenerate scenario summary
    ax = axes[3]
    degen_labels = ['No Goal\nNodes', 'No Agent\nNodes', 'No Vuln\nNodes', 'No Remote\nVulns']
    degen_vals   = [
        cb.get('Scenarios with Zero Goal Nodes', 0),
        cb.get('Degenerate: No Agent Scenarios', 0),
        cb.get('Degenerate: No Vuln Scenarios',  0),
        cb.get('Degenerate: No Remote Vuln Scenarios', 0),
    ]
    n_scen_total = max(len(df_sc), 1)
    degen_pcts   = [v / n_scen_total * 100 for v in degen_vals]
    bars = ax.bar(degen_labels, degen_pcts,
                  color=[PALETTE[3] if v > 0 else PALETTE[2] for v in degen_vals],
                  edgecolor=BG)
    for bar, raw in zip(bars, degen_vals):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 0.3,
                f"{raw}", ha='center', fontsize=9, color=TEXT)
    ax.set_title("Degenerate Scenarios Count")
    ax.set_ylabel("% of All Scenarios"); ax.grid(True, axis="y")

    # 6 – Node value distribution with skew annotation
    ax = axes[5]
    vals = df['value'].dropna()
    ax.hist(vals, bins=40, color=PALETTE[4], edgecolor=BG, alpha=0.9)
    ax.axvline(vals.mean(),   color=PALETTE[1], lw=2, ls='--', label=f"Mean={vals.mean():.0f}")
    ax.axvline(np.median(vals), color=PALETTE[2], lw=2, ls=':',  label=f"Median={np.median(vals):.0f}")
    skew = cb.get('Node Value Skewness', 0)
    kurt = cb.get('Node Value Kurtosis', 0)
    ax.text(0.97, 0.97, f"Skew={skew:.2f}\nKurt={kurt:.2f}",
            ha='right', va='top', transform=ax.transAxes,
            fontsize=9, color=SUBTEXT, fontfamily='monospace')
    ax.set_title("Node Value Distribution (shape annotated)")
    ax.set_xlabel("Value"); ax.set_ylabel("# Nodes")
    ax.legend(); ax.grid(True, axis="y")

    _save_or_show(fig, "class_balance")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 14 – ATTACK SURFACE & LATERAL MOVEMENT
# ═══════════════════════════════════════════════════════════════════════════════

def plot_attack_surface_detail(analyzer):
    """6 graphs on pivot nodes, crown jewels, goal exposure, and attack chains."""
    _style()
    atk    = getattr(analyzer, 'attack_surface', None)
    df     = analyzer.get_node_dataframe()
    df_sc  = analyzer.get_scenario_dataframe()
    domain = analyzer.domain_name
    if atk is None:
        analyzer.analyze_attack_surface()
        atk = analyzer.attack_surface

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"ATTACK SURFACE & LATERAL MOVEMENT  ·  {domain.upper()}")
    axes = axes.flatten()

    # 1 – Node role breakdown: pivot / crown jewel / goal / other
    ax = axes[0]
    n = len(df)
    pivot_mask = (df.get('remote_vulnerabilities', pd.Series([0])) > 0) & \
                 (df.get('total_creds_leaked',     pd.Series([0])) > 0)
    val_q75    = df['value'].quantile(0.75)
    crown_mask = (df['value'] >= val_q75) & \
                 (df.get('remote_vulnerabilities', pd.Series([0])) > 0)
    goal_mask  = df.get('is_goal', pd.Series([False])).astype(bool)
    cats  = ['Pivot', 'Crown Jewel', 'Goal', 'Other']
    pivot_n = int(pivot_mask.sum())
    crown_n = int(crown_mask.sum())
    goal_n  = int(goal_mask.sum())
    other_n = n - pivot_n - crown_n - goal_n
    vals  = [max(pivot_n,0), max(crown_n,0), max(goal_n,0), max(other_n,0)]
    ax.pie(vals, labels=[f'{c}\n({v})' for c,v in zip(cats,vals)],
           colors=[PALETTE[3],PALETTE[1],PALETTE[0],PALETTE[8]],
           autopct='%1.1f%%', startangle=140,
           textprops={'color': TEXT, 'fontsize':9},
           wedgeprops={'edgecolor': BG, 'linewidth': 1.5})
    ax.set_title("Node Role Breakdown")

    # 2 – Crown jewel nodes: value vs remote vulns
    ax = axes[1]
    sample = df.sample(min(2000, n), random_state=42)
    sc = ax.scatter(sample['value'], sample.get('remote_vulnerabilities', pd.Series([0]*len(sample))),
                    alpha=0.4, s=20,
                    c=sample.get('is_goal', pd.Series([False]*len(sample))).astype(int),
                    cmap='RdYlGn', edgecolors='none')
    plt.colorbar(sc, ax=ax, label='Is Goal')
    ax.axvline(val_q75, color=PALETTE[1], lw=1.5, ls='--', alpha=0.7, label='Value Q75')
    ax.axhline(0.5,     color=PALETTE[3], lw=1.5, ls='--', alpha=0.7, label='Has Remote Vuln')
    ax.set_title("Value vs Remote Vulns\n(top-right = crown jewels)")
    ax.set_xlabel("Node Value"); ax.set_ylabel("Remote Vulnerabilities")
    ax.legend(fontsize=8); ax.grid(True)

    # 3 – Goal node protection profile (radar-style bar)
    ax = axes[2]
    goal_df    = df[goal_mask]
    all_df     = df
    protect_metrics = {
        'Avg FW Rules': (
            goal_df.get('firewall_incoming', pd.Series([0])).mean() +
            goal_df.get('firewall_outgoing', pd.Series([0])).mean()
            if not goal_df.empty else 0,
            all_df.get('firewall_incoming', pd.Series([0])).mean() +
            all_df.get('firewall_outgoing', pd.Series([0])).mean()
        ),
        'Avg Privilege': (
            goal_df['privilege_level'].mean() if not goal_df.empty else 0,
            all_df['privilege_level'].mean()
        ),
        'Avg Value': (
            goal_df['value'].mean() if not goal_df.empty else 0,
            all_df['value'].mean()
        ),
    }
    x = np.arange(len(protect_metrics))
    w = 0.35
    goal_vals = [v[0] for v in protect_metrics.values()]
    all_vals  = [v[1] for v in protect_metrics.values()]
    ax.bar(x - w/2, goal_vals, w, label='Goal Nodes', color=PALETTE[0], edgecolor=BG)
    ax.bar(x + w/2, all_vals,  w, label='All Nodes',  color=PALETTE[8], edgecolor=BG, alpha=0.6)
    ax.set_xticks(x); ax.set_xticklabels(list(protect_metrics.keys()))
    ax.set_title("Goal Node Protection Profile\nvs Domain Average")
    ax.legend(); ax.grid(True, axis="y")

    # 4 – Scenarios with full attack chain (entry + cred leak)
    ax = axes[3]
    if 'total_remote_vulns' in df_sc.columns and 'total_creds_leaked' in df_sc.columns:
        has_entry  = df_sc['total_remote_vulns']  > 0
        has_creds  = df_sc['total_creds_leaked']  > 0
        has_goal_s = df_sc.get('nodes_is_goal', pd.Series([0])) > 0
        full_chain = has_entry & has_creds & has_goal_s
        partial    = (has_entry & has_creds) & ~has_goal_s
        entry_only = has_entry & ~has_creds
        neither    = ~has_entry
        cat_labels = ['Full Chain\n(entry+cred+goal)', 'Partial\n(entry+cred)',
                      'Entry Only', 'No Entry Point']
        cat_vals   = [full_chain.sum(), partial.sum(), entry_only.sum(), neither.sum()]
        bars = ax.bar(cat_labels, cat_vals,
                      color=[PALETTE[2], PALETTE[1], PALETTE[5], PALETTE[3]],
                      edgecolor=BG)
        _bar_labels(ax, bars, fmt="{:.0f}")
        ax.set_title("Attack Chain Completeness per Scenario")
        ax.set_ylabel("# Scenarios"); ax.grid(True, axis="y")
    else:
        _empty(ax, "No chain data"); ax.set_title("Attack Chains")

    # 5 – High-privilege remote-exposed nodes by privilege level
    ax = axes[4]
    if 'privilege_level' in df.columns and 'remote_vulnerabilities' in df.columns:
        grp = df.groupby('privilege_level').apply(
            lambda g: (g['remote_vulnerabilities'] > 0).sum()
        ).reset_index()
        grp.columns = ['privilege_level', 'exposed_count']
        total_per   = df.groupby('privilege_level').size().reset_index(name='total')
        grp = grp.merge(total_per, on='privilege_level')
        grp['exposed_pct'] = grp['exposed_count'] / grp['total'] * 100
        bars = ax.bar(grp['privilege_level'].astype(str), grp['exposed_pct'],
                      color=[PALETTE[i % len(PALETTE)] for i in range(len(grp))],
                      edgecolor=BG)
        _bar_labels(ax, bars, fmt="{:.1f}")
        ax.set_title("Remote-Exposed Nodes (%) by Privilege Level")
        ax.set_xlabel("Privilege Level"); ax.set_ylabel("% Exposed")
        ax.grid(True, axis="y")
    else:
        _empty(ax, "No data"); ax.set_title("Exposure by Privilege")

    # 6 – Credential leak potential per scenario
    ax = axes[5]
    if 'total_creds_leaked' in df_sc.columns:
        ax.scatter(df_sc['num_nodes'], df_sc['total_creds_leaked'],
                   alpha=0.4, s=15, color=PALETTE[3], edgecolors='none')
        ax.set_title("Scenario Size vs Credentials Leaked")
        ax.set_xlabel("# Nodes"); ax.set_ylabel("Total Credentials Leaked")
        ax.grid(True)
    else:
        _empty(ax, "No leakage data"); ax.set_title("Credential Leakage")

    _save_or_show(fig, "attack_surface_detail")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 15 – REWARD SIGNAL QUALITY
# ═══════════════════════════════════════════════════════════════════════════════

def plot_reward_signal(analyzer):
    """6 graphs on RL reward density, reachability, goal isolation, and solvability."""
    _style()
    rs     = getattr(analyzer, 'reward_signal', None)
    df     = analyzer.get_node_dataframe()
    df_sc  = analyzer.get_scenario_dataframe()
    domain = analyzer.domain_name
    if rs is None:
        analyzer.analyze_reward_signal()
        rs = analyzer.reward_signal

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"REWARD SIGNAL QUALITY  ·  {domain.upper()}")
    axes = axes.flatten()

    # 1 – Reward density per scenario
    ax = axes[0]
    if 'total_node_value' in df_sc.columns and 'num_nodes' in df_sc.columns:
        density = df_sc['total_node_value'] / df_sc['num_nodes'].replace(0, np.nan)
        ax.hist(density.dropna(), bins=30, color=PALETTE[0], edgecolor=BG)
        ax.axvline(density.mean(), color=PALETTE[1], lw=2, ls='--',
                   label=f"Mean={density.mean():.1f}")
        ax.set_title("Reward Density per Scenario\n(total value / # nodes)")
        ax.set_xlabel("Density"); ax.set_ylabel("# Scenarios")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "No density data"); ax.set_title("Reward Density")

    # 2 – Reachable vs unreachable value (bar)
    ax = axes[1]
    reach_val   = rs.get('Reachable Value (remote-exp nodes)', 0)
    unreach_val = df['value'].sum() - reach_val
    bars = ax.bar(['Reachable\n(remote-exp)', 'Unreachable'],
                  [reach_val, unreach_val],
                  color=[PALETTE[2], PALETTE[8]], edgecolor=BG)
    for bar in bars:
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() * 1.01,
                f"{bar.get_height():,.0f}", ha='center', fontsize=9, color=TEXT)
    ax.set_title(f"Total Value: Reachable vs Unreachable\n"
                 f"({rs.get('Reachable Value (%)' ,0):.1f}% reachable)")
    ax.set_ylabel("Total Value"); ax.grid(True, axis="y")

    # 3 – Solvability rate (pie)
    ax = axes[2]
    solv_rate  = rs.get('Solvability Rate (%)', 0)
    soft_rate  = rs.get('Soft Solvability Rate (%)', 0)
    n_scen     = len(df_sc)
    hard_solv  = int(n_scen * solv_rate  / 100)
    soft_only  = int(n_scen * soft_rate  / 100) - hard_solv
    unsolvable = n_scen - hard_solv - soft_only
    ax.pie([max(hard_solv,0), max(soft_only,0), max(unsolvable,0)],
           labels=[f'Fully Solvable\n({hard_solv})',
                   f'Partially\n({soft_only})',
                   f'Unsolvable\n({unsolvable})'],
           colors=[PALETTE[2], PALETTE[1], PALETTE[3]],
           autopct='%1.1f%%', startangle=140,
           textprops={'color': TEXT, 'fontsize': 9},
           wedgeprops={'edgecolor': BG, 'linewidth': 1.5})
    ax.set_title("Scenario Solvability\n(entry+cred+goal = fully solvable)")

    # 4 – Goal isolation score distribution
    ax = axes[3]
    goal_df = df[df.get('is_goal', pd.Series([False])).astype(bool)]
    if not goal_df.empty:
        fw_in  = goal_df.get('firewall_incoming', pd.Series([0]))
        fw_out = goal_df.get('firewall_outgoing', pd.Series([0]))
        total_fw = fw_in.values + fw_out.values
        ax.hist(total_fw, bins=20, color=PALETTE[4], edgecolor=BG)
        ax.axvline(np.mean(total_fw), color=PALETTE[1], lw=2, ls='--',
                   label=f"Mean={np.mean(total_fw):.1f}")
        ax.set_title("Goal Nodes: Total Firewall Rules\n(proxy for isolation)")
        ax.set_xlabel("Total FW Rules"); ax.set_ylabel("# Goal Nodes")
        ax.legend(); ax.grid(True, axis="y")
    else:
        _empty(ax, "No goal nodes"); ax.set_title("Goal Isolation")

    # 5 – Reachable vs unreachable node value CDF
    ax = axes[5]
    if 'remote_vulnerabilities' in df.columns:
        for label, mask_val, color in [
            ('Reachable (remote-exp)', df['remote_vulnerabilities'] > 0, PALETTE[2]),
            ('Unreachable',            df['remote_vulnerabilities'] == 0, PALETTE[3]),
        ]:
            vals = df[mask_val]['value'].sort_values()
            if len(vals) > 0:
                cdf = np.arange(1, len(vals)+1) / len(vals)
                ax.plot(vals, cdf, lw=2, color=color, label=label)
        ax.set_title("CDF of Node Value: Reachable vs Unreachable")
        ax.set_xlabel("Node Value"); ax.set_ylabel("Cumulative Probability")
        ax.legend(); ax.grid(True)
    else:
        _empty(ax, "No reachability data"); ax.set_title("Value CDF")

    # 6 – Reward density vs solvability scatter per scenario
    ax = axes[4]
    if 'total_node_value' in df_sc.columns and 'total_remote_vulns' in df_sc.columns:
        density_s = df_sc['total_node_value'] / df_sc['num_nodes'].replace(0, np.nan)
        solvable_s = (
            (df_sc.get('nodes_is_goal',    pd.Series([0])) > 0) &
            (df_sc['total_remote_vulns'] > 0)
        ).astype(int)
        ax.scatter(density_s, df_sc['total_remote_vulns'],
                   c=solvable_s, cmap='RdYlGn', alpha=0.5, s=15, edgecolors='none')
        ax.set_title("Reward Density vs Remote Vulns\n(green=solvable scenario)")
        ax.set_xlabel("Reward Density"); ax.set_ylabel("Total Remote Vulns")
        ax.grid(True)
    else:
        _empty(ax, "No data"); ax.set_title("Density vs Solvability")

    _save_or_show(fig, "reward_signal")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 16 – CROSS-DOMAIN STATISTICAL COMPARISON
# ═══════════════════════════════════════════════════════════════════════════════

def plot_statistical_comparison(analyzers: list):
    """
    Cross-domain statistical tests: Mann-Whitney U pairwise comparisons,
    Cohen's d effect sizes, one-way ANOVA, and a summary heatmap.
    Pass list of fully-analysed DomainAnalysis objects.
    """
    from scipy import stats as sp_stats
    _style()

    domains  = [a.domain_name for a in analyzers]
    n_dom    = len(domains)
    colors   = [PALETTE[i % len(PALETTE)] for i in range(n_dom)]

    TEST_METRICS = {
        'Node Value':          'value',
        'Total Vulns':         'total_vulnerabilities',
        'FW Rules (in)':       'firewall_incoming',
        'SLA Weight':          'sla_weight',
        'Services':            'num_services',
    }

    fig, axes = plt.subplots(2, 3, figsize=(20, 12))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, "CROSS-DOMAIN STATISTICAL COMPARISON",
               "Mann-Whitney U  ·  Cohen's d  ·  ANOVA")
    axes = axes.flatten()

    def cohens_d(a, b):
        na, nb = len(a), len(b)
        if na < 2 or nb < 2: return np.nan
        pooled = np.sqrt(((na-1)*np.var(a,ddof=1) + (nb-1)*np.var(b,ddof=1)) / (na+nb-2))
        return (np.mean(a) - np.mean(b)) / pooled if pooled != 0 else 0.0

    # 1 – Mann-Whitney p-value heatmap (per metric, pairwise)
    # Use first metric as the primary heatmap
    ax = axes[0]
    mw_matrix = np.ones((n_dom, n_dom))
    primary_col = list(TEST_METRICS.values())[0]
    data_arrays = []
    for a in analyzers:
        df = a.get_node_dataframe()
        data_arrays.append(df[primary_col].dropna().values if primary_col in df.columns else np.array([0]))

    for i in range(n_dom):
        for j in range(n_dom):
            if i != j and len(data_arrays[i]) > 0 and len(data_arrays[j]) > 0:
                _, p = sp_stats.mannwhitneyu(data_arrays[i], data_arrays[j],
                                              alternative='two-sided')
                mw_matrix[i, j] = round(p, 4)

    short_domains = [d.replace('_', '\n') for d in domains]
    sns.heatmap(mw_matrix, ax=ax, cmap='RdYlGn_r', vmin=0, vmax=0.1,
                annot=True, fmt='.3f',
                xticklabels=short_domains, yticklabels=short_domains,
                linewidths=0.5, linecolor=BG,
                cbar_kws={'label': 'p-value'})
    ax.set_title(f"Mann-Whitney U p-values\n({list(TEST_METRICS.keys())[0]})")
    ax.tick_params(labelsize=7)

    # 2 – Cohen's d heatmap (same primary metric)
    ax = axes[1]
    cd_matrix = np.zeros((n_dom, n_dom))
    for i in range(n_dom):
        for j in range(n_dom):
            if i != j:
                cd_matrix[i, j] = abs(cohens_d(data_arrays[i], data_arrays[j]))

    sns.heatmap(cd_matrix, ax=ax, cmap='Blues', vmin=0,
                annot=True, fmt='.2f',
                xticklabels=short_domains, yticklabels=short_domains,
                linewidths=0.5, linecolor=BG,
                cbar_kws={'label': "|Cohen's d|"})
    ax.set_title(f"|Cohen's d| Effect Sizes\n({list(TEST_METRICS.keys())[0]})")
    ax.tick_params(labelsize=7)

    # 3 – ANOVA F-statistic across domains for each metric
    ax = axes[2]
    anova_results = {}
    for metric_name, col in TEST_METRICS.items():
        groups = []
        for a in analyzers:
            df = a.get_node_dataframe()
            if col in df.columns:
                g = df[col].dropna().values
                if len(g) > 1:
                    groups.append(g)
        if len(groups) >= 2:
            try:
                f, p = sp_stats.f_oneway(*groups)
                anova_results[metric_name] = {'F': round(float(f),2), 'p': round(float(p),4)}
            except Exception:
                pass

    if anova_results:
        met_labels = list(anova_results.keys())
        f_vals     = [anova_results[m]['F'] for m in met_labels]
        p_vals_a   = [anova_results[m]['p'] for m in met_labels]
        bar_cols   = [PALETTE[2] if p < 0.05 else PALETTE[8] for p in p_vals_a]
        bars = ax.bar(met_labels, f_vals, color=bar_cols, edgecolor=BG)
        for bar, pv in zip(bars, p_vals_a):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() * 1.02,
                    f"p={pv:.3f}", ha='center', fontsize=7, color=TEXT)
        ax.set_title("One-way ANOVA F-statistic\n(green = p<0.05 significant)")
        ax.set_ylabel("F-statistic"); ax.grid(True, axis="y")
        ax.tick_params(axis="x", rotation=20)
    else:
        _empty(ax, "ANOVA failed"); ax.set_title("ANOVA")

    # 4 – Distribution violin plots side-by-side (node value)
    ax = axes[3]
    vdata = [a.get_node_dataframe()['value'].dropna().values for a in analyzers
             if 'value' in a.get_node_dataframe().columns]
    if vdata:
        parts = ax.violinplot(vdata, positions=range(n_dom), showmedians=True,
                              showextrema=True, bw_method=0.3)
        for i, pc in enumerate(parts['bodies']):
            pc.set_facecolor(colors[i]); pc.set_alpha(0.7)
        ax.set_xticks(range(n_dom))
        ax.set_xticklabels([d.replace('_','\n') for d in domains], fontsize=7)
        ax.set_title("Node Value Distribution per Domain (Violin)")
        ax.set_ylabel("Node Value"); ax.grid(True, axis="y")
    else:
        _empty(ax, "No value data"); ax.set_title("Value Violins")

    # 5 – Diversity index comparison (bar)
    ax = axes[4]
    div_vals  = [a.domain_summary.get('Diversity: Index (0=identical,1=unique)', np.nan)
                 for a in analyzers]
    gini_vals = [a.domain_summary.get('Property Frequency Gini', np.nan) for a in analyzers]
    x = np.arange(n_dom); w = 0.35
    ax.bar(x - w/2, div_vals,  w, label='Diversity Index', color=PALETTE[0], edgecolor=BG)
    ax.bar(x + w/2, gini_vals, w, label='Property Gini',   color=PALETTE[3], edgecolor=BG)
    ax.set_xticks(x); ax.set_xticklabels([d.replace('_','\n') for d in domains], fontsize=7)
    ax.set_title("Diversity Index vs Property Gini\nper Domain")
    ax.set_ylim(0, 1.1); ax.legend(); ax.grid(True, axis="y")

    # 6 – Solvability + reward density comparison
    ax = axes[5]
    solv_vals   = [a.domain_summary.get('Solvability Rate (%)',      0) for a in analyzers]
    reward_dens = [a.domain_summary.get('Reward Density (total value / nodes)', 0) for a in analyzers]
    x2   = np.arange(n_dom)
    ax2b = ax.twinx()
    bars1 = ax.bar(x2 - 0.2, solv_vals,   0.35, label='Solvability %',  color=PALETTE[2], edgecolor=BG, alpha=0.9)
    bars2 = ax2b.bar(x2 + 0.2, reward_dens, 0.35, label='Reward Density', color=PALETTE[1], edgecolor=BG, alpha=0.7)
    ax.set_ylabel("Solvability Rate (%)"); ax2b.set_ylabel("Reward Density")
    ax.set_xticks(x2); ax.set_xticklabels([d.replace('_','\n') for d in domains], fontsize=7)
    ax.set_title("Solvability Rate vs Reward Density")
    lines1, lab1 = ax.get_legend_handles_labels()
    lines2, lab2 = ax2b.get_legend_handles_labels()
    ax.legend(lines1 + lines2, lab1 + lab2, fontsize=8)
    ax.grid(True, axis="y")

    _save_or_show(fig, "statistical_comparison")
# ═══════════════════════════════════════════════════════════════════════════════

def plot_global_coverage(analyzer, global_ids: dict):
    """
    6 graphs comparing a domain's observed identifiers against the
    joint global identifier library.

    Parameters
    ----------
    analyzer   : DomainAnalysis (already processed)
    global_ids : dict parsed from joint_identifiers.yaml
    """
    _style()

    # Ensure comparison has been run
    if not hasattr(analyzer, 'global_comparison') or not analyzer.global_comparison:
        analyzer.compare_with_global(global_ids)

    gc     = analyzer.global_comparison
    df     = analyzer.get_node_dataframe()
    domain = analyzer.domain_name

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, f"GLOBAL IDENTIFIER COVERAGE  ·  {domain.upper()}",
               f"vs. joint_identifiers.yaml  ·  {gc['Global: Total Identifiers']:,} global identifiers")
    axes = axes.flatten()

    # 1 – Coverage % per category (bar chart)
    ax = axes[0]
    cats   = ['Properties', 'Service\nPorts', 'Local\nVulns', 'Remote\nVulns', 'Overall']
    covers = [
        gc.get('Coverage: Properties vs Global (%)',    0),
        gc.get('Coverage: Service Ports vs Global (%)', 0),
        gc.get('Coverage: Local Vulns vs Global (%)',   0),
        gc.get('Coverage: Remote Vulns vs Global (%)',  0),
        gc.get('Coverage: Overall Identifiers (%)',     0),
    ]
    colors = [PALETTE[i % len(PALETTE)] for i in range(len(cats))]
    bars   = ax.bar(cats, covers, color=colors, edgecolor=BG)
    for bar, v in zip(bars, covers):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.8,
                f"{v:.1f}%", ha="center", fontsize=9, color=TEXT)
    ax.axhline(100, color=SUBTEXT, lw=1, ls="--", alpha=0.5)
    ax.set_ylim(0, 115)
    ax.set_title("Coverage of Global Identifier Library (%)")
    ax.set_ylabel("Coverage (%)"); ax.grid(True, axis="y")

    # 2 – Used vs Unused global properties (stacked bar)
    ax = axes[1]
    used_ct   = gc.get('Domain: Unique Properties Observed', 0)
    unused_ct = gc.get('Unused Global Properties Count', 0)
    novel_ct  = gc.get('Novel Properties Count', 0)
    g_total   = gc.get('Global: Total Properties', 1)
    slices = {
        'Used (in global)':     used_ct - novel_ct,
        'Novel (not in global)':novel_ct,
        'Unused global props':  unused_ct,
    }
    wedge_colors = [PALETTE[2], PALETTE[1], PALETTE[3]]
    ax.pie(list(slices.values()), labels=list(slices.keys()),
           colors=wedge_colors, autopct='%1.1f%%',
           startangle=140, textprops={'color': TEXT, 'fontsize': 9},
           wedgeprops={'edgecolor': BG, 'linewidth': 1.5})
    ax.set_title(f"Property Pool Breakdown\n(Global={g_total})")

    # 3 – Top 10 used global properties (frequency bar)
    ax = axes[2]
    top_used = gc.get('Top 10 Used Global Properties', {})
    if top_used:
        labels_t = list(top_used.keys())
        vals_t   = list(top_used.values())
        colors_t = [PALETTE[i % len(PALETTE)] for i in range(len(labels_t))]
        ax.barh(labels_t[::-1], vals_t[::-1], color=colors_t[::-1], edgecolor=BG)
        ax.set_title("Top 10 Used Global Properties\n(by occurrence in domain)")
        ax.set_xlabel("Occurrence Count"); ax.grid(True, axis="x")
    else:
        _empty(ax, "No property usage data"); ax.set_title("Top Used Properties")

    # 4 – Property usage entropy gauge (simple horizontal bar)
    ax = axes[3]
    entropy = gc.get('Property Usage Entropy (normalised)', 0)
    ax.barh(['Entropy'], [entropy],        color=PALETTE[0],  edgecolor=BG, label='Domain')
    ax.barh(['Entropy'], [1 - entropy],    color=PALETTE[8],  edgecolor=BG,
            left=[entropy], alpha=0.3, label='Remaining')
    ax.axvline(0.5, color=SUBTEXT, lw=1.5, ls="--", alpha=0.7, label='Mid')
    ax.set_xlim(0, 1)
    ax.text(entropy / 2, 0, f"{entropy:.3f}", ha="center", va="center",
            fontsize=13, fontweight="bold", color=TEXT)
    ax.set_title("Property Usage Entropy (normalised)\n0 = specialised · 1 = broad/uniform")
    ax.set_xlabel("Entropy Score"); ax.legend(fontsize=8)
    ax.grid(True, axis="x")

    # 5 – Never-used global properties count by prefix group
    ax = axes[4]
    never_used = gc.get('Never-Used Global Properties', [])
    if never_used:
        # Group by first capital-letter run (e.g. "Solvability", "Remote", "Local", other)
        groups = Counter()
        for p in never_used:
            if '.' in p:
                groups[p.split('.')[0]] += 1
            elif p[0].isupper():
                groups[p[:3]] += 1
            else:
                groups['other'] += 1
        g_labels = list(groups.keys())[:12]
        g_vals   = [groups[k] for k in g_labels]
        colors_g = [PALETTE[i % len(PALETTE)] for i in range(len(g_labels))]
        ax.barh(g_labels[::-1], g_vals[::-1], color=colors_g[::-1], edgecolor=BG)
        ax.set_title(f"Never-Used Global Properties ({len(never_used)} total)\ngrouped by prefix")
        ax.set_xlabel("Count"); ax.grid(True, axis="x")
    else:
        _empty(ax, "All global properties used!"); ax.set_title("Never-Used Properties")

    # 6 – Per-node property diversity: domain vs global coverage heatmap
    ax = axes[5]
    # Scatter: node value vs num_properties, coloured by whether the node
    # uses exclusively global props (0) or has novel props (1+)
    if 'properties' in df.columns and 'value' in df.columns:
        g_props_set = set(global_ids.get('properties', []))
        df_plot = df.copy()
        df_plot['novel_prop_count'] = df_plot['properties'].apply(
            lambda lst: sum(1 for p in (lst or []) if p not in g_props_set)
        )
        sample = df_plot.sample(min(2000, len(df_plot)), random_state=42)
        sc = ax.scatter(sample['num_properties'], sample['novel_prop_count'],
                        alpha=0.5, s=20, c=sample['value'],
                        cmap='viridis', edgecolors='none')
        plt.colorbar(sc, ax=ax, label="Node Value")
        ax.set_title("Properties per Node vs Novel Property Count\n(coloured by node value)")
        ax.set_xlabel("# Properties (deduped)"); ax.set_ylabel("# Novel (not in global)")
        ax.grid(True)
    else:
        _empty(ax, "No property data"); ax.set_title("Property Diversity")

    _save_or_show(fig, "global_coverage")


def plot_cross_domain_coverage(analyzers: list, global_ids: dict):
    """
    Cross-domain comparison focused on global identifier coverage and specialisation.
    Pass a list of DomainAnalysis objects (already processed + compare_with_global called).
    """
    _style()

    for a in analyzers:
        if not hasattr(a, 'global_comparison') or not a.global_comparison:
            a.compare_with_global(global_ids)

    domains = [a.domain_name for a in analyzers]
    colors  = [PALETTE[i % len(PALETTE)] for i in range(len(domains))]

    fig, axes = plt.subplots(2, 3, figsize=(18, 11))
    fig.patch.set_facecolor(BG)
    _fig_title(fig, "CROSS-DOMAIN · GLOBAL IDENTIFIER COVERAGE",
               " · ".join(domains))
    axes = axes.flatten()

    def _bar(ax, key, title, ylabel=""):
        vals  = [a.global_comparison.get(key, 0) for a in analyzers]
        bars  = ax.bar(domains, vals, color=colors, edgecolor=BG)
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() * 1.01,
                    f"{bar.get_height():.1f}", ha="center", fontsize=8, color=TEXT)
        ax.set_title(title); ax.set_ylabel(ylabel or key)
        ax.tick_params(axis="x", rotation=20); ax.grid(True, axis="y")

    _bar(axes[0], 'Coverage: Properties vs Global (%)',    "Property Coverage vs Global",       "%")
    _bar(axes[1], 'Coverage: Local Vulns vs Global (%)',   "Local Vuln Coverage vs Global",     "%")
    _bar(axes[2], 'Coverage: Remote Vulns vs Global (%)',  "Remote Vuln Coverage vs Global",    "%")
    _bar(axes[3], 'Unused Global Properties (%)',          "Unused Global Properties",          "%")
    _bar(axes[4], 'Novel Properties Count',                "Novel Properties (not in global)",  "Count")
    _bar(axes[5], 'Property Usage Entropy (normalised)',   "Property Usage Entropy\n(0=specialised, 1=broad)", "Entropy")

    _save_or_show(fig, "cross_domain_coverage")


# ═══════════════════════════════════════════════════════════════════════════════
#  CONVENIENCE WRAPPER
# ═══════════════════════════════════════════════════════════════════════════════

def plot_all(analyzer, global_ids: dict = None):
    """Run all single-domain plot suites for a given DomainAnalysis object.
    Pass global_ids (parsed joint_identifiers.yaml) to include coverage suite.
    """
    if not analyzer.domain_summary:
        analyzer.process_domain()
    # Core topology & scenario
    plot_node_graphs(analyzer)
    plot_scenario_graphs(analyzer)
    plot_security_graphs(analyzer)
    plot_properties_graphs(analyzer)
    plot_services_graphs(analyzer)
    plot_vuln_rates_graphs(analyzer)
    plot_firewall_graphs(analyzer)
    plot_complexity_dashboard(analyzer)
    # Thesis-grade analysis
    plot_data_quality(analyzer)
    plot_diversity(analyzer)
    plot_class_balance(analyzer)
    plot_attack_surface_detail(analyzer)
    plot_reward_signal(analyzer)
    if global_ids is not None:
        plot_global_coverage(analyzer, global_ids)
    print(f"✅  All plots rendered for domain: {analyzer.domain_name}")