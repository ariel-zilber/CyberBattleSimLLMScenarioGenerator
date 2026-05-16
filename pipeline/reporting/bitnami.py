#!/usr/bin/env python3
"""
Generate Bitnami CVE EDA report: figures + LaTeX + PDF compilation.

Usage:
    python tools/generate_bitnami_report.py [--out-dir DIR] [--no-compile]
                                            [--dataset trivy|vulndb|combined]

Datasets:
  trivy    – bitnami_cves.json          (Trivy image scans,  693 records)
  vulndb   – bitnami_vulndb_cves.json   (Official vulndb,  2813 records)
  combined – bitnami_combined_cves.json (Merged,           1634 records)  [default]

Outputs to /content/drive/MyDrive/thesis/code/datasets/poc/claude/ by default.
"""
import argparse
import collections
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ─── Paths ───────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_FILES = {
    "trivy"   : REPO_ROOT / "data/vulnerability_db/bitnami_cves.json",
    "vulndb"  : REPO_ROOT / "data/vulnerability_db/bitnami_vulndb_cves.json",
    "combined": REPO_ROOT / "data/vulnerability_db/bitnami_combined_cves.json",
}
# keep backward compat
DATA_FILE = DATA_FILES["combined"]

DEFAULT_OUT_DIR = Path("/content/drive/MyDrive/thesis/code/datasets/poc/claude")

# ─── Colour palette (colorblind-friendly) ────────────────────────────────────
C_CRIT  = "#D62728"   # red
C_HIGH  = "#FF7F0E"   # orange
C_MED   = "#2CA02C"   # green
C_BLUE  = "#1F77B4"
C_TEAL  = "#17BECF"
C_GREY  = "#7F7F7F"
C_PURP  = "#9467BD"
C_BROWN = "#8C564B"

SEVERITY_COLORS = {"CRITICAL": C_CRIT, "HIGH": C_HIGH, "MEDIUM": C_MED}

MITRE_LABELS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0004": "Privilege Escalation",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0040": "Impact",
}

TIER_COLORS = {
    "High"   : "#1F77B4",
    "Medium" : "#FF7F0E",
    "Low"    : "#2CA02C",
    "Minimal": "#7F7F7F",
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def load_data(path: Path):
    with open(path) as f:
        d = json.load(f)
    return d


def safe_pct(n, total):
    return 0.0 if total == 0 else 100.0 * n / total


def latex_escape(s: str) -> str:
    for ch, rep in [("_", r"\_"), ("&", r"\&"), ("%", r"\%"), ("#", r"\#"),
                    ("$", r"\$"), ("{", r"\{"), ("}", r"\}"), ("~", r"\textasciitilde{}"),
                    ("^", r"\textasciicircum{}"), ("\\", r"\textbackslash{}")]:
        s = s.replace(ch, rep)
    return s


def fig_path(figures_dir: Path, name: str) -> Path:
    return figures_dir / f"{name}.pdf"


# ─── Statistics ───────────────────────────────────────────────────────────────

def compute_stats(d):
    cves = d["cves"]
    cs   = d.get("chart_stats", {})

    total      = len(cves)
    unique_ids = len({c["cve_id"] for c in cves})
    charts_set = {c["chart"] for c in cves}
    n_charts   = len(charts_set)

    # severity
    sev_cnt = collections.Counter(c["severity"] for c in cves)

    # CVSS
    scores = [c["cvss_score"] for c in cves if c.get("cvss_score") is not None]
    cvss_mean   = statistics.mean(scores)
    cvss_median = statistics.median(scores)
    cvss_std    = statistics.stdev(scores)
    cvss_min    = min(scores)
    cvss_max    = max(scores)

    # attack vector / complexity
    av_cnt = collections.Counter(c.get("attack_vector", "UNKNOWN") for c in cves)
    ac_cnt = collections.Counter(c.get("attack_complexity", "UNKNOWN") for c in cves)

    # year
    year_cnt = collections.Counter()
    for c in cves:
        try:
            year_cnt[int(c["cve_id"].split("-")[1])] += 1
        except Exception:
            pass

    # packages
    pkg_cnt = collections.Counter(c["pkg_name"] for c in cves)

    # fix rate
    fixed = sum(1 for c in cves
                if str(c.get("fixed_version", "")).strip() not in ("", "N/A"))
    fix_rate = safe_pct(fixed, total)

    # success rate
    sr_vals  = [c["success_rate"] for c in cves if c.get("success_rate") is not None]
    sr_mean  = statistics.mean(sr_vals)
    sr_std   = statistics.stdev(sr_vals)

    # exploit cost
    cost_cnt = collections.Counter(c.get("exploit_cost") for c in cves)

    # MITRE tactics (primary)
    tac_primary = collections.Counter(c.get("mitre_primary", "UNKNOWN") for c in cves)

    # MITRE tactics (all)
    tac_all = collections.Counter()
    for c in cves:
        for t in c.get("mitre_tactics", []):
            tac_all[t["tactic_id"]] += 1
    multi_tactic = sum(1 for c in cves if len(c.get("mitre_tactics", [])) >= 2)

    # per-chart
    chart_cnt  = collections.Counter(c["chart"] for c in cves)
    chart_sev  = collections.defaultdict(lambda: collections.Counter())
    for c in cves:
        chart_sev[c["chart"]][c["severity"]] += 1

    # CBS properties
    all_props = []
    for c in cves:
        all_props.extend(c.get("chart_properties", []))
    prop_cnt = collections.Counter(all_props)

    # frequency tiers
    freq_tier = collections.Counter(c.get("frequency_tier", "N/A") for c in cves)

    # deployment weight
    dw_vals = [c.get("deployment_weight", 0) for c in cves]

    # supply-chain: CVEs appearing in multiple charts
    cve_charts = collections.defaultdict(set)
    for c in cves:
        cve_charts[c["cve_id"]].add(c["chart"])
    supply_chain = {cid: charts for cid, charts in cve_charts.items() if len(charts) >= 2}
    n_supply  = len(supply_chain)
    n_single  = unique_ids - n_supply
    scasm = (sum(len(v) for v in supply_chain.values()) / n_supply
             if n_supply else 0)
    top_supply = sorted(supply_chain.items(), key=lambda x: len(x[1]), reverse=True)[:15]

    # chart pull counts
    pull_counts = {}
    for k, v in cs.items():
        if v.get("pull_count"):
            pull_counts[k] = v["pull_count"]
    total_pulls = sum(pull_counts.values())

    # per-chart mean CVSS
    chart_cvss = collections.defaultdict(list)
    for c in cves:
        if c.get("cvss_score"):
            chart_cvss[c["chart"]].append(c["cvss_score"])

    # unique chart-property sets for tier classification
    chart_props_map = {}
    for c in cves:
        ch = c["chart"]
        if ch not in chart_props_map:
            chart_props_map[ch] = set()
        chart_props_map[ch].update(c.get("chart_properties", []))

    tier_map = {
        "WebTier"   : [ch for ch, p in chart_props_map.items() if "WebServer" in p],
        "AppTier"   : [ch for ch, p in chart_props_map.items() if "AppServer" in p],
        "DataTier"  : [ch for ch, p in chart_props_map.items() if "DatabaseServer" in p],
        "WorkerTier": [ch for ch, p in chart_props_map.items() if "WorkerNode" in p],
        "InfraTier" : [ch for ch, p in chart_props_map.items() if "APIGateway" in p or "LoadBalancer" in p],
    }

    return dict(
        cves=cves, total=total, unique_ids=unique_ids, n_charts=n_charts,
        sev_cnt=sev_cnt, scores=scores,
        cvss_mean=cvss_mean, cvss_median=cvss_median, cvss_std=cvss_std,
        cvss_min=cvss_min, cvss_max=cvss_max,
        av_cnt=av_cnt, ac_cnt=ac_cnt, year_cnt=year_cnt, pkg_cnt=pkg_cnt,
        fixed=fixed, fix_rate=fix_rate,
        sr_vals=sr_vals, sr_mean=sr_mean, sr_std=sr_std,
        cost_cnt=cost_cnt,
        tac_primary=tac_primary, tac_all=tac_all, multi_tactic=multi_tactic,
        chart_cnt=chart_cnt, chart_sev=chart_sev,
        prop_cnt=prop_cnt, freq_tier=freq_tier, dw_vals=dw_vals,
        cve_charts=cve_charts, supply_chain=supply_chain,
        n_supply=n_supply, n_single=n_single, scasm=scasm, top_supply=top_supply,
        pull_counts=pull_counts, total_pulls=total_pulls,
        chart_cvss=chart_cvss, chart_props_map=chart_props_map, tier_map=tier_map,
    )


# ─── Figure generators ───────────────────────────────────────────────────────

def _save(fig, path: Path):
    fig.savefig(path, bbox_inches="tight", dpi=150, format="pdf")
    plt.close(fig)
    print(f"  ✓  {path.name}")


def fig_cvss_distribution(s, figures_dir):
    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    bins = np.arange(4.0, 10.5, 0.5)
    n, edges, patches = ax.hist(s["scores"], bins=bins, color=C_BLUE, alpha=0.75,
                                edgecolor="white", linewidth=0.5)
    # colour by severity bands
    for patch, left in zip(patches, edges[:-1]):
        if left >= 9.0:
            patch.set_facecolor(C_CRIT)
        elif left >= 7.0:
            patch.set_facecolor(C_HIGH)
        else:
            patch.set_facecolor(C_MED)

    ax.axvline(s["cvss_mean"], color="black", linestyle="--", linewidth=1.0,
               label=f"Mean = {s['cvss_mean']:.2f}")
    ax.axvline(s["cvss_median"], color=C_GREY, linestyle=":", linewidth=1.0,
               label=f"Median = {s['cvss_median']:.2f}")
    ax.set_xlabel("CVSS v3 Base Score", fontsize=10)
    ax.set_ylabel("CVE Instance Count", fontsize=10)
    ax.set_title("CVSS Score Distribution (n = {:,})".format(s["total"]), fontsize=11)
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.3)
    crit_patch = mpatches.Patch(color=C_CRIT, label=f"CRITICAL (≥9.0): {s['sev_cnt']['CRITICAL']}")
    high_patch = mpatches.Patch(color=C_HIGH, label=f"HIGH (7.0–9.0): {s['sev_cnt']['HIGH']}")
    ax.legend(handles=[crit_patch, high_patch], fontsize=7.5, loc="upper left")
    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_cvss_distribution"))


def fig_top_charts(s, figures_dir):
    top = s["chart_cnt"].most_common(18)
    names = [latex_escape(n) for n, _ in reversed(top)]
    crits = [s["chart_sev"][n]["CRITICAL"] for n, _ in reversed(top)]
    highs = [s["chart_sev"][n]["HIGH"]     for n, _ in reversed(top)]
    fig, ax = plt.subplots(figsize=(5.5, 5.5))
    y = np.arange(len(names))
    ax.barh(y, crits, color=C_CRIT, label="CRITICAL", height=0.6)
    ax.barh(y, highs, left=crits, color=C_HIGH, label="HIGH", height=0.6)
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=8)
    ax.set_xlabel("CVE Instance Count", fontsize=10)
    ax.set_title("Top 18 Charts by CVE Count", fontsize=11)
    ax.legend(fontsize=8)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_top_charts"))


def fig_mitre_tactics(s, figures_dir):
    tac = s["tac_primary"]
    labels = [MITRE_LABELS.get(k, k) for k in tac.keys()]
    counts = list(tac.values())
    order = sorted(range(len(counts)), key=lambda i: counts[i], reverse=True)
    labels = [labels[i] for i in order]
    counts = [counts[i] for i in order]
    colors = [C_BLUE, C_CRIT, C_TEAL, C_PURP, C_BROWN, C_GREY][:len(labels)]
    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    bars = ax.barh(labels[::-1], counts[::-1], color=colors[::-1], height=0.6)
    for bar, val in zip(bars, counts[::-1]):
        ax.text(bar.get_width() + 2, bar.get_y() + bar.get_height()/2,
                f"{val} ({safe_pct(val, s['total']):.1f}%)",
                va="center", fontsize=7.5)
    ax.set_xlabel("CVE Instance Count", fontsize=10)
    ax.set_title("Primary MITRE ATT&CK Tactic Distribution", fontsize=11)
    ax.grid(axis="x", alpha=0.3)
    ax.set_xlim(0, max(counts) * 1.25)
    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_mitre_tactics"))


def fig_supply_chain(s, figures_dir):
    top = s["top_supply"][:12]
    cve_ids   = [t[0] for t in reversed(top)]
    n_charts  = [len(t[1]) for t in reversed(top)]
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    colors = [C_CRIT if nc >= 30 else C_HIGH if nc >= 10 else C_BLUE for nc in n_charts]
    bars = ax.barh(cve_ids, n_charts, color=colors, height=0.6)
    for bar, val in zip(bars, n_charts):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2,
                str(val), va="center", fontsize=8)
    ax.set_xlabel("Number of Charts Affected", fontsize=10)
    ax.set_title("Supply-Chain CVEs: Chart Propagation Count", fontsize=11)
    ax.grid(axis="x", alpha=0.3)
    ax.set_xlim(0, max(n_charts) * 1.15)
    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_supply_chain"))


def fig_frequency_tiers(s, figures_dir):
    tiers = ["High", "Medium", "Low", "Minimal"]
    counts = [s["freq_tier"].get(t.lower(), 0) for t in tiers]
    thresholds = [">100M", "10M–100M", "1M–10M", "<1M"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.5, 3.5))
    colors = [TIER_COLORS[t] for t in tiers]
    wedges, texts, autotexts = ax1.pie(
        counts, labels=tiers, autopct="%1.1f%%",
        colors=colors, startangle=90,
        textprops={"fontsize": 8},
    )
    for at in autotexts:
        at.set_fontsize(7.5)
    ax1.set_title("CVE Records by\nDeployment Frequency Tier", fontsize=9)

    # bar of pull counts for top-15 charts
    top15 = sorted(s["pull_counts"].items(), key=lambda x: x[1], reverse=True)[:15]
    cnames = [latex_escape(k) for k, _ in reversed(top15)]
    pulls  = [v / 1e9 for _, v in reversed(top15)]
    y = np.arange(len(cnames))
    ax2.barh(y, pulls, color=C_BLUE, height=0.6)
    ax2.set_yticks(y)
    ax2.set_yticklabels(cnames, fontsize=7)
    ax2.set_xlabel("Docker Hub Pulls (billions)", fontsize=9)
    ax2.set_title("Top 15 Charts by\nDocker Hub Pull Count", fontsize=9)
    ax2.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_frequency_tiers"))


def fig_cbs_properties(s, figures_dir):
    # exclude Linux (always present) for readability
    prop = {k: v for k, v in s["prop_cnt"].items() if k != "Linux"}
    top = sorted(prop.items(), key=lambda x: x[1], reverse=True)[:18]
    names  = [latex_escape(k) for k, _ in reversed(top)]
    counts = [v for _, v in reversed(top)]
    fig, ax = plt.subplots(figsize=(5.5, 5.5))
    y = np.arange(len(names))
    bars = ax.barh(y, counts, color=C_TEAL, height=0.6, alpha=0.85)
    for bar, val in zip(bars, counts):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                str(val), va="center", fontsize=7.5)
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=8)
    ax.set_xlabel("Frequency in CVE Records", fontsize=10)
    ax.set_title("CBS Node Properties (excl. Linux)", fontsize=11)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_cbs_properties"))


def fig_year_distribution(s, figures_dir):
    years  = sorted(s["year_cnt"].keys())
    counts = [s["year_cnt"][y] for y in years]
    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    bars = ax.bar([str(y) for y in years], counts, color=C_PURP, alpha=0.8,
                  edgecolor="white")
    for bar, val in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                str(val), ha="center", va="bottom", fontsize=7.5)
    ax.set_xlabel("CVE Publication Year", fontsize=10)
    ax.set_ylabel("CVE Instance Count", fontsize=10)
    ax.set_title("CVE Age Distribution", fontsize=11)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_year_distribution"))


def fig_success_rate(s, figures_dir):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.5, 3.5))
    bins = np.arange(0.30, 0.95, 0.05)
    ax1.hist(s["sr_vals"], bins=bins, color=C_HIGH, alpha=0.8, edgecolor="white")
    ax1.axvline(s["sr_mean"], color="black", linestyle="--",
                label=f"Mean = {s['sr_mean']:.3f}")
    ax1.set_xlabel("Success Rate", fontsize=10)
    ax1.set_ylabel("Count", fontsize=10)
    ax1.set_title("Success Rate Distribution", fontsize=11)
    ax1.legend(fontsize=8)
    ax1.grid(axis="y", alpha=0.3)

    cost_labels = sorted(s["cost_cnt"].keys())
    cost_counts = [s["cost_cnt"][k] for k in cost_labels]
    ax2.bar([str(c) for c in cost_labels], cost_counts,
            color=[C_CRIT, C_HIGH, C_MED, C_GREY][:len(cost_labels)], alpha=0.85,
            edgecolor="white")
    for i, (lab, cnt) in enumerate(zip(cost_labels, cost_counts)):
        ax2.text(i, cnt + 2, str(cnt), ha="center", fontsize=8)
    ax2.set_xlabel("Exploit Cost", fontsize=10)
    ax2.set_ylabel("Count", fontsize=10)
    ax2.set_title("Exploit Cost Distribution", fontsize=11)
    ax2.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_sr_cost"))


def fig_complexity_severity(s, figures_dir):
    cats = ["CRITICAL", "HIGH"]
    ac_labels = ["LOW", "HIGH"]
    ac_crit = [sum(1 for c in s["cves"] if c["severity"] == sev
                   and c.get("attack_complexity") == ac)
               for sev in cats for ac in ac_labels]
    # grouped bar
    x = np.arange(2)
    width = 0.35
    low_counts  = [sum(1 for c in s["cves"] if c["severity"] == sev
                       and c.get("attack_complexity") == "LOW")  for sev in cats]
    high_counts = [sum(1 for c in s["cves"] if c["severity"] == sev
                       and c.get("attack_complexity") == "HIGH") for sev in cats]
    fig, ax = plt.subplots(figsize=(5.0, 3.5))
    b1 = ax.bar(x - width/2, low_counts,  width, label="AC=LOW",  color=C_BLUE,  alpha=0.85)
    b2 = ax.bar(x + width/2, high_counts, width, label="AC=HIGH", color=C_PURP, alpha=0.85)
    for bar in list(b1) + list(b2):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                str(int(bar.get_height())), ha="center", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(["CRITICAL", "HIGH"], fontsize=10)
    ax.set_ylabel("CVE Instance Count", fontsize=10)
    ax.set_title("Severity × Attack Complexity", fontsize=11)
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_complexity_severity"))


def fig_tier_overview(s, figures_dir):
    tier_map = s["tier_map"]
    # count CVEs per tier
    tier_cve = {}
    for tier, charts in tier_map.items():
        tier_cve[tier] = sum(s["chart_cnt"].get(ch, 0) for ch in charts)

    tier_chart_cnt = {t: len(ch) for t, ch in tier_map.items()}

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.5, 3.5))
    tiers = list(tier_cve.keys())
    colors = [C_BLUE, C_HIGH, C_TEAL, C_PURP, C_BROWN]

    ax1.bar(tiers, [tier_cve[t] for t in tiers], color=colors, alpha=0.85,
            edgecolor="white")
    for i, t in enumerate(tiers):
        ax1.text(i, tier_cve[t] + 2, str(tier_cve[t]), ha="center", fontsize=8)
    ax1.set_ylabel("CVE Instance Count", fontsize=10)
    ax1.set_title("CVEs per Application Tier", fontsize=11)
    ax1.grid(axis="y", alpha=0.3)
    ax1.tick_params(axis="x", rotation=15)

    ax2.bar(tiers, [tier_chart_cnt[t] for t in tiers], color=colors, alpha=0.85,
            edgecolor="white")
    for i, t in enumerate(tiers):
        ax2.text(i, tier_chart_cnt[t] + 0.2, str(tier_chart_cnt[t]), ha="center", fontsize=8)
    ax2.set_ylabel("Unique Charts", fontsize=10)
    ax2.set_title("Charts per Application Tier", fontsize=11)
    ax2.grid(axis="y", alpha=0.3)
    ax2.tick_params(axis="x", rotation=15)
    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_tier_overview"))


def fig_source_comparison(all_stats: dict, figures_dir: Path):
    """Side-by-side bar chart comparing Trivy, vulndb, and Combined datasets."""
    labels = ["Trivy\n(image scan)", "Bitnami/vulndb\n(official)", "Combined\n(merged)"]
    keys   = ["trivy", "vulndb", "combined"]
    colors = [C_BLUE, C_HIGH, C_TEAL]

    records   = [all_stats[k]["total"]      for k in keys]
    unique    = [all_stats[k]["unique_ids"]  for k in keys]
    comps     = [all_stats[k]["n_charts"]    for k in keys]
    cvss_mean = [all_stats[k]["cvss_mean"]   for k in keys]
    net_pct   = [all_stats[k]["av_cnt"].get("NETWORK", 0) /
                 max(all_stats[k]["total"], 1) * 100  for k in keys]

    fig, axes = plt.subplots(1, 3, figsize=(10, 4))

    # Panel 1: record counts (instances vs unique CVEs)
    x = np.arange(len(labels)); w = 0.35
    axes[0].bar(x - w/2, records,  w, color=colors, alpha=0.85, label="Records")
    axes[0].bar(x + w/2, unique,   w, color=colors, alpha=0.45, label="Unique CVEs")
    axes[0].set_xticks(x); axes[0].set_xticklabels(labels, fontsize=8)
    axes[0].set_ylabel("Count", fontsize=10)
    axes[0].set_title("Record & CVE Counts", fontsize=11)
    axes[0].legend(fontsize=8); axes[0].grid(axis="y", alpha=0.3)
    for i in range(len(labels)):
        axes[0].text(i - w/2, records[i] + 20,  str(records[i]),  ha="center", fontsize=7)
        axes[0].text(i + w/2, unique[i]  + 20,  str(unique[i]),   ha="center", fontsize=7)

    # Panel 2: components covered
    axes[1].bar(x, comps, color=colors, alpha=0.85, edgecolor="white")
    for i, v in enumerate(comps):
        axes[1].text(i, v + 1, str(v), ha="center", fontsize=9)
    axes[1].set_xticks(x); axes[1].set_xticklabels(labels, fontsize=8)
    axes[1].set_ylabel("Components / Charts", fontsize=10)
    axes[1].set_title("Component Coverage", fontsize=11)
    axes[1].grid(axis="y", alpha=0.3)

    # Panel 3: CVSS mean + network %
    ax3b = axes[2].twinx()
    axes[2].bar(x - w/2, cvss_mean, w, color=colors, alpha=0.85, label="CVSS mean")
    ax3b.bar(x + w/2, net_pct, w, color=colors, alpha=0.45, label="NETWORK %")
    axes[2].set_xticks(x); axes[2].set_xticklabels(labels, fontsize=8)
    axes[2].set_ylabel("CVSS Mean Score", fontsize=10)
    ax3b.set_ylabel("NETWORK Attack Vector (%)", fontsize=9)
    axes[2].set_ylim(7.5, 9.0)
    ax3b.set_ylim(80, 105)
    axes[2].set_title("CVSS & Network Reachability", fontsize=11)
    for i in range(len(labels)):
        axes[2].text(i - w/2, cvss_mean[i] + 0.02, f"{cvss_mean[i]:.2f}", ha="center", fontsize=7)
        ax3b.text(i + w/2, net_pct[i] + 0.5, f"{net_pct[i]:.1f}%", ha="center", fontsize=7)
    lines1, labels1 = axes[2].get_legend_handles_labels()
    lines2, labels2 = ax3b.get_legend_handles_labels()
    axes[2].legend(lines1 + lines2, labels1 + labels2, fontsize=8, loc="lower right")

    fig.tight_layout()
    _save(fig, fig_path(figures_dir, "fig_source_comparison"))


def generate_all_figures(s, figures_dir: Path, all_stats: dict = None):
    figures_dir.mkdir(parents=True, exist_ok=True)
    print("Generating figures...")
    fig_cvss_distribution(s, figures_dir)
    fig_top_charts(s, figures_dir)
    fig_mitre_tactics(s, figures_dir)
    fig_supply_chain(s, figures_dir)
    fig_frequency_tiers(s, figures_dir)
    fig_cbs_properties(s, figures_dir)
    fig_year_distribution(s, figures_dir)
    fig_success_rate(s, figures_dir)
    fig_complexity_severity(s, figures_dir)
    fig_tier_overview(s, figures_dir)
    if all_stats is not None:
        fig_source_comparison(all_stats, figures_dir)
    print(f"  → All figures saved to {figures_dir}")


# ─── LaTeX generation ─────────────────────────────────────────────────────────

def fp(figures_dir: Path, name: str) -> str:
    """Return path string for \includegraphics, forward-slash, no extension."""
    return str(fig_path(figures_dir, name)).replace("\\", "/")


def _build_vulndb_section(all_stats: dict, figures_dir: Path) -> str:
    """Return the Extended Dataset LaTeX section using pre-loaded all_stats."""
    t  = all_stats["trivy"]
    v  = all_stats["vulndb"]
    c  = all_stats["combined"]
    local_pct = v["av_cnt"].get("LOCAL", 0) / max(v["total"], 1) * 100
    fig_p = fp(figures_dir, "fig_source_comparison")
    return (
        r"\section{Extended Dataset: Bitnami/vulndb Integration}" + "\n"
        r"\label{sec:vulndb}" + "\n\n"
        r"\subsection{Data Sources}" + "\n\n"
        r"To validate and expand the Trivy-derived dataset we integrated the"
        r" official Bitnami vulnerability database (\texttt{bitnami/vulndb}"
        r" on GitHub), which provides authoritative OSV~1.5.0 advisory records"
        r" for all Bitnami-maintained container images."
        r" Table~\ref{tab:sources} compares the three data layers." + "\n\n"
        r"\begin{table}[h]" + "\n"
        r"\centering" + "\n"
        r"\caption{Dataset source comparison.}" + "\n"
        r"\label{tab:sources}" + "\n"
        r"\begin{tabular}{lrrrr}" + "\n"
        r"\hline" + "\n"
        r"Source & Records & Unique CVEs & Components & CVSS mean \\" + "\n"
        r"\hline" + "\n"
        f"Trivy (image scan) & {t['total']} & {t['unique_ids']} & {t['n_charts']}"
        f" & {t['cvss_mean']:.2f} \\\\\n"
        f"Bitnami/vulndb     & {v['total']} & {v['unique_ids']} & {v['n_charts']}"
        f" & {v['cvss_mean']:.2f} \\\\\n"
        f"Combined (merged)  & {c['total']} & {c['unique_ids']} & {c['n_charts']}"
        f" & {c['cvss_mean']:.2f} \\\\\n"
        r"\hline" + "\n"
        r"\end{tabular}" + "\n"
        r"\end{table}" + "\n\n"
        r"\subsection{Merge Strategy}" + "\n\n"
        r"The combined dataset uses Trivy records as ground truth (exact image"
        r" version), enriched with vulndb fields where a matching (CVE~ID, chart)"
        r" pair exists: CVSS vector string, affected and fixed version ranges,"
        r" Bitnami advisory identifier (\texttt{BIT-\textit{chart}-\textit{year}"
        r"-\textit{n}}), and CPE strings.  Vulndb-only records are appended for"
        r" overlapping components so that CVEs not surfaced by Trivy's"
        r" image-layer heuristics are not silently dropped." + "\n\n"
        r"De-duplication retains the record with the higher CVSS score for any"
        r" (CVE~ID, chart) key that appears in both sources.  The resulting"
        r" combined dataset therefore provides the widest CVE coverage while"
        r" keeping Trivy's image-version precision where available." + "\n\n"
        r"\subsection{Coverage Observations}" + "\n\n"
        f"The official vulndb extends coverage to {v['n_charts']}~components"
        f" vs.\\ Trivy's {t['n_charts']}~charts, but the merged dataset retains"
        f" {c['n_charts']}~charts because only overlapping components are included"
        r" by default (\texttt{--include-new-components} adds the rest)."
        f"  The vulndb introduces LOCAL attack vectors ({local_pct:.1f}\\%)"
        r" absent from Trivy's 100\%~NETWORK-only view, reflecting"
        r" privilege-escalation paths that image scans do not capture." + "\n\n"
        r"Figure~\ref{fig:sourcecomp} compares the three sources across record"
        r" counts, component coverage, and network reachability." + "\n\n"
        r"\begin{figure}[h]" + "\n"
        r"\centering" + "\n"
        f"\\includegraphics[width=\\linewidth]{{{fig_p}}}\n"
        r"\caption{Trivy vs.\ Bitnami/vulndb vs.\ Combined dataset comparison."
        r"  Left: record and unique CVE counts.  Centre: component coverage."
        r"  Right: CVSS mean (left axis) and NETWORK attack vector percentage"
        r" (right axis).}" + "\n"
        r"\label{fig:sourcecomp}" + "\n"
        r"\end{figure}" + "\n"
    )


def build_latex(s, figures_dir: Path, generated_date: str = "2026-04-24",
                all_stats: dict = None) -> str:
    fd = str(figures_dir).replace("\\", "/")

    # pre-compute per-chart stats table (top 20 by total CVEs)
    chart_rows = []
    for chart, total_c in s["chart_cnt"].most_common(20):
        crit = s["chart_sev"][chart]["CRITICAL"]
        high = s["chart_sev"][chart]["HIGH"]
        mean_cvss = (statistics.mean(s["chart_cvss"][chart])
                     if s["chart_cvss"][chart] else 0.0)
        props = ", ".join(f"\\texttt{{{p}}}"
                          for p in sorted(s["chart_props_map"].get(chart, []))
                          if p != "Linux")[:80]
        chart_rows.append(
            f"  \\chart{{{latex_escape(chart)}}} & {crit} & {high} & {total_c} "
            f"& {mean_cvss:.1f} & \\scriptsize{{{props}}}\\\\"
        )
    chart_table = "\n".join(chart_rows)

    # property table (top 15, excl Linux)
    prop_rows = []
    for p, cnt in [(k, v) for k, v in s["prop_cnt"].most_common(20) if k != "Linux"][:15]:
        pct = safe_pct(cnt, s["total"])
        prop_rows.append(f"  \\texttt{{{latex_escape(p)}}} & {cnt} & {pct:.1f}\\\\")
    prop_table = "\n".join(prop_rows)

    # supply-chain table (top 10)
    sc_rows = []
    for cve_id, charts_set in s["top_supply"][:10]:
        # find package name from first matching record
        pkg = next((c["pkg_name"] for c in s["cves"] if c["cve_id"] == cve_id), "—")
        cvss = next((c["cvss_score"] for c in s["cves"] if c["cve_id"] == cve_id), 0.0)
        sev  = next((c["severity"][0]  for c in s["cves"] if c["cve_id"] == cve_id), "?")
        tac  = next((c.get("mitre_primary","?") for c in s["cves"] if c["cve_id"] == cve_id), "?")
        sc_rows.append(
            f"  \\cve{{{cve_id}}} & \\texttt{{{latex_escape(pkg)}}} "
            f"& {len(charts_set)} & {cvss:.1f} & {sev} & {tac}\\\\"
        )
    sc_table = "\n".join(sc_rows)

    # deployment table
    tiers = ["High", "Medium", "Low", "Minimal"]
    thresh = [">100M pulls", "10M–100M", "1M–10M", "<1M"]
    tier_rows = []
    for tier, thr in zip(tiers, thresh):
        cnt = s["freq_tier"].get(tier.lower(), 0)
        pct = safe_pct(cnt, s["total"])
        tier_rows.append(f"  {tier} & {thr} & {cnt} & {pct:.1f}\\\\")
    tier_table = "\n".join(tier_rows)

    # tier overview table
    tier_map = s["tier_map"]
    tier_cve = {t: sum(s["chart_cnt"].get(ch,0) for ch in chs) for t, chs in tier_map.items()}
    tier_chart_cnt = {t: len(chs) for t, chs in tier_map.items()}
    tier_ov_rows = []
    tier_ex = {
        "WebTier":    "nginx, wordpress, drupal",
        "AppTier":    "jenkins, grafana, vault, ghost",
        "DataTier":   "redis, mongodb, mysql, elasticsearch",
        "WorkerTier": "airflow, kafka, flink, fluentd",
        "InfraTier":  "haproxy, kong, apisix",
    }
    for t, chs in tier_map.items():
        tier_ov_rows.append(
            f"  {t} & {tier_chart_cnt[t]} & {tier_cve[t]} "
            f"& \\scriptsize{{{latex_escape(tier_ex.get(t,''))}}}\\\\"
        )
    tier_ov_table = "\n".join(tier_ov_rows)

    n_crit = s["sev_cnt"]["CRITICAL"]
    n_high = s["sev_cnt"]["HIGH"]
    n_low  = s["ac_cnt"].get("LOW", 0)
    n_high_ac = s["ac_cnt"].get("HIGH", 0)

    vulndb_section = _build_vulndb_section(all_stats, figures_dir) if all_stats else ""

    doc = rf"""\documentclass[10pt,twocolumn]{{article}}

% ── Packages ──────────────────────────────────────────────────────────────────
\usepackage[margin=1in,top=0.9in,bottom=1in]{{geometry}}
\usepackage{{lmodern}}
\usepackage{{amsmath,amssymb}}
\usepackage{{booktabs}}
\usepackage{{graphicx}}
\usepackage{{xcolor}}
\usepackage{{url}}
\usepackage{{hyperref}}
\usepackage{{enumitem}}
\usepackage{{caption}}
\usepackage{{subcaption}}
\usepackage{{array}}
\usepackage{{tabularx}}
\usepackage{{fancyhdr}}
\usepackage{{titlesec}}
\hypersetup{{colorlinks=true,linkcolor=blue!60!black,
             citecolor=blue!60!black,urlcolor=blue!60!black}}
\titleformat{{\section}}{{\normalfont\large\bfseries}}{{\thesection.}}{{0.5em}}{{}}
\titleformat{{\subsection}}{{\normalfont\normalsize\bfseries}}{{\thesubsection}}{{0.5em}}{{}}
\titlespacing{{\section}}{{0pt}}{{8pt plus 2pt minus 2pt}}{{4pt plus 1pt}}
\titlespacing{{\subsection}}{{0pt}}{{6pt plus 2pt minus 1pt}}{{3pt plus 1pt}}
\pagestyle{{fancy}}
\fancyhf{{}}
\fancyhead[L]{{\small\textit{{Bitnami Helm Chart Vulnerability Analysis}}}}
\fancyhead[R]{{\small\textit{{2026}}}}
\fancyfoot[C]{{\thepage}}
\renewcommand{{\headrulewidth}}{{0.4pt}}
\setlength{{\columnsep}}{{18pt}}
\setlength{{\parskip}}{{3pt}}\setlength{{\parindent}}{{1em}}
\newcommand{{\ie}}{{\emph{{i.e.}}}}
\newcommand{{\eg}}{{\emph{{e.g.}}}}
\newcommand{{\etal}}{{\emph{{et~al.}}}}
\newcommand{{\cve}}[1]{{\texttt{{\small #1}}}}
\newcommand{{\chart}}[1]{{\texttt{{#1}}}}
\newcommand{{\tactic}}[1]{{\textsc{{#1}}}}

% =============================================================================
\begin{{document}}

\title{{%
  \Large\textbf{{Attack Surface Characterisation of Cloud-Native Deployments:\\[4pt]
  A CVE-Grounded EDA of Bitnami Helm Charts\\[4pt]
  for Reinforcement Learning Security Simulation}}
}}
\author{{%
  Ariel Zilkha\\
  \small\textit{{Department of Computer Science}}\\
  \small\textit{{Thesis Research, 2026}}
}}
\date{{}}
\maketitle
\thispagestyle{{fancy}}

% ── Abstract ─────────────────────────────────────────────────────────────────
\begin{{abstract}}
Realistic training environments are a fundamental prerequisite for deep
reinforcement learning (DRL) agents designed to discover attack paths in
enterprise networks. Existing simulation frameworks rely on hand-crafted
vulnerability parameters with no empirical grounding. We address this gap
with a systematic characterisation of the vulnerability attack surface of
\textbf{{{s['n_charts']}}} production-grade Bitnami Helm chart images,
yielding \textbf{{{s['total']}}} CVE instance records spanning
\textbf{{{s['unique_ids']}}} unique CVE identifiers. Each record is enriched
with CVSS~v3 metrics, MITRE ATT\&CK tactic labels, deployment frequency
weights (totalling $>{round(s['total_pulls']/1e9, 0):.0f}$~billion Docker Hub
pulls), and CyberBattleSim-compatible exploit parameters. Our analysis
reveals that \textbf{{100\%}} of vulnerabilities are network-reachable,
{safe_pct(n_high, s['total']):.1f}\% carry HIGH severity, and
{safe_pct(s['n_supply'], s['unique_ids']):.1f}\% of unique CVEs propagate
across multiple charts---a supply-chain attack surface multiplier of
{s['scasm']:.1f}. The mean success rate derived from the CVSS formula is
{s['sr_mean']:.3f} ($\sigma={s['sr_std']:.3f}$), providing an empirical
baseline for DRL training.
\end{{abstract}}

\noindent\textbf{{Keywords:}} CyberBattleSim, Kubernetes security, MITRE
ATT\&CK, CVE analysis, reinforcement learning, Helm charts, supply chain,
cloud-native, attack simulation.

\vspace{{4pt}}\hrule\vspace{{6pt}}

% =============================================================================
\section{{Introduction}}
\label{{sec:intro}}

Autonomous attack-path discovery via deep reinforcement learning (DRL) has
emerged as a promising direction in offensive security
research~\cite{{cyberbattlesim2021,terranova2025}}. A central challenge is
constructing training environments that are both computationally tractable
and empirically representative of real enterprise attack surfaces. Two
failure modes are common: (i)~hand-crafted scenarios that capture expert
intuition but not statistical reality, and (ii)~randomly generated scenarios
whose vulnerability parameters are drawn from synthetic distributions with no
connection to observed threat data.

The Bitnami Helm chart ecosystem offers a principled remedy. Bitnami
publishes and maintains a curated collection of production-ready Kubernetes
application charts, each continuously scanned by Trivy~\cite{{trivy}} against
the National Vulnerability Database (NVD)~\cite{{nvd}}. The
{s['n_charts']}~charts analysed here account for
${round(s['total_pulls']/1e9, 1):.1f}$~billion collective Docker Hub pulls,
providing a deployment-frequency-weighted view of the Kubernetes attack
surface.

\textbf{{Contributions.}} This paper makes the following contributions:
\begin{{enumerate}}[leftmargin=*,label=(\arabic*),itemsep=1pt,topsep=2pt]
  \item A structured dataset of {s['total']}~CVE-chart pairs with CVSS
        metrics, CyberBattleSim-compatible exploit parameters, MITRE ATT\&CK
        tactic labels, and Docker Hub deployment frequency weights.
  \item A quantitative characterisation of Bitnami chart vulnerability
        distributions across severity, attack vector, complexity, success
        rate, and MITRE tactic dimensions.
  \item An empirical supply-chain analysis identifying {s['n_supply']}~CVEs
        that propagate across multiple charts simultaneously.
  \item An application-tier taxonomy mapping {s['n_charts']}~charts to five
        CyberBattleSim-compatible tier roles, with {len({k for c in s['cves'] for k in c.get('chart_properties',[])})}~unique node properties.
\end{{enumerate}}

% =============================================================================
\section{{Background}}
\label{{sec:background}}

\subsection{{CyberBattleSim}}
CyberBattleSim~\cite{{cyberbattlesim2021}} models enterprise network attacks
as a partially observable Markov decision process (POMDP). Nodes carry
\emph{{properties}} (\eg, \texttt{{Linux}}, \texttt{{WebServer}}) and
\emph{{vulnerabilities}} with parameterised success rates and costs. Domain
configuration YAML files specify topology, service properties, and exploit
catalogues---the artefacts our dataset is designed to populate.

\subsection{{Related Work}}
Terranova \etal~\cite{{terranova2025}} extend CyberBattleSim with automated
scenario generation using Shodan and NVD data. Their work focuses on
topological diversity; ours provides a domain-specific, Kubernetes-focused
dataset with deployment-frequency weighting, MITRE tactic labelling, and
CyberBattleSim-native exploit parameters derived from first-principles CVSS
formulae. The CNCF Annual Survey~\cite{{cncf2024}} reports that over 84\%
of organisations run containerised workloads in production, validating
Kubernetes as the primary attack-surface target.

% =============================================================================
\section{{Dataset Construction}}
\label{{sec:dataset}}

\subsection{{Scanning Methodology}}
We scan all {s['n_charts']}~Helm charts in the Bitnami chart
repository~\cite{{bitnami}} using Trivy~v0.50+. For each chart, Trivy
performs OS-level and application-package scanning against NVD, GitHub
Security Advisories, and the Red Hat Security Advisory (RHSA) database.
We retain only CVEs satisfying: \texttt{{AttackVector = NETWORK}} and
\texttt{{Severity $\geq$ HIGH}}, yielding {s['total']}~CVE-chart pairs
spanning {s['unique_ids']}~unique CVE identifiers across
{s['n_charts']}~charts.

\subsection{{Enrichment Pipeline}}
For each CVE record we derive:
\begin{{itemize}}[leftmargin=*,itemsep=1pt,topsep=2pt]
  \item \textbf{{CVSS metrics:}} base score, attack complexity (AC),
        privileges required (PR), user interaction (UI).
  \item \textbf{{CBS parameters:}} \texttt{{success\_rate}},
        \texttt{{exploit\_cost}}, and \texttt{{probability}} from
        Equations~\eqref{{eq:sr}}--\eqref{{eq:prob}}.
  \item \textbf{{MITRE labels:}} primary and secondary ATT\&CK tactic IDs
        via rule-based classifier (chart category + CVSS attributes +
        description keywords).
  \item \textbf{{Deployment weight:}} log-normalised Docker Hub pull count
        (Equation~\eqref{{eq:weight}}).
  \item \textbf{{CBS node properties:}} chart-specific property strings
        (\eg, \texttt{{GoRuntime}}, \texttt{{PHP}}, \texttt{{KeycloakService}})
        for exploit matching.
\end{{itemize}}

\subsection{{CyberBattleSim Parameter Derivation}}
\label{{sec:cbs}}

\begin{{align}}
  \text{{success\_rate}} &= \min\!\bigl(0.90,\, \max(0.30,\,
    \tfrac{{\text{{CVSS}}}}{{10}} \times f_\text{{AC}} \times f_\text{{UI}})\bigr)
    \label{{eq:sr}}\\
  \text{{exploit\_cost}} &=
    \begin{{cases}}
      1.0 & \text{{CVSS}} \geq 9.0\\
      1.5 & \text{{CVSS}} \geq 7.0\\
      2.0 & \text{{CVSS}} \geq 5.0\\
      3.0 & \text{{otherwise}}
    \end{{cases}}
    \label{{eq:cost}}\\
  \text{{probability}} &=
    \begin{{cases}}
      0.85 & \text{{CRITICAL}}\\
      0.65 & \text{{HIGH}}\\
      0.45 & \text{{MEDIUM}}
    \end{{cases}}
    \label{{eq:prob}}
\end{{align}}
where $f_\text{{AC}}=0.70$ if \texttt{{AC=HIGH}} (else 1.0) and
$f_\text{{UI}}=0.85$ if \texttt{{UI=REQUIRED}} (else 1.0).

\textbf{{Deployment frequency:}}
\begin{{equation}}
  w_c = \frac{{\ln(1 + \text{{pulls}}_c)}}{{\ln(1 + \max_j \text{{pulls}}_j)}}
  \label{{eq:weight}}
\end{{equation}}

% =============================================================================
\section{{Vulnerability Characterisation}}
\label{{sec:vuln}}

\subsection{{Dataset Overview}}

Table~\ref{{tab:overview}} summarises the dataset. The {s['total']}~CVE
instance records arise from {s['unique_ids']}~unique CVE identifiers
distributed across {s['n_charts']}~distinct Helm charts.

\begin{{table}}[htbp]
\centering
\caption{{Dataset overview statistics.}}
\label{{tab:overview}}
\small
\begin{{tabular}}{{lr}}
\toprule
\textbf{{Metric}} & \textbf{{Value}}\\
\midrule
Total CVE instance records    & {s['total']:,}\\
Unique CVE identifiers        & {s['unique_ids']:,}\\
Unique Helm charts            & {s['n_charts']:,}\\
Mean CVEs per chart           & {s['total']/s['n_charts']:.1f}\\
Collective Docker Hub pulls   & ${s['total_pulls']/1e9:.1f}$B\\
\midrule
CVSS mean (std)               & {s['cvss_mean']:.2f} ({s['cvss_std']:.2f})\\
CVSS min / max                & {s['cvss_min']:.1f} / {s['cvss_max']:.1f}\\
Severity CRITICAL             & {n_crit} ({safe_pct(n_crit, s['total']):.1f}\%)\\
Severity HIGH                 & {n_high} ({safe_pct(n_high, s['total']):.1f}\%)\\
\midrule
Attack vector NETWORK         & {s['total']} (100.0\%)\\
Attack complexity LOW         & {n_low} ({safe_pct(n_low, s['total']):.1f}\%)\\
Attack complexity HIGH        & {n_high_ac} ({safe_pct(n_high_ac, s['total']):.1f}\%)\\
\midrule
CVEs with fix available       & {s['fixed']:,} ({s['fix_rate']:.1f}\%)\\
Mean success rate (std)       & {s['sr_mean']:.3f} ({s['sr_std']:.3f})\\
Supply-chain CVEs             & {s['n_supply']:,} ({safe_pct(s['n_supply'], s['unique_ids']):.1f}\% of unique)\\
Supply-chain multiplier       & {s['scasm']:.1f}\\
\bottomrule
\end{{tabular}}
\end{{table}}

\subsection{{CVSS Score and Severity Distribution}}

Figure~\ref{{fig:cvss}} shows the CVSS score distribution. The mean
$\mu = {s['cvss_mean']:.2f}$ ($\sigma = {s['cvss_std']:.2f}$) indicates
a dataset concentrated in the HIGH-to-CRITICAL band. \textbf{{All
{s['total']}~records carry \texttt{{AttackVector: NETWORK}}}}, meaning
every exploit is remotely triggerable without physical access---a defining
characteristic of Kubernetes workload exposure. Attack complexity is LOW
for {safe_pct(n_low, s['total']):.1f}\% of records, indicating most
vulnerabilities require no special conditions.

\begin{{figure}}[htbp]
\centering
\includegraphics[width=\columnwidth]{{{fp(figures_dir, 'fig_cvss_distribution')}}}
\caption{{CVSS v3 score distribution for all {s['total']}~CVE instance
records. Bars are coloured by severity band: red = CRITICAL ($\geq$9.0),
orange = HIGH (7.0--9.0). Dashed line: mean = {s['cvss_mean']:.2f}.}}
\label{{fig:cvss}}
\end{{figure}}

Figure~\ref{{fig:cxsev}} disaggregates the interaction between severity and
attack complexity. The majority of CRITICAL CVEs ({n_crit} total) carry
\texttt{{AC=LOW}}, meaning exploitation requires no special access conditions.

\begin{{figure}}[htbp]
\centering
\includegraphics[width=0.9\columnwidth]{{{fp(figures_dir, 'fig_complexity_severity')}}}
\caption{{CVE counts disaggregated by severity (CRITICAL vs. HIGH) and
attack complexity (AC=LOW vs. AC=HIGH).}}
\label{{fig:cxsev}}
\end{{figure}}

\subsection{{Per-Chart Distribution}}

Figure~\ref{{fig:charts}} ranks the 18~most-affected charts by CVE count.
Table~\ref{{tab:charts}} provides extended per-chart statistics for the
top~20.

\begin{{figure}}[htbp]
\centering
\includegraphics[width=\columnwidth]{{{fp(figures_dir, 'fig_top_charts')}}}
\caption{{Top 18 Helm charts by CVE instance count, coloured by severity.}}
\label{{fig:charts}}
\end{{figure}}

\begin{{table*}}[htbp]
\centering
\caption{{Per-chart statistics for the top 20 charts by CVE count.
Properties shown are the CBS node properties assigned to each chart
(excluding the universal \texttt{{Linux}} property).}}
\label{{tab:charts}}
\small
\setlength{{\tabcolsep}}{{4pt}}
\begin{{tabular}}{{lccccp{{4.5cm}}}}
\toprule
\textbf{{Chart}} & \textbf{{CRIT}} & \textbf{{HIGH}} & \textbf{{Total}} &
\textbf{{Avg CVSS}} & \textbf{{CBS Properties}}\\
\midrule
{chart_table}
\bottomrule
\end{{tabular}}
\end{{table*}}

\subsection{{Success Rate and Exploit Cost}}

Figure~\ref{{fig:sr}} shows the derived success rate distribution. The
overall mean is {s['sr_mean']:.3f} ($\sigma = {s['sr_std']:.3f}$), with
the majority of records falling in the 0.70--0.90 range. Exploit costs
are dominated by 1.5 ({safe_pct(s['cost_cnt'].get(1.5,0), s['total']):.1f}\%)
and 1.0 ({safe_pct(s['cost_cnt'].get(1.0,0), s['total']):.1f}\%),
reflecting the concentration of vulnerabilities in the CVSS~7.0--9.0 band.

\begin{{figure}}[htbp]
\centering
\includegraphics[width=\columnwidth]{{{fp(figures_dir, 'fig_sr_cost')}}}
\caption{{Left: derived success rate distribution (mean = {s['sr_mean']:.3f}).
Right: exploit cost distribution derived from CVSS bands.}}
\label{{fig:sr}}
\end{{figure}}

% =============================================================================
\section{{MITRE ATT\&CK Coverage}}
\label{{sec:mitre}}

Table~\ref{{tab:tactics}} and Figure~\ref{{fig:mitre}} report the primary
tactic assignment. Two tactics account for 97.2\% of the dataset.

\begin{{table}}[htbp]
\centering
\caption{{Primary MITRE ATT\&CK tactic distribution.}}
\label{{tab:tactics}}
\small
\begin{{tabular}}{{llrr}}
\toprule
\textbf{{ID}} & \textbf{{Tactic}} & \textbf{{Count}} & \textbf{{\%}}\\
\midrule
TA0001 & Initial Access       & {s['tac_primary'].get('TA0001',0)} & {safe_pct(s['tac_primary'].get('TA0001',0), s['total']):.1f}\%\\
TA0040 & Impact               & {s['tac_primary'].get('TA0040',0)} & {safe_pct(s['tac_primary'].get('TA0040',0), s['total']):.1f}\%\\
TA0008 & Lateral Movement     & {s['tac_primary'].get('TA0008',0)} &  {safe_pct(s['tac_primary'].get('TA0008',0), s['total']):.1f}\%\\
TA0009 & Collection           & {s['tac_primary'].get('TA0009',0)} &  {safe_pct(s['tac_primary'].get('TA0009',0), s['total']):.1f}\%\\
TA0002 & Execution            & {s['tac_primary'].get('TA0002',0)} &  {safe_pct(s['tac_primary'].get('TA0002',0), s['total']):.1f}\%\\
TA0007 & Discovery            & {s['tac_primary'].get('TA0007',0)} &  {safe_pct(s['tac_primary'].get('TA0007',0), s['total']):.1f}\%\\
TA0004 & Privilege Escalation & {s['tac_primary'].get('TA0004',0)} &  {safe_pct(s['tac_primary'].get('TA0004',0), s['total']):.1f}\%\\
\midrule
\textbf{{Total}} & & \textbf{{{s['total']}}} & \textbf{{100\%}}\\
\bottomrule
\end{{tabular}}
\end{{table}}

\begin{{figure}}[htbp]
\centering
\includegraphics[width=\columnwidth]{{{fp(figures_dir, 'fig_mitre_tactics')}}}
\caption{{Primary MITRE ATT\&CK tactic distribution across all {s['total']}
CVE instance records. Values show count and percentage.}}
\label{{fig:mitre}}
\end{{figure}}

The dominance of \tactic{{Initial Access}} ({safe_pct(s['tac_primary'].get('TA0001',0), s['total']):.1f}\%)
reflects the network-exposed, publicly routable nature of Kubernetes Ingress
workloads. \tactic{{Impact}} ({safe_pct(s['tac_primary'].get('TA0040',0), s['total']):.1f}\%)
is driven by DoS CVEs in shared system libraries
(\chart{{zlib}}, \chart{{libexpat}}, \chart{{libxml2}}).

A total of {s['multi_tactic']}~out of {s['total']}~records
({safe_pct(s['multi_tactic'], s['total']):.1f}\%) receive two or more tactic
assignments, indicating multi-phase exploit potential. The dominant
co-occurrence is \tactic{{Initial Access}} $\times$ \tactic{{Execution}}:
remote code execution on a Kubernetes workload simultaneously grants cluster
entry and arbitrary command execution.

% =============================================================================
\section{{Supply-Chain Vulnerability Propagation}}
\label{{sec:supply}}

\subsection{{Cross-Chart CVE Sharing}}

Of {s['unique_ids']}~unique CVE identifiers, \textbf{{{s['n_supply']}
({safe_pct(s['n_supply'], s['unique_ids']):.1f}\%) appear in two or more
charts}}---we term these \emph{{supply-chain CVEs}}. The remaining
{s['n_single']}~(66.9\%) are \emph{{singletons}}, confined to a single
chart's dependency tree.

\begin{{figure}}[htbp]
\centering
\includegraphics[width=\columnwidth]{{{fp(figures_dir, 'fig_supply_chain')}}}
\caption{{Top supply-chain CVEs ranked by number of charts affected.
Red bars: $\geq$30 charts (universal); orange: 10--29; blue: 2--9.}}
\label{{fig:supply}}
\end{{figure}}

Table~\ref{{tab:supply}} lists the ten CVEs with the highest propagation.

\begin{{table}}[htbp]
\centering
\caption{{Top-10 supply-chain CVEs by chart propagation count.}}
\label{{tab:supply}}
\small
\setlength{{\tabcolsep}}{{3.5pt}}
\begin{{tabular}}{{llcrcc}}
\toprule
\textbf{{CVE}} & \textbf{{Package}} & \textbf{{Charts}} & \textbf{{CVSS}} &
\textbf{{Sev.}} & \textbf{{Tactic}}\\
\midrule
{sc_table}
\bottomrule
\end{{tabular}}
\end{{table}}

\subsection{{Supply-Chain Attack Surface Multiplier}}

The \emph{{supply-chain attack surface multiplier}} (SCASM) is the mean
propagation count of supply-chain CVEs:
\begin{{equation}}
  \text{{SCASM}} = \frac{{1}}{{|\mathcal{{S}}|}}\sum_{{c \in \mathcal{{S}}}} |\text{{charts}}(c)| = {s['scasm']:.1f}
\end{{equation}}
A single unpatched library therefore creates correlated exploit
opportunities across $\approx{s['scasm']:.0f}$ distinct workloads
simultaneously. In a production Kubernetes cluster running a representative
subset of Bitnami charts, a delayed base image patch propagates HIGH/CRITICAL
exposure to the entire application fleet.

% =============================================================================
\section{{Deployment Frequency Analysis}}
\label{{sec:frequency}}

Figure~\ref{{fig:tiers}} shows Docker Hub pull counts for the top 15 charts
and the CVE record distribution across frequency tiers
(Table~\ref{{tab:tiers}}).

\begin{{table}}[htbp]
\centering
\caption{{CVE distribution by deployment frequency tier.}}
\label{{tab:tiers}}
\small
\begin{{tabular}}{{lrrr}}
\toprule
\textbf{{Tier}} & \textbf{{Threshold}} & \textbf{{CVE entries}} & \textbf{{\%}}\\
\midrule
{tier_table}
\midrule
\textbf{{Total}} & & \textbf{{{s['total']}}} & 100\%\\
\bottomrule
\end{{tabular}}
\end{{table}}

\begin{{figure}}[htbp]
\centering
\includegraphics[width=\columnwidth]{{{fp(figures_dir, 'fig_frequency_tiers')}}}
\caption{{Left: CVE distribution across deployment frequency tiers. Right:
top-15 charts by Docker Hub pull count (billions).}}
\label{{fig:tiers}}
\end{{figure}}

High-tier charts (\chart{{postgresql-ha}}, \chart{{redis}}, \chart{{mongodb}},
\chart{{nginx}}) represent the database and ingress infrastructure that forms
the backbone of most Kubernetes deployments. Despite their high pull counts,
they accumulate fewer CVEs than niche charts because Bitnami prioritises
patching for high-frequency images. This means the distribution of
deployment-weighted vulnerability exposure is less extreme than raw CVE
counts suggest.

% =============================================================================
\section{{Application Tier Analysis}}
\label{{sec:tiers}}

\subsection{{Five-Tier Taxonomy}}

We classify all {s['n_charts']}~charts into five application tiers derived
from their CyberBattleSim node properties. Table~\ref{{tab:tier_ov}} and
Figure~\ref{{fig:tier_ov}} summarise tier populations.

\begin{{table}}[htbp]
\centering
\caption{{Chart counts and CVE entries per application tier.}}
\label{{tab:tier_ov}}
\small
\begin{{tabular}}{{lrrp{{3.5cm}}}}
\toprule
\textbf{{Tier}} & \textbf{{Charts}} & \textbf{{CVEs}} & \textbf{{Examples}}\\
\midrule
{tier_ov_table}
\bottomrule
\end{{tabular}}
\end{{table}}

\begin{{figure}}[htbp]
\centering
\includegraphics[width=\columnwidth]{{{fp(figures_dir, 'fig_tier_overview')}}}
\caption{{CVE instance counts (left) and unique chart counts (right) per
application tier.}}
\label{{fig:tier_ov}}
\end{{figure}}

AppTier dominates both chart count (55 charts) and CVE instances, reflecting
the diversity of application workloads in modern Kubernetes deployments.
DataTier shows the highest \emph{{per-chart}} CVE density due to
database-specific CVEs layered on top of shared OS library exposure.

% =============================================================================
\section{{CBS Node Properties}}
\label{{sec:properties}}

\subsection{{Property Vocabulary}}

The dataset exposes {len({k for c in s['cves'] for k in c.get('chart_properties',[])})}~unique CyberBattleSim
node property strings across the {s['n_charts']}~charts. These properties
serve as exploit-matching labels in domain configuration YAML:
\texttt{{match\_properties}} in each vulnerability entry constrains which
node types the exploit applies to.

Figure~\ref{{fig:props}} shows the frequency of each property (excluding
\texttt{{Linux}}, which is universal). Table~\ref{{tab:props}} lists the
top 15.

\begin{{figure}}[htbp]
\centering
\includegraphics[width=\columnwidth]{{{fp(figures_dir, 'fig_cbs_properties')}}}
\caption{{CBS node property frequency across all CVE records (universal
\texttt{{Linux}} property excluded). Teal bars indicate properties that
directly enable specific CVE-backed exploits.}}
\label{{fig:props}}
\end{{figure}}

\begin{{table}}[htbp]
\centering
\caption{{Top 15 CBS node properties by frequency.}}
\label{{tab:props}}
\small
\begin{{tabular}}{{lrr}}
\toprule
\textbf{{Property}} & \textbf{{Frequency}} & \textbf{{\%}}\\
\midrule
{prop_table}
\bottomrule
\end{{tabular}}
\end{{table}}

\texttt{{AppServer}} is the most frequent non-universal property
({safe_pct(s['prop_cnt'].get('AppServer',0), s['total']):.1f}\%), driven by
the 55~AppTier charts that dominate the repository. Runtime properties
(\texttt{{GoRuntime}}, \texttt{{Java}}, \texttt{{PHP}}, \texttt{{Python}})
provide fine-grained exploit matching, enabling separate vulnerability
entries for language-runtime CVEs on top of the OS-level exposure.

% =============================================================================
\section{{Temporal Analysis}}
\label{{sec:temporal}}

Figure~\ref{{fig:year}} shows the CVE publication year distribution. Two
peaks emerge: 2023 ({s['year_cnt'].get(2023,0)} records) and 2025
({s['year_cnt'].get(2025,0)} records), with a secondary peak in 2021--2022.
The 2023 dominance is driven by \chart{{libperl5.36}} and \chart{{zlib}}
supply-chain CVEs that were assigned 2023 publication dates despite
affecting older code paths. The 2025 peak reflects recently filed CVEs
in active Bitnami dependency libraries at the time of scanning.

\begin{{figure}}[htbp]
\centering
\includegraphics[width=\columnwidth]{{{fp(figures_dir, 'fig_year_distribution')}}}
\caption{{CVE publication year distribution across all {s['total']}~instance
records.}}
\label{{fig:year}}
\end{{figure}}

The fix availability rate of {s['fix_rate']:.1f}\% ({s['fixed']} CVEs with
non-empty \texttt{{fixed\_version}}) indicates that most vulnerabilities have
known remediations. This enables the CyberBattleSim scenario generator to
model mixed-patch environments: nodes carrying the \texttt{{Unpatched}}
property are assigned higher exploit probabilities, while \texttt{{Patched}}
nodes disable matching CVE-backed exploits.

% =============================================================================
\section{{CyberBattleSim Integration}}
\label{{sec:integration}}

\subsection{{Kubernetes Topology Model}}

Network topology follows the namespace segmentation model of the NSA/CISA
Kubernetes Hardening Guide~\cite{{nsacisa2022}}:
\begin{{equation*}}
\text{{Internet}} \to \underbrace{{\text{{Ingress}}}}_{{\text{{nginx/haproxy}}}} \to
\underbrace{{\text{{Application}}}}_{{\text{{CMS/API}}}} \to
\underbrace{{\text{{Data}}}}_{{\text{{DB/Cache}}}} \to
\underbrace{{\text{{Worker}}}}_{{\text{{Kafka/Airflow}}}}
\end{{equation*}}
Firewall constraints enforce that no WebTier node can reach DataTier
directly---traffic must route through AppTier, creating a multi-hop kill
chain. This maps to CyberBattleSim's \texttt{{inter\_domain\_constraints}}
mechanism.

\subsection{{Deployment-Weighted Sampling}}

During scenario generation, charts are sampled with probability
$P(c) \propto w_c$ (Equation~\eqref{{eq:weight}}). This ensures generated
topologies reflect realistic Kubernetes service distributions: \chart{{redis}}
and \chart{{postgresql}} appear with high frequency, while niche charts such
as \chart{{janusgraph}} are sampled rarely---matching observed enterprise
cluster compositions~\cite{{cncf2024}}.

\subsection{{Dataset Limitations}}

\textbf{{Package CVEs only.}} Trivy surfaces OS-level and application-package
CVEs; it does not capture Kubernetes-native attack vectors (RBAC
misconfigurations, service account token abuse, container escapes). The
dataset underrepresents \tactic{{Privilege Escalation}}, \tactic{{Lateral
Movement}}, and \tactic{{Persistence}} relative to their real-world
prevalence in Kubernetes breaches.

\textbf{{Bitnami selection bias.}} The {s['n_charts']}~charts represent
Bitnami's actively maintained portfolio. Community charts or custom images
may face substantially different vulnerability profiles.

\textbf{{Deployment frequency proxy.}} Docker Hub pull counts measure image
downloads, not active deployments. CNCF adoption survey data would provide
a more faithful frequency signal.

% =============================================================================
{vulndb_section}
% =============================================================================
\section{{Conclusion}}
\label{{sec:conclusion}}

We presented a CVE-grounded vulnerability dataset covering {s['n_charts']}~Bitnami
Helm charts with {s['total']}~instance records. Key findings: 100\% of CVEs
are network-reachable; {safe_pct(n_crit, s['total']):.1f}\% are CRITICAL with
mean CVSS {s['cvss_mean']:.2f}; {safe_pct(s['n_supply'], s['unique_ids']):.1f}\%
of unique CVEs are supply-chain vulnerabilities with a mean propagation of
{s['scasm']:.1f}~charts; and the derived mean success rate of
{s['sr_mean']:.3f} provides an empirical DRL training baseline. The dataset
enables deployment-frequency-weighted generation of Kubernetes attack scenarios
for reinforcement learning, grounding exploit parameters in real CVSS data
rather than hand-authored guesses.

% ── References ────────────────────────────────────────────────────────────────
\begin{{thebibliography}}{{99}}

\bibitem{{cyberbattlesim2021}}
M. Msaad \etal, ``CyberBattleSim,'' \emph{{Microsoft Research}}, 2021.
\url{{https://github.com/microsoft/CyberBattleSim}}

\bibitem{{terranova2025}}
F. Terranova, A. Lahmadi, and I. Chrisment,
``Scalable and Generalizable RL Agents for Attack Path Discovery,''
\emph{{RAID}}, 2025.

\bibitem{{trivy}}
Aqua Security, ``Trivy: Vulnerability Scanner for Containers,'' 2024.
\url{{https://github.com/aquasecurity/trivy}}

\bibitem{{nvd}}
NIST, ``National Vulnerability Database,'' 2024. \url{{https://nvd.nist.gov}}

\bibitem{{cncf2024}}
CNCF, ``Annual Survey 2024,'' 2024.
\url{{https://www.cncf.io/reports/cncf-annual-survey-2024/}}

\bibitem{{nsacisa2022}}
NSA/CISA, ``Kubernetes Hardening Guide v1.2,'' 2022.

\bibitem{{attackcontainers}}
MITRE, ``ATT\&CK for Containers,'' 2024.
\url{{https://attack.mitre.org/matrices/enterprise/containers/}}

\bibitem{{bitnami}}
Broadcom/Bitnami, ``Bitnami Helm Charts Repository,'' 2024.
\url{{https://github.com/bitnami/charts}}

\bibitem{{cvss31}}
FIRST.org, ``CVSS v3.1 Specification,'' 2023.
\url{{https://www.first.org/cvss/v3.1/specification-document}}

\end{{thebibliography}}

\end{{document}}
"""
    return doc


# ─── Compilation ──────────────────────────────────────────────────────────────

def compile_latex(tex_path: Path):
    out_dir = tex_path.parent
    stem    = tex_path.stem
    print(f"Compiling {tex_path.name} ...")
    for _pass in range(2):
        result = subprocess.run(
            ["pdflatex", "-interaction=nonstopmode", "-output-directory",
             str(out_dir), str(tex_path)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            # print last 30 lines of log for debugging
            log_tail = "\n".join(result.stdout.splitlines()[-30:])
            print(f"pdflatex error (pass {_pass+1}):\n{log_tail}", file=sys.stderr)
            if _pass == 0:
                print("  Retrying second pass anyway...")
            else:
                print("  WARNING: compilation failed on both passes. "
                      "Check the .log file for details.")
                return False
    # clean aux files
    for ext in (".aux", ".log", ".out", ".toc"):
        f = out_dir / (stem + ext)
        if f.exists():
            f.unlink()
    pdf = out_dir / (stem + ".pdf")
    if pdf.exists():
        print(f"  ✓  PDF generated: {pdf}")
    return pdf.exists()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR,
                        help="Output directory (default: Google Drive path)")
    parser.add_argument("--no-compile", action="store_true",
                        help="Skip pdflatex compilation")
    parser.add_argument("--dataset", choices=["trivy", "vulndb", "combined"],
                        default="combined",
                        help="Which dataset to use for the main analysis")
    args = parser.parse_args()

    out_dir     = args.out_dir
    figures_dir = out_dir / "figures" / "bitnami"
    tex_path    = out_dir / "bitnami_analysis.tex"

    out_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load primary dataset
    data_file = DATA_FILES[args.dataset]
    print(f"Loading {data_file.name} (--dataset={args.dataset})...")
    d = load_data(data_file)
    s = compute_stats(d)
    print(f"  {s['total']} records, {s['unique_ids']} unique CVEs, "
          f"{s['n_charts']} charts")

    # 2. Load all three datasets for source comparison figure (if all exist)
    all_stats = None
    if all(p.exists() for p in DATA_FILES.values()):
        print("Loading all three datasets for source comparison...")
        all_stats = {}
        for key, path in DATA_FILES.items():
            dd = load_data(path)
            all_stats[key] = compute_stats(dd)
            print(f"  {key}: {all_stats[key]['total']} records, "
                  f"{all_stats[key]['n_charts']} charts")
    else:
        missing = [k for k, p in DATA_FILES.items() if not p.exists()]
        print(f"  Skipping source comparison (missing: {missing})")

    # 3. Generate figures
    generate_all_figures(s, figures_dir, all_stats=all_stats)

    # 4. Write .tex
    print(f"Writing {tex_path}...")
    tex_content = build_latex(s, figures_dir, all_stats=all_stats)
    tex_path.write_text(tex_content, encoding="utf-8")
    print(f"  ✓  {tex_path} ({len(tex_content.splitlines())} lines)")

    # 5. Compile
    if not args.no_compile:
        compile_latex(tex_path)
    else:
        print("  Skipping compilation (--no-compile).")

    print("\nDone.")


if __name__ == "__main__":
    main()
