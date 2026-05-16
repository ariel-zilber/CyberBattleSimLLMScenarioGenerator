"""
tools/cve_scenario_graphs.py
=============================
CVE-grounding visualisations for CyberBattleSim domain config YAML files.

Generates 4 matplotlib figures:
  1. success_rate distribution & implied CVSS
  2. Attack surface map (REMOTE vs LOCAL per category)
  3. Exploit cost tier distribution
  4. Match-property coverage heatmap + CVE grounding dashboard

Usage:
    # from pipeline.reporting.cve_scenario_graphs import generate_cve_graphs
    paths = generate_cve_graphs(eval_result, out_dir=Path("figures/"))
"""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ── Style ─────────────────────────────────────────────────────────────────────

DARK_BG  = "#1a1a2e"
MID_BG   = "#16213e"
CARD_BG  = "#0f3460"
ACCENT   = "#e94560"
TEXT     = "#eaeaea"
GRID     = "#2a2a4a"

CAT_COLORS = {
    "remote_access":  "#e94560",
    "credential_leak":"#f5a623",
    "discovery":      "#7ed321",
    "goal_access":    "#9b59b6",
}

COST_COLORS = {
    1.0: "#e94560",  # CRITICAL
    1.5: "#f5a623",  # HIGH
    2.0: "#4a90d9",  # MEDIUM
    3.0: "#7ed321",  # LOW
}

COST_LABELS = {1.0: "CRITICAL\n(CVSS≥9.0)", 1.5: "HIGH\n(7≤CVSS<9)", 2.0: "MEDIUM\n(5≤CVSS<7)", 3.0: "LOW\n(CVSS<5)"}

def _style(fig, axes=None):
    fig.patch.set_facecolor(DARK_BG)
    if axes is None:
        return
    for ax in (axes if hasattr(axes, "__iter__") else [axes]):
        ax.set_facecolor(MID_BG)
        ax.tick_params(colors=TEXT, labelsize=8)
        ax.xaxis.label.set_color(TEXT)
        ax.yaxis.label.set_color(TEXT)
        if ax.get_title():
            ax.title.set_color(TEXT)
        for spine in ax.spines.values():
            spine.set_edgecolor(GRID)
        ax.grid(color=GRID, linewidth=0.5, alpha=0.7)


# ── Figure 1: Success-Rate Distribution & Implied CVSS ───────────────────────

def plot_success_rate_distribution(metrics: dict, out_path: Path) -> Path:
    """
    Two-panel figure:
      Left:  histogram of success_rate values, colour-coded by category
      Right: implied CVSS distribution (success_rate × 10), with CVSS band annotations
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("Vulnerability Success-Rate Distribution & Implied CVSS", color=TEXT, fontsize=13, y=1.01)
    _style(fig, [ax1, ax2])

    sr_records = metrics.get("success_rates", [])
    if not sr_records:
        for ax in (ax1, ax2):
            ax.text(0.5, 0.5, "No data", ha="center", va="center", color=TEXT, transform=ax.transAxes)
        fig.tight_layout()
        fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
        plt.close(fig)
        return out_path

    # Left: histogram by category
    bins = np.linspace(0.25, 1.0, 20)
    for cat, col in CAT_COLORS.items():
        vals = [r["sr"] for r in sr_records if r["category"] == cat]
        if vals:
            ax1.hist(vals, bins=bins, color=col, alpha=0.75, label=cat.replace("_", " "), edgecolor=DARK_BG, linewidth=0.5)

    ax1.axvline(0.65, color=ACCENT, linestyle="--", linewidth=1, label="HIGH CVE floor (CVSS 6.5)")
    ax1.axvline(0.90, color="#7ed321", linestyle="--", linewidth=1, label="CRITICAL cap (CVSS 9.0+)")
    ax1.set_xlabel("success_rate")
    ax1.set_ylabel("Count")
    ax1.set_title("By Category", color=TEXT, fontsize=10)
    ax1.legend(fontsize=7, facecolor=CARD_BG, labelcolor=TEXT, framealpha=0.8)

    # Right: implied CVSS histogram with band shading
    implied = [r["sr"] * 10 for r in sr_records]
    cvss_bins = np.linspace(0, 10, 25)
    ax2.hist(implied, bins=cvss_bins, color=ACCENT, alpha=0.8, edgecolor=DARK_BG, linewidth=0.5)

    # Band annotations
    for lo, hi, label, col in [
        (0, 4, "LOW", "#7ed321"), (4, 7, "MEDIUM", "#4a90d9"),
        (7, 9, "HIGH", "#f5a623"), (9, 10, "CRITICAL", ACCENT),
    ]:
        ax2.axvspan(lo, hi, alpha=0.08, color=col)
        ax2.text((lo + hi) / 2, ax2.get_ylim()[1] * 0.92 if ax2.get_ylim()[1] > 0 else 1,
                 label, ha="center", va="top", color=col, fontsize=7, fontweight="bold")

    ax2.axvline(np.mean(implied), color=TEXT, linestyle=":", linewidth=1.2,
                label=f"Mean: {np.mean(implied):.1f}")
    ax2.set_xlabel("Implied CVSS (success_rate × 10)")
    ax2.set_ylabel("Count")
    ax2.set_title("Implied CVSS Distribution", color=TEXT, fontsize=10)
    ax2.legend(fontsize=7, facecolor=CARD_BG, labelcolor=TEXT, framealpha=0.8)

    # Stats annotation
    all_sr = [r["sr"] for r in sr_records]
    stats_txt = (f"n={len(all_sr)}  mean={np.mean(all_sr):.2f}  "
                 f"median={np.median(all_sr):.2f}  min={min(all_sr):.2f}  max={max(all_sr):.2f}")
    fig.text(0.5, -0.02, stats_txt, ha="center", color=TEXT, fontsize=8, alpha=0.8)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    plt.close(fig)
    return out_path


# ── Figure 2: Attack Surface Map ─────────────────────────────────────────────

def plot_attack_surface_map(metrics: dict, out_path: Path) -> Path:
    """
    Two-panel figure:
      Left:  stacked horizontal bar per category (REMOTE vs LOCAL count)
      Right: scatter of each vulnerability (x=success_rate, y=implied_cost, col=category)
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("Attack Surface Map — Exploit Type & Parameter Space", color=TEXT, fontsize=13, y=1.01)
    _style(fig, [ax1, ax2])

    sr_records = metrics.get("success_rates", [])

    # Left: stacked bar REMOTE vs LOCAL per category
    cats = ["remote_access", "credential_leak", "discovery", "goal_access"]
    remote_counts = [sum(1 for r in sr_records if r["category"] == c and r["type"] == "REMOTE") for c in cats]
    local_counts  = [sum(1 for r in sr_records if r["category"] == c and r["type"] == "LOCAL")  for c in cats]
    cat_labels = [c.replace("_", " ") for c in cats]
    y = np.arange(len(cats))

    bars_r = ax1.barh(y, remote_counts, color=ACCENT, label="REMOTE", alpha=0.85, height=0.4)
    bars_l = ax1.barh(y - 0.42, local_counts, color="#4a90d9", label="LOCAL", alpha=0.85, height=0.4)

    for bar, val in zip(bars_r, remote_counts):
        if val > 0:
            ax1.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                     str(val), va="center", color=TEXT, fontsize=9)
    for bar, val in zip(bars_l, local_counts):
        if val > 0:
            ax1.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                     str(val), va="center", color=TEXT, fontsize=9)

    ax1.set_yticks(y - 0.21)
    ax1.set_yticklabels(cat_labels, color=TEXT, fontsize=9)
    ax1.set_xlabel("Count")
    ax1.set_title("REMOTE vs LOCAL per Category", color=TEXT, fontsize=10)
    ax1.legend(fontsize=8, facecolor=CARD_BG, labelcolor=TEXT)

    # Right: scatter success_rate vs exploit_cost
    costs = metrics.get("exploit_costs", [])
    for rec, cost in zip(sr_records, costs + [2.0] * max(0, len(sr_records) - len(costs))):
        col = CAT_COLORS.get(rec["category"], TEXT)
        ax2.scatter(rec["sr"], cost, color=col, alpha=0.7, s=60, edgecolors=DARK_BG, linewidths=0.5)

    # Horizontal lines for cost bands
    for cost, label in COST_LABELS.items():
        ax2.axhline(cost, color=COST_COLORS[cost], linestyle="--", linewidth=0.8, alpha=0.6)
        ax2.text(0.27, cost + 0.04, label.split("\n")[0], color=COST_COLORS[cost], fontsize=7)

    ax2.set_xlabel("success_rate")
    ax2.set_ylabel("exploit_cost")
    ax2.set_title("success_rate vs exploit_cost per Vulnerability", color=TEXT, fontsize=10)
    ax2.set_xlim(0.25, 0.95)
    ax2.set_ylim(0.5, 3.5)

    legend_patches = [mpatches.Patch(color=c, label=cat.replace("_"," ")) for cat, c in CAT_COLORS.items()]
    ax2.legend(handles=legend_patches, fontsize=7, facecolor=CARD_BG, labelcolor=TEXT)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    plt.close(fig)
    return out_path


# ── Figure 3: Exploit Cost Distribution ──────────────────────────────────────

def plot_exploit_cost_distribution(metrics: dict, out_path: Path) -> Path:
    """
    Two-panel figure:
      Left:  pie chart of exploit cost tier distribution
      Right: bar chart of OS coverage (Windows vs Linux vulns)
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle("Exploit Cost Tiers & OS CVE Coverage", color=TEXT, fontsize=13, y=1.01)
    _style(fig, [ax1, ax2])

    cost_dist = metrics.get("cost_dist", {})
    if cost_dist:
        vals   = [cost_dist.get(c, 0) for c in [1.0, 1.5, 2.0, 3.0]]
        labels = [COST_LABELS.get(c, str(c)) for c in [1.0, 1.5, 2.0, 3.0]]
        colors = [COST_COLORS.get(c, TEXT) for c in [1.0, 1.5, 2.0, 3.0]]
        non_zero = [(v, l, c) for v, l, c in zip(vals, labels, colors) if v > 0]
        if non_zero:
            v_nz, l_nz, c_nz = zip(*non_zero)
            wedges, texts, autotexts = ax1.pie(
                v_nz, labels=l_nz, colors=c_nz, autopct="%1.0f%%",
                startangle=140, textprops={"color": TEXT, "fontsize": 8},
                wedgeprops={"edgecolor": DARK_BG, "linewidth": 1.5},
            )
            for a in autotexts:
                a.set_color(DARK_BG)
                a.set_fontweight("bold")
    ax1.set_title("Exploit Cost Tier Distribution\n(CVSS band mapping)", color=TEXT, fontsize=10)

    # Right: Windows vs Linux coverage
    win  = metrics.get("windows_count", 0)
    lin  = metrics.get("linux_count",   0)
    tot  = metrics.get("total_vulns",   1)
    other = max(0, tot - win - lin)

    bar_labels = ["Windows\nCVEs", "Linux\nCVEs", "Other /\nGeneric"]
    bar_vals   = [win, lin, other]
    bar_colors = ["#4a90d9", "#7ed321", "#888"]
    bars = ax2.bar(bar_labels, bar_vals, color=bar_colors, alpha=0.85, width=0.5,
                   edgecolor=DARK_BG, linewidth=1)
    for bar, val in zip(bars, bar_vals):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
                 str(val), ha="center", va="bottom", color=TEXT, fontsize=10, fontweight="bold")
    ax2.set_ylabel("Vulnerability Count")
    ax2.set_title("OS / Platform Coverage", color=TEXT, fontsize=10)
    ax2.set_ylim(0, max(bar_vals) * 1.25 if max(bar_vals) > 0 else 5)

    # Coverage status annotation
    if win > 0 and lin > 0:
        status, col = "✓ Full OS Coverage (Windows + Linux)", "#7ed321"
    elif win > 0:
        status, col = "⚠ Windows only — add Linux CVEs", "#f5a623"
    elif lin > 0:
        status, col = "⚠ Linux only — add Windows CVEs", "#f5a623"
    else:
        status, col = "✗ No OS-specific CVEs", ACCENT
    ax2.text(0.5, -0.12, status, ha="center", va="top", color=col,
             fontsize=9, transform=ax2.transAxes, fontweight="bold")

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    plt.close(fig)
    return out_path


# ── Figure 4: Property Coverage Heatmap + Grounding Dashboard ────────────────

def plot_property_coverage_and_grounding(metrics: dict, eval_result: dict, out_path: Path) -> Path:
    """
    Two-panel figure:
      Left:  horizontal bar chart of top match_properties (freq across all vulns)
      Right: CVE grounding scorecard (key metrics as a dashboard)
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("Property Coverage & CVE Grounding Scorecard", color=TEXT, fontsize=13, y=1.01)
    _style(fig, [ax1, ax2])

    # Left: property frequency bar chart
    prop_freq = metrics.get("property_freq", {})
    if prop_freq:
        props  = list(prop_freq.keys())[:16]
        counts = [prop_freq[p] for p in props]

        # Color by whether it's CVE-backed
        CVE_BACKED = {
            "GoRuntime", "LibCrypto", "ImageMagick", "WordPressInstall", "KeycloakService",
            "MongoDB", "Redis", "MySQL", "AuthServer", "APIGateway", "AppServer", "WorkerNode",
            "Python", "SMBv1", "PrintSpooler", "ADCS", "MailServer", "MSSQLServer", "IISServer",
        }
        colors = [ACCENT if p in CVE_BACKED else "#4a90d9" for p in props]
        y = np.arange(len(props))
        bars = ax1.barh(y, counts, color=colors, alpha=0.85, height=0.6, edgecolor=DARK_BG)
        ax1.set_yticks(y)
        ax1.set_yticklabels(props, color=TEXT, fontsize=8)
        ax1.set_xlabel("Frequency in match_properties")
        ax1.set_title("Top match_properties\n(red = CVE-backed, blue = generic)", color=TEXT, fontsize=10)
        for bar, val in zip(bars, counts):
            ax1.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                     str(val), va="center", color=TEXT, fontsize=8)
    else:
        ax1.text(0.5, 0.5, "No match_properties data", ha="center", va="center",
                 color=TEXT, transform=ax1.transAxes)

    # Right: CVE grounding scorecard
    ax2.set_xlim(0, 10)
    ax2.set_ylim(0, 10)
    ax2.axis("off")

    cve_dim = eval_result.get("dimensions", {}).get("cve_grounding", {})
    cve_score = cve_dim.get("score", 0)
    cve_grade = cve_dim.get("grade", "?")

    total   = metrics.get("total_vulns", 0)
    cve_n   = metrics.get("cve_named_count", 0)
    form_n  = metrics.get("formula_rate_count", 0)
    remote  = metrics.get("remote_count", 0)
    local   = metrics.get("local_count", 0)
    win     = metrics.get("windows_count", 0)
    lin     = metrics.get("linux_count", 0)

    # Score gauge
    score_col = "#7ed321" if cve_score >= 8 else ("#f5a623" if cve_score >= 6 else ACCENT)
    ax2.text(5, 9.3, "CVE Grounding Score", ha="center", color=TEXT, fontsize=11, fontweight="bold")
    ax2.text(5, 8.5, f"{cve_score}/10  ({cve_grade})", ha="center", color=score_col, fontsize=20, fontweight="bold")

    bar_w = cve_score * 0.8
    ax2.add_patch(mpatches.FancyBboxPatch((1, 7.8), 8, 0.4, boxstyle="round,pad=0.05",
                                           facecolor=GRID, edgecolor=GRID))
    ax2.add_patch(mpatches.FancyBboxPatch((1, 7.8), bar_w, 0.4, boxstyle="round,pad=0.05",
                                           facecolor=score_col, edgecolor=score_col))

    # Metrics table
    metrics_rows = [
        ("Total vulnerabilities",    str(total),                       TEXT),
        ("CVE ID in name/desc",      f"{cve_n}/{total} ({_pct(cve_n,total)}%)",
         "#7ed321" if cve_n/max(total,1) >= 0.5 else "#f5a623"),
        ("Formula-derived SR",       f"{form_n}/{total} ({_pct(form_n,total)}%)",
         "#7ed321" if form_n/max(total,1) >= 0.6 else "#f5a623"),
        ("REMOTE exploits",          f"{remote} ({_pct(remote,total)}%)", ACCENT),
        ("LOCAL exploits",           f"{local} ({_pct(local,total)}%)",   "#4a90d9"),
        ("Windows CVE props",        str(win),  "#4a90d9"),
        ("Linux CVE props",          str(lin),  "#7ed321"),
        ("Dual OS coverage",
         "✓ YES" if win > 0 and lin > 0 else "✗ NO",
         "#7ed321" if (win > 0 and lin > 0) else ACCENT),
    ]
    y0 = 7.2
    for label, value, col in metrics_rows:
        ax2.text(1.2, y0, label, color=TEXT, fontsize=8.5, va="center")
        ax2.text(8.8, y0, value, color=col, fontsize=8.5, va="center", ha="right", fontweight="bold")
        ax2.axhline(y0 - 0.28, xmin=0.1, xmax=0.9, color=GRID, linewidth=0.5)
        y0 -= 0.7

    # Top findings from CVE grounding dimension
    findings = cve_dim.get("findings", [])
    fails = [f["message"][:60] for f in findings if f["type"] in ("fail", "critical")]
    if fails:
        ax2.text(5, y0 - 0.1, "⚠ Issues:", ha="center", color="#f5a623", fontsize=8, fontweight="bold")
        for i, msg in enumerate(fails[:2]):
            ax2.text(5, y0 - 0.55 - i * 0.5, f"• {msg}", ha="center", color=ACCENT, fontsize=7)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    plt.close(fig)
    return out_path


def _pct(n: int, total: int) -> int:
    return round(100 * n / max(total, 1))


# ── Public API ────────────────────────────────────────────────────────────────

def generate_cve_graphs(
    eval_result: dict,
    out_dir: Path,
    prefix: str = "",
) -> dict[str, Path]:
    """
    Generate all 4 CVE-grounding figures for a scenario evaluation result.

    Args:
        eval_result: Output of ScenarioQualityEvaluator.evaluate()
        out_dir:     Directory to write PNG files
        prefix:      Optional filename prefix (e.g. scenario name)

    Returns:
        Dict mapping graph name → output path
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pfx = f"{prefix}_" if prefix else ""

    metrics = eval_result.get("cve_metrics", {})

    paths = {}
    paths["success_rate"] = plot_success_rate_distribution(
        metrics, out_dir / f"{pfx}cve_01_success_rate.png"
    )
    paths["attack_surface"] = plot_attack_surface_map(
        metrics, out_dir / f"{pfx}cve_02_attack_surface.png"
    )
    paths["cost_os"] = plot_exploit_cost_distribution(
        metrics, out_dir / f"{pfx}cve_03_cost_os_coverage.png"
    )
    paths["grounding_scorecard"] = plot_property_coverage_and_grounding(
        metrics, eval_result, out_dir / f"{pfx}cve_04_grounding_scorecard.png"
    )
    return paths


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json, sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from scenario_quality_evaluator import evaluate_yaml_file

    parser = argparse.ArgumentParser(description="Generate CVE grounding graphs for a domain config")
    parser.add_argument("config", help="Path to domain config YAML")
    parser.add_argument("--out", default="figures/cve_graphs", help="Output directory")
    args = parser.parse_args()

    result = evaluate_yaml_file(Path(args.config))
    out_paths = generate_cve_graphs(result, Path(args.out), prefix=Path(args.config).stem)
    print(f"Generated {len(out_paths)} figures in {args.out}:")
    for name, p in out_paths.items():
        print(f"  {name}: {p}")
