from pathlib import Path
from ..latex_base import e
from ..visual_utils import (
    save_attack_path_figure,
    save_action_type_figure,
    save_strategic_metrics_figure,
    save_chokepoint_heatmap,
)


def _fmt(s: dict, key: str, fmt: str = "{:.2f}") -> str:
    if not isinstance(s, dict):
        return "---"
    v = s.get(key)
    if v is None or v == "---":
        return "---"
    try:
        return fmt.format(float(v))
    except (TypeError, ValueError):
        return "---"


def attack_path_section(entries: list, workdir: Path) -> str:
    """Full attack path metrics section (§3.4)."""
    ap_bar_pdf    = workdir / "attack_path_bars.pdf"
    act_type_pdf  = workdir / "action_type_bars.pdf"
    strat_pdf     = workdir / "strategic_metrics_bars.pdf"
    choke_map_pdf = workdir / "choke_point_heatmap.pdf"

    save_attack_path_figure(entries,      ap_bar_pdf)
    save_action_type_figure(entries,      act_type_pdf)
    save_strategic_metrics_figure(entries, strat_pdf)
    save_chokepoint_heatmap(entries,      choke_map_pdf)

    def _inc(p, w=r"0.96\linewidth"):
        return rf"\includegraphics[width={w}]{{{p.name}}}" if p.exists() else ""

    # ── Guard: only render if any entry has attack path data ─────────────────
    has_data = any(entry.get("attack_path_stats", {}).get("n_samples", 0) > 0
                   for entry in entries)
    if not has_data:
        return ""

    # ── Summary table ─────────────────────────────────────────────────────────
    rows = ""
    for entry in entries:
        aps = entry.get("attack_path_stats", {})
        if not aps.get("n_samples"):
            continue
        hops_m  = _fmt(aps.get("avg_hops", {}),             "mean", "{:.1f}")
        acts_m  = _fmt(aps.get("avg_actions", {}),           "mean", "{:.1f}")
        prob_m  = _fmt(aps.get("avg_success_prob", {}),      "mean", "{:.3f}")
        own_m   = _fmt(aps.get("avg_min_nodes_to_own", {}),  "mean", "{:.1f}")
        cost_m  = _fmt(aps.get("avg_cost", {}),              "mean", "{:.1f}")
        reach   = f"{aps.get('reachable_ratio', 0)*100:.0f}\\%"
        dom     = e(aps.get("dominant_action_type", "---").replace("_", " ").title())
        n_samp  = aps.get("n_samples", 0)
        rows += (
            rf"  {e(entry['short_name'])} & {n_samp} & {hops_m} & {own_m} & "
            rf"{acts_m} & {prob_m} & {cost_m} & {reach} & {dom} \\" + "\n"
        )

    # ── Elite Metrics Table ───────────────────────────────────────────────────
    strat_rows = ""
    for entry in entries:
        aps = entry.get("attack_path_stats", {})
        if not aps.get("n_samples"):
            continue
        red_m   = _fmt(aps.get("avg_path_redundancy", {}), "mean", "{:.2f}")
        vis_m   = _fmt(aps.get("avg_visibility", {}),      "mean", "{:.3f}")
        choke_m = _fmt(aps.get("avg_chokepoints", {}),     "mean", "{:.1f}")
        stl_m   = _fmt(aps.get("avg_stealth", {}),          "mean", "{:.2f}")
        st_cnt  = aps.get("stealthy_count", 0)
        n_samp  = aps.get("n_samples", 1)
        st_pct  = f"{st_cnt/n_samp*100:.0f}\\%"
        strat_rows += (
            rf"  {e(entry['short_name'])} & {red_m} & {vis_m} & {choke_m} & {stl_m} & {st_pct} \\" + "\n"
        )

    # ── Per-goal example table ────────────────────────────────────────────────
    goal_rows = ""
    for entry in entries:
        examples = entry.get("attack_path_stats", {}).get("per_goal_examples", [])
        if not examples:
            continue
        # Show up to 3 goals from the first scenario that has examples
        for gm in examples[:3]:
            gid  = e(gm.get("goal", "?"))
            hops = gm.get("total_hops", "?")
            own  = gm.get("min_nodes_to_own", "?")
            acts = gm.get("total_actions", "?")
            prob = gm.get("success_probability", 0)
            att  = gm.get("expected_attempts", "?")
            cost = gm.get("total_cost", "?")
            tc   = gm.get("action_type_counts", {})
            dom  = max(tc, key=tc.get) if tc else "---"
            path = " $\\rightarrow$ ".join(e(n) for n in gm.get("path", []))
            goal_rows += (
                rf"  \small {gid} & {hops} & {own} & {acts} & "
                rf"{prob:.3f} & {att if att else '---'} & {cost} & "
                rf"\small\textit{{{e(dom.replace('_',' ').title())}}} \\" + "\n"
                + rf"  \multicolumn{{8}}{{l}}{{\footnotesize Path: {path}}} \\" + "\n"
                + r"  \addlinespace" + "\n"
            )
        break   # only show examples from first scenario with data

    goal_table = ""
    if goal_rows:
        goal_table = (
            r"\subsubsection*{Representative Per-Goal Attack Paths}" + "\n\n"
            + r"{\small The table shows BFS-optimal paths for representative goals from one"
            + r" scenario instance.  $P_{success}$ is the product of all action success rates"
            + r" along the path; Expected attempts = $1/P_{success}$.}" + "\n\n"
            + r"\smallskip" + "\n"
            + r"\noindent" + "\n"
            + r"{\setlength{\tabcolsep}{4pt}" + "\n"
            + r"\begin{tabular}{p{5.5cm}rrrrrrl}" + "\n"
            + r"\toprule" + "\n"
            + r"\textbf{Goal node} & \textbf{Hops} & \textbf{Own} & \textbf{Acts} &"
            + r" \textbf{$P_{suc}$} & \textbf{Att} & \textbf{Cost} & \textbf{Dominant action} \\" + "\n"
            + r"\midrule" + "\n"
            + goal_rows
            + r"\bottomrule" + "\n"
            + r"\end{tabular}" + "\n"
            + r"}" + "\n"
            + r"\textit{\footnotesize Own = intermediate nodes to own before goal."
            + r"  Acts = total CBS action steps."
            + r"  Att = expected independent attempts for one successful run.}" + "\n"
        )

    ap_bar_inc   = _inc(ap_bar_pdf,    r"0.75\linewidth")
    act_type_inc = _inc(act_type_pdf,  r"0.80\linewidth")
    strat_inc    = _inc(strat_pdf,     r"0.75\linewidth")
    choke_inc    = _inc(choke_map_pdf, r"0.85\linewidth")

    return rf"""
\newpage
\subsection{{Attack Path Metrics (\S 3.4)}}
\label{{sec:attack_paths}}

Static BFS analysis of the minimum-hop attack path from the attacker entry point
to each goal node, computed from generated scenario node files (no agent required).
For each scenario configuration up to 30 randomly sampled instances are analysed;
reported values are means across instances.

\smallskip\noindent\textbf{{Metric definitions.}}
\begin{{itemize}}
  \item \textbf{{Avg hops}} --- mean number of lateral-movement hops (node-ownership transitions)
        from \texttt{{start}} to a goal across all goals.
  \item \textbf{{Avg nodes to own}} --- mean number of \emph{{intermediate}} nodes that must be
        compromised before the goal (excludes \texttt{{start}} and the goal itself).
  \item \textbf{{Avg actions}} --- mean count of individual CBS action steps on the optimal path,
        including prerequisite local actions (discovery, credential-leak) at each hop and
        post-compromise actions (privesc, dump) at the goal.
  \item \textbf{{$P_{{success}}$}} --- probability a single optimal-path run succeeds end-to-end,
        computed as the product of all action \texttt{{success\_rate}} values.
  \item \textbf{{Avg cost}} --- sum of \texttt{{cost}} fields across all path actions.
  \item \textbf{{Dominant action}} --- the most frequent CBS action type across all goal paths.
\end{{itemize}}

\subsubsection*{{Per-Scenario Summary}}

\noindent
{{\setlength{{\tabcolsep}}{{4pt}}
\begin{{tabular}}{{lrrrrrrrp{{3.2cm}}}}
\toprule
\textbf{{Scenario}} & \textbf{{N}} &
\textbf{{Hops}} & \textbf{{Own}} & \textbf{{Acts}} &
\textbf{{$P_{{suc}}$}} & \textbf{{Cost}} & \textbf{{Reach\%}} & \textbf{{Dominant action}} \\
\midrule
{rows}\bottomrule
\end{{tabular}}
}}
\textit{{\footnotesize N = instances analysed.
  Reach\% = fraction of goals reachable from \texttt{{start}} in the hop graph.
  $P_{{suc}}$ = mean success probability (product of action rates).}}

\medskip
\begin{{center}}
{ap_bar_inc}
\end{{center}}

\subsubsection*{{Action-Type Composition}}

The stacked bars show what fraction of CBS actions on optimal paths fall into each
action type.  \textbf{{LOCAL\_CRED\_LEAK}} dominates scenarios relying on credential
chains; \textbf{{REMOTE\_EXPLOIT}} dominates scenarios with rich remote vulnerability
coverage.

\begin{{center}}
{act_type_inc}
\end{{center}}

\textit{{\footnotesize
  REMOTE\_EXPLOIT: exploit a REMOTE vulnerability from an owned source node.
  CREDENTIAL\_USE: connect to a service port using stolen credentials (deterministic, $p=1.0$).
  LOCAL\_CRED\_LEAK: run a LOCAL vulnerability that leaks credentials for downstream nodes.
  LOCAL\_DISCOVERY: run a LOCAL vulnerability that reveals neighbour node IDs.
  LOCAL\_PRIVESC: privilege escalation on the goal node.
  LOCAL\_DUMP: credential dump / data exfil on the goal node.
}}

\newpage
\subsection{{Strategic Complexity Analysis}}
\label{{sec:strategic_complexity}}

This section introduces "elite" metrics that quantify the strategic challenge posed
by a scenario's topology and vulnerability placement.

\smallskip\noindent\textbf{{Strategic metric definitions.}}
\begin{{itemize}}
  \item \textbf{{Path Redundancy Factor}} --- Count of unique optimal (shortest) paths to the goal.
        Higher redundancy implies the attacker has multiple tactical options.
  \item \textbf{{Visibility Index}} --- Fraction of node properties and vulnerabilities
        discoverable without owning the node. High visibility aids attacker planning.
  \item \textbf{{Choke Point Centrality}} --- Count of nodes that appear on \emph{{every}}
        optimal path to a goal. These are critical defensive priorities.
  \item \textbf{{Stealth Margin}} --- The difference between the cumulative detection
        probability threshold and the actual detection cost of the optimal path.
        Positive values indicate a "stealthy" path exists.
\end{{itemize}}

\subsubsection*{{Strategic Metrics Summary}}

\noindent
{{\setlength{{\tabcolsep}}{{6pt}}
\begin{{tabular}}{{lrrrrr}}
\toprule
\textbf{{Scenario}} & \textbf{{Redundancy}} & \textbf{{Visibility}} & \textbf{{Choke Points}} & \textbf{{Stealth Margin}} & \textbf{{Stealthy\%}} \\
\midrule
{strat_rows}\bottomrule
\end{{tabular}}
}}
\textit{{\footnotesize Redundancy = unique optimal paths. Visibility index (0-1).
  Choke Points = nodes on all optimal paths. Stealthy\% = instances with positive margin.}}

\medskip
\begin{{center}}
{strat_inc}
\end{{center}}

\subsubsection*{{Global Choke Point Map}}

The heatmap identifies service groups that consistently act as bottlenecks (choke points)
across different network strata. Nodes in these groups appear on \emph{{every}} optimal
attack path, making them the highest-value targets for both attackers (to control)
and defenders (to harden).

\begin{{center}}
{choke_inc}
\end{{center}}

{goal_table}
"""


def graph_statistics_section(entries: list, workdir: Path) -> str:
    """Full graph statistics / distribution analysis section."""
    box_struct_pdf  = workdir / "graph_boxplots_struct.pdf"
    box_payload_pdf = workdir / "graph_boxplots_payload.pdf"
    scatter_pdf     = workdir / "graph_scatter.pdf"
    degree_dist_pdf = workdir / "degree_dist.pdf"

    # Import from data_utils (they live there even though they create charts)
    from ..visual_utils import (
        save_graph_boxplots as _sgb,
        save_payload_boxplots as _spb,
        save_nodes_edges_scatter as _sns,
        save_degree_dist_chart as _sdd,
    )
    _sgb(entries, box_struct_pdf)
    _spb(entries, box_payload_pdf)
    _sns(entries, scatter_pdf)
    _sdd(entries, degree_dist_pdf)

    def _inc(p: Path, w: str) -> str:
        return rf"\includegraphics[width={w}]{{{p.name}}}" if p.exists() else ""

    box_struct_inc  = _inc(box_struct_pdf,  r"\linewidth")
    box_payload_inc = _inc(box_payload_pdf, r"\linewidth")
    scatter_inc     = _inc(scatter_pdf,     r"0.50\linewidth")
    degree_inc      = _inc(degree_dist_pdf, r"0.46\linewidth")

    # Cross-domain extended statistics table
    col_keys = [
        ("nodes",         "Nodes"),
        ("edges",         "Edges"),
        ("density",       "Density"),
        ("diameter",      "Diam."),
        ("avg_degree",    "Avg Deg"),
        ("max_degree",    "Max Deg"),
        ("vuln_inst",     "Vulns"),
        ("unique_vulns",  "UVulns"),
        ("unique_props",  "UProps"),
        ("vuln_per_node", "V/N"),
    ]

    def _fmtval(val, key):
        if val == "---" or val is None:
            return "---"
        try:
            fv = float(val)
        except (TypeError, ValueError):
            return "---"
        if key in ("density", "vuln_per_node"):
            return f"{fv:.3f}"
        return str(int(fv)) if fv == int(fv) else f"{fv:.1f}"

    header_cols = " & ".join(
        rf"\textbf{{{e(lbl)}}}" for _, lbl in col_keys
    )
    metric_rows = ""
    for entry in entries:
        ss    = entry.get("sample_stats", {})
        cells = []
        for key, _ in col_keys:
            s  = ss.get(key, {})
            mn = _fmtval(s.get("mean", "---"), key)
            sd = _fmtval(s.get("stdev", "---"), key)
            cells.append(f"{mn} ({sd})")
        metric_rows += rf"  {e(entry['short_name'])} & " + " & ".join(cells) + r" \\" + "\n"

    n_cols   = len(col_keys)
    col_spec = "l" + "r" * n_cols

    return rf"""
\newpage
\subsection{{Graph \& Scenario Statistical Analysis}}

This section provides distribution analysis of graph structural and payload properties
across all generated scenarios, giving a quantitative characterisation of the dataset's
diversity and complexity.

\subsubsection*{{Graph Structure Distribution}}

Each box shows the spread of values across scenarios within a domain (median, IQR, whiskers).

\begin{{center}}
{box_struct_inc}
\end{{center}}

\subsubsection*{{Payload (Vulnerability \& Property) Distribution}}

\begin{{center}}
{box_payload_inc}
\end{{center}}

\subsubsection*{{Degree Distribution and Node--Edge Relationship}}

\begin{{center}}
{degree_inc}\hfill
{scatter_inc}
\end{{center}}

\vspace{{4pt}}
\noindent\textit{{\footnotesize
  Left: mean avg/max degree per domain.  Right: each point = one scenario;
  point size $\propto$ unique vulnerabilities; colour = domain.}}

\subsection*{{Cross-Domain Summary Statistics}}

\noindent Values shown as \textit{{mean (SD)}} over scenarios within each domain.
Column abbreviations: Diam.=diameter, Avg/Max Deg=in-degree, UVulns/UProps=unique
vulnerability/property types, V/N=vulnerabilities per node.

\begin{{center}}
{{\small
\setlength{{\tabcolsep}}{{4pt}}
\begin{{tabular}}{{{col_spec}}}
\toprule
\textbf{{Domain}} & {header_cols} \\
\midrule
{metric_rows}\bottomrule
\end{{tabular}}
}}
\end{{center}}
"""
