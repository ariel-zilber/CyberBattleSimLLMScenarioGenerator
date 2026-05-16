import shutil
from pathlib import Path
from ..latex_base import e, slug, score_cmd
from ..data_utils import stats_table, copy_png_capped
from ..visual_utils import save_quality_bars, save_solve_donut

# Maps full outcome keys → short display labels (left col, right col pairs)
_OUTCOME_PAIRS = [
    ("LeakedCredentials",  "CredLeak",   "AdminEscalation",   "AdminEsc"),
    ("LeakedNodesId",      "NodeDisc",   "SystemEscalation",  "SysEsc"),
    ("LateralMove",        "Lateral",    "ProbeSucceeded",    "ProbeOK"),
    ("PrivilegeEscalation","PrivEsc",    "ExploitFailed",     "ExploitFail"),
]


def scenario_pages(entries: list, workdir: Path) -> str:
    """Generate full multi-page scenario section with all sub-content."""
    out = []
    for idx, entry in enumerate(entries):
        out.append(_scenario_page(entry, workdir, idx))
    return "\n".join(out)


def _scenario_page(entry: dict, workdir: Path, idx: int) -> str:
    name    = entry["name"]
    label   = slug(name)
    agg     = entry["agg"]
    desc    = entry.get("desc", {})
    div     = entry.get("diversity", {})
    p1      = entry.get("p1_score", 0)
    grade   = entry.get("p1_grade", "?")
    aps     = entry.get("attack_path_stats", {})

    # ── figures ──────────────────────────────────────────────────────────────
    bars_pdf  = workdir / f"bars_{idx}.pdf"
    donut_pdf = workdir / f"donut_{idx}.pdf"
    topo_file = None

    if entry.get("dim_scores"):
        save_quality_bars(entry["dim_scores"], bars_pdf)

    save_solve_donut(agg, donut_pdf)

    topo_src = entry.get("topo_graph")
    if topo_src and Path(topo_src).exists():
        ext       = Path(topo_src).suffix
        topo_file = workdir / f"topo_{idx}{ext}"
        shutil.copy(topo_src, topo_file)

    # Copy per-scenario graph PNGs
    graph_files: dict = {}
    for key in ("attack_paths", "network_graph", "compact_subnet", "subnet_topology"):
        src = entry.get("graph_pngs", {}).get(key)
        if src and Path(src).exists():
            dst = workdir / f"graph_{idx}_{key}.png"
            copy_png_capped(Path(src), dst, max_width=2400)
            graph_files[key] = dst
    if "subnet_topology" not in graph_files and topo_file and topo_file.exists():
        graph_files["subnet_topology"] = topo_file

    # Copy schema architecture diagram (zone-level, no individual instances)
    schema_src = entry.get("schema_diagram")
    schema_file = None
    if schema_src and Path(schema_src).exists():
        schema_dst = workdir / f"schema_{idx}.png"
        copy_png_capped(Path(schema_src), schema_dst, max_width=3200)
        schema_file = schema_dst

    # ── attack progression ────────────────────────────────────────────────────
    prog_items = "".join(
        rf"  \item \small {e(step.strip())}" + "\n"
        for step in desc.get("progression", []) if step.strip()
    )
    prog_block = (
        rf"\begin{{itemize}}{prog_items}\end{{itemize}}"
        if prog_items
        else r"\textit{See YAML config for details.}"
    )

    overview_raw = desc.get("overview", "")
    overview     = e(overview_raw)

    # ── generation specification block ───────────────────────────────────────
    hdr      = entry.get("yaml_header", {})
    gen_req  = entry.get("generation_request", "")
    spec_rows = ""
    if hdr.get("title"):
        spec_rows += rf"  \textbf{{Scenario}} & \small {e(hdr['title'])} \\" + "\n"
    if hdr.get("agent"):
        spec_rows += rf"  \textbf{{Agent}} & \small\texttt{{{e(hdr['agent'])}}} \\" + "\n"
    if hdr.get("zones"):
        spec_rows += rf"  \textbf{{Zones}} & \small {e(hdr['zones'])} \\" + "\n"
    if hdr.get("goal"):
        spec_rows += rf"  \textbf{{Terminal Goal}} & \small\texttt{{{e(hdr['goal'])}}} \\" + "\n"
    if hdr.get("nodes"):
        spec_rows += rf"  \textbf{{Node Count}} & \small {e(hdr['nodes'])} \\" + "\n"
    if gen_req:
        spec_rows += rf"  \textbf{{User Prompt}} & \small {e(gen_req)} \\" + "\n"

    gen_req_block = ""
    if spec_rows:
        gen_req_block = (
            r"\vspace{0.3cm}" + "\n"
            r"\noindent\colorbox{gray!8}{\parbox{\linewidth}{\smallskip" + "\n"
            r"\noindent\textbf{\small Generation Specification (used to produce this scenario's YAML template):}\\" + "\n"
            r"\smallskip" + "\n"
            r"\noindent\begin{tabular}{@{}ll@{}}" + "\n"
            + spec_rows +
            r"\end{tabular}" + "\n"
            r"\smallskip}}" + "\n"
            r"\vspace{0.2cm}" + "\n"
        )

    # ── schema architecture diagram ───────────────────────────────────────────
    schema_block = ""
    if schema_file and schema_file.exists():
        schema_block = (
            r"\vspace{0.3cm}" + "\n"
            r"\noindent\textbf{Network Architecture (zone-level overview):} \\" + "\n"
            rf"\noindent\includegraphics[width=\linewidth,height=0.28\textheight,keepaspectratio]{{{schema_file.name}}}" + "\n"
            r"\vspace{0.2cm}" + "\n"
        )

    # ── quality bars include ──────────────────────────────────────────────────
    bars_include = (rf"\includegraphics[width=\linewidth]{{{bars_pdf.name}}}"
                    if bars_pdf.exists() else "")
    donut_include = (rf"\includegraphics[width=0.8\linewidth]{{{donut_pdf.name}}}"
                     if donut_pdf.exists() else "")

    # ── action outcomes table ─────────────────────────────────────────────────
    ot = agg.get("outcome_totals", {})
    outcome_rows = ""
    for lk, ls, rk, rs in _OUTCOME_PAIRS:
        lv = int(ot.get(lk, 0))
        rv = int(ot.get(rk, 0))
        outcome_rows += rf"    {ls} & {lv} & {rs} & {rv} \\" + "\n"

    outcome_table = rf"""
\vspace{{0.4cm}}
\begin{{tabular}}{{lr|lr}}
  \toprule
  \multicolumn{{4}}{{c}}{{\textbf{{Action Outcomes}}}} \\
  \midrule
{outcome_rows}  \bottomrule
\end{{tabular}}"""

    # ── runtime metrics table ─────────────────────────────────────────────────
    sr_pct    = round(agg.get("solve_rate", 0) * 100)
    threshold = 50
    sr_color  = "titleblue" if sr_pct >= threshold else "red"

    def _apv(key_path, fmt="{:.2f}"):
        keys = key_path.split(".")
        obj  = aps
        for k in keys:
            if not isinstance(obj, dict):
                return "---"
            obj = obj.get(k)
            if obj is None:
                return "---"
        try:
            return fmt.format(float(obj))
        except (TypeError, ValueError):
            return e(str(obj))

    runtime_rows = rf"""  Mean Steps   & {int(agg.get('mean_steps', 0))} \\
  Mean Reward  & {agg.get('mean_reward', 0):.1f} \\
  Mean Nodes   & {agg.get('mean_nodes', 0):.1f} \\
  Mean Creds   & {agg.get('mean_creds', 0):.1f} \\
  Density      & {agg.get('mean_density', 0):.4f} \\
  Diameter     & {e(str(agg.get('mean_diameter', '---')))} \\
  Tree Ratio   & {agg.get('tree_ratio', 0):.2f} \\"""

    ap_rows = ""
    if aps.get("n_samples"):
        dom_act = e(aps.get("dominant_action_type", "---").replace("_", " ").title())
        ap_rows = (
            rf"  Avg Hops     & {_apv('avg_hops.mean', '{:.1f}')} \\" + "\n"
            + rf"  Avg Nodes    & {_apv('avg_min_nodes_to_own.mean', '{:.1f}')} \\" + "\n"
            + rf"  Avg Actions  & {_apv('avg_actions.mean', '{:.1f}')} \\" + "\n"
            + rf"  Reachability & {int(aps.get('reachable_ratio', 0)*100)}\% \\" + "\n"
            + rf"  Dom.\ Action  & {dom_act} \\" + "\n"
        )

    runtime_table = rf"""
\subsection*{{Runtime Metrics}}
\begin{{tabular}}{{lr}}
\toprule
\textbf{{Metric}} & \textbf{{Value}} \\
\midrule
{runtime_rows}
{ap_rows}\bottomrule
\end{{tabular}}

\smallskip
\textbf{{Solve rate:}} \textcolor{{{sr_color}}}{{\textbf{{{agg.get('solved', 0)}/{agg.get('total', 0)} ({sr_pct}\%)}}}}"""

    # Per-instance inline topology removed — schema_block above covers architecture
    topo_inline_block = ""

    # ── diversity table ───────────────────────────────────────────────────────
    groups     = div.get("group_summary", [])
    group_rows = "".join(
        rf"  {e(g['name'])} & {e(g['service'])} & {g['min']}--{g['max']} \\" + "\n"
        for g in groups
    )
    os_str = ", ".join(div.get("os_types", [])) or "---"
    het    = "Yes" if div.get("heterogeneous_os") else "No"

    role_items = "".join(
        rf"\item {e(r)}" + "\n" for r in div.get("node_roles", [])
    ) or r"\item ---"
    goal_items = "".join(
        rf"\item {e(g)}" + "\n" for g in div.get("goal_services", [])
    ) or r"\item ---"

    diversity_block = rf"""
\subsubsection*{{Network Diversity \& Connectivity}}
\begin{{tabular}}{{llll}}
\toprule
Service types & {div.get("n_service_types","---")} &
Domains / subnets & {div.get("n_domains","---")} \\
OS types & {e(os_str)} &
Heterogeneous OS & {het} \\
Firewall rules & {div.get("n_must_connect","---")} &
Cred-leak paths & {div.get("n_cred_paths","---")} \\
\bottomrule
\end{{tabular}}

\smallskip
\textbf{{Node roles:}}
\begin{{itemize}}
{role_items}\end{{itemize}}
\textbf{{Goal services:}}
\begin{{itemize}}
{goal_items}\end{{itemize}}
"""

    groups_block = rf"""
\subsubsection*{{Node Groups}}
\noindent\begin{{tabular}}{{lll}}
\toprule
\textbf{{Group}} & \textbf{{Service archetype}} & \textbf{{Count range}} \\
\midrule
{group_rows}\bottomrule
\end{{tabular}}
"""

    # Per-instance topology gallery removed — replaced by schema_block above
    topo_gallery = ""

    stats_blk = stats_table(entry.get("sample_stats", {}))

    return rf"""
\newpage
\subsection{{{e(entry['short_name'])}}}\label{{sec:{label}}}

\noindent\textbf{{Architecture:}} {e(entry.get('arch_type','---'))} \quad
\textbf{{Quality:}} {score_cmd(p1, grade)} \quad
\textbf{{Config:}} \texttt{{{e(name)}}}
\smallskip

{gen_req_block}
{schema_block}
\noindent
\begin{{minipage}}[t]{{0.55\linewidth}}
  \subsection*{{Scenario Overview}}
  \small {overview}

  \subsection*{{Attacker Progression}}
  {prog_block}
\end{{minipage}}
\hfill
\begin{{minipage}}[t]{{0.42\linewidth}}
  \centering
  \vspace{{0pt}}
  {bars_include}
\end{{minipage}}

\vspace{{0.8cm}}

\noindent
\begin{{minipage}}[t]{{0.25\linewidth}}
  \centering
  {donut_include}
  {outcome_table}
\end{{minipage}}
\hfill
\begin{{minipage}}[t]{{0.30\linewidth}}
{runtime_table}
\end{{minipage}}
{topo_inline_block}

{diversity_block}
\medskip
{groups_block}
{topo_gallery}
{stats_blk}
"""
