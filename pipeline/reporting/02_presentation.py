"""
tools/generate_presentation.py
================================
Generate a Beamer PDF presentation:
  "Data Generation for CyberBattleSim — Current Status"

Usage:
  python3 tools/generate_presentation.py \
    --phase2-root output/phase2 \
    --configs-root data \
    --output output/reports/presentation.pdf
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import yaml

TOOLS_DIR = Path(__file__).parent
sys.path.insert(0, str(TOOLS_DIR))

try:
    from yaml import CLoader as _LOADER
except ImportError:
    from yaml import Loader as _LOADER

# ── reuse entry loading from executive report ─────────────────────────────────
from generate_executive_report import build_entries  # noqa: E402

# ── zone metadata from scenario graph ────────────────────────────────────────
from generate_scenario_graph import (               # noqa: E402
    _GT_ZONES, _GT_SERVICE_PREFIX, _ZONE_CANONICAL_CIDRS,
)

# ─────────────────────────────────────────────────────────────────────────────
# Colour palette & design constants
# ─────────────────────────────────────────────────────────────────────────────
_NAVY   = "0d1b2a"
_CYAN   = "00b4d8"
_GREY   = "f5f5f5"
_ORANGE = "f0a500"
_GREEN  = "4caf50"
_CHAR   = "2d2d2d"

# 6 distinct per-scenario accent colours (cycling)
_SCENARIO_COLOURS = ["e63946", "2196f3", "4caf50", "ff9800", "9c27b0", "00b4d8"]

# Dimension display names
_DIM_LABELS = {
    "topology_realism":      "Topology Realism",
    "vulnerability_realism": "Vuln Realism",
    "scenario_difficulty":   "Difficulty",
    "firewall_realism":      "Firewall Rules",
    "general_realism":       "General Realism",
    "cve_grounding":         "CVE Grounding",
}

# ─────────────────────────────────────────────────────────────────────────────
# LaTeX escape
# ─────────────────────────────────────────────────────────────────────────────
def _e(text: str) -> str:
    text = str(text)
    for old, new in [
        ("\\", r"\textbackslash{}"), ("&",  r"\&"), ("%", r"\%"),
        ("$",  r"\$"), ("#", r"\#"), ("_",  r"\_"), ("{", r"\{"),
        ("}",  r"\}"), ("~", r"\textasciitilde{}"), ("^", r"\textasciicircum{}"),
        ("<",  r"\textless{}"), (">", r"\textgreater{}"),
    ]:
        text = text.replace(old, new)
    for old, new in [
        ("→", r"$\rightarrow$"), ("←", r"$\leftarrow$"),
        ("—", "--"), ("–", "-"), ("×", r"$\times$"),
        ("✓", r"\checkmark"), ("✗", r"$\times$"), ("•", r"\textbullet{}"),
        (" ", " "), (" ", " "),
    ]:
        text = text.replace(old, new)
    return text


# ─────────────────────────────────────────────────────────────────────────────
# Beamer preamble
# ─────────────────────────────────────────────────────────────────────────────
def _preamble() -> str:
    return rf"""
\PassOptionsToPackage{{table}}{{xcolor}}
\documentclass[aspectratio=169,10pt]{{beamer}}

% ── packages ──────────────────────────────────────────────────────────────────
\usepackage{{graphicx}}
\usepackage{{booktabs}}
\usepackage{{array}}
\usepackage{{tikz}}
\usepackage{{multirow}}
\usepackage{{calc}}
\usepackage{{textcomp}}
\usepackage{{lmodern}}
\usepackage{{listings}}
\lstset{{basicstyle=\tiny\ttfamily,breaklines=true,breakatwhitespace=true,frame=none,aboveskip=2pt,belowskip=2pt}}
\usetikzlibrary{{arrows.meta,positioning,shapes.geometric,fit,backgrounds,calc}}

% ── custom colours ────────────────────────────────────────────────────────────
\definecolor{{gtnavy}}{{HTML}}{{{_NAVY}}}
\definecolor{{gtcyan}}{{HTML}}{{{_CYAN}}}
\definecolor{{gtgrey}}{{HTML}}{{{_GREY}}}
\definecolor{{gtorange}}{{HTML}}{{{_ORANGE}}}
\definecolor{{gtgreen}}{{HTML}}{{{_GREEN}}}
\definecolor{{gtcharcoal}}{{HTML}}{{{_CHAR}}}
\definecolor{{scA}}{{HTML}}{{e63946}}
\definecolor{{scB}}{{HTML}}{{2196f3}}
\definecolor{{scC}}{{HTML}}{{4caf50}}
\definecolor{{scD}}{{HTML}}{{ff9800}}
\definecolor{{scE}}{{HTML}}{{9c27b0}}
\definecolor{{scF}}{{HTML}}{{00b4d8}}

% ── theme ─────────────────────────────────────────────────────────────────────
\usetheme{{default}}
\usecolortheme{{default}}
\setbeamercolor{{normal text}}{{fg=gtcharcoal,bg=white}}
\setbeamercolor{{frametitle}}{{fg=gtnavy,bg=white}}
\setbeamercolor{{title}}{{fg=white,bg=gtnavy}}
\setbeamercolor{{author}}{{fg=gtcyan}}
\setbeamercolor{{date}}{{fg=gtcyan}}
\setbeamercolor{{itemize item}}{{fg=gtcyan}}
\setbeamercolor{{itemize subitem}}{{fg=gtcyan}}
\setbeamercolor{{block title}}{{fg=white,bg=gtnavy}}
\setbeamercolor{{block body}}{{fg=gtcharcoal,bg=gtgrey}}
\setbeamercolor{{footline}}{{fg=gtnavy!60,bg=white}}
\setbeamerfont{{frametitle}}{{size=\large,series=\bfseries}}
\setbeamerfont{{title}}{{size=\Large,series=\bfseries}}

% ── frametitle rule ───────────────────────────────────────────────────────────
\addtobeamertemplate{{frametitle}}{{}}{{%
  \vspace{{-6pt}}\textcolor{{gtcyan}}{{\rule{{\textwidth}}{{1.5pt}}}}%
  \vspace{{2pt}}%
}}

% ── footline: left=title  centre=section  right=n/N ───────────────────────────
\setbeamertemplate{{footline}}{{%
  \leavevmode%
  \hbox{{%
    \begin{{beamercolorbox}}[wd=.40\paperwidth,ht=2.25ex,dp=1ex,left]{{footline}}%
      \hspace{{4pt}}\tiny Data Generation for CyberBattleSim%
    \end{{beamercolorbox}}%
    \begin{{beamercolorbox}}[wd=.30\paperwidth,ht=2.25ex,dp=1ex,center]{{footline}}%
      \tiny\insertsectionhead%
    \end{{beamercolorbox}}%
    \begin{{beamercolorbox}}[wd=.30\paperwidth,ht=2.25ex,dp=1ex,right]{{footline}}%
      \tiny\insertframenumber{{}}/\inserttotalframenumber\hspace{{4pt}}%
    \end{{beamercolorbox}}%
  }}%
}}
\setbeamertemplate{{navigation symbols}}{{}}

% ── globally scale body text ~10% smaller ────────────────────────────────────
\setbeamerfont{{normal text}}{{size=\small}}
\setbeamerfont{{itemize/enumerate body}}{{size=\small}}
\setbeamerfont{{itemize/enumerate subbody}}{{size=\footnotesize}}
\setbeamerfont{{block body}}{{size=\small}}
\setbeamerfont{{block title}}{{size=\normalsize,series=\bfseries}}
\AtBeginDocument{{\small}}

\begin{{document}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Section / scenario dividers
# ─────────────────────────────────────────────────────────────────────────────
def _section_divider(title: str, subtitle: str = "") -> str:
    sub = rf"\\\medskip{{\color{{gtcyan}}\large {_e(subtitle)}}}" if subtitle else ""
    return rf"""
{{\setbeamercolor{{background canvas}}{{bg=gtnavy}}
\begin{{frame}}[plain]
  \vfill
  \centering
  {{\color{{white}}\LARGE\bfseries {_e(title)}}}
  {sub}
  \par\medskip
  \textcolor{{gtcyan}}{{\rule{{0.5\textwidth}}{{1.5pt}}}}
  \vfill
\end{{frame}}}}
"""


def _scenario_divider(entry: dict, colour: str) -> str:
    short = _e(entry.get("short_name", entry["name"]))
    full  = _e(entry.get("yaml_header", {}).get("title") or entry["name"])
    grade = _e(entry.get("p1_grade", "?"))
    score = entry.get("p1_score", 0)
    sr    = round(entry.get("agg", {}).get("solve_rate", 0) * 100)
    return rf"""
{{\setbeamercolor{{background canvas}}{{bg=gtnavy}}
\begin{{frame}}[plain]
  \vfill
  \centering
  {{\color{{white}}\huge\bfseries {short}}}\\[6pt]
  {{\color{{gtcyan}}\large {full}}}\\[14pt]
  \textcolor{{gtcyan}}{{\rule{{0.45\textwidth}}{{1pt}}}}\\[10pt]
  \begin{{tikzpicture}}
    \node[fill={colour},rounded corners=4pt,inner sep=6pt,text=white,font=\bfseries\large]
      {{Quality: {score:.1f}/10 \textbf{{{grade}}}}};
  \end{{tikzpicture}}
  \quad
  \begin{{tikzpicture}}
    \node[fill=gtcyan,rounded corners=4pt,inner sep=6pt,text=gtnavy,font=\bfseries\large]
      {{Solve rate: {sr}\%}};
  \end{{tikzpicture}}
  \vfill
\end{{frame}}}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Frame 1 — Title
# ─────────────────────────────────────────────────────────────────────────────
def _title_frame(date_str: str) -> str:
    return rf"""
\title{{\textbf{{Data Generation for CyberBattleSim}}\\[4pt]\large Current Status}}
\subtitle{{Scenario Dataset — {_e(date_str)}}}
\author{{Ariel Zilbershteyn}}
\date{{}}
\begin{{frame}}[plain]
  \titlepage
\end{{frame}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Frames 2a–2d — Source of Data
# ─────────────────────────────────────────────────────────────────────────────
def _frame_2a(ref_png: "Path | None", workdir: Path) -> str:
    img_block = ""
    if ref_png and ref_png.exists():
        dst = workdir / "globaltech_ref_pres.png"
        shutil.copy(ref_png, dst)
        img_block = r"\includegraphics[width=\linewidth,height=0.75\textheight,keepaspectratio]{globaltech_ref_pres.png}"
    else:
        img_block = r"\textit{(ref.png not found)}"

    return rf"""
\section{{Source of Data}}
\begin{{frame}}{{Source of Data: GLOBALTECH Reference Architecture}}
  \begin{{columns}}[T]
    \begin{{column}}{{0.55\textwidth}}
      {img_block}
    \end{{column}}
    \begin{{column}}{{0.43\textwidth}}
      \begin{{itemize}}\setlength\itemsep{{6pt}}
        \item \textbf{{8 named zones}} with fixed subnet ranges and service archetypes
        \item Zones: Internet Edge, HQ Edge, Corporate HQ VLANs, Server Farm, AWS Cloud (Z6), Branch Office, Remote Users, Key Management
        \item Each scenario targets \textbf{{one or more zones}}
        \item Defines the vocabulary: CIDR blocks, service types, inter-zone firewall rules
        \item Source for all scenario YAML templates
      \end{{itemize}}
    \end{{column}}
  \end{{columns}}
\end{{frame}}
"""


def _frame_2b() -> str:
    return r"""
\begin{frame}{Source of Data: CVE Vulnerability Databases}
  \begin{columns}[T]
    \begin{column}{0.48\textwidth}
      \begin{block}{3 Curated Databases}
        \begin{tabular}{lrr}
          \toprule
          \textbf{Database} & \textbf{CVEs} & \textbf{Platform} \\
          \midrule
          \rowcolor{gtgrey} Windows & 268 & Windows Server \\
          Bitnami & 693 & Linux / Cloud \\
          \rowcolor{gtgrey} NetDev & 240 & Network Devices \\
          \midrule
          \textbf{Total} & \textbf{1\,201} & \\
          \bottomrule
        \end{tabular}
      \end{block}
    \end{column}
    \begin{column}{0.48\textwidth}
      \begin{itemize}\setlength\itemsep{6pt}
        \item Each scenario service group is \textbf{grounded to real CVEs} from the matching database
        \item CVEs carry \textbf{CVSS score}, \textbf{EPSS exploitation probability}, MITRE ATT\&CK tactic, and affected versions
        \item \textbf{EPSS} is used directly as the \texttt{probability} field in solvability vulnerabilities --- the single best predictor of real-world exploitation
        \item Used during generation to populate \texttt{vulnerabilities} blocks in YAML
        \item Coverage spans \textbf{TA0001--TA0011} MITRE tactics
        \item Year range: 2015--2024 (emphasis on recent high-impact CVEs)
      \end{itemize}
    \end{column}
  \end{columns}
\end{frame}
"""


def _frame_2c() -> str:
    return r"""
\begin{frame}{Source of Data: CyberBattleSim Framework}
  \begin{columns}[T]
    \begin{column}{0.48\textwidth}
      \begin{block}{What is CBS?}
        An \textbf{OpenAI Gym}-compatible network attack simulation environment.
        The agent navigates a graph of nodes, exploiting vulnerabilities and
        leaking credentials to reach a terminal goal node.
      \end{block}
      \vspace{6pt}
      \begin{block}{Action Space}
        \begin{itemize}
          \item \texttt{remote} --- exploit a reachable node via a known CVE
          \item \texttt{local} --- escalate privileges on an already-owned node
          \item \texttt{connect} --- access a node using a leaked credential
          \item \texttt{movement} --- traverse the network to a reachable node
        \end{itemize}
      \end{block}
    \end{column}
    \begin{column}{0.48\textwidth}
      \begin{block}{Reward Structure}
        \begin{itemize}
          \item $+r$ for owning a new node
          \item $+r$ for leaking a credential
          \item $+10000$ for owning the terminal goal
          \item Episode ends at goal or step budget
        \end{itemize}
      \end{block}
      \vspace{6pt}
      \begin{block}{YAML $\rightarrow$ Environment}
        \begin{itemize}
          \item \texttt{domains} $\rightarrow$ subnets
          \item \texttt{groups} $\rightarrow$ node instances (stratified count)
          \item \texttt{vulnerabilities} $\rightarrow$ exploitable actions
          \item \texttt{is\_goal} $\rightarrow$ terminal node
        \end{itemize}
      \end{block}
    \end{column}
  \end{columns}
\end{frame}
"""


def _frame_2d() -> str:
    return r"""
\begin{frame}{Source of Data: LLM Generation Pipeline}
  \begin{columns}[T]
    \begin{column}{0.50\textwidth}
      \begin{block}{Generation Inputs}
        \fontsize{6.5}{8}\selectfont
        \begin{itemize}
          \item User prompt (scenario description)
          \item \texttt{ref.md} --- GLOBALTECH reference architecture
          \item CBS YAML schema (structural constraints)
          \item CVE catalogs (3 databases, filtered by zone/OS)
        \end{itemize}
      \end{block}
      \vspace{6pt}
      \begin{block}{Output}
        \fontsize{6.5}{8}\selectfont
        \begin{itemize}
          \item Complete scenario YAML config
          \item Train / test split per scenario
        \end{itemize}
      \end{block}
    \end{column}
    \begin{column}{0.47\textwidth}
      \begin{block}{Iterative Refinement}
        \fontsize{6.5}{8}\selectfont
        \begin{enumerate}\setlength\itemsep{4pt}
          \item LLM generates YAML from prompt
          \item Quality critic scores 6 dimensions
          \item If score $<$ threshold: critic feedback $\rightarrow$ LLM repairs YAML
          \item Repeat up to $N$ rounds
        \end{enumerate}
      \end{block}
      \vspace{6pt}
      \begin{block}{Quality Dimensions}
        \fontsize{6.5}{8}\selectfont
        \begin{itemize}\setlength\itemsep{1pt}
          \item Topology Realism
          \item Vulnerability Realism
          \item Difficulty
          \item Firewall Rules
          \item General Realism
          \item CVE Grounding
        \end{itemize}
      \end{block}
    \end{column}
  \end{columns}
\end{frame}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Frames 3a–3b — Methodology
# ─────────────────────────────────────────────────────────────────────────────
def _frame_3a() -> str:
    return r"""
\section{Methodology}
\begin{frame}{Methodology: Pipeline Overview}
\centering
\resizebox{\textwidth}{!}{%
\begin{tikzpicture}[
  node distance=0.35cm and 0.5cm,
  box/.style={draw, rounded corners=3pt, minimum width=1.55cm, minimum height=0.58cm,
              align=center, font=\small\bfseries, text=white},
  gen/.style={box, fill=gtnavy},
  stat/.style={box, fill=gtcyan!80!black},
  sim/.style={box, fill=gtgreen!80!black},
  eval/.style={box, fill=gtorange!90!black},
  arr/.style={-Stealth, thick, gray!60},
  fb1/.style={-Stealth, thick, gtcyan!80!black, dashed},
  fb2/.style={-Stealth, thick, gtorange!90!black, dashed},
]
  % Generation phase
  \node[gen]                   (prompt) {User\\Prompt};
  \node[gen, right=of prompt]  (llm)    {LLM\\Generator};
  \node[gen, right=of llm]     (yaml)   {YAML\\Config};

  % Static evaluation phase: binary check + quality critic (both Phase 1)
  \node[stat, right=of yaml]   (valid)  {Format\\Check};
  \node[stat, right=of valid]  (critic) {Quality\\Critic};

  % Simulation phase
  \node[sim, right=of critic]  (inst)   {Instance\\Generator};
  \node[sim, right=of inst]    (sim)    {CBS\\Simulation};

  % Dynamic evaluation phase
  \node[eval, right=of sim]    (bfs)    {BFS Path\\Analysis};
  \node[eval, right=of bfs]    (sr)     {Solve Rate\\Check};

  % Forward arrows
  \draw[arr] (prompt) -- (llm);
  \draw[arr] (llm)    -- (yaml);
  \draw[arr] (yaml)   -- (valid);
  \draw[arr] (valid)  -- (critic);
  \draw[arr] (critic) -- (inst);
  \draw[arr] (inst)   -- (sim);
  \draw[arr] (sim)    -- (bfs);
  \draw[arr] (bfs)    -- (sr);

  % Loop 1 (Phase 1 inner): quality score < 7.0 -> LLM, up to 5x (above)
  \draw[fb1] (critic.north) -- ++(0,0.7) -| (llm.north)
    node[midway, above, font=\scriptsize, text=gtcyan!80!black]
    {score $<$ 7.0 --- up to 5 rounds};

  % Loop 2 (Phase 2 outer): solve rate < 50% -> LLM, up to 10x (below)
  \draw[fb2] (sr.south) -- ++(0,-0.65) -| (llm.south)
    node[midway, below, font=\scriptsize, text=gtorange!90!black]
    {solve rate $<$ 50\% --- up to 10 rounds};

  % Phase background boxes
  \begin{scope}[on background layer]
    \node[fit=(prompt)(llm)(yaml), draw=gtnavy, fill=gtnavy!10,
          rounded corners=5pt, inner sep=5pt,
          label={[font=\scriptsize\bfseries,text=gtnavy]above:Generation}] {};
    \node[fit=(valid)(critic), draw=gtcyan!80!black, fill=gtcyan!10,
          rounded corners=5pt, inner sep=5pt,
          label={[font=\scriptsize\bfseries,text=gtcyan!80!black]above:Static Eval (Phase 1)}] {};
    \node[fit=(inst)(sim), draw=gtgreen!80!black, fill=gtgreen!10,
          rounded corners=5pt, inner sep=5pt,
          label={[font=\scriptsize\bfseries,text=gtgreen!80!black]above:Simulation}] {};
    \node[fit=(bfs)(sr), draw=gtorange!90!black, fill=gtorange!10,
          rounded corners=5pt, inner sep=5pt,
          label={[font=\scriptsize\bfseries,text=gtorange!90!black]above:Dynamic Eval (Phase 2)}] {};
  \end{scope}
\end{tikzpicture}%
}
\end{frame}
"""


def _frame_3b() -> str:
    return r"""
\begin{frame}{Methodology: Step-by-Step}
  \begin{enumerate}\setlength\itemsep{3pt}
    \item \textbf{User Prompt $\rightarrow$ YAML Config} ---
      Claude receives the prompt, \texttt{ref.md}, the CBS YAML schema, and filtered CVE catalogs.
      Outputs a complete scenario config: domains, groups, vulnerabilities, attack\_flow.

    \item \textbf{Static Eval --- Phase 1 inner loop (up to 5 rounds)} ---
      \emph{Step A — Format Check (binary):} structural and schema validation; any error
      triggers immediate LLM repair.\\
      \emph{Step B --- Quality Critic (scored):} Claude scores the YAML on 6 dimensions.
      If overall score $<$ \textbf{7.0 / 10}, a structured critique is fed back to the LLM.
      Both steps share the same inner loop.

    \item \textbf{Instance Generation \& CBS Simulation} ---
      Approved config instantiated into train/test episodes; each runs in the CyberBattleSim
      gym until the terminal goal is reached or the step budget is exhausted.

    \item \textbf{Dynamic Eval --- BFS Path Analysis} ---
      Shortest-path analysis on the runtime ownership graph: avg.\ hops,
      reachability ratio, dominant action type, and per-path success probability.

    \item \textbf{Solve Rate Check --- Phase 2 outer loop (up to 10 rounds)} ---
      If solve rate $<$ \textbf{50\%} across episodes, the entire Phase 1 loop is
      re-triggered with the original prompt. Up to 10 outer attempts before giving up.

  \end{enumerate}
\end{frame}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Frame 4 — Summary table
# ─────────────────────────────────────────────────────────────────────────────
def _frame_summary(entries: list) -> str:
    rows = ""
    colours = ["scA", "scB", "scC", "scD", "scE", "scF"]
    for i, entry in enumerate(entries):
        col   = colours[i % len(colours)]
        short = _e(entry.get("short_name", entry["name"]))
        agent = _e(entry.get("yaml_header", {}).get("agent", "---").split("(")[0].strip())
        zones = _e(entry.get("yaml_header", {}).get("zones", "---"))
        raw_nodes = str(entry.get("yaml_header", {}).get("nodes", "---"))
        nodes = _e(raw_nodes.split("|")[0].strip())
        sr    = round(entry.get("agg", {}).get("solve_rate", 0) * 100)
        grade = _e(entry.get("p1_grade", "?"))
        score = entry.get("p1_score", 0)
        sr_color = "gtgreen" if sr >= 90 else ("gtorange" if sr >= 50 else "red")
        rows += (
            rf"  \textcolor{{{col}}}{{\textbullet}} {short} & "
            rf"\texttt{{{agent}}} & "
            rf"{zones} & "
            rf"{nodes} & "
            rf"\textcolor{{{sr_color}}}{{\textbf{{{sr}\%}}}} & "
            rf"\textbf{{{score:.1f}}} ({grade}) \\" + "\n"
            r"  \addlinespace[2pt]" + "\n"
        )

    return rf"""
\section{{Scenarios}}
\begin{{frame}}{{Scenarios: Summary}}
  \centering\tiny
  \begin{{tabular}}{{@{{}}>{{}}p{{2.8cm}}>{{}}p{{1.5cm}}>{{}}p{{3.8cm}}>{{}}p{{0.8cm}}cc@{{}}}}
    \toprule
    \textbf{{Scenario}} & \textbf{{Agent}} & \textbf{{Zones}} &
    \textbf{{Nodes}} & \textbf{{Solve}} & \textbf{{Quality}} \\
    \midrule
{rows}    \bottomrule
  \end{{tabular}}
\end{{frame}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Frame A — Network Architecture (full-slide PNG)
# ─────────────────────────────────────────────────────────────────────────────
def _frame_arch(entry: dict, workdir: Path) -> str:
    schema_src   = entry.get("schema_diagram")
    short        = _e(entry.get("short_name", entry["name"]))
    gen_req      = _e(entry.get("generation_request", ""))
    hdr          = entry.get("yaml_header", {})
    overview     = _e(entry.get("desc", {}).get("overview", ""))
    progression  = entry.get("desc", {}).get("progression", [])

    img_block = r"\textit{(architecture diagram not available)}"
    if schema_src and Path(schema_src).exists():
        dst = workdir / f"pres_schema_{entry['name']}.png"
        shutil.copy(schema_src, dst)
        img_block = rf"\includegraphics[width=\linewidth,height=0.82\textheight,keepaspectratio]{{{dst.name}}}"

    # progression steps (capped at 5)
    prog_items = "".join(
        rf"  \item \scriptsize {_e(step.strip())}" + "\n"
        for step in progression[:5] if step.strip()
    )
    prog_block = (
        rf"\begin{{itemize}}\setlength\itemsep{{2pt}}{prog_items}\end{{itemize}}"
        if prog_items else ""
    )

    spec_rows = ""
    if hdr.get("agent"):
        spec_rows += rf"  \textbf{{Agent}} & \scriptsize\texttt{{{_e(hdr['agent'])}}} \\" + "\n"
    if hdr.get("zones"):
        spec_rows += rf"  \textbf{{Zones}} & \scriptsize {_e(hdr['zones'])} \\" + "\n"
    if hdr.get("goal"):
        spec_rows += rf"  \textbf{{Goal}} & \scriptsize\texttt{{{_e(hdr['goal'])}}} \\" + "\n"
    if hdr.get("nodes"):
        spec_rows += rf"  \textbf{{Nodes}} & \scriptsize {_e(hdr['nodes'])} \\" + "\n"

    spec_block = ""
    if spec_rows:
        spec_block = (
            r"\smallskip\noindent\begin{tabular}{@{}ll@{}}" + "\n"
            + spec_rows
            + r"\end{tabular}"
        )

    return rf"""
\begin{{frame}}{{{short}: Network Architecture}}
  \centering
  {img_block}
\end{{frame}}
"""


def _frame_prompt(entry: dict) -> str:
    short    = _e(entry.get("short_name", entry["name"]))
    gen_req  = entry.get("generation_request", "")
    hdr      = entry.get("yaml_header", {})
    overview = entry.get("desc", {}).get("overview", "")

    spec_rows = ""
    if hdr.get("agent"):
        spec_rows += rf"  \textbf{{Agent}} & \footnotesize\texttt{{{_e(hdr['agent'])}}} \\" + "\n"
    if hdr.get("zones"):
        spec_rows += rf"  \textbf{{Zones}} & \footnotesize {_e(hdr['zones'])} \\" + "\n"
    if hdr.get("goal"):
        spec_rows += rf"  \textbf{{Goal}} & \footnotesize\texttt{{{_e(hdr['goal'])}}} \\" + "\n"
    if hdr.get("nodes"):
        spec_rows += rf"  \textbf{{Nodes}} & \footnotesize {_e(hdr['nodes'])} \\" + "\n"

    spec_block = ""
    if spec_rows:
        spec_block = (
            r"\vspace{6pt}\noindent\begin{tabular}{@{}ll@{}}" + "\n"
            + spec_rows
            + r"\end{tabular}"
        )

    overview_frame = ""
    if overview:
        overview_frame = rf"""
\begin{{frame}}{{{short}: Scenario Overview}}
  \begin{{block}}{{Overview}}
    \footnotesize {_e(overview)}
  \end{{block}}
\end{{frame}}
"""

    return rf"""
\begin{{frame}}{{{short}: User Prompt \& Specification}}
  \begin{{block}}{{User Prompt (sent to LLM to generate this scenario)}}
    \footnotesize\textbf{{{_e(gen_req)}}}
  \end{{block}}
  {spec_block}
\end{{frame}}
{overview_frame}"""


# ─────────────────────────────────────────────────────────────────────────────
# Frame B — Metrics
# ─────────────────────────────────────────────────────────────────────────────
def _frame_metrics(entry: dict, workdir: Path) -> str:
    short = _e(entry.get("short_name", entry["name"]))
    agg   = entry.get("agg", {})
    div   = entry.get("diversity", {})
    aps   = entry.get("attack_path_stats", {})
    dim   = entry.get("dim_scores", {})

    # ── quality dimension table ───────────────────────────────────────────────
    dim_rows = ""
    for key, label in _DIM_LABELS.items():
        info  = dim.get(key, {})
        score = info.get("score", 0)
        grade = info.get("grade", "?")
        bar_w = max(0.05, score / 10)
        dim_rows += (
            rf"    {_e(label)} & "
            rf"\begin{{tikzpicture}}[baseline=-1pt]"
            rf"\fill[gtcyan!30](0,0)rectangle({bar_w:.2f}\linewidth,5pt);"
            rf"\fill[gtcyan](0,0)rectangle({bar_w:.2f}\linewidth,5pt);"
            rf"\end{{tikzpicture}} & "
            rf"{score:.1f} ({grade}) \\" + "\n"
        )

    # ── action outcomes ───────────────────────────────────────────────────────
    ot = agg.get("outcome_totals", {})
    outcome_pairs = [
        ("LeakedCredentials", "Cred Leak"),
        ("LateralMove",       "Lateral Move"),
        ("ProbeSucceeded",    "Probe OK"),
        ("ExploitFailed",     "Exploit Fail"),
    ]
    out_rows = "".join(
        rf"    {lab} & {int(ot.get(key,0))} \\" + "\n"
        for key, lab in outcome_pairs
    )

    # ── graph stats ───────────────────────────────────────────────────────────
    sr_pct   = round(agg.get("solve_rate", 0) * 100)
    sr_color = "gtgreen" if sr_pct >= 90 else ("gtorange" if sr_pct >= 50 else "red")

    def _ap(k):
        v = aps.get(k)
        if v is None: return "---"
        try: return f"{float(v):.2f}"
        except: return str(v)

    avg_hops    = _ap("avg_hops") if isinstance(aps.get("avg_hops"), (int,float)) else \
                  (f"{aps['avg_hops'].get('mean',0):.1f}" if isinstance(aps.get("avg_hops"), dict) else "---")
    dom_act     = _e(str(aps.get("dominant_action_type","---")).replace("_"," ").title())
    reachability = f"{int(aps.get('reachable_ratio',0)*100)}\\%" if aps.get("n_samples") else "---"

    # ── diversity ─────────────────────────────────────────────────────────────
    os_str = ", ".join(div.get("os_types", [])) or "---"
    het    = "Yes" if div.get("heterogeneous_os") else "No"

    return rf"""
\begin{{frame}}{{{short}: Metrics}}
  \tiny
  \setlength{{\tabcolsep}}{{2pt}}
  \begin{{columns}}[T]
    % ── col 1: quality + outcomes + solve rate ────────────────────────────────
    \begin{{column}}{{0.36\textwidth}}
      \textbf{{\scriptsize Quality Dimensions}}\\[0pt]
      \begin{{tabular}}{{@{{}}p{{1.9cm}}p{{1.5cm}}r@{{}}}}
        \toprule \textbf{{Dimension}} & & \textbf{{Score}} \\ \midrule
{dim_rows}        \bottomrule
      \end{{tabular}}

      \vspace{{0pt}}
      \textbf{{\scriptsize Action Outcomes \& Solve Rate}}\\[0pt]
      \begin{{tabular}}{{@{{}}lr@{{}}}}
        \toprule \textbf{{Outcome}} & \textbf{{Count}} \\ \midrule
{out_rows}        \midrule
        \textbf{{Solve Rate}} &
          \textcolor{{{sr_color}}}{{\textbf{{{agg.get('solved',0)}/{agg.get('total',0)} ({sr_pct}\%)}}}} \\
        \bottomrule
      \end{{tabular}}
    \end{{column}}
    % ── col 2: graph stats + diversity ────────────────────────────────────────
    \begin{{column}}{{0.30\textwidth}}
      \textbf{{\scriptsize Graph Statistics}}\\[0pt]
      \begin{{tabular}}{{@{{}}lr@{{}}}}
        \toprule \textbf{{Metric}} & \textbf{{Value}} \\ \midrule
        Mean Steps   & {int(agg.get('mean_steps',0))} \\
        Mean Nodes   & {agg.get('mean_nodes',0):.1f} \\
        Mean Creds   & {agg.get('mean_creds',0):.1f} \\
        Density      & {agg.get('mean_density',0):.4f} \\
        Diameter     & {_e(str(agg.get('mean_diameter','---')))} \\
        Avg Hops     & {avg_hops} \\
        Reachability & {reachability} \\
        Dom.\ Action & {dom_act} \\
        \bottomrule
      \end{{tabular}}

      \vspace{{0pt}}
      \textbf{{\scriptsize Network Diversity}}\\[0pt]
      \begin{{tabular}}{{@{{}}lr@{{}}}}
        \toprule \textbf{{Property}} & \textbf{{Value}} \\ \midrule
        Svc types       & {div.get('n_service_types','---')} \\
        Domains         & {div.get('n_domains','---')} \\
        OS types        & {_e(os_str)} \\
        Heterogeneous   & {het} \\
        FW rules        & {div.get('n_must_connect','---')} \\
        Cred paths      & {div.get('n_cred_paths','---')} \\
        \bottomrule
      \end{{tabular}}
    \end{{column}}
    % ── col 3: node groups ────────────────────────────────────────────────────
    \begin{{column}}{{0.31\textwidth}}
      \textbf{{\scriptsize Node Groups}}\\[0pt]
      \begin{{tabular}}{{@{{}}llr@{{}}}}
        \toprule \textbf{{Group}} & \textbf{{Service}} & \textbf{{N}} \\ \midrule
{_group_rows(div)}        \bottomrule
      \end{{tabular}}
    \end{{column}}
  \end{{columns}}
\end{{frame}}
"""


def _group_rows(div: dict) -> str:
    rows = ""
    for g in div.get("group_summary", [])[:8]:
        rows += rf"        {_e(g['name'])} & \tiny {_e(g['service'])} & {g['min']}--{g['max']} \\" + "\n"
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Frame C — Gemini image-generation prompt
# ─────────────────────────────────────────────────────────────────────────────
def _build_gemini_prompt(entry: dict, config_path: "Path | None") -> str:
    """Auto-generate a Gemini image-gen prompt matching the ref.md Part 1 style."""

    # Vendor-display name mapping — matches GLOBALTECH canonical device types
    _VENDOR = {
        "WAFAppliance":        ("firewall icon",  "WAF Appliance"),
        "IPSAppliance":        ("firewall icon",  "Inline IPS"),
        "ISPRouter":           ("router icon",    "ISP Router"),
        "PaloAltoFirewall":    ("firewall icon",  "Palo Alto PA-5200 (HA Active/Passive)"),
        "CiscoEdgeRouter":     ("router icon",    "Cisco ISR 4451 Edge Router"),
        "CiscoISEAppliance":   ("server icon",    "Cisco ISE (NAC)"),
        "FortiGateAppliance":  ("firewall icon",  "FortiGate Next-Gen Firewall"),
        "F5LoadBalancer":      ("server icon",    "F5 BIG-IP Load Balancer"),
        "JuniperRouter":       ("router icon",    "Juniper MX Router"),
        "CiscoNXOS":           ("switch icon",    "Cisco NX-OS Core Switch"),
        "AWSWebServer":        ("cloud server",   "AWS EC2 Web Server (Nginx/Linux)"),
        "AWSAppServer":        ("cloud server",   "AWS EC2 App Server (container)"),
        "AWSPostgreSQL":       ("database icon",  "AWS RDS PostgreSQL (Alpine)"),
        "AWSRedis":            ("database icon",  "AWS ElastiCache Redis (Misconfigured)"),
        "AWSMySQL":            ("database icon",  "AWS RDS MySQL"),
        "AWSElasticsearch":    ("database icon",  "AWS OpenSearch / Elasticsearch"),
        "AWSTransitGateway":   ("cloud icon",     "AWS Transit Gateway"),
        "AWSWorkerNode":       ("cloud server",   "AWS EC2 Worker Node (container)"),
        "AWSRabbitMQ":         ("server icon",    "AWS MQ / RabbitMQ"),
        "AWSJenkins":          ("server icon",    "Jenkins CI Server"),
        "AWSGitLab":           ("server icon",    "GitLab Server"),
        "AWSAuthServer":       ("server icon",    "Auth Server (Keycloak)"),
        "DomainController":    ("server icon",    "Windows Server — Domain Controller (AD DS)"),
        "MSSQLServer":         ("database icon",  "Microsoft SQL Server"),
        "FileServer":          ("server icon",    "Windows File Server"),
        "ExchangeServer":      ("server icon",    "Microsoft Exchange Server"),
        "PrintServer":         ("server icon",    "Windows Print Server"),
        "SalesWorkstation":    ("workstation",    "Sales Workstation (Windows 10)"),
        "AdminWorkstation":    ("workstation",    "Admin Workstation (Windows 10)"),
        "FinanceWorkstation":  ("workstation",    "Finance Workstation (Windows 10)"),
        "RnDWorkstation":      ("workstation",    "R&D Workstation (Windows 10)"),
        "SplunkSIEM":          ("server icon",    "Splunk SIEM (Enterprise)"),
        "CyberArkPAM":         ("server icon",    "CyberArk PAM Vault"),
        "SolarWindsNPM":       ("server icon",    "SolarWinds NPM"),
        "CiscoISEServer":      ("server icon",    "Cisco ISE Policy Server"),
    }

    zone_order = [
        "InternetEdge", "HQ_Edge",
        "Z6_WebTier", "Z6_AppTier", "Z6_WorkerTier", "Z6_DataTier",
        "Z1_HQVLANs", "Z1_ServerFarm",
    ]
    zone_meta = {
        "InternetEdge":  ("Z4 — Internet Edge",              "10.0.1.0/24", "light yellow (#fffde7)"),
        "HQ_Edge":       ("Z2 — HQ Edge",                    "10.0.2.0/24", "light red (#ffebee)"),
        "Z6_WebTier":    ("Z6 — AWS Cloud / Web Tier",       "10.3.1.0/24", "light blue (#e3f2fd)"),
        "Z6_AppTier":    ("Z6 — AWS Cloud / App Tier",       "10.3.2.0/24", "light blue (#e3f2fd)"),
        "Z6_WorkerTier": ("Z6 — AWS Cloud / Worker Tier",    "10.3.3.0/24", "light blue (#e3f2fd)"),
        "Z6_DataTier":   ("Z6 — AWS Cloud / Data Tier",      "10.3.4.0/24", "light blue (#e3f2fd)"),
        "Z1_HQVLANs":    ("Z1 — Corporate HQ / VLANs",       "10.1.0.0/24", "light purple (#f3e5f5)"),
        "Z1_ServerFarm": ("Z1 — Corporate HQ / Server Farm", "10.1.10.0/24","light purple (#f3e5f5)"),
    }
    zone_connections = {
        ("InternetEdge", "HQ_Edge"):       "HTTPS / REST (inter-domain constraint)",
        ("HQ_Edge",      "Z1_HQVLANs"):   "LDAP / Kerberos / HTTPS",
        ("HQ_Edge",      "Z1_ServerFarm"): "LDAP / Kerberos / SMB",
        ("Z1_HQVLANs",   "Z1_ServerFarm"): "LDAP / SMB / Kerberos",
        ("Z6_WebTier",   "Z6_AppTier"):    "HTTP / internal API",
        ("Z6_AppTier",   "Z6_WorkerTier"): "message queue / RPC",
        ("Z6_WorkerTier","Z6_DataTier"):   "SQL / Redis protocol",
        ("Z6_AppTier",   "Z6_DataTier"):   "SQL / Redis (credential path)",
    }

    short_title = entry.get("yaml_header", {}).get("title") or entry["name"]

    if not config_path or not config_path.exists():
        return f"[Config YAML not found for {entry['name']}]"

    with open(config_path, encoding="utf-8") as f:
        cfg = yaml.load(f, Loader=_LOADER) or {}

    zone_services: dict = {}
    for d in (cfg.get("domains") or []):
        if not isinstance(d, dict):
            continue
        for g in (d.get("groups") or []):
            svc     = str(g.get("service", "?"))
            min_c   = int(g.get("min_count", 1))
            max_c   = int(g.get("max_count", 1))
            is_goal = bool(g.get("is_goal", False))
            zk = _GT_SERVICE_PREFIX.get(svc) or str(d.get("name", "UnknownZone"))
            zone_services.setdefault(zk, []).append((svc, min_c, max_c, is_goal))

    active_zones = [z for z in zone_order if z in zone_services]
    for zk in zone_services:
        if zk not in active_zones:
            active_zones.append(zk)

    # Build zone description blocks
    zone_blocks = []
    for zk in active_zones:
        full, cidr, colour = zone_meta.get(zk, (zk, "", "light grey"))
        header = f"### Zone: {full} (subnet {cidr}) — bounding box colour: {colour}"
        lines  = [header]
        for svc, mn, mx, goal in zone_services[zk]:
            icon, vendor = _VENDOR.get(svc, ("server icon", svc))
            count = f"×{mn}" if mn == mx else f"×{mn}–{mx}"
            goal_tag = "  ← ★ TERMINAL GOAL NODE (star/crown marker)" if goal else ""
            lines.append(f"  - {count} {vendor}: {icon}, labeled \"{svc}\"{goal_tag}")
        zone_blocks.append("\n".join(lines))

    # Inter-zone connections present in this scenario
    conn_lines = []
    for (za, zb), proto in zone_connections.items():
        if za in active_zones and zb in active_zones:
            fa = zone_meta.get(za, (za,))[0]
            fb = zone_meta.get(zb, (zb,))[0]
            conn_lines.append(f"  - {fa}  →  {fb}  [solid line, labeled \"{proto}\"]")

    conn_block = "\n".join(conn_lines) if conn_lines else "  (see zone arrangement)"

    # Attack flow
    flow = " → ".join(zone_meta.get(z, (z,))[0] for z in active_zones)
    goal_svc = next(
        (svc for svcs in zone_services.values() for svc, _, _, g in svcs if g),
        "terminal node"
    )

    prompt = f"""Generate a highly detailed, professional enterprise network architecture diagram titled:
"{short_title}"

Style: clean flat-vector technical illustration, white or very light grey background,
rounded-rectangle zone bounding boxes with coloured fills as specified, standard IT vector icons
(routers, firewalls, switches, servers, database cylinders, workstations, cloud VMs).
Use solid lines for wired connections, dashed lines for VPN/credential paths, and bold red arrows
for the attack flow. Include a legend box in the top-right corner defining:
  — Solid line: network connection
  — Dashed line: VPN / credential propagation path
  — Bold red arrow: attacker movement / exploit path
  — Star / crown marker: terminal goal node
Layout: landscape orientation (16:9), zones arranged left-to-right in kill-chain order.

---

ACTIVE ZONES (draw as labelled bounding boxes with the specified fill colour):

{chr(10).join(zone_blocks)}

---

INTER-ZONE CONNECTIONS (draw as solid lines with protocol labels):

{conn_block}

---

ATTACK FLOW — draw as bold red arrows:
  {flow}
  Terminal goal: {goal_svc} (mark with a star/crown icon)

Add an ATTACKER node (hacker silhouette icon, labeled "Attacker") outside and to the left of the
leftmost zone, connected to it with a dashed red arrow labeled "initial access".

Keep the diagram clean, uncluttered, clearly readable, and suitable for a thesis presentation slide."""

    return prompt


def _ascii(text: str) -> str:
    """Replace Unicode punctuation with ASCII equivalents for lstlisting."""
    return (text
        .replace("—", "--").replace("–", "-")
        .replace("→", "->").replace("←", "<-")
        .replace("×", "x").replace(" ", " ")
        .replace("’", "'").replace("“", '"').replace("”", '"')
        .encode("ascii", errors="replace").decode("ascii")
    )


def _frame_gemini(entry: dict, config_path: "Path | None",
                  images_dir: "Path | None" = None,
                  workdir: "Path | None" = None) -> str:
    """Image placeholder frame. Shows the generated image if it exists in
    images_dir, otherwise a dashed placeholder with drop-in instructions."""
    short = _e(entry.get("short_name", entry["name"]))
    name  = entry["name"]

    img_file = None
    if images_dir:
        for ext in (".png", ".jpg", ".jpeg"):
            candidate = images_dir / f"{name}{ext}"
            if candidate.exists():
                img_file = candidate
                break

    if img_file:
        # Copy to workdir so pdflatex can find it
        if workdir:
            dst = workdir / f"gemini_{name}{img_file.suffix}"
            shutil.copy(img_file, dst)
            img_ref = dst.name
        else:
            img_ref = str(img_file).replace("\\", "/")
        return rf"""
\begin{{frame}}{{{short}: Network Architecture (AI-Generated)}}
  \centering
  \includegraphics[width=\linewidth,height=0.85\textheight,keepaspectratio]{{{img_ref}}}
\end{{frame}}
"""
    else:
        ename = _e(name)
        return rf"""
\begin{{frame}}{{{short}: Network Architecture (AI-Generated)}}
  \vfill
  \begin{{block}}{{INSERT AI-GENERATED IMAGE HERE}}
    \centering\vspace{{0.4cm}}
    Scenario: \textbf{{{short}}}\\[6pt]
    Save your image to:\\[4pt]
    \texttt{{output/reports/gemini\_images/{ename}.png}}\\[8pt]
    Then re-run \texttt{{generate\_presentation.py}} to embed it automatically.
    \vspace{{0.4cm}}
  \end{{block}}
  \vfill
\end{{frame}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Agent Design slides
# ─────────────────────────────────────────────────────────────────────────────
def _frame_agents_overview() -> str:
    return r"""
\section{Agent Design}
\begin{frame}{Agent Design: Specialist Overview}
  \centering\tiny
  \setlength{\tabcolsep}{4pt}
  \begin{tabular}{@{}p{1.4cm}p{2.8cm}p{1.3cm}p{1.2cm}p{2.2cm}p{2.2cm}@{}}
    \toprule
    \textbf{Agent} & \textbf{Zones} & \textbf{OS} & \textbf{CVEs} & \textbf{Action Emphasis} & \textbf{Key MITRE Tactics} \\
    \midrule
    \rowcolor{gtgrey}
    \texttt{S\_NetPerim} &
      Z4 Internet Edge, Z2 HQ Edge &
      Network appliances &
      240 (NetDev) &
      \texttt{probe} $\to$ \texttt{remote} $\to$ \texttt{cred\_leak} &
      TA0001, TA0006, TA0008 \\
    \texttt{S\_Cloud} &
      Z6 AWS Cloud (all tiers) &
      Linux / Alpine &
      693 (Bitnami) &
      \texttt{remote} + \texttt{local} + \texttt{cred\_leak} &
      TA0001, TA0006, TA0009, TA0011 \\
    \rowcolor{gtgrey}
    \texttt{S\_AD} &
      Z1 Server Farm, Z1 HQ VLANs &
      Windows &
      268 (Windows) &
      \texttt{remote} + \texttt{local} + \texttt{goal\_access} &
      TA0003, TA0004, TA0006, TA0008 \\
    \texttt{S\_Lateral} &
      All zone boundaries &
      N/A (no exploit) &
      None (CBS constraints) &
      \texttt{cred\_leak} + \texttt{discovery} only &
      TA0006, TA0007 \\
    \rowcolor{gtgrey}
    \texttt{S\_Mgmt} &
      Z8 Management Plane &
      Windows + appliances &
      Windows + NetDev &
      \texttt{goal\_access} $\gg$ \texttt{remote} &
      TA0004, TA0006, TA0040 \\
    \bottomrule
  \end{tabular}
  \vspace{5pt}
  \begin{block}{\scriptsize Design Rationale}
    \tiny
    Agents are partitioned by \textbf{attack surface + CVE family}, not by MITRE phase.
    Each specialist trains only on CVEs it will encounter in deployment.
    A \textbf{meta-agent} coordinates zone-transition timing via a learned routing policy.
  \end{block}
\end{frame}
"""


def _frame_agents_detail() -> str:
    return r"""
\begin{frame}{Agent Design: Per-Specialist Profile}
  \begin{columns}[T]
    \begin{column}{0.48\textwidth}
      \begin{block}{\tiny\texttt{S\_NetPerim} --- Network Perimeter}
        \tiny
        \textbf{OS:} PAN-OS, IOS/NX-OS, FortiOS, F5-TMOS, JunOS \quad \textbf{CVEs:} 240 (NetDev)\\
        \textbf{Actions:} probe $\to$ remote (e.g.\ CiscoASA IKE HeapOvf CVSS 10.0 SR 0.90,
        PanOS GlobalProtect RCE CVSS 9.8, FortiOS SSL-VPN CVSS 9.8) $\to$ cred\_leak
        (running-config dump, TACACS+ secret)\\
        \textbf{MITRE:} TA0001 Initial Access $\cdot$ TA0006 Cred Access $\cdot$ TA0008 Lateral\\
        \textit{Goal: CiscoEdgeRouter (value 10\,000).}
      \end{block}
      \vspace{2pt}
      \begin{block}{\tiny\texttt{S\_Cloud} --- Cloud \& Container}
        \tiny
        \textbf{OS:} Linux (Alpine, Debian) \quad \textbf{CVEs:} 693 (Bitnami)\\
        \textbf{Actions:} remote (Concourse container escape CVSS 10.0, SnakeYAML deser.\ CVSS 9.8,
        ImageMagick shell inject CVSS 9.8) + local (Docker socket escape SR 0.85,
        K8s HostPID SR 0.80) + cred\_leak (env vars, \texttt{\textasciitilde/.aws/credentials})\\
        \textbf{MITRE:} TA0001 $\cdot$ TA0006 $\cdot$ TA0009 Collection $\cdot$ TA0011 Exfil\\
        \textit{Goal: AWSRedis (standalone, value 10\,000) / AWSPostgreSQL (meta).}
      \end{block}
      \vspace{2pt}
      \begin{block}{\tiny\texttt{S\_AD} --- Windows \& Active Directory}
        \tiny
        \textbf{OS:} Windows 7/10/Server 2019/2022 \quad \textbf{CVEs:} 268 (Windows)\\
        \textbf{Actions:} remote OS (SMBGhost CVSS 10.0, BlueKeep CVSS 9.8, ProxyShell CVSS 9.1)
        + local PrivEsc (PrintNightmare SR 0.88, SeImpersonate SR 0.75)
        + AD protocol (Kerberoasting, PetitPotam, ZeroLogon CVE-2020-1472)
        + goal\_access (DCSync SR 0.60, ADCS ESC1 SR 0.60, GoldenTicket SR 0.55)\\
        \textbf{MITRE:} TA0003 Persistence $\cdot$ TA0004 PrivEsc $\cdot$ TA0006 Cred $\cdot$ TA0008\\
        \textit{Goal: DomainController (value 10\,000).}
      \end{block}
    \end{column}
    \begin{column}{0.48\textwidth}
      \begin{block}{\tiny\texttt{S\_Lateral} --- Information Scout}
        \tiny
        \textbf{OS:} N/A --- no exploitation \quad \textbf{CVEs:} None (CBS constraint mechanics only)\\
        \textbf{Actions:} discovery (BloodHound SR 0.80, DNS zone transfer SR 0.55,
        AWS IMDSv1 SR 0.85) + cred\_leak (Mimikatz LSASS SR 0.85,
        LAPS read SR 0.65, Redis noauth SR 0.80, Docker socket creds SR 0.80,
        LEAK\_KNOWN\_CREDENTIALS cross-node propagation)\\
        \textbf{No remote\_access. No goal\_access. Never terminates an episode.}\\
        \textbf{MITRE:} TA0006 Cred Access $\cdot$ TA0007 Discovery\\
        \textit{Goal: AdminWorkstation (value 10\,000) via shaped rewards.}
      \end{block}
      \vspace{2pt}
      \begin{block}{\tiny\texttt{S\_Mgmt} --- Management Plane}
        \tiny
        \textbf{OS:} Windows Server + appliance OS \quad \textbf{CVEs:} Windows + NetDev (TBD)\\
        \textbf{Actions:} remote (SolarWinds NPM RCE) + goal\_access (CyberArk PAM vault dump,
        Splunk SIEM token exfil, Cisco ISE config extract)\\
        \textbf{Prerequisite:} DomainController must be owned before Z8 is reachable.\\
        \textbf{MITRE:} TA0004 Priv Esc $\cdot$ TA0006 Cred Access $\cdot$ TA0040 Impact\\
        \textit{Goal: CyberArkPAM (value 10\,000); SolarWindsNPM near-goal (3\,500).}
      \end{block}
      \vspace{2pt}
      \begin{alertblock}{\tiny Meta-Agent}
        \tiny
        PPO + LSTM routing policy: $\pi_\text{meta}(s_t) \to \{$S\_NetPerim, S\_Cloud, S\_AD,
        S\_Lateral, S\_Mgmt$\}$. Specialist weights are \textbf{frozen} during meta-training.
        Trained via 4-stage curriculum (single-zone $\to$ full kill chain).
      \end{alertblock}
    \end{column}
  \end{columns}
\end{frame}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Main assembler
# ─────────────────────────────────────────────────────────────────────────────
def build_presentation(phase2_root: Path, configs_roots: list,
                        output: Path, title: str = "") -> None:

    entries = build_entries(phase2_root, configs_roots, fast=True)
    if not entries:
        print("No entries — aborting.")
        sys.exit(1)

    date_str = datetime.now().strftime("%d %B %Y")
    ref_png  = TOOLS_DIR.parent / "prompts" / "llm_prompts" / "ref.png"

    # config path lookup
    def _cfg(entry):
        for root in configs_roots:
            for ext in (".yaml", ".yml"):
                p = Path(root) / (entry["name"] + ext)
                if p.exists():
                    return p
        return None

    with tempfile.TemporaryDirectory() as _tmp:
        workdir = Path(_tmp)

        frames = []
        frames.append(_preamble())
        frames.append(_title_frame(date_str))

        # ── Section: Source of Data ───────────────────────────────────────────
        frames.append(_section_divider("Source of Data"))
        frames.append(_frame_2a(ref_png, workdir))
        frames.append(_frame_2b())
        frames.append(_frame_2c())
        frames.append(_frame_2d())

        # ── Section: Methodology ──────────────────────────────────────────────
        frames.append(_section_divider("Methodology"))
        frames.append(_frame_3a())
        frames.append(_frame_3b())

        # ── Section: Agent Design ─────────────────────────────────────────────
        frames.append(_section_divider("Agent Design"))
        frames.append(_frame_agents_overview())
        frames.append(_frame_agents_detail())

        # ── Section: Scenarios ────────────────────────────────────────────────
        frames.append(_section_divider("Scenarios"))
        frames.append(_frame_summary(entries))

        # ── Save one Gemini prompt file per scenario ──────────────────────────
        images_dir   = output.parent / "gemini_images"
        prompts_dir  = output.parent / "gemini_prompts"
        images_dir.mkdir(parents=True, exist_ok=True)
        prompts_dir.mkdir(parents=True, exist_ok=True)
        for entry in entries:
            cfg_path    = _cfg(entry)
            prompt_text = _build_gemini_prompt(entry, cfg_path)
            prompt_file = prompts_dir / f"{entry['name']}.txt"
            with open(prompt_file, "w", encoding="utf-8") as pf:
                pf.write(prompt_text)
        print(f"\n  Gemini prompts saved: {prompts_dir}/ ({len(entries)} files)")

        colours = ["scA", "scB", "scC", "scD", "scE", "scF"]
        for i, entry in enumerate(entries):
            cfg_path = _cfg(entry)
            col      = colours[i % len(colours)]
            frames.append(_scenario_divider(entry, col))
            frames.append(_frame_prompt(entry))
            frames.append(_frame_arch(entry, workdir))
            frames.append(_frame_metrics(entry, workdir))
            frames.append(_frame_gemini(entry, cfg_path, images_dir, workdir))

        # ── Compile ───────────────────────────────────────────────────────────
        tex = "\n".join(frames) + "\n\\end{document}\n"

        tex_path = workdir / "presentation.tex"
        tex_path.write_text(tex, encoding="utf-8")

        print("\n  Compiling presentation (3 pdflatex passes)...")
        ok = True
        for p in range(1, 4):
            print(f"    pass {p}/3 ...")
            r = subprocess.run(
                ["pdflatex", "-interaction=nonstopmode", "-halt-on-error",
                 "presentation.tex"],
                cwd=str(workdir), capture_output=True,
            )
            if r.returncode != 0:
                print(f"  [ERROR] pdflatex failed on pass {p}")
                log = (workdir / "presentation.log").read_text(errors="replace")
                for ln in log.splitlines()[-30:]:
                    print("  " + ln)
                ok = False
                break

        out_pdf = workdir / "presentation.pdf"
        if ok and out_pdf.exists():
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(out_pdf, output)
            shutil.copy(tex_path, output.with_suffix(".tex"))
            print(f"\n  Presentation saved: {output}")
        else:
            print("\n  ERROR: PDF not produced.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate CyberBattleSim status presentation")
    parser.add_argument("--phase2-root",   required=True, type=Path)
    parser.add_argument("--configs-root",  default="",   type=str)
    parser.add_argument("--extra-configs", nargs="*",    default=[])
    parser.add_argument("--output",        default="output/reports/presentation.pdf", type=Path)
    parser.add_argument("--title",         default="Data Generation for CyberBattleSim — Current Status")
    args = parser.parse_args()

    roots = [Path(r) for r in ([args.configs_root] if args.configs_root else []) +
             (args.extra_configs or [])]

    build_presentation(args.phase2_root, roots, args.output, args.title)
