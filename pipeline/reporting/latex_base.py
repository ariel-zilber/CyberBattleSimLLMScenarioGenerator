import re

# ── dimension keys → short display names ────────────────────────────────────
DIM_SHORT = {
    "topology_realism":      "Network Topology",
    "vulnerability_realism": "Vuln Realism",
    "scenario_difficulty":   "Difficulty",
    "firewall_realism":      "Firewall Rules",
    "general_realism":       "General Realism",
    "cve_grounding":         "CVE Grounding",
}

GRADE_COLOR = {
    "A+": "scoreAplus", "A": "scoreA", "B": "scoreB",
    "C": "scoreC",  "D": "scoreD",  "F": "scoreF",
}

PREAMBLE = r"""
\documentclass[a4paper,10pt]{article}
\usepackage{lmodern}
\usepackage[T1]{fontenc}
\usepackage[utf8]{inputenc}
\usepackage[landscape,top=1.4cm,bottom=1.4cm,left=1.6cm,right=1.6cm]{geometry}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{xcolor}
\usepackage{colortbl}
\usepackage{hyperref}
\usepackage{rotating}
\usepackage{float}
\usepackage{tabularx}
\usepackage{amssymb}
\usepackage{titlesec}
\usepackage{fancyhdr}
\usepackage{multicol}
\usepackage{array}
\usepackage{enumitem}
\usepackage{amsmath}
\usepackage{tikz}
\usetikzlibrary{shapes.geometric,arrows.meta,positioning,fit,backgrounds}
\usepackage{listings}
\lstset{
  basicstyle=\scriptsize\ttfamily,
  breaklines=true,
  breakatwhitespace=false,
  frame=single,
  framesep=4pt,
  xleftmargin=4pt,
  xrightmargin=4pt,
  columns=flexible,
  keepspaces=true,
  showstringspaces=false,
}

%% colours
\definecolor{titleblue}{RGB}{26,58,92}
\definecolor{scoreAplus}{RGB}{26,122,26}
\definecolor{scoreA}{RGB}{46,204,113}
\definecolor{scoreB}{RGB}{243,156,18}
\definecolor{scoreC}{RGB}{230,126,34}
\definecolor{scoreD}{RGB}{231,76,60}
\definecolor{scoreF}{RGB}{192,57,43}
\definecolor{lightgray}{gray}{0.93}
\definecolor{midgray}{gray}{0.60}

%% headings
\titleformat{\section}{\large\bfseries\color{titleblue}}{}{0em}{}[\titlerule]
\titleformat{\subsection}{\normalsize\bfseries\color{titleblue}}{}{0em}{}
\titleformat{\subsubsection}{\small\bfseries}{}{0em}{}

%% header / footer
\pagestyle{fancy}
\fancyhf{}
\renewcommand{\headrulewidth}{0.4pt}
\fancyhead[L]{\small\color{midgray}\textit{CyberBattleSim --- Scenario Dataset}}
\fancyhead[R]{\small\color{midgray}\thepage}

%% hyperref setup
\hypersetup{colorlinks=true,linkcolor=titleblue,urlcolor=titleblue,
            pdftitle={CyberBattleSim Executive Report}}

%% KPI tile: coloured background box using colorbox + minipage
\newcommand{\kpibox}[2]{%
  \colorbox{lightgray}{%
    \begin{minipage}[t][1.8cm][c]{3.8cm}
      \centering
      {\Large\bfseries\color{titleblue}#1}\\[3pt]
      {\footnotesize\color{midgray}#2}
    \end{minipage}}}

\setlist[itemize]{noitemsep,topsep=2pt,leftmargin=1.4em}
\usepackage{pifont}
\newcommand{\cmark}{\ding{51}}
\newcommand{\xmark}{\ding{55}}
"""

def e(text: str) -> str:
    """Escape a plain string for use in LaTeX."""
    text = str(text)
    # Step 1: escape LaTeX-special characters in the raw input
    for old, new in [
        ("\\", r"\textbackslash{}"),
        ("&",  r"\&"),
        ("%",  r"\%"),
        ("$",  r"\$"),
        ("#",  r"\#"),
        ("_",  r"\_"),
        ("{",  r"\{"),
        ("}",  r"\}"),
        ("~",  r"\textasciitilde{}"),
        ("^",  r"\textasciicircum{}"),
        ("<",  r"\textless{}"),
        (">",  r"\textgreater{}"),
    ]:
        text = text.replace(old, new)
    # Step 2: substitute Unicode chars with valid LaTeX commands (safe after step 1)
    for old, new in [
        ("\u2192", r"$\rightarrow$"),   # →
        ("\u2190", r"$\leftarrow$"),    # ←
        ("\u2014", "--"),                # em dash
        ("\u2013", "-"),                 # en dash
        ("\u2018", "`"),                 # left single quote
        ("\u2019", "'"),                 # right single quote
        ("\u201c", "``"),                # left double quote
        ("\u201d", "''"),                # right double quote
        ("\u2026", r"\ldots{}"),         # ellipsis
        ("\u00a0", " "),                 # non-breaking space
        ("\u2265", r"$\geq$"),           # ≥
        ("\u2264", r"$\leq$"),           # ≤
        ("\u2260", r"$\neq$"),           # ≠
        ("\u2713", r"$\checkmark$"),     # ✓
        ("\u2714", r"$\checkmark$"),     # ✔
        ("\u2705", r"$\checkmark$"),     # ✅ green check emoji
        ("\u2717", r"$\times$"),          # ✗
        ("\u2718", r"$\times$"),          # ✘
        ("\u274c", r"$\times$"),          # ❌ red X emoji
        ("\u2191", r"$\uparrow$"),       # ↑
        ("\u2193", r"$\downarrow$"),     # ↓
        ("\u2248", r"$\approx$"),         # ≈
        ("\u00b7", r"$\cdot$"),           # ·
        ("\u26a0", "[!]"),               # ⚠ warning sign
        ("\u2b50", "*"),                  # ⭐ star
    ]:
        text = text.replace(old, new)
    # Catch-all: strip any remaining non-ASCII characters (unmapped emoji/symbols)
    text = re.sub(r'[^\x00-\x7E]', '', text)
    return text

def slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "", text)

def score_cmd(score: float, grade: str) -> str:
    color = (GRADE_COLOR.get(grade) or
             ("scoreAplus" if score >= 9 else "scoreA" if score >= 7.5
              else "scoreB" if score >= 6 else "scoreC" if score >= 5
              else "scoreD"))
    return rf"\textcolor{{{color}}}{{\textbf{{{grade} ({score:.1f})}}}}"
