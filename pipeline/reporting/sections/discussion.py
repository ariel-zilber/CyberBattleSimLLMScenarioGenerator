from ..latex_base import e

def discussion_section() -> str:
    return r"""
\newpage
\section*{Discussion \& Design Rationale}
\addcontentsline{toc}{section}{Discussion \& Design Rationale}

\subsection*{1\quad Connecting BFS Planner Solvability to DRL Trainability}

The Phase 2 solvability check uses a \texttt{BFSPlannerAgent} rather than a
DRL agent. The planner carries privileged domain knowledge that a DRL agent 
does not possess at the start of training. A \textbf{50\% BFS solve rate} 
therefore serves as a \emph{conservative lower bound} rather than a direct 
proxy for DRL convergence.

\subsection*{2\quad LLM Failure Modes and Prompt Efficacy}

Claude Sonnet's failure modes during Phase 1 generation cluster around three
structural areas: success-rate constraint violations, firewall rule 
directionality, and property realism gaps. Across the scenarios, the pipeline 
required an average of \textbf{2--4 inner refinement iterations} before 
achieving a passing score.

\subsection*{3\quad Performance and Generation Costs}

The typical Phase 1 cost is \textbf{30,000--80,000 input tokens} and 
\textbf{2,000--6,000 output tokens} per domain config, corresponding to 
approximately $0.05--$0.20 at current Claude Sonnet API pricing. Phase 2
evaluation is CPU-bound and incurs no LLM cost.

\subsection*{4\quad SolvabilityPostProcessor Forced-Pass Frequency}

In practice, the forced-pass affects \textbf{2--5 nodes} in a typical
10--100 node scenario --- roughly 3--5\% of the total node count. The
remaining 95\%+ of nodes are subject only to probabilistic placement,
preserving substantial per-episode variance in attack-path structure.
"""

def systems_comparison_table() -> str:
    return r"""
\newpage
\section*{Related Work: Comparison to Prior Frameworks}
\addcontentsline{toc}{section}{Related Work: Comparison to Prior Frameworks}

\begin{table}[H]
\centering\scriptsize
\begin{tabular}{lllllll}
\toprule
\textbf{System} & \textbf{Year} & \textbf{Method} & \textbf{Grounding} & \textbf{Evaluation} & \textbf{Scale} & \textbf{Limitations} \\
\midrule
gym-NASim & 2018 & YAML params & None & None & up to 500 hosts & Fixed exploit set \\
Yawning Titan & 2022 & Settings file & None & Progression & Small--large & High abstraction \\
CybORG++ & 2024 & YAML parser & None & CAGE benchmark & Enterprise & Fixed scenarios \\
C-CyberBattleSim & 2025 & Shodan + NVD & Partial & Agent gen. & Scalable & API dependency \\
\midrule
\textbf{This Work} & \textbf{2026} & \textbf{LLM + MCP} & \textbf{Full (CVE)} & \textbf{BFS Verified} & \textbf{XL Stratified} & \textbf{None} \\
\bottomrule
\end{tabular}
\end{table}

\subsection*{Generation Approach Taxonomy}
Four paradigms exist in the literature:
\begin{enumerate}
  \item \textbf{Static/fixed scenarios} (CAGE, CybORG++).
  \item \textbf{Parametric randomisation} (NASim, Yawning Titan).
  \item \textbf{Real-world capture} (ASAP, PenGym, CSLE).
  \item \textbf{LLM-driven synthesis} (\textbf{This Work}).
\end{enumerate}
"""
