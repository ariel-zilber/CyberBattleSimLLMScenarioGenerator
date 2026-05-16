import shutil
from pathlib import Path
from ..latex_base import e


def quality_appendix() -> str:
    return r"""
\clearpage
\section*{Appendix: Quality Metric Evaluation Reference}
\addcontentsline{toc}{section}{Appendix: Quality Metric Evaluation Reference}

Each generated domain configuration is scored across \textbf{six quality
dimensions}, each on a 0--10 scale.  The overall score is the unweighted mean
of the six dimension scores.  Deductions are capped at 0 (a dimension cannot
go negative).

\smallskip
\begin{center}
\begin{tabular}{lccl}
\toprule
\textbf{Grade} & \textbf{Score range} & \textbf{Label} & \textbf{Meaning} \\
\midrule
A+ & $\geq 9$ & Excellent     & Production-quality, minimal issues \\
A  & $\geq 8$ & Good          & Minor warnings only \\
B  & $\geq 7$ & Above average & One non-critical gap \\
C  & $\geq 6$ & Average       & Notable issues present \\
D  & $\geq 5$ & Below average & Significant gaps \\
F  & $< 5$   & Poor          & Critical failures \\
\bottomrule
\end{tabular}
\end{center}

% Dimension 1
\clearpage
\subsection*{Dimension 1 --- Network Topology Realism}

Assesses whether the generated network layout is structurally plausible as a
real enterprise or cloud environment.

\begin{center}
\begin{tabularx}{\linewidth}{p{4cm}>{\raggedright\arraybackslash}X p{2.8cm}>{\raggedright\arraybackslash}X}
\toprule
\textbf{Check} & \textbf{YAML field} & \textbf{Severity / Pts} & \textbf{Rationale} \\
\midrule
Attacker start subnet is public
  & \texttt{start\_node.subnet}
  & CRITICAL $-4$
  & The attacker enters from the public internet; an RFC\,1918 start address
    would mean the attacker is already inside the network, skipping the
    initial compromise phase entirely. \\
Internal domains use RFC\,1918 addresses
  & \texttt{domains[].subnet}
  & FAIL $-2$ each
  & Real enterprise subnets are always private (10.x, 172.16--31.x,
    192.168.x).  Public addresses on internal nodes break firewall semantics. \\
No subnet overlaps
  & \texttt{domains[].subnet}
  & CRITICAL $-3$ each
  & Overlapping subnets are a routing conflict; CBS cannot create valid
    firewall rules between two domains that share the same IP range. \\
OS distribution heterogeneity
  & \texttt{domains[].os\_distribution}
  & WARNING $-1$
  & 100\% single-OS domains appear in only the simplest lab setups.
    Mixed Linux/Windows reflects real enterprise sprawl. \\
Minimum node count $\geq 5$
  & \texttt{config.min\_total\_nodes}
  & WARNING $-1$
  & Fewer than five nodes produce trivially small graphs in which a DRL
    agent can reach the goal by exhaustive enumeration rather than
    meaningful policy learning. \\
Node count range factor $\geq 1.5\times$
  & \texttt{config.min/max\_total\_nodes}
  & WARNING $-1$
  & A narrow min--max range (e.g.\ 20--22) collapses the three strata
    (small, medium, large) into nearly identical episodes, reducing
    dataset diversity. \\
At least one domain defined
  & \texttt{domains}
  & FAIL $-4$
  & A config with no domains has no nodes and is un-runnable. \\
\bottomrule
\end{tabularx}
\end{center}

% Dimension 2
\clearpage
\subsection*{Dimension 2 --- Properties \& Vulnerabilities Realism}

Evaluates whether the vulnerability profile matches real-world exploit
characteristics and whether each vulnerability is sufficiently specific.

\begin{center}
\begin{tabularx}{\linewidth}{p{4cm}>{\raggedright\arraybackslash}X p{2.8cm}>{\raggedright\arraybackslash}X}
\toprule
\textbf{Check} & \textbf{YAML field} & \textbf{Severity / Pts} & \textbf{Rationale} \\
\midrule
No \texttt{success\_rate=1.0} on non-discovery vulns
  & \texttt{solvability\_vulnerabilities}
  & FAIL $-2$
  & A 100\% success rate means the exploit always works, removing
    probabilistic challenge.  Real exploits fail due to patching,
    AV detection, and race conditions. \\
No \texttt{success\_rate > 0.80} on exploits
  & \texttt{solvability\_vulnerabilities}
  & WARNING $-1$
  & Rates above 0.80 push scenarios towards being trivially solvable;
    the CVE formula caps CRITICAL CVEs at 0.90. \\
All vulns have \texttt{match\_properties}
  & \texttt{solvability\_vulnerabilities[].match\_properties}
  & WARNING $-2$
  & Without \texttt{match\_properties}, an exploit applies to every node in
    the network regardless of OS or role --- unrealistic and produces
    over-dense attack graphs. \\
Vulnerability names reference real exploits
  & \texttt{solvability\_vulnerabilities[].name}
  & WARNING $-1$
  & Generic names (e.g.\ \texttt{exploit1}) indicate hand-authored entries
    unconnected to real-world CVE data.  Names should follow the pattern
    \texttt{CVE-YYYY-NNNN} or a named exploit family. \\
Both REMOTE and LOCAL types present
  & \texttt{solvability\_vulnerabilities[].type}
  & CRITICAL $-3$ / WARNING $-1$
  & REMOTE exploits model network-level initial access; LOCAL exploits model
    post-compromise privilege escalation.  Missing either breaks the
    realistic two-phase attack structure. \\
All four categories populated
  & \texttt{remote\_access, credential\_leak, discovery, goal\_access}
  & WARNING $-2$
  & Each category covers a distinct attack phase.  Absent categories
    produce incomplete kill chains where the DRL agent cannot learn
    realistic lateral movement. \\
\texttt{leak\_known\_credentials} defined with \texttt{node\_probability $\geq$ 0.40}
  & \texttt{constraint\_vulnerabilities}
  & FAIL $-2$ / WARNING $-1$
  & Credential harvesting is the primary lateral movement primitive in CBS.
    Missing or low probability means the agent rarely accumulates
    credentials and cannot traverse the network. \\
\texttt{leak\_neighbors} defined
  & \texttt{constraint\_vulnerabilities.leak\_neighbors}
  & FAIL $-2$
  & Without neighbour discovery, the agent cannot learn which hosts are
    reachable from a compromised node, breaking the reconnaissance phase. \\
\bottomrule
\end{tabularx}
\end{center}

% Dimension 3
\clearpage
\subsection*{Dimension 3 --- Scenario Difficulty}

Checks that the scenario is neither trivially solvable nor unsolvable ---
the ``Goldilocks'' zone where DRL training is most informative.

\begin{center}
\begin{tabularx}{\linewidth}{p{4cm}>{\raggedright\arraybackslash}X p{2.8cm}>{\raggedright\arraybackslash}X}
\toprule
\textbf{Check} & \textbf{YAML field} & \textbf{Severity / Pts} & \textbf{Rationale} \\
\midrule
\texttt{attack\_flow} defines $\geq 2$ hops
  & \texttt{attack\_flow}
  & WARNING $-2$ / FAIL $-3$
  & A single-hop flow means the attacker goes directly to the goal with no
    intermediate lateral movement, trivialising the scenario for RL. \\
\texttt{min\_total\_nodes $\geq 10$} (recommended)
  & \texttt{config.min\_total\_nodes}
  & FAIL $-3$ if $<5$, WARNING $-1$ if $<10$
  & Very small networks are solved by random exploration in fewer steps
    than the agent's episode budget; no meaningful policy is learned. \\
Goal density $\leq 30\%$ of services
  & \texttt{services[].is\_goal}
  & WARNING $-2$ / CRITICAL $-5$
  & If most services are goals, the agent trivially wins by touching any
    node.  Zero goals makes the scenario unsolvable. \\
\texttt{min\_credential\_leaking\_nodes $\geq 0.50$}
  & \texttt{solvability\_rules}
  & WARNING $-1$
  & A low fraction of credential-leaking nodes means the agent finds few
    pivot opportunities, making the scenario hard to solve but for the
    wrong reasons (starvation rather than policy). \\
\texttt{remote\_access} and \texttt{goal\_access} both populated
  & \texttt{solvability\_vulnerabilities}
  & FAIL $-2$ each
  & Missing entry vector or goal-access vector makes the scenario
    structurally unsolvable regardless of agent policy. \\
Mean vulnerability probability in [0.40, 0.85]
  & \texttt{solvability\_vulnerabilities[].probability}
  & WARNING $-1$
  & Probabilities near 1.0 make every exploit attempt succeed (too easy);
    probabilities near 0 mean the agent rarely discovers anything
    (too hard for signal). \\
\bottomrule
\end{tabularx}
\end{center}

% Dimension 4
\clearpage
\subsection*{Dimension 4 --- Firewall Rules Realism}

Validates that access-control constraints reflect real network segmentation
practices (DMZ / App Tier / Core architecture).

\begin{center}
\begin{tabularx}{\linewidth}{p{4cm}>{\raggedright\arraybackslash}X p{2.8cm}>{\raggedright\arraybackslash}X}
\toprule
\textbf{Check} & \textbf{YAML field} & \textbf{Severity / Pts} & \textbf{Rationale} \\
\midrule
Multi-domain configs define \texttt{inter\_domain\_constraints}
  & \texttt{inter\_domain\_constraints}
  & CRITICAL $-4$
  & Without cross-tier firewall rules, all tiers are unrestricted to each
    other --- the scenario behaves as a flat network and multi-domain
    topology is meaningless. \\
All constraints specify a concrete protocol
  & \texttt{constraints[].protocol}
  & FAIL $-2$ each
  & A protocol of \texttt{ALL} or blank is equivalent to a ``permit any''
    firewall rule, which is unrealistic in any properly segmented network. \\
No direct DMZ $\to$ Core connection
  & \texttt{inter\_domain\_constraints}
  & CRITICAL $-4$
  & Defence-in-depth mandates that the public-facing DMZ can only reach
    the application tier; direct DMZ--to--database/AD connections are a
    critical misconfiguration. \\
DMZ does not use internal management protocols (SMB, RDP, LDAP, MSSQL, WinRM)
  & \texttt{inter\_domain\_constraints[].constraints[].protocol}
  & FAIL $-2$ each
  & These protocols are never legitimately initiated from the DMZ toward
    internal tiers; allowing them replicates a known attack pivot vector. \\
Entry points are not in the core tier
  & \texttt{entry\_points[].domain}
  & CRITICAL $-3$
  & Placing the initial attacker foothold inside the core domain
    (database, AD) skips all intermediate attack phases. \\
Single-domain configs define intra-domain constraints
  & \texttt{domains[0].constraints}
  & WARNING $-2$
  & Even flat networks should model at least some access controls between
    service groups to produce non-trivial firewall graphs. \\
\bottomrule
\end{tabularx}
\end{center}

% Dimension 5
\clearpage
\subsection*{Dimension 5 --- General Realism}

Holistic checks on naming, service variety, goal value assignment, and
structural correctness that do not fit a single category.

\begin{center}
\begin{tabularx}{\linewidth}{p{4cm}>{\raggedright\arraybackslash}X p{2.8cm}>{\raggedright\arraybackslash}X}
\toprule
\textbf{Check} & \textbf{YAML field} & \textbf{Severity / Pts} & \textbf{Rationale} \\
\midrule
No generic service names
  & \texttt{services} keys
  & WARNING $-1$
  & Names like \texttt{service1} or \texttt{host2} do not map to any real
    enterprise archetype and prevent meaningful CVE grounding. \\
Goal services have \texttt{value $\geq$ 1000}
  & \texttt{services[is\_goal].value}
  & WARNING $-1$ each
  & Low-value goals produce weak reward signals in DRL.  High-value targets
    (databases, domain controllers) naturally reflect their business impact. \\
$\geq 3$ distinct service types
  & \texttt{services}
  & WARNING $-2$
  & Fewer than three service types collapses all nodes into one or two
    roles, producing a homogeneous network with limited attack-surface
    diversity. \\
Every domain has at least one group
  & \texttt{domains[].groups}
  & WARNING $-1$
  & A domain without groups has no nodes; the subnet exists in the YAML
    but contributes nothing to the generated scenario. \\
Group \texttt{max\_count $\geq$ min\_count}
  & \texttt{groups[].min\_count / max\_count}
  & FAIL $-1$
  & Inverted counts produce invalid range constraints that the generator
    cannot satisfy, causing scenario generation to fail silently. \\
Attack flow targets at least one goal service
  & \texttt{attack\_flow[].targets}
  & WARNING $-1$
  & If the declared pivot chain never points at a goal node, the agent
    learns a policy that terminates short of the objective. \\
\texttt{probe\_vulnerabilities} defined
  & \texttt{probe\_vulnerabilities}
  & WARNING $-1$
  & OS fingerprinting (e.g.\ nmap probes) is a standard reconnaissance
    step; omitting it removes a realistic early-phase attacker action. \\
\bottomrule
\end{tabularx}
\end{center}

% Dimension 6
\clearpage
\subsection*{Dimension 6 --- CVE Grounding}

Verifies that vulnerability parameters were derived from real CVE records
rather than hand-authored with round numbers.  The CBS Domain Generator
applies the formula $\mathrm{SR} = \min(0.90,\, \mathrm{CVSS}/10)$ for
CRITICAL/HIGH CVEs and $\mathrm{SR} = \mathrm{CVSS}/10$ for others.

\begin{center}
\begin{tabularx}{\linewidth}{p{4cm}>{\raggedright\arraybackslash}X p{2.8cm}>{\raggedright\arraybackslash}X}
\toprule
\textbf{Check} & \textbf{YAML field} & \textbf{Severity / Pts} & \textbf{Rationale} \\
\midrule
$\geq 50\%$ of vulns reference a CVE ID
  & \texttt{solvability\_vulnerabilities[].name}
  & FAIL $-2$ / WARNING $-1$
  & CVE IDs provide a traceable provenance chain from NVD score to
    exploit success rate.  Without them, parameters cannot be audited
    or justified to reviewers. \\
$\geq 60\%$ of remote success rates are formula-derived
  & \texttt{remote\_access[].success\_rate}
  & FAIL $-2$ / WARNING $-1$
  & Formula-derived rates are recognisable by being non-round (e.g.\
    0.86, 0.78, 0.63).  Round multiples of 0.05 indicate hand-authoring
    that bypasses CVE calibration. \\
Remote exploit success rates $\geq 0.65$
  & \texttt{remote\_access[].success\_rate}
  & WARNING $-1$
  & CVSS HIGH ($\geq 7.0$) and CRITICAL ($\geq 9.0$) CVEs produce
    success rates $\geq 0.65$ under the formula.  Lower rates imply
    the CVE was scored as MEDIUM or the formula was not applied. \\
Exploit costs in $\{1.0, 1.5, 2.0, 3.0\}$
  & \texttt{solvability\_vulnerabilities[].exploit\_cost}
  & WARNING $-1$
  & The CBS cost bands map directly to CVE severity tiers
    (CRITICAL $\to$ 1.0, HIGH $\to$ 1.5, MEDIUM $\to$ 2.0,
    LOW $\to$ 3.0).  Out-of-band costs break this calibration. \\
$\geq 3$ CVE-backed \texttt{match\_properties} used
  & \texttt{solvability\_vulnerabilities[].match\_properties}
  & FAIL $-2$ / WARNING $-1$
  & Properties such as \texttt{GoRuntime}, \texttt{LibCrypto},
    \texttt{WordPressInstall}, \texttt{MySQL} are derived from
    Bitnami/NVD scans.  Absent CVE-backed properties indicate the
    match criteria were invented rather than extracted from scan data. \\
Both Windows and Linux CVEs covered
  & \texttt{match\_properties}
  & WARNING $-1$ each
  & Mixed-OS scenarios should include CVEs from both ecosystems.
    Windows-only or Linux-only scenarios underfit the OS diversity
    of the generated network. \\
\bottomrule
\end{tabularx}
\end{center}

\subsection*{Scoring formula}

\[
  \text{Overall} = \frac{1}{6} \sum_{i=1}^{6} \text{score}_i, \quad
  \text{score}_i = \max\!\left(0,\; 10 - \sum_{\text{findings}} \text{deduction}\right)
\]

Deductions from multiple findings in the same dimension accumulate, but the
floor is 0.  The overall score is rounded to one decimal place before
computing the grade.
"""


def methodology_appendix(workdir: Path, repo_root: Path) -> str:
    """Input methodology.tex after copying it to workdir."""
    src = repo_root / "tools" / "methodology.tex"
    if src.exists():
        shutil.copy(src, workdir / "methodology.tex")
        return r"\input{methodology.tex}"
    return ""


def formulas_appendix(workdir: Path, repo_root: Path) -> str:
    """Input formulas_appendix.tex after copying it to workdir."""
    src = repo_root / "tools" / "formulas_appendix.tex"
    if src.exists():
        shutil.copy(src, workdir / "formulas_appendix.tex")
        return r"\input{formulas_appendix.tex}"
    return r"""
\clearpage
\section*{Appendix: Parameter Derivation Formulas}
\addcontentsline{toc}{section}{Appendix: Parameter Derivation Formulas}
The relationship between CVSS scores and Reinforcement Learning success rates is defined by:
\[
  \text{SR} = \min\!\bigl(0.90,\;\max\!\bigl(0.30,\; \tfrac{\text{CVSS}}{10} \times w_{\text{AC}} \times w_{\text{UI}}\bigr)\bigr)
\]
where $w_{\text{AC}}=0.70$ when Attack Complexity is HIGH and $w_{\text{UI}}=0.85$
when User Interaction is REQUIRED.
"""


def reproducibility_sys_section() -> str:
    return r"""
\newpage
\section*{System Configuration \& Reproducibility}
\addcontentsline{toc}{section}{System Configuration \& Reproducibility}

This section documents the exact software configuration used to produce the
scenarios and evaluation results in this report, enabling independent
reproduction of the dataset.

% LLM Configuration
\subsection*{LLM Configuration (Phase 1 --- Domain Generation)}

Domain configuration YAML files are generated by \textbf{Claude Sonnet} (Anthropic)
operating as the \emph{host model} of the pipeline.  The pipeline itself is
implemented as an MCP server (\texttt{mcp\_server/domain\_generator\_mcp.py})
that exposes tools to Claude; Claude calls those tools to build, validate, and
refine each YAML.  No temperature, top-p, or other sampling parameters are set
programmatically by the pipeline code---generation behaviour is determined
entirely by the MCP client (Claude's default inference settings) and by the
structured prompt files listed below.

\begin{table}[H]
\centering
\setlength{\tabcolsep}{6pt}
\begin{tabular}{ll}
\toprule
\textbf{Parameter} & \textbf{Value} \\
\midrule
Model family        & Claude Sonnet (Anthropic) \\
Interface           & Anthropic MCP protocol \\
Temperature         & MCP client default (not overridden by pipeline) \\
Top-p               & MCP client default (not overridden by pipeline) \\
Max output tokens   & MCP client default (not overridden by pipeline) \\
Prompt engineering  & Structured multi-file prompt stack (see Appendix) \\
\bottomrule
\end{tabular}
\caption*{LLM inference settings used during Phase 1 domain generation.}
\end{table}

% BFS Planner Agent Configuration
\subsection*{BFS Planner Agent Configuration (Phase 2 --- Solvability Evaluation)}

Scenario solvability is assessed by a \textbf{BFSPlannerAgent}
(\texttt{tools/test\_env\_integration.py}).  One agent runs per episode; it
builds a complete attack plan from the current owned-node frontier and executes
steps in shortest-hop order, replanning automatically whenever new nodes are
owned or new credentials are discovered.

\subsubsection*{Action-Selection Algorithm}

At each step the agent applies the following directed policy:

\begin{enumerate}
  \item \textbf{Replan} if the owned-node set or credential count has changed
        since the last call (triggered by a successful exploit or connection).
  \item \textbf{Local exploits first} (hop distance 0): try every
        \texttt{LOCAL} vulnerability on each currently owned node to discover
        credentials and properties before lateral movement.
  \item \textbf{BFS lateral movement}: for each owned source node, attempt
        \texttt{REMOTE} vulnerabilities and port connections to reachable
        target nodes in hop-distance order.  Goal nodes are prioritised within
        each hop level (score offset 0 vs.\ 1 for non-goals).
  \item \textbf{Cursor navigation}: before each exploit, move the source and
        target cursors to the required position using the shortest
        forward/backward path.
  \item \textbf{Retry \& skip}: each \texttt{(src, tgt, action)} triple is
        retried up to \textbf{10 times} before being permanently skipped.
  \item \textbf{Fallback}: when the plan is exhausted, issue a random
        cursor-forward to expose undiscovered nodes.
\end{enumerate}

\begin{table}[H]
\centering
\setlength{\tabcolsep}{6pt}
\begin{tabular}{ll}
\toprule
\textbf{Parameter} & \textbf{Value} \\
\midrule
Agent class              & \texttt{BFSPlannerAgent} \\
Agents per episode       & 1 (single directed planner) \\
Planning strategy        & BFS from owned frontier; goal nodes prioritised \\
Max retries per action   & 10 per \texttt{(src, tgt, action)} triple \\
Replan trigger           & New owned node or new credential discovered \\
Steps per episode        & 5\,000 \\
Episodes per scenario    & 3 \\
Solve criterion          & Any episode in which \textbf{all} attack goals are reached \\
Environment capacity     & \texttt{max\_credentials=1000}, \texttt{max\_nodes=100},
                           \texttt{neighborhood\_size=30} \\
\bottomrule
\end{tabular}
\caption*{BFSPlannerAgent evaluation parameters.}
\end{table}

A scenario is recorded as \textbf{solved} if at least one of the three episodes
achieves every declared attack goal.  The best episode is selected by
(goals\_reached, nodes\_owned, cumulative\_reward) in lexicographic order.
"""
