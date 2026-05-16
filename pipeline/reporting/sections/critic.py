import json
import re as _re
from pathlib import Path
from ..latex_base import e


def _e_md(text: str) -> str:
    """Escape text for LaTeX, converting **bold** markdown to \\textbf{}."""
    parts = _re.split(r'\*\*(.*?)\*\*', text)
    result = []
    for i, part in enumerate(parts):
        if i % 2 == 1:
            result.append(rf"\textbf{{{e(part)}}}")
        else:
            result.append(e(part))
    return "".join(result)


def llm_critic_section(phase2_root: Path, entries: list) -> str:
    """Generate a LaTeX section from llm_critic_response.json files in each domain dir."""
    critic_blocks = ""
    for entry in entries:
        critic_file = phase2_root / entry["name"] / "llm_critic_response.json"
        if not critic_file.exists():
            continue
        try:
            data = json.loads(critic_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        critique = data.get("critique", "").strip()
        if not critique:
            continue
        model_name = data.get("model", "claude-3-5-sonnet")
        usage      = data.get("usage", {})
        in_tok     = usage.get("input_tokens", "?")
        out_tok    = usage.get("output_tokens", "?")

        # Convert markdown to LaTeX, tracking open itemize environments
        tex_lines = []
        in_list   = False

        def _close_list():
            nonlocal in_list
            if in_list:
                tex_lines.append(r"\end{itemize}")
                in_list = False

        def _open_list():
            nonlocal in_list
            if not in_list:
                tex_lines.append(r"\begin{itemize}")
                in_list = True

        for line in critique.splitlines():
            # ### heading -> \subsubsection*
            m3 = _re.match(r'^#{3}\s+(.*)', line)
            m2 = _re.match(r'^#{1,2}\s+(.*)', line)
            if m3:
                _close_list()
                tex_lines.append(rf"\subsubsection*{{{_e_md(m3.group(1))}}}")
                continue
            if m2:
                _close_list()
                tex_lines.append(rf"\textbf{{{_e_md(m2.group(1))}}}\\")
                continue
            # bullet or numbered list item
            is_bullet   = bool(_re.match(r'^\s*[-*]\s+', line))
            is_numbered = bool(_re.match(r'^\s*\d+\.\s+', line))
            if is_bullet or is_numbered:
                _open_list()
                txt = (_re.sub(r'^\s*[-*]\s+', '', line) if is_bullet
                       else _re.sub(r'^\s*\d+\.\s+', '', line))
                tex_lines.append(rf"\item {_e_md(txt)}")
                continue
            # Markdown table row (| col | col |) -> skip separator rows, render as items
            if _re.match(r'^\s*\|', line):
                if _re.match(r'^\s*\|[-:\s|]+\|', line):
                    continue  # skip separator row
                _open_list()
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                tex_lines.append(r"\item " + r" \quad ".join(e(c) for c in cells if c))
                continue
            # blank line -- close any open list, emit paragraph break
            if not line.strip():
                _close_list()
                tex_lines.append("")
                continue
            # plain paragraph
            _close_list()
            tex_lines.append(_e_md(line))

        _close_list()
        body_tex = "\n".join(tex_lines)

        critic_blocks += rf"""
\subsection*{{{e(entry['short_name'])}}}
{{\footnotesize \textit{{Model: {e(model_name)} \quad Tokens: {in_tok} in / {out_tok} out}}}}

\begin{{quote}}
{body_tex}
\end{{quote}}
"""

    if not critic_blocks:
        return ""

    return rf"""
\newpage
\subsection{{LLM Critic Evaluation}}

Qualitative assessment produced by Claude (claude-3-5-sonnet) after receiving
all run metrics for each domain. The critic evaluates topological realism,
segmentation health, lateral movement mechanics, and node role distribution,
and provides actionable generator improvement recommendations.
{critic_blocks}
"""


def critic_prompt_appendix(workdir: Path) -> str:
    """Write the LLM critic prompt template to a file and return the LaTeX section."""
    template = r"""You are an expert Cyber Range Architect evaluating a CyberBattleSim domain
configuration for AI security research quality.

## Task
Score this configuration on 6 dimensions (0-10 each). Consider both the YAML
structure and any runtime metrics from actual agent runs.

## Config: {config_name}

```yaml
{DOMAIN YAML CONFIGURATION -- inserted verbatim at evaluation time}
```

==================================================================
  RUNTIME AGENT EVALUATION RESULTS (section present when BFS
  metrics are available; omitted for pure-YAML evaluation)
==================================================================
Heuristic agents (3 agents x 3 episodes/scenario) over N scenarios:

### Episode Outcomes
- Scenarios evaluated    : N
- Scenarios solved       : M/N  (solve_rate%)
- Mean steps (solved)    : <value>
- Mean total reward      : <value>
- Mean nodes owned       : <value>
- Mean creds found       : <value>

### Graph Structure
- Mean node count        : <value>
- Mean edge count        : <value>
- Mean density           : <value>   (target: 0.05-0.40)
- Mean diameter          : <value>   (target: > 3)
- Diameter distribution  : d1=N, d2=N, d3=N, ...
- Mean avg in-degree     : <value>
- Tree ratio             : <value>   (> 2 = mesh-like)
- Topology types         : {type: count, ...}
- Isolated subnets (avg) : <value>
- Routing zones (avg)    : <value>

### Attack Paths
- Mean steps to first goal  : <value>
- Mean steps to final goal  : <value>
- Steps distribution        : min=... p25=... median=... p75=... max=... mean=...
- Mean goals captured ratio : <value>
- Mean nodes owned          : <value>   (% owned: <value>)
- Mean nodes discovered     : <value>   (% disc:  <value>)
- Nodes owned distribution  : min=... median=... max=...

### Credentials
- Mean creds discovered    : <value>
- Mean creds in cache      : <value>
- Mean creds discovered %  : <value>
- Creds distribution       : min=... median=... max=... mean=...

### Vulnerability & Property Distribution
- Mean vuln instances : <value> per scenario
- Mean unique vulns   : <value>
- Mean unique props   : <value>
- Top properties      : {prop: count, ...}

### Firewall Metrics
- Mean rules/node     : <value>
- Firewall coverage   : <value>
- Mean allow rules    : <value>
- Mean block rules    : <value>
- Common allowed ports: SSH, HTTPS, ...

### Agent Action Stats
- Local attack success rate   : <value>
- Remote attack success rate  : <value>
- Port conn success rate      : <value>
- Overall action success rate : <value>

### Action Outcome Totals
  LeakedCredentials=N, LateralMove=N, PrivilegeEscalation=N, ...

### Per-Stratum Breakdown
  small   solved=M/N (rate%)  diameter~D  density=d  nodes~n  steps~s  creds~c  owned~o

Primary difficulty targets (used for scenario_difficulty scoring):
  - Solve rate 40-80% is ideal. < 30% = too hard / unsolvable. > 85% = too easy.
  - Mean steps to first goal > 200 indicates non-trivial attack depth.
  - Mean nodes owned < 50% of total at termination suggests good segmentation.
  - Creds in cache >> creds discovered gap = good credential decay (hard).

NOTE: 0% local/remote attack success rates are NORMAL and do NOT indicate a broken
scenario. CyberBattleSim agents navigate primarily via credential leaks
(LeakedCredentials) and lateral movement (LateralMove). local_attacks_success_rate
and remote_attacks_success_rate only count explicit exploit actions; when agents
move via credentials they do not fire exploits, so these rates are naturally 0%.
Judge difficulty from solve rate, steps, and LateralMove / LeakedCredentials counts.

NOTE on density and diameter: These are computed from the CyberBattleSim firewall
graph which contains wildcard port rules (*) injected by the simulator internals,
making it near-complete regardless of YAML design. Density > 0.40 and diameter <= 3
are EXPECTED and do NOT indicate poor design -- do NOT penalise these values.
==================================================================
  END OF RUNTIME SECTION
==================================================================

## Evaluation Dimensions and Criteria

**1. topology_realism** -- Network Topology Realism
- start_node.subnet must be public (0.0.0.0/0 or 203.0.113.0/24) -- attacker enters from internet
- Internal domain subnets must use RFC 1918 (10.x, 172.16.x, 192.168.x)
- No overlapping subnets between domains
- OS distribution should reflect the domain type (Windows AD => mostly Windows;
  web stack => mostly Linux)
- Multi-domain configs need distinct subnets for each tier (DMZ / App / Data / Core)
- Single-domain configs with many nodes should still have group-level zone separation

**2. vulnerability_realism** -- Properties & Vulnerabilities Realism
- success_rate on non-discovery exploits: realistic range 0.40-0.85 (never 1.0)
- All vulnerabilities must have match_properties (no untargeted exploits)
- Vulnerability names should reference real-world exploits (CVE IDs, named techniques
  like Mimikatz, EternalBlue)
- Both REMOTE and LOCAL vulnerability types needed
- All 4 solvability categories populated: remote_access, credential_leak, discovery,
  goal_access
- Credential leak templates should have realistic individual probabilities (0.15-0.25)

**3. scenario_difficulty** -- Scenario Difficulty
- attack_flow should have >= 4 hops (entry -> service A -> service B -> goal)
- min_credential_leaking_nodes target: 0.10-0.20 (higher values saturate lateral movement)
- Combined credential-leak probability across all templates:
    1 - prod(1 - p_i)  must be <= 0.65
- If runtime metrics available: PRIMARY signals are solve rate 40-80% AND mean steps > 200
- Goal nodes should not be directly reachable from the entry node in one hop
- DO NOT use density or diameter as difficulty signals -- they reflect simulator internals,
  not design quality

**4. firewall_realism** -- Firewall Rules Realism
- No ALL/ANY protocols -- every MUST_CONNECT must name a specific protocol
  (SSH, HTTPS, SMB, etc.)
- No direct DMZ-to-Core/Database access without an App tier intermediary
- Multi-domain configs must define inter_domain_constraints between tiers
- Deny-by-default philosophy: only needed flows should be explicitly permitted
- Intra-domain groups should have controlled connectivity (not fully open)

**5. general_realism** -- General Realism
- Service and group names must be descriptive and match the domain type
  (e.g. NginxProxy, DomainController)
- Goal services must have value >= 1000 (reflects asset criticality for DRL reward shaping)
- attack_flow must include goal service(s) as final targets
- Probe vulnerabilities should be defined for OS fingerprinting realism
- The scenario must tell a coherent, realistic attack story (does the attacker
  motivation make sense?)
- Credential chain should be realistic for the network type (e.g. AD => pass-the-hash;
  web stack => wp-config.php)

**6. cve_grounding** -- CVE Grounding
- >= 50% of vulnerabilities should reference a CVE ID in name or description
- success_rate values should look formula-derived: not round 0.05 multiples
  (0.50, 0.60, 0.70 are suspicious)
- match_properties should include CVE-backed properties: GoRuntime, LibCrypto,
  ImageMagick, MySQL, Redis, WordPressInstall, SMBv1, PrintSpooler, DomainController,
  etc.
- Both Windows CVEs (EternalBlue, BlueKeep, PrintNightmare) and Linux CVEs for
  mixed environments

## Response Format (STRICT -- one block per dimension, then overall)

DIMENSION: topology_realism
SCORE: <0-10>
FINDINGS:
[PASS] <finding text>
[WARN] <finding text>
[FAIL] <finding text>

DIMENSION: vulnerability_realism
SCORE: <0-10>
FINDINGS:
[PASS/WARN/FAIL] <finding>
...

DIMENSION: scenario_difficulty
SCORE: <0-10>
FINDINGS: ...

DIMENSION: firewall_realism
SCORE: <0-10>
FINDINGS: ...

DIMENSION: general_realism
SCORE: <0-10>
FINDINGS: ...

DIMENSION: cve_grounding
SCORE: <0-10>
FINDINGS: ...

OVERALL: <X.X>
SUMMARY: <2-3 sentences on the scenario's overall realism and attack coherence>
"""
    prompt_file = workdir / "llm_critic_prompt_template.txt"
    prompt_file.write_text(template, encoding="utf-8")

    return r"""
\clearpage
\section*{Appendix: LLM Quality Critic Prompt}
\addcontentsline{toc}{section}{Appendix: LLM Quality Critic Prompt}

This appendix reproduces the prompt template sent to the LLM critic
(\texttt{ScenarioQualityEvaluator} in \texttt{tools/scenario\_quality\_evaluator.py})
during Phase~2 evaluation.  The prompt is issued once per actor-critic round after
heuristic BFS agent evaluation completes.  Two dynamic sections are inserted at
runtime: the full domain YAML configuration and, when available, the aggregated BFS
runtime metrics (solve rate, graph statistics, attack path distribution, credential
counts, action outcomes, and per-stratum breakdowns).  The static evaluation
criteria and response format shown below are identical for every invocation.

The model used is \texttt{claude-3-5-sonnet-20241022} (with \texttt{gemini-2.0-flash} as fallback) with \texttt{max\_tokens=2048}.
Parsed output (per-dimension score + \texttt{[PASS]/[WARN]/[FAIL]} findings)
drives both the score gate (Section~2, Phase~2 step~3) and the actor's targeted
repair prompt.

\bigskip
\lstinputlisting[
  basicstyle=\tiny\ttfamily,
  breaklines=true,
  breakatwhitespace=false,
  frame=single,
  framesep=4pt,
  xleftmargin=4pt,
  xrightmargin=4pt,
  numbers=left,
  numberstyle=\tiny\color{gray},
  numbersep=6pt,
  keepspaces=true,
  columns=fullflexible,
  captionpos=b,
  caption={LLM Quality Critic Prompt Template (\texttt{scenario\_quality\_evaluator.py})}
]{llm_critic_prompt_template.txt}
"""
