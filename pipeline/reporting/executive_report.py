#!/usr/bin/env python3
"""
tools/generate_executive_report.py
====================================
Thin orchestrator: collect data → call section functions → compile PDFs.

Outputs
-------
  <output>                               — combined executive_report.pdf
  <output_parent>/sections/             — standalone PDF + TEX per section
  <output_parent>/detailed_report.pdf   — merged per-scenario PDFs (if available)

Usage
-----
python tools/generate_executive_report.py \\
    --phase2-root /path/to/phase2 \\
    --configs-root /path/to/configs \\
    --output /path/to/reports/executive_report.pdf \\
    --title "CyberBattleSim Scenario Dataset"
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

import matplotlib
matplotlib.use("Agg")
import yaml

# ── Package path setup ───────────────────────────────────────────────────────
TOOLS_DIR = Path(__file__).resolve().parent        # pipeline/reporting/
REPO_ROOT = TOOLS_DIR.parent.parent                # repository root
sys.path.insert(0, str(TOOLS_DIR))
sys.path.insert(0, str(TOOLS_DIR.parent))          # pipeline/ → allows `from reporting.xxx`

from reporting.latex_base import e, slug                                    # noqa: E402
from reporting.section_compiler import compile_section, compile_full_report # noqa: E402
from reporting.visual_utils import save_summary_bars                        # noqa: E402

try:
    from generate_schema_diagram import generate_schema_diagram              # noqa: E402
    _HAS_SCHEMA_GEN = True
except ImportError:
    _HAS_SCHEMA_GEN = False

# Ensure repo root is in path for consolidated packages
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ── Section imports ──────────────────────────────────────────────────────────
from pipeline.reporting.sections.summary    import cover_page                        # noqa: E402
from pipeline.reporting.sections.scenarios  import scenario_pages                   # noqa: E402
from pipeline.reporting.sections.topology   import (                                 # noqa: E402
    outcomes_and_topology_section,
    diversity_metrics_section,
)
from pipeline.reporting.sections.attack_paths import (                               # noqa: E402
    attack_path_section,
    graph_statistics_section,
)
from pipeline.reporting.sections.critic     import llm_critic_section               # noqa: E402
from pipeline.reporting.sections.appendices import (                                 # noqa: E402
    quality_appendix,
    methodology_appendix,
    formulas_appendix,
    reproducibility_sys_section,
)
from pipeline.reporting.sections.vulnerability import properties_vulns_section      # noqa: E402
from pipeline.reporting.sections.services     import services_credentials_section   # noqa: E402
from pipeline.reporting.sections.ablation     import ablation_section               # noqa: E402
from pipeline.reporting.sections.discussion   import discussion_section             # noqa: E402
from pipeline.reporting.sections.prompts      import llm_generation_prompt_appendix  # noqa: E402
from pipeline.reporting.sections.critic       import critic_prompt_appendix          # noqa: E402
from pipeline.reporting.sections.eda          import cve_eda_section                 # noqa: E402
from pipeline.reporting.sections.agent_design import agent_design_section             # noqa: E402

try:
    from pipeline.quality_evaluator import ScenarioQualityEvaluator         # noqa: E402
    _HAS_EVALUATOR = True
except ImportError:
    _HAS_EVALUATOR = False


# ─────────────────────────────────────────────────────────────────────────────
# Inline helper sections  (ported from monolithic build_report)
# ─────────────────────────────────────────────────────────────────────────────

def _methodology_inline() -> str:
    """Inline Q&A methodology section (fallback if methodology.tex is absent)."""
    return r"""
\newpage
\section{How Scenarios Are Generated \& What They Represent}

\subsection*{Q1 --- What does each node represent?}

Each node represents an \textbf{individual host} (VM, container, or physical server).
Hosts of the same \emph{service archetype} are grouped in the same subnet.
Within a group all hosts share the same vulnerability profile and property tags.
The generator creates between \texttt{min\_count} and \texttt{max\_count} instances
per group per episode, so total node count varies across episodes.

\subsection*{Q2 --- Network diversity: service types, roles, and OS mix}

\begin{itemize}
  \item \textbf{Service archetypes} --- each config declares distinct service types.
  \item \textbf{OS heterogeneity} --- configs can mix Windows and Linux nodes.
  \item \textbf{Node role diversity} --- properties such as \texttt{DomainController},
        \texttt{WebServer}, \texttt{DatabaseServer} control which exploits apply.
  \item \textbf{Strata} --- \emph{small}, \emph{medium}, and \emph{large} strata
        scale group instance counts while preserving topology structure.
\end{itemize}

\subsection*{Q3 --- How is connectivity controlled?}

\begin{center}
\begin{tabular}{lll}
\toprule
\textbf{Relation} & \textbf{Effect} & \textbf{Purpose} \\
\midrule
\texttt{MUST\_CONNECT}            & One-way firewall rule on a specific protocol & Reachable lateral-movement paths \\
\texttt{MUST\_REACH}              & Opens all ports from source to target         & Unrestricted reachability \\
\texttt{LEAK\_KNOWN\_CREDENTIALS} & Seeds credentials from source to target (prob.) & Credential-reuse attacks \\
\texttt{CLIENT\_OF}               & Alias for LEAK\_KNOWN\_CREDENTIALS            & Privileged-service credential flows \\
\bottomrule
\end{tabular}
\end{center}
"""


def _related_work_inline() -> str:
    _SYSTEMS = [
        ("gym-NASim",        "2018", "YAML params + random host config",          "None",    "None",                    r"up to 500 hosts"),
        ("ASAP",             "2020", "Real Nmap scanning + attack graph",          "Partial", "Real network execution",  r"\textasciitilde{}300 hosts"),
        ("AutoPentest-DRL",  "2020", "Nmap + MulVAL attack graphs",               "Partial", "Real network execution",  "Small real nets"),
        ("CyGIL",            "2021", "MITRE ATT\\&CK APT templates",               "None",    "Design-based review",     "Unspecified"),
        ("FARLAND",          "2021", "Topology + complexity gradation",            "None",    "RL performance proxy",    "RLLib-scalable"),
        ("CSLE",             "2022", "Linux container emulation",                  "None",    "Partial (CI/CD)",         "Laptop to cluster"),
        ("Yawning Titan",    "2022", "Settings file + topology graph",             "None",    "Scenario progression",    "Small--large (abstract)"),
        ("NASimEmu",         "2023", "Static + random + dynamic (NASim core)",     "None",    "Sim-to-emul.\ transfer",  "Flexible"),
        ("CybORG++",         "2024", r"YAML parser $\rightarrow$ simulator",        "None",    "CAGE benchmark",          "Enterprise (abstract)"),
        ("PenGym",           "2024", "Template-driven cyber range",                "Partial", "Real execution",          "Real networks"),
        ("Cyberwheel",       "2024", "Config-driven (sim + QEMU emulation)",       "None",    "Deception case study",    "100K+ nodes (emulation)"),
        ("CAGE Challenge 4", "2025", "Fixed YAML enterprise topology",             "None",    "MARL competition",        "Multi-zone enterprise"),
        ("C-CyberBattleSim", "2025", "Shodan + NVD data + domain randomisation",   "Partial", "Agent generalisation",    "Scalable (complexity split)"),
    ]
    rows = ""
    for name, year, gen, cve, solv, scale in _SYSTEMS:
        rows += f"  {name} & {year} & {gen} & {cve} & {solv} & {scale} \\\\\n"
    rows += (r"  \midrule" + "\n"
             r"  \textbf{This Work} & \textbf{2025} & LLM (Claude Sonnet) + MCP server "
             r"& \textbf{Full (CVSS formula)} & \textbf{BFS solvability + LLM quality} "
             r"& \textbf{30--250 nodes, 8+ domains} \\" + "\n")
    return r"""
\clearpage
\section*{Related Work: Comparison to Prior RL Cyber-Range Frameworks}
\addcontentsline{toc}{section}{Related Work: Comparison to Prior Frameworks}

\begin{table}[H]
\centering\small\setlength{\tabcolsep}{4pt}
\begin{tabular}{llp{4.2cm}p{2.4cm}p{3.2cm}p{2.8cm}}
\toprule
\textbf{System} & \textbf{Year} & \textbf{Generation Method} & \textbf{CVE Grounding} & \textbf{Solvability Validation} & \textbf{Scale} \\
\midrule
""" + rows + r"""\bottomrule
\end{tabular}
\caption*{Comparison of scenario generation methods across prior frameworks.}
\end{table}
"""


def _ethics_inline() -> str:
    return r"""
\clearpage
\section*{Ethical Considerations \& Responsible Disclosure}
\addcontentsline{toc}{section}{Ethical Considerations}

\subsection*{Dual-Use Considerations}

Generating realistic attack scenarios raises legitimate dual-use concerns.
The following safeguards are built into the pipeline:

\begin{itemize}
  \item \textbf{Purely simulated environments.}  No real systems, networks, or
        infrastructure are accessed at any stage.
  \item \textbf{Publicly available CVE data only.}  The vulnerability catalog draws
        exclusively from NVD and Trivy public feeds.  No zero-day exploits are included.
  \item \textbf{No working exploit code.}  Entries encode only statistical properties
        of CVEs; they do not contain proof-of-concept code or exploitation instructions.
  \item \textbf{Defensive RL research intent.}  Designed for training blue-team RL
        agents; not intended as an attacker training tool.
  \item \textbf{No personally identifiable information.}  All node names and
        credential strings are synthetic.
\end{itemize}
"""


def _open_source_inline() -> str:
    return r"""
\clearpage
\section*{Reproducibility Package \& Open-Source Statement}
\addcontentsline{toc}{section}{Reproducibility Package}

\subsection*{Released Artefacts}

\begin{table}[H]
\centering\small\setlength{\tabcolsep}{5pt}
\begin{tabular}{p{5cm}p{5.5cm}p{6cm}}
\toprule
\textbf{Artefact} & \textbf{Location} & \textbf{Description} \\
\midrule
Domain config YAMLs     & \texttt{data/*.yaml}                                & All generated domain configurations \\
CVE database — Bitnami  & \texttt{data/vulnerability\_db/bitnami\_cves.json}  & Bitnami Helm-chart CVEs \\
CVE database — Windows  & \texttt{data/vulnerability\_db/windows\_cves.json}  & Windows CVEs \\
CVE database — SCADA    & \texttt{data/vulnerability\_db/scada\_cves.json}    & ICS/SCADA CVEs \\
CVE database — NetDev   & \texttt{data/vulnerability\_db/network\_devices\_cves.json} & Network device CVEs \\
Generation pipeline     & \texttt{cbsim/}, \texttt{cli.py}, \texttt{tools/}  & Full Python source \\
MCP server              & \texttt{mcp\_server/}                               & LLM tool server for Phase~1 \\
Prompt stack            & \texttt{prompts/}                                   & System prompt + schema + catalogs \\
BFS evaluator           & \texttt{tools/test\_env\_integration.py}            & Solvability planner agent \\
Dataset generator       & \texttt{tools/generate\_dataset.py}                 & BFS-verified stratified generator \\
Quality evaluator       & \texttt{tools/scenario\_quality\_evaluator.py}      & LLM multi-dimension quality scorer \\
\bottomrule
\end{tabular}
\caption*{Released artefacts in the supplementary material.}
\end{table}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Data collection helpers
# ─────────────────────────────────────────────────────────────────────────────

_OUTCOME_KEYS = [
    "LeakedCredentials", "LeakedNodesId", "LateralMove",
    "PrivilegeEscalation", "AdminEscalation", "SystemEscalation",
    "ProbeSucceeded", "ExploitFailed",
]


def _collect_run_metrics(scenario_dir: Path) -> list:
    metrics = []
    for p in sorted(scenario_dir.rglob("run_metrics.json")):
        try:
            metrics.append(json.loads(p.read_text()))
        except Exception:
            pass
    return metrics


def _aggregate_metrics(metrics: list) -> dict:
    if not metrics:
        return {}
    solved = [m for m in metrics if m.get("is_solved")]
    n = len(metrics)

    def _t(m, k):
        return m.get("topology_metrics", {}).get("routing", {}).get(k, 0)

    outcome_totals: dict = {k: 0 for k in _OUTCOME_KEYS}
    for m in metrics:
        for k in _OUTCOME_KEYS:
            outcome_totals[k] += m.get("action_outcomes", {}).get(k, 0)

    avg_nodes   = sum(_t(m, "node_count") for m in metrics) / n
    avg_density = sum(_t(m, "density")    for m in metrics) / n
    tree_ratio  = round(avg_density * max(avg_nodes, 2), 2)

    return {
        "total":           n,
        "solved":          len(solved),
        "solve_rate":      round(len(solved) / n, 3),
        "mean_steps":      round(sum(m.get("steps_taken",  0) for m in solved) / max(len(solved), 1)),
        "mean_reward":     round(sum(m.get("total_reward", 0) for m in metrics) / n, 1),
        "mean_nodes":      round(sum(m.get("nodes_owned",  0) for m in metrics) / n, 1),
        "mean_creds":      round(sum(m.get("credentials_discovered", 0) for m in metrics) / n, 1),
        "mean_density":    round(avg_density, 4),
        "mean_diameter":   round(sum(_t(m, "diameter")   for m in metrics) / n, 1),
        "mean_node_count": round(avg_nodes, 1),
        "tree_ratio":      tree_ratio,
        "outcome_totals":  outcome_totals,
    }


def _find_config(scenario_dir: Path, configs_roots: list) -> "Path | None":
    name = scenario_dir.name
    base = re.sub(r"_v\d+$", "", name)
    for root in configs_roots:
        for stem in (name, base, f"{base}_v1"):
            for ext in (".yaml", ".yml"):
                c = root / (stem + ext)
                if c.exists():
                    return c
    return None


def _merge_progression(raw_lines: list) -> list:
    step_re  = re.compile(r"^\d+[\.\)]\s+")
    label_re = re.compile(r"^\w[\w\s]{0,15}:\s+")
    steps, current = [], None
    for line in raw_lines:
        if step_re.match(line):
            if current is not None:
                steps.append(current)
            text = step_re.sub("", line).strip()
            text = label_re.sub("", text).strip()
            current = text
        else:
            if current is not None:
                current = current + " " + line.strip()
    if current:
        steps.append(current)
    return steps if steps else raw_lines


def _extract_yaml_header(config_path: Path) -> dict:
    """Extract the top =====...===== comment block: title, agent, zones, goal, nodes."""
    lines  = config_path.read_text(encoding="utf-8").splitlines()
    result = {"title": "", "agent": "", "zones": "", "goal": "", "nodes": "",
              "raw_header": ""}
    in_block, raw_lines = False, []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("# ==="):
            if not in_block:
                in_block = True
                continue
            else:
                break   # closing ===
        if not in_block:
            continue
        stripped = stripped.lstrip("# ").strip()
        if not stripped or stripped.startswith("="):
            continue
        raw_lines.append(stripped)
        low = stripped.lower()
        if ":" in stripped:
            key, _, val = stripped.partition(":")
            val = val.strip()
            k = key.strip().lower()
            if k in ("agent",):               result["agent"]  = val
            elif "zone" in k:                 result["zones"]  = val
            elif "terminal" in k or "goal" in k: result["goal"] = val
            elif "node" in k:                 result["nodes"]  = val
            elif not result["title"]:
                result["title"] = stripped    # first key:value line is the title
    result["raw_header"] = "\n".join(raw_lines)
    return result


def _extract_yaml_description(config_path: Path) -> dict:
    lines  = config_path.read_text(encoding="utf-8").splitlines()
    result = {"overview": "", "progression": [], "name": config_path.stem}
    section, buf = None, []
    for line in lines:
        stripped = line.strip().lstrip("#").strip()
        if "SCENARIO OVERVIEW" in line:
            section = "overview";     buf = []; continue
        if "ATTACKER PROGRESSION" in line:
            if section == "overview":
                result["overview"] = " ".join(buf).strip()
            section = "progression";  buf = []; continue
        if ("DESIGN DECISIONS" in line or "NETWORK ARCHITECTURE" in line
                or "FIREWALL RULES" in line
                or (line.startswith("config:") and section)):
            if section == "overview":
                result["overview"] = " ".join(buf).strip()
            elif section == "progression":
                result["progression"] = _merge_progression([l for l in buf if l])
            section = None
            if line.startswith("config:"):
                break
            continue
        if section and stripped and not stripped.startswith("="):
            buf.append(stripped)
    if section == "progression" and buf:
        result["progression"] = _merge_progression([l for l in buf if l])
    if not result["overview"]:
        for line in lines[:10]:
            s = line.strip().lstrip("#").strip()
            if s and not s.startswith("=") and len(s) > 20:
                result["overview"] = s;  break
    return result


def _extract_diversity_metrics(config_path: Path) -> dict:
    try:
        cfg = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    groups, n_connect, n_leak = [], 0, 0
    n_domains = len(cfg.get("domains", []))
    for domain in cfg.get("domains", []):
        groups += domain.get("groups", [])
        for c in domain.get("constraints", []):
            rel = c.get("relation", "").upper()
            if rel in ("MUST_CONNECT", "MUST_REACH", "CLIENT_OF"):  n_connect += 1
            if rel in ("LEAK_KNOWN_CREDENTIALS", "CLIENT_OF"):       n_leak    += 1
    for idc in cfg.get("inter_domain_constraints", []):
        for c in idc.get("constraints", []):
            rel = c.get("relation", "").upper()
            if rel in ("MUST_CONNECT", "MUST_REACH", "CLIENT_OF"):  n_connect += 1
            if rel in ("LEAK_KNOWN_CREDENTIALS", "CLIENT_OF"):       n_leak    += 1
    services = cfg.get("services", {})
    os_types, roles = set(), set()
    for svc in services.values():
        for p in svc.get("default_properties", []):
            if p in {"Windows", "Linux", "MacOS"}:              os_types.add(p)
            if p in {"Workstation", "FileServer", "AppServer",
                     "DomainController", "WebServer", "DatabaseServer",
                     "LegacyWorkstation", "ModernWorkstation"}:  roles.add(p)
    return {
        "n_service_types": len(services),
        "n_groups":        len(groups),
        "n_domains":       n_domains,
        "n_must_connect":  n_connect,
        "n_cred_paths":    n_leak,
        "os_types":        sorted(os_types),
        "node_roles":      sorted(roles),
        "goal_services":   [n for n, s in services.items() if s.get("is_goal")],
        "group_summary":   [{"name": g.get("name", "?"), "service": g.get("service", "?"),
                              "min": g.get("min_count", 0), "max": g.get("max_count", 0)}
                             for g in groups],
        "heterogeneous_os": len(os_types) > 1,
    }


def _find_topology_png(scenario_dir: Path) -> "Path | None":
    for split in ("train", "test"):
        for pat in ("graphs/subnet_topology.png", "graphs/compact_subnet_topology.png"):
            for p in sorted((scenario_dir / split).rglob(pat)):
                if p.exists() and p.stat().st_size > 0:
                    return p
    sg = scenario_dir / "scenario_graphs"
    if sg.is_dir():
        pngs = [p for p in sorted(sg.glob("*.png")) if p.stat().st_size > 0]
        if pngs:
            return pngs[0]
    return None


def _find_scenario_graph_pngs(scenario_dir: Path) -> dict:
    wanted = [
        ("attack_paths.png",            "attack_paths"),
        ("network_graph.png",           "network_graph"),
        ("compact_subnet_topology.png", "compact_subnet"),
        ("subnet_topology.png",         "subnet_topology"),
    ]
    result: dict = {}
    for split in ("train", "test"):
        split_dir = scenario_dir / split
        if not split_dir.is_dir():
            continue
        for graphs_dir in sorted(split_dir.rglob("graphs")):
            for fname, key in wanted:
                if key in result:
                    continue
                p = graphs_dir / fname
                if p.exists() and p.stat().st_size > 0:
                    result[key] = p
        if result:
            break
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Entry data collection
# ─────────────────────────────────────────────────────────────────────────────

def _load_zone_manifest(repo_root: Path) -> dict:
    """Return {config_name: {specialist, description}} from zone_manifest.yaml."""
    manifest_path = repo_root / "data" / "zone_manifest.yaml"
    if not manifest_path.exists():
        return {}
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        return raw.get("configs", {}) or {}
    except Exception:
        return {}


def build_entries(phase2_root: Path, configs_roots: list, fast: bool = False) -> list:
    """Discover scenario dirs, load metrics/quality/config, return entries list."""
    from reporting.data_utils import collect_scenario_stats, collect_attack_path_stats
    _zone_manifest = _load_zone_manifest(REPO_ROOT)

    scenario_dirs = sorted(
        d for d in phase2_root.iterdir()
        if d.is_dir() and (d / "manifest.json").exists()
    )
    if not scenario_dirs:
        print(f"No scenarios found under {phase2_root}")
        return []

    # Deduplicate: keep only highest version for each base name
    _ver_re = re.compile(r'^(.+?)(?:_v(\d+))?$')
    _latest: dict = {}
    for d in scenario_dirs:
        m    = _ver_re.match(d.name)
        base = m.group(1) if m else d.name
        ver  = int(m.group(2)) if m and m.group(2) else 0
        if base not in _latest or ver > _latest[base][1]:
            _latest[base] = (d, ver)
    deduped = sorted(v[0] for v in _latest.values())
    skipped = [d.name for d in scenario_dirs if d not in deduped]
    if skipped:
        print(f"  Deduplication: skipping older versions: {skipped}")
    scenario_dirs = deduped

    print(f"Found {len(scenario_dirs)} scenario(s): " + ", ".join(d.name for d in scenario_dirs))

    entries = []
    for sd in scenario_dirs:
        print(f"\n  Processing: {sd.name}")
        entry: dict = {
            "name":               sd.name,
            "short_name":         re.sub(r"_v\d+$", "", sd.name).replace("_", " ").title(),
            "arch_type":          "Single Domain",
            "agg":                {},
            "dim_scores":         {},
            "p1_score":           0.0,
            "p1_grade":           "?",
            "desc":               {},
            "diversity":          {},
            "generation_request": "",
            "yaml_header":        {},
        }

        # ── BFS metrics ────────────────────────────────────────────────────────
        bfs_cache = sd / "bfs_metrics.json"
        if bfs_cache.exists():
            try:
                entry["agg"] = json.loads(bfs_cache.read_text(encoding="utf-8"))
                print(f"    Metrics: {entry['agg'].get('solved')}/{entry['agg'].get('total')} solved  (cached)")
            except Exception as exc:
                print(f"    [WARN] bfs_metrics.json unreadable: {exc}")
        if not entry["agg"]:
            raw = _collect_run_metrics(sd)
            if raw:
                entry["agg"] = _aggregate_metrics(raw)
                print(f"    Metrics: {entry['agg'].get('solved')}/{entry['agg'].get('total')} solved")

        # ── Quality scores ─────────────────────────────────────────────────────
        quality_cache = sd / "quality_evaluation.json"
        cfg_path = _find_config(sd, configs_roots)
        cfg = None
        if quality_cache.exists():
            try:
                result = json.loads(quality_cache.read_text(encoding="utf-8"))
                entry["p1_score"] = result.get("overall_score", 0)
                entry["p1_grade"] = result.get("overall_grade", "?")
                entry["dim_scores"] = {
                    k: {"score": v.get("score", 0), "grade": v.get("grade", "?")}
                    for k, v in result.get("dimensions", {}).items()
                }
                print(f"    Quality: {entry['p1_score']:.1f}/10 ({entry['p1_grade']})  (cached)")
            except Exception as exc:
                print(f"    [WARN] quality_evaluation.json unreadable: {exc}")

        if cfg_path:
            print(f"    Config : {cfg_path.name}")
            try:
                cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
                domains = cfg.get("domains", [])
                if isinstance(domains, list) and len(domains) > 1:
                    entry["arch_type"] = f"Multi-Domain ({len(domains)} tiers)"
                if not entry["p1_score"] and _HAS_EVALUATOR:
                    agg = entry.get("agg", {})
                    graph_metrics = {
                        "density":     agg.get("mean_density",    0),
                        "diameter":    agg.get("mean_diameter",   0),
                        "node_count":  agg.get("mean_node_count", 0),
                        "solve_rate":  agg.get("solve_rate",      0),
                        "n_scenarios": agg.get("total",           0),
                    } if agg else {}
                    ev     = ScenarioQualityEvaluator(cfg, config_name=cfg_path.stem)
                    result = ev.evaluate_with_llm(graph_metrics=graph_metrics or None)
                    entry["p1_score"] = result.get("overall_score", 0)
                    entry["p1_grade"] = result.get("overall_grade", "?")
                    entry["dim_scores"] = {
                        k: {"score": v.get("score", 0), "grade": v.get("grade", "?")}
                        for k, v in result.get("dimensions", {}).items()
                    }
                    print(f"    Quality: {entry['p1_score']:.1f}/10 ({entry['p1_grade']})")
            except Exception as exc:
                print(f"    [WARN] Quality eval failed: {exc}")
            entry["desc"]       = _extract_yaml_description(cfg_path)
            entry["diversity"]  = _extract_diversity_metrics(cfg_path)
            entry["yaml_header"] = _extract_yaml_header(cfg_path)
            if cfg is not None:
                entry["_config"] = cfg
        else:
            print(f"    [WARN] Config YAML not found for {sd.name}")

        # ── Schema architecture diagram ────────────────────────────────────────
        entry["schema_diagram"] = None
        if cfg_path and _HAS_SCHEMA_GEN:
            schema_png = sd / "schema_diagram.png"
            if not schema_png.exists():
                try:
                    ok = generate_schema_diagram(cfg_path, schema_png,
                                                 title=entry["short_name"])
                    if ok:
                        print(f"    Schema diagram: generated")
                    else:
                        print(f"    [WARN] Schema diagram generation returned False")
                except Exception as exc:
                    print(f"    [WARN] Schema diagram failed: {exc}")
            if schema_png.exists():
                entry["schema_diagram"] = schema_png

        # ── Generation request (user prompt) ──────────────────────────────────
        user_prompt_file = sd / "user_prompt.txt"
        if user_prompt_file.exists():
            entry["generation_request"] = user_prompt_file.read_text(encoding="utf-8").strip()
        else:
            # Fall back to zone manifest description + specialist label
            manifest_entry = _zone_manifest.get(sd.name, {})
            specialist = manifest_entry.get("specialist", "")
            description = manifest_entry.get("description", "")
            if specialist or description:
                parts = [p for p in [specialist, description] if p]
                entry["generation_request"] = " — ".join(parts)

        entry["topo_graph"]   = _find_topology_png(sd)
        entry["graph_pngs"]   = _find_scenario_graph_pngs(sd)

        print(f"    Sample stats: collecting...")
        entry["sample_stats"] = collect_scenario_stats(sd)

        if fast:
            entry["attack_path_stats"] = {}
            print(f"    Attack paths: skipped (--fast)")
        else:
            print(f"    Attack paths: collecting BFS path metrics...")
            entry["attack_path_stats"] = collect_attack_path_stats(sd)
            aps = entry["attack_path_stats"]
            if aps.get("n_samples"):
                print(f"      {aps['n_samples']} instances evaluated  "
                      f"avg_hops={aps.get('avg_hops', {}).get('mean', '?')}  "
                      f"avg_p_success={aps.get('avg_success_prob', {}).get('mean', '?')}")

        entries.append(entry)

    return entries


# ─────────────────────────────────────────────────────────────────────────────
# Merged detailed report helper
# ─────────────────────────────────────────────────────────────────────────────

def _build_merged_detailed_report(phase2_root: Path, entries: list,
                                   executive_output: Path) -> None:
    """Merge pre-existing per-scenario phase2_report.pdf files into detailed_report.pdf."""
    pdfs_to_merge = []
    for entry in entries:
        sd  = phase2_root / entry["name"]
        pdf = sd / "phase2_report.pdf"
        if not pdf.exists():
            # Try to generate it from phase2_report.txt + figures
            report_txt  = sd / "phase2_report.txt"
            figures_dir = sd / "figures"
            if report_txt.exists():
                try:
                    from phase2_human_report import _generate_pdf  # noqa
                    saved_plots = [
                        (p.stem.replace("_", " ").title(), p)
                        for p in sorted(figures_dir.glob("*.png"))
                    ] if figures_dir.is_dir() else []
                    _generate_pdf(report_txt, figures_dir, saved_plots,
                                  phase1_report_path=None)
                    if pdf.exists():
                        print(f"  Generated detailed PDF: {pdf}")
                except Exception as exc:
                    print(f"  [WARN] Could not generate detailed PDF for {entry['name']}: {exc}")
        if pdf.exists():
            pdfs_to_merge.append(pdf)

    if not pdfs_to_merge:
        print("  [WARN] No per-scenario PDFs found — detailed report skipped")
        return

    merged_path = executive_output.parent / "detailed_report.pdf"
    result = subprocess.run(
        ["pdfunite"] + [str(p) for p in pdfs_to_merge] + [str(merged_path)],
        capture_output=True,
    )
    if result.returncode == 0 and merged_path.exists():
        print(f"  Detailed report saved: {merged_path}  ({len(pdfs_to_merge)} scenarios)")
    else:
        print(f"  [WARN] pdfunite failed: {result.stderr.decode()[:200]}")


# ─────────────────────────────────────────────────────────────────────────────
# Main report builder
# ─────────────────────────────────────────────────────────────────────────────

def build_report(phase2_root: Path, configs_roots: list,
                 output: Path, title: str, fast: bool = False) -> None:

    entries = build_entries(phase2_root, configs_roots, fast=fast)
    if not entries:
        print("No entries — aborting.")
        sys.exit(1)

    date_str  = datetime.now().strftime("%d %B %Y")
    repo_root = REPO_ROOT  # noqa: F841 — used by section builders below

    with tempfile.TemporaryDirectory() as _tmp:
        workdir = Path(_tmp)

        # ── Pre-compile figures that feed multiple sections ───────────────────
        print("\n  Generating summary chart...")
        summary_pdf = workdir / "summary_bars.pdf"
        try:
            save_summary_bars(entries, summary_pdf)
        except Exception as exc:
            print(f"  [WARN] summary_bars failed: {exc}")

        # ── Build each section content ────────────────────────────────────────
        print("  Building sections...")

        # 01 — Cover + overview
        s01 = (
            cover_page(title, entries, date_str)
            + r"\tableofcontents" + "\n"
            + r"\newpage" + "\n"
            + _overview_full(entries, summary_pdf)
        )

        # 02 — Methodology Q&A (inline; methodology.tex is appended later)
        s02 = _methodology_inline()

        # 03 — Individual scenario pages
        print("    scenarios...")

        # Copy ref.png to workdir so it can be \includegraphics'd
        _ref_src = REPO_ROOT / "prompts" / "schema" / "topology.png"
        _ref_block = ""
        if _ref_src.exists():
            import shutil as _shutil
            _ref_dst = workdir / "globaltech_ref.png"
            _shutil.copy(_ref_src, _ref_dst)
            _ref_block = (
                "\\begin{figure}[H]\\centering\n"
                "\\includegraphics[width=\\linewidth,height=0.55\\textheight,keepaspectratio]{globaltech_ref.png}\n"
                "\\caption{GLOBALTECH Enterprise Network Reference Architecture. "
                "All scenarios are derived from one or more zones of this topology.}\n"
                "\\label{fig:globaltech_ref}\n"
                "\\end{figure}\n"
                "\\vspace{0.3cm}\n"
            )

        s03 = (
            "\n\\clearpage\n"
            "\\section{Scenarios}\n"
            "\\label{sec:scenarios}\n"
            "\\noindent\n"
            "All scenarios in this dataset were generated from a single, unified reference architecture: the\n"
            "\\textbf{GLOBALTECH Enterprise Network} (Figure~\\ref{fig:globaltech_ref}). "
            "GLOBALTECH is a multi-site enterprise comprising\n"
            "eight named zones --- Corporate HQ VLANs~(Z1), HQ Edge~(Z2), Internet~(Z3), Internet\n"
            "Edge~(Z4), Branch Office~(Z5), AWS Public Cloud~(Z6), Remote Users~(Z7), and Key\n"
            "Management~(Z8) --- each with a fixed set of service archetypes, subnet addresses, and\n"
            "inter-zone firewall rules.\n"
            "\n"
            "\\smallskip\n"
            "\\noindent\n"
            "Each scenario targets one or more of these zones. The \\textbf{Network Architecture}\n"
            "diagram shown at the top of every scenario page is a \\emph{zone-level schematic} derived\n"
            "directly from the scenario's YAML configuration: it shows which GLOBALTECH zones are in\n"
            "scope, the service archetypes present in each zone, and the count range\n"
            "(\\textit{min}--\\textit{max} instances per episode) for every group. Attack-flow arrows\n"
            "indicate the intended lateral-movement path through the network.\n"
            "\\vspace{0.3cm}\n"
            + _ref_block
            + scenario_pages(entries, workdir)
        )

        # 03b — Agent design
        print("    agent design...")
        try:
            s03b = agent_design_section(entries)
        except Exception as exc:
            print(f"  [WARN] agent_design_section: {exc}")
            s03b = ""

        # 04 — Cross-scenario analysis
        print("    cross-scenario analysis...")
        s04 = "\n\\clearpage\n\\section{Cross-Scenario Analysis}\n\\label{sec:analysis}\n"

        # 04a — Properties & Vulnerabilities matrix
        print("      properties & vulnerabilities...")
        try:
            s04 += properties_vulns_section(entries, workdir)
        except Exception as exc:
            print(f"  [WARN] properties_vulns_section: {exc}")

        # 04b — Outcomes + topology
        print("      outcomes & topology...")
        try:
            s04 += outcomes_and_topology_section(entries, workdir)
        except Exception as exc:
            print(f"  [WARN] outcomes_and_topology_section: {exc}")

        # 04c — Attack paths
        print("      attack paths...")
        try:
            s04 += attack_path_section(entries, workdir)
        except Exception as exc:
            print(f"  [WARN] attack_path_section: {exc}")

        # 04d — Graph statistics
        print("      graph statistics...")
        try:
            s04 += graph_statistics_section(entries, workdir)
        except Exception as exc:
            print(f"  [WARN] graph_statistics_section: {exc}")

        # 04e — LLM critic evaluation
        print("      LLM critic...")
        try:
            s04 += llm_critic_section(phase2_root, entries)
        except Exception as exc:
            print(f"  [WARN] llm_critic_section: {exc}")

        # 04f — Diversity metrics + MITRE heatmap
        print("      diversity metrics...")
        try:
            s04 += diversity_metrics_section(entries)
        except Exception as exc:
            print(f"  [WARN] diversity_metrics_section: {exc}")

        # 04g — Services & credential flows
        print("      services & credentials...")
        try:
            s04 += services_credentials_section(entries)
        except Exception as exc:
            print(f"  [WARN] services_credentials_section: {exc}")

        # 04h — Ablation study
        try:
            s04 += ablation_section(entries)
        except Exception as exc:
            print(f"  [WARN] ablation_section: {exc}")

        # 05 — CVE EDA
        print("      CVE EDA...")
        try:
            s05 = cve_eda_section()
        except Exception as exc:
            print(f"  [WARN] cve_eda_section: {exc}")
            s05 = ""

        # 06 — Related work
        s06 = _related_work_inline()

        # 07 — Ethics + open source
        s07 = _ethics_inline() + _open_source_inline()

        # 08 — Appendices (methodology.tex, formulas, quality rubric, reproducibility)
        print("      appendices...")
        s08 = ""
        try:
            s08 += methodology_appendix(workdir, repo_root)
        except Exception as exc:
            print(f"  [WARN] methodology_appendix: {exc}")
        try:
            s08 += formulas_appendix(workdir, repo_root)
        except Exception as exc:
            print(f"  [WARN] formulas_appendix: {exc}")
        try:
            s08 += quality_appendix()
        except Exception as exc:
            print(f"  [WARN] quality_appendix: {exc}")
        try:
            s08 += reproducibility_sys_section()
        except Exception as exc:
            print(f"  [WARN] reproducibility_sys_section: {exc}")
        try:
            s08 += discussion_section()
        except Exception as exc:
            print(f"  [WARN] discussion_section: {exc}")

        # 09 — Prompt appendix
        print("      prompt appendix...")
        s09 = ""
        try:
            s09 += llm_generation_prompt_appendix(repo_root, workdir)
        except Exception as exc:
            print(f"  [WARN] llm_generation_prompt_appendix: {exc}")
        try:
            s09 += critic_prompt_appendix(workdir)
        except Exception as exc:
            print(f"  [WARN] critic_prompt_appendix: {exc}")

        # ── Compile individual section PDFs ───────────────────────────────────
        sections_dir = output.parent / "sections"
        print("\n  Compiling section PDFs...")
        _section_list = [
            ("01_overview",         s01),
            ("02_methodology",      s02),
            ("03_scenarios",        s03),
            ("03b_agent_design",    s03b),
            ("04_cross_analysis",   s04),
            ("05_cve_eda",          s05),
            ("06_related_work",     s06),
            ("07_ethics",           s07),
            ("08_appendices",       s08),
            ("09_prompt_appendix",  s09),
        ]
        for sec_name, sec_content in _section_list:
            if sec_content.strip():
                print(f"    Compiling {sec_name}...")
                try:
                    compile_section(sec_name, sec_content, output.parent, workdir)
                except Exception as exc:
                    print(f"  [WARN] compile_section({sec_name}): {exc}")
            else:
                print(f"    Skipping {sec_name} (empty)")

        # ── Compile combined report ───────────────────────────────────────────
        print("\n  Compiling combined executive report (3 pdflatex passes)...")
        non_empty = [(n, c) for n, c in _section_list if c.strip()]
        result_path = compile_full_report(title, non_empty, output, workdir)

        if result_path:
            print(f"\n  Executive report saved: {result_path}")
        else:
            print("\n  ERROR: Combined report compilation failed.")
            # Still save a .tex so the user can debug
            combined_tex = output.with_suffix(".tex")
            print(f"  LaTeX source may be at {combined_tex} (if written by compiler)")

        # ── Merged detailed report ────────────────────────────────────────────
        _build_merged_detailed_report(phase2_root, entries, output)


# ─────────────────────────────────────────────────────────────────────────────
# Overview table (full version with dim scores) — adapted from monolithic
# ─────────────────────────────────────────────────────────────────────────────

_DIM_SHORT = {
    "topology_realism":      "Network Topology",
    "vulnerability_realism": "Vuln Realism",
    "scenario_difficulty":   "Difficulty",
    "firewall_realism":      "Firewall Rules",
    "general_realism":       "General Realism",
    "cve_grounding":         "CVE Grounding",
}
_GRADE_COLOR = {
    "A+": "scoreAplus", "A": "scoreA", "B": "scoreB",
    "C": "scoreC",  "D": "scoreD",  "F": "scoreF",
}


def _score_cmd_local(score: float, grade: str) -> str:
    color = (_GRADE_COLOR.get(grade) or
             ("scoreAplus" if score >= 9 else "scoreA" if score >= 7.5
              else "scoreB" if score >= 6 else "scoreC" if score >= 5 else "scoreD"))
    return rf"{{\bfseries\color{{{color}}}{score:.1f}/10\ ({e(grade)})}}"


def _overview_full(entries: list, summary_pdf: Path) -> str:
    rows = ""
    for entry in entries:
        agg = entry["agg"]
        p1  = entry.get("p1_score", 0)
        gr  = entry.get("p1_grade", "?")
        sr  = agg.get("solve_rate", 0)
        rows += (
            rf"  \hyperref[sec:{slug(entry['name'])}]{{{e(entry['short_name'])}}} & "
            rf"{e(entry.get('arch_type', '—'))} & "
            rf"{int(agg.get('mean_node_count', 0))} & "
            rf"{agg.get('total', '—')} & "
            rf"{_score_cmd_local(p1, gr)} & "
            rf"\textbf{{{agg.get('solved', '?')}/{agg.get('total', '?')} "
            rf"({sr * 100:.0f}\%)}} & "
            rf"{int(agg.get('mean_steps', 0))} \\"
            "\n"
        )

    dim_cols   = list(_DIM_SHORT.values())
    dim_header = " & ".join(rf"\textbf{{{e(d)}}}" for d in dim_cols)
    qual_rows  = ""
    for entry in entries:
        dim_scores = entry.get("dim_scores", {})
        cells = []
        for key in _DIM_SHORT:
            info  = dim_scores.get(key, {})
            s     = info.get("score", 0)
            gr    = info.get("grade", "F")
            color = (_GRADE_COLOR.get(gr) or
                     ("scoreAplus" if s >= 9 else "scoreA" if s >= 7.5
                      else "scoreB" if s >= 6 else "scoreC" if s >= 5 else "scoreD"))
            cells.append(rf"{{\color{{{color}}}{s:.0f}}}")
        qual_rows += (
            rf"  \hyperref[sec:{slug(entry['name'])}]{{{e(entry['short_name'])}}} & "
            + " & ".join(cells) + r" \\" + "\n"
        )

    _dim_col_types = ["l", "X", "X", "X", "l", "X"]
    dim_col_specs  = [f">{{\\centering\\arraybackslash}}{t}" for t in _dim_col_types]
    col_spec       = r"p{4.5cm}" + "".join(dim_col_specs)

    summary_inc = ""
    if summary_pdf.exists():
        summary_inc = (
            r"\subsection*{Quality \& Solvability Overview}" + "\n"
            + rf"\begin{{center}}\includegraphics[width=0.85\linewidth]{{{summary_pdf.name}}}\end{{center}}"
            + "\n"
        )

    return rf"""
\section{{Dataset Overview}}
\begin{{center}}
\begin{{tabular}}{{lllrrrr}}
\toprule
\textbf{{Scenario}} & \textbf{{Architecture}} & \textbf{{Avg Nodes}} &
\textbf{{Episodes}} & \textbf{{P1 Quality}} & \textbf{{Solve Rate}} &
\textbf{{Avg Steps (solved)}} \\
\midrule
{rows}\bottomrule
\end{{tabular}}
\end{{center}}

\smallskip
\subsubsection*{{Quality Dimension Scores}}
{{\setlength{{\tabcolsep}}{{6pt}}
\begin{{tabularx}}{{\linewidth}}{{{col_spec}}}
\toprule
\textbf{{Scenario}} & {dim_header} \\
\midrule
{qual_rows}\bottomrule
\end{{tabularx}}
}}

{summary_inc}
"""


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    DEFAULT_OUTPUT = "/content/drive/MyDrive/thesis/code/datasets/poc/claude/reports/executive_report.pdf"
    _repo_root = REPO_ROOT

    parser = argparse.ArgumentParser(description="Generate executive PDF report via LaTeX")
    parser.add_argument("--phase2-root",   required=True,
                        help="Directory containing per-scenario phase2 result dirs")
    parser.add_argument("--configs-root",  default="",
                        help="Primary directory containing domain config YAML files")
    parser.add_argument("--extra-configs", nargs="*", default=[],
                        help="Additional directories to search for config YAMLs")
    parser.add_argument("--output",        default=DEFAULT_OUTPUT,
                        help=f"Output PDF path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--title",         default="CyberBattleSim Scenario Dataset",
                        help="Report title shown on cover page")
    parser.add_argument("--fast",          action="store_true",
                        help="Skip expensive BFS attack-path stats (faster layout testing)")
    args = parser.parse_args()

    phase2_root  = Path(args.phase2_root)
    configs_root = (Path(args.configs_root) if args.configs_root
                    else phase2_root.parent / "configs")
    configs_roots = [
        configs_root,
        *[Path(p) for p in (args.extra_configs or [])],
        _repo_root / "data",
        _repo_root / "data" / "scenarios",
        _repo_root / "prompts" / "examples",
    ]

    build_report(
        phase2_root   = phase2_root,
        configs_roots = configs_roots,
        output        = Path(args.output),
        title         = args.title,
        fast          = args.fast,
    )


if __name__ == "__main__":
    main()
