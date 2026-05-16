#!/usr/bin/env python3
"""
pipeline/phase2/_04_quality_evaluator.py
========================================
Quality evaluator for CyberBattleSim domain configuration YAML files.

Evaluates 7 dimensions: 6 via LLM + 1 static rule-count (D-P3).

Dimensions:
  1. topology_realism      — Network Topology Realism          [LLM]
  2. vulnerability_realism — Properties & Vulnerabilities      [LLM]
  3. scenario_difficulty   — Scenario Difficulty               [LLM]
  4. firewall_realism      — Firewall Rules Realism            [LLM]
  5. general_realism       — General Realism                   [LLM]
  6. cve_grounding         — CVE Grounding                     [LLM]
  7. template_alignment    — GLOBALTECH Template Alignment     [static rule count]

Usage (CLI):
  python tools/quality_evaluator.py data/enterprise_ad_v2.yaml
  python tools/quality_evaluator.py data/enterprise_ad_v2.yaml --json
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

import yaml

# ── kept for _extract_cve_metrics (used by graph generation) ─────────────────
CVE_ID_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
FORMULA_FINGERPRINT_RATES = {
    0.90, 0.88, 0.86, 0.85, 0.83, 0.81, 0.78, 0.75,
    0.63, 0.57, 0.52, 0.49, 0.56, 0.62,
}

DIMENSION_NAMES: Dict[str, str] = {
    "topology_realism":      "Network Topology Realism",
    "vulnerability_realism": "Properties & Vulnerabilities Realism",
    "scenario_difficulty":   "Scenario Difficulty",
    "firewall_realism":      "Firewall Rules Realism",
    "general_realism":       "General Realism",
    "cve_grounding":         "CVE Grounding",
    # template_alignment is NOT in the LLM dimensions — it is computed statically
    # from architectural rule counts (D-P3) and injected after LLM evaluation.
}

# Compact GLOBALTECH zone inventory injected into the LLM prompt (Part 2 of ref.md)
_GLOBALTECH_ZONE_CONTEXT = """
## GLOBALTECH Enterprise Network — Zone Reference (ref.md Part 2)

### Zone Inventory
| Zone | Name | Role |
|------|------|------|
| Z1 | Corporate HQ / Main Site | Campus LAN: Core/Dist/Access hierarchy; VLANs for Sales, R&D, Finance, Admin; Server Farm |
| Z2 | HQ Edge | Perimeter security: Palo Alto PA-5200 HA pair, Cisco ISR 4451 Edge Router, Cisco ISE NAC, MEC gateway |
| Z3 | Internet | Public internet hub (not an attack surface in CBS) |
| Z4 | Internet Edge | ISP-A / ISP-B routers, WAF, IPS/Security Stack, Web Gateway |
| Z5 | Branch Office | SD-WAN (Cisco Meraki MX), MPLS cloud, Branch Router |
| Z6 | Public Cloud (AWS) | VPC with Web Tier, App Tier, DB Tier (PostgreSQL); Transit Gateways TGW-1/TGW-2 |
| Z7 | Remote Users | SASE, Client-to-Site VPN (Cisco AnyConnect), Remote Workers / BYOD |
| Z8 | Key Management | SolarWinds NPM, Splunk SIEM, Cisco ISE |

### Key Device Expectations per Zone
- **Z1 VLANs**: SalesWorkstation (VLAN1), R&D (VLAN2), Finance (VLAN3), Admin (VLAN4) — all Windows, DomainJoined
- **Z1 ServerFarm**: DomainController (Windows, DomainController), FileServer, ExchangeServer, IISServer, MSSQLServer, HyperVHost, PrintServer; optionally ADCS_Server (ADCS property)
- **Z2**: PaloAltoFirewall (Firewall, PAN-OS), CiscoEdgeRouter (Router, CiscoIOS), Cisco ISE implied
- **Z4**: ISP-A/ISP-B (NetworkDevice, Router), WAFAppliance (WAF), IPSAppliance (IPS)
- **Z6**: AWSWebServer (Linux, WebServer), AWSAppServer/AWSJenkins (Linux, AppServer), AWSWorkerNode/AWSRabbitMQ (Linux, WorkerNode), AWSAuthServer (Linux, AuthServer), AWSPostgreSQL/AWSMySQL/AWSRedis/AWSElasticsearch (Linux, DatabaseServer)
- **Z5** (if present): SD-WAN device, MPLS node, Branch Router
- **Z7** (if present): SASE node, VPN endpoint, Remote endpoints
"""


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _grade(score: float) -> str:
    if score >= 9:  return "A+"
    if score >= 8:  return "A"
    if score >= 7:  return "B"
    if score >= 6:  return "C"
    if score >= 5:  return "D"
    return "F"


def _finding(ftype: str, message: str, ref: str = "", deduction: int = 0) -> dict:
    f: dict = {"type": ftype, "message": message}
    if ref:       f["ref"] = ref
    if deduction: f["deduction"] = deduction
    return f


# ─────────────────────────────────────────────────────────────────────────────
# LLM helpers
# ─────────────────────────────────────────────────────────────────────────────

def _yaml_to_str(cfg: dict) -> str:
    return yaml.dump(cfg, default_flow_style=False, allow_unicode=True, sort_keys=False)


def _read_env_key(key_name: str = "ANTHROPIC_API_KEY") -> str:
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if not env_file.exists():
        return ""
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line.startswith(f"{key_name}=") and not line.startswith("#"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def _call_gemini(prompt: str, api_key: str) -> Optional[str]:
    """Call Gemini and return the response text."""
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(prompt)
        return response.text
    except Exception as exc:
        print(f"  [WARN] Gemini evaluator failed: {exc}")
        return None


def _call_gemini_cli(prompt: str) -> Optional[str]:
    """Call the gemini CLI as an ultimate fallback."""
    import subprocess
    import tempfile
    import os
    
    # We use a temp file for the prompt to avoid shell escaping issues with large prompts
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(prompt)
        temp_prompt_path = f.name
        
    try:
        print("  [INFO] Calling Gemini CLI for fallback critic...")
        # We tell gemini to be non-interactive and use the prompt file
        # The '-p' flag can take the prompt string, but for safety we might pipe it
        # Actually, let's try piped input if gemini supports it, or just use the file
        result = subprocess.run(
            ["gemini", "-p", f"Please act as a critic for this CyberBattleSim scenario. Use the context and prompt provided below to generate a JSON response as specified.\n\nSOURCE PROMPT:\n{prompt}"],
            capture_output=True,
            text=True,
            timeout=180 # 3 minute timeout for CLI
        )
        if result.returncode == 0:
            return result.stdout
        else:
            print(f"  [WARN] Gemini CLI failed with exit code {result.returncode}: {result.stderr}")
            return None
    except Exception as exc:
        print(f"  [WARN] Gemini CLI call failed: {exc}")
        return None
    finally:
        if os.path.exists(temp_prompt_path):
            os.remove(temp_prompt_path)


def _call_llm_eval(prompt: str) -> Optional[str]:
    """Call Claude (primary), Gemini API (secondary), or Gemini CLI (fallback) and return the response text."""
    import os
    
    # 1. Try Claude
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "") or _read_env_key("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=anthropic_key)
            msg = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text
        except Exception as exc:
            print(f"  [WARN] Claude evaluator failed: {exc}")

    # 2. Try Gemini API fallback
    google_key = os.environ.get("GOOGLE_API_KEY", "") or _read_env_key("GOOGLE_API_KEY")
    if google_key:
        print("  [INFO] Using Gemini API as fallback critic...")
        return _call_gemini(prompt, google_key)

    # 3. Try Gemini CLI fallback
    return _call_gemini_cli(prompt)


def _build_llm_eval_prompt(yaml_text: str, config_name: str,
                            graph_metrics: Optional[dict]) -> str:
    runtime_section = ""
    if graph_metrics:
        sr = graph_metrics.get("solve_rate", "N/A")
        sr_str = f"{sr:.0%}" if isinstance(sr, float) else str(sr)
        n      = graph_metrics.get("n_scenarios", graph_metrics.get("total", "N/A"))
        g      = graph_metrics.get("graph", {})
        seg    = graph_metrics.get("segmentation", {})
        ap     = graph_metrics.get("attack_paths", {})
        cr     = graph_metrics.get("credentials", {})
        pay    = graph_metrics.get("payloads", {})
        fw     = graph_metrics.get("firewall", {})
        ast    = graph_metrics.get("action_stats", {})
        oc     = graph_metrics.get("outcome_totals", {})
        strata = graph_metrics.get("by_stratum", {})

        def _pct(v) -> str:
            return f"{v:.0%}" if isinstance(v, float) else str(v)
        def _f2(v) -> str:
            return f"{v:.3f}" if isinstance(v, float) else str(v)

        # Per-stratum table
        strata_lines = ""
        for s, st in strata.items():
            diam_d = st.get("diameter_distribution", {})
            diam_str = " ".join(f"d{k}={v}" for k, v in sorted(diam_d.items())) if diam_d else "—"
            strata_lines += (
                f"  {s:<8}  solved={st.get('solved', '?')}/{st.get('total', '?')} ({_pct(st.get('solve_rate', 0))})  "
                f"diameter≈{st.get('mean_diameter', '?')}  [{diam_str}]  "
                f"density={_f2(st.get('mean_density', 0))}  "
                f"nodes≈{st.get('mean_nodes', '?')}  steps≈{st.get('mean_steps', '?')}  "
                f"creds≈{st.get('mean_creds', '?')}  owned≈{st.get('mean_nodes_owned', '?')}\n"
            )

        # Top properties
        top_props = pay.get("top_properties", {})
        props_str = "  " + ",  ".join(f"{k}={v}" for k, v in list(top_props.items())[:12]) if top_props else "  (none)"

        # Action outcomes
        oc_str = "  " + ",  ".join(
            f"{k}={v}" for k, v in sorted(oc.items(), key=lambda x: -x[1]) if v > 0
        ) if oc else "  (none)"

        # ── Cumulative Success Rate (CSR) Calculation (Q27) ──────────────────
        # Computes end-to-end probability floor for DRL training feasibility.
        csr_data = ""
        path_info = graph_metrics.get("attack_paths", {}).get("shortest_path_to_goal", [])
        if path_info and isinstance(path_info, list):
            # Calculate end-to-end SR: P(success) = Product(SR_i)
            # We assume a base SR of 0.75 for missing data, or use actual metrics if available.
            path_srs = [node.get("exploit_sr", 0.75) if isinstance(node, dict) else 0.75 for node in path_info]
            cumulative_sr = 1.0
            for sr in path_srs:
                cumulative_sr *= sr
            
            csr_status = "CRITICAL (Reward Sparsity)" if cumulative_sr < 0.10 else \
                         "WARNING (Slow Convergence)" if cumulative_sr < 0.25 else "HEALTHY"
            
            csr_data = f"""
### DRL Training Feasibility: Cumulative Success Rate (CSR)
- Shortest Attack Path : {len(path_info)} hops
- Cumulative SR (CSR)  : {cumulative_sr:.2%}
- Convergence Signal   : {csr_status}
  (Success reward seen ~1 in {int(1/cumulative_sr) if cumulative_sr > 0 else 'inf'} training episodes)
"""
        # ─────────────────────────────────────────────────────────────────────

        # Allowed ports
        ports_str = ", ".join(fw.get("common_allowed_ports", {}).keys()) or "(none)"

        # Diameter distribution string
        diam_dist = g.get("diameter_distribution", {})
        diam_dist_str = "  " + ",  ".join(f"d{k}={v}" for k, v in sorted(diam_dist.items())) if diam_dist else "  (none)"

        # Attack path distribution strings
        steps_d = ap.get("steps_distribution", {})
        steps_d_str = (f"min={steps_d.get('min','?')}  p25={steps_d.get('p25','?')}  "
                       f"median={steps_d.get('median','?')}  p75={steps_d.get('p75','?')}  "
                       f"max={steps_d.get('max','?')}  mean={steps_d.get('mean','?')}") if steps_d else "(none)"
        owned_d = ap.get("nodes_owned_distribution", {})
        owned_d_str = (f"min={owned_d.get('min','?')}  median={owned_d.get('median','?')}  "
                       f"max={owned_d.get('max','?')}") if owned_d else "(none)"

        # Credential distribution string
        creds_d = cr.get("creds_discovered_distribution", {})
        creds_d_str = (f"min={creds_d.get('min','?')}  median={creds_d.get('median','?')}  "
                       f"max={creds_d.get('max','?')}  mean={creds_d.get('mean','?')}") if creds_d else "(none)"

        runtime_section = f"""
## Runtime Agent Evaluation Results
Heuristic agents (3 agents × 3 episodes/scenario) over {n} scenarios:

### Episode Outcomes (Dynamic BFS Round)
- Scenarios evaluated : {n}
- Scenarios solved    : {graph_metrics.get('solved', '?')}/{n}  ({sr_str})
- Mean steps (solved) : {graph_metrics.get('mean_steps', 'N/A')}
- Mean total reward   : {graph_metrics.get('mean_reward', 'N/A')}
- Mean nodes owned    : {graph_metrics.get('mean_nodes', 'N/A')}
- Mean creds found    : {graph_metrics.get('mean_creds', 'N/A')}

### Graph Structure
- Mean node count     : {g.get('mean_node_count', 'N/A')}
- Mean edge count     : {g.get('mean_edge_count', 'N/A')}
- Mean density        : {_f2(g.get('mean_density', 0))}  (target: 0.05–0.40)
- Mean diameter       : {g.get('mean_diameter', 'N/A')}  (target: > 3)
- Diameter distribution:
{diam_dist_str}
- Mean avg in-degree  : {g.get('mean_avg_in_deg', 'N/A')}
- Max in-degree (avg) : {g.get('max_in_degree', 'N/A')}
- Tree ratio          : {g.get('tree_ratio', 'N/A')}  (> 2 = mesh-like)
- Topology types      : {g.get('topology_types', {})}
- Isolated subnets    : {seg.get('mean_isolated_subnets', 'N/A')}
- Routing zones       : {seg.get('mean_routing_zones', 'N/A')}

### Attack Paths
- Mean steps to first goal : {ap.get('mean_steps_to_first_goal', 'N/A')}
- Mean steps to final goal : {ap.get('mean_steps_to_final_goal', 'N/A')}
- Steps distribution       : {steps_d_str}
- Mean goals captured ratio: {ap.get('mean_goals_captured_ratio', 'N/A')}
- Mean nodes owned         : {ap.get('mean_nodes_owned', 'N/A')}  (% owned: {_pct(ap.get('mean_pct_owned', 0))})
- Mean nodes discovered    : {ap.get('mean_nodes_discovered', 'N/A')}  (% disc: {_pct(ap.get('mean_pct_discovered', 0))})
- Nodes owned distribution : {owned_d_str}

### Credentials
- Mean creds discovered    : {cr.get('mean_creds_discovered', 'N/A')}
- Mean creds in cache      : {cr.get('mean_creds_in_cache', 'N/A')}
- Mean creds discovered %  : {_pct(cr.get('mean_creds_pct', 0))}
- Creds distribution       : {creds_d_str}

### Vulnerability & Property Distribution
- Mean vuln instances : {pay.get('mean_vuln_instances', 'N/A')} per scenario
- Mean unique vulns   : {pay.get('mean_unique_vulns', 'N/A')}
- Mean unique props   : {pay.get('mean_unique_props', 'N/A')}
- Top properties:
{props_str}

### Firewall Metrics
- Mean rules/node     : {fw.get('mean_rules_per_node', 'N/A')}
- Firewall coverage   : {_pct(fw.get('mean_firewall_coverage', 0))}
- Mean allow rules    : {fw.get('mean_allow_rules', 'N/A')}
- Mean block rules    : {fw.get('mean_block_rules', 'N/A')}
- Common allowed ports: {ports_str}

### Agent Action Stats
- Local attack success rate  : {_pct(ast.get('mean_local_attack_sr', 0))}
- Remote attack success rate : {_pct(ast.get('mean_remote_attack_sr', 0))}
- Port conn success rate     : {_pct(ast.get('mean_port_conn_sr', 0))}
- Overall action success rate: {_pct(ast.get('mean_overall_sr', 0))}

### Action Outcome Totals
{oc_str}
{csr_data}
### Per-Stratum Breakdown
{strata_lines.rstrip()}

**Primary difficulty targets (use these for scenario_difficulty scoring):**
- Solve rate 40–80% is ideal. < 30% = too hard / unsolvable. > 85% = too easy.
- **CSR Target: 20–40%**. CSR < 10% is "scientifically difficult" but "DRL-impossible" due to reward sparsity.
- Mean steps to first goal > 200 indicates non-trivial attack depth.
- Mean nodes owned < 50% of total at termination suggests good segmentation.
- Mean creds in cache ≈ mean creds discovered = zero decay (bad); large gap = good decay (hard).

**NOTE — 0% local/remote attack success rates are NORMAL and do NOT indicate a broken
scenario.** CyberBattleSim agents navigate primarily via credential leaks (LeakedCredentials)
and lateral movement (LateralMove/Movement outcomes). local_attacks_success_rate and
remote_attacks_success_rate only count explicit exploit actions; when agents move via
credentials they do not fire exploits, so these rates are naturally 0%. Judge difficulty
from solve rate, steps, and LateralMove/LeakedCredentials counts instead.

**NOTE on density and diameter:** These are computed from the CyberBattleSim firewall graph
which contains wildcard port rules (`*`) injected by the simulator internals, making it
near-complete regardless of YAML design. Density > 0.40 and diameter ≤ 3 are EXPECTED
and do NOT indicate credential saturation or poor design — do NOT penalise these values.
"""

    return f"""You are an expert Cyber Range Architect evaluating a CyberBattleSim domain \
configuration for AI security research quality.

## Task
Score this configuration on 6 dimensions (0–10 each). Consider both the YAML structure \
and any runtime metrics from actual agent runs.
{_GLOBALTECH_ZONE_CONTEXT}

## Config: {config_name}

```yaml
{yaml_text}
```
{runtime_section}
## Evaluation Dimensions and Criteria

**1. topology_realism** — Network Topology Realism
- start_node.subnet must be public (0.0.0.0/0 or 203.0.113.0/24) — attacker enters from internet
- Internal domain subnets must use RFC 1918 (10.x, 172.16.x, 192.168.x)
- No overlapping subnets between domains
- OS distribution should reflect the domain type (Windows AD → mostly Windows; web stack → mostly Linux)
- Multi-domain configs need distinct subnets for each tier (DMZ / App / Data / Core)
- Single-domain configs with many nodes should still have group-level zone separation

**2. vulnerability_realism** — Properties & Vulnerabilities Realism
- success_rate on non-discovery exploits: realistic range 0.40–0.85 (never 1.0)
- All vulnerabilities must have match_properties (no untargeted exploits)
- Vulnerability names should reference real-world exploits (CVE IDs, named techniques like Mimikatz, EternalBlue)
- Both REMOTE and LOCAL vulnerability types needed
- All 4 solvability categories populated: remote_access, credential_leak, discovery, goal_access
- Credential leak templates should have realistic individual probabilities (0.15–0.25)

**3. scenario_difficulty** — Scenario Difficulty
- attack_flow should have ≥ 4 hops (entry → service A → service B → goal)
- min_credential_leaking_nodes target: 0.10–0.20 (higher values saturate lateral movement)
- Combined credential-leak probability across all templates: 1 − ∏(1 − pᵢ) must be ≤ 0.65
- If runtime metrics available: PRIMARY signals are solve rate 40–80% AND mean steps > 200
- Goal nodes should not be directly reachable from the entry node in one hop
- DO NOT use density or diameter as difficulty signals — they reflect simulator internals, not design quality

**4. firewall_realism** — Firewall Rules Realism
- No ALL/ANY protocols — every MUST_CONNECT must name a specific protocol (SSH, HTTPS, SMB, etc.)
- No direct DMZ-to-Core/Database access without an App tier intermediary
- Multi-domain configs must define inter_domain_constraints between tiers
- Deny-by-default philosophy: only needed flows should be explicitly permitted
- Intra-domain groups should have controlled connectivity (not fully open)

**5. general_realism** — General Realism
- Service and group names must be descriptive and match the domain type (e.g. NginxProxy, DomainController)
- Goal services must have value ≥ 1000 (reflects asset criticality for DRL reward shaping)
- attack_flow must include goal service(s) as final targets
- Probe vulnerabilities should be defined for OS fingerprinting realism
- The scenario must tell a coherent, realistic attack story (does the attacker motivation make sense?)
- Credential chain should be realistic for the network type (e.g. AD → pass-the-hash; web stack → wp-config.php)

**6. cve_grounding** — CVE Grounding
- ≥ 50% of vulnerabilities should reference a CVE ID in name or description
- success_rate values should look formula-derived: not round 0.05 multiples (0.50, 0.60, 0.70 are suspicious)
- match_properties should include CVE-backed properties: GoRuntime, LibCrypto, ImageMagick, MySQL, Redis, \
WordPressInstall, SMBv1, PrintSpooler, DomainController, etc.
- Both Windows CVEs (EternalBlue, BlueKeep, PrintNightmare) and Linux CVEs for mixed environments

## Response Format (STRICT — one block per dimension, then overall)

DIMENSION: topology_realism
SCORE: <0-10>
FINDINGS:
[PASS] <finding>
[WARN] <finding>
[FAIL] <finding>

DIMENSION: vulnerability_realism
SCORE: <0-10>
FINDINGS:
[PASS] <finding>
...

DIMENSION: scenario_difficulty
SCORE: <0-10>
FINDINGS:
...

DIMENSION: firewall_realism
SCORE: <0-10>
FINDINGS:
...

DIMENSION: general_realism
SCORE: <0-10>
FINDINGS:
...

DIMENSION: cve_grounding
SCORE: <0-10>
FINDINGS:
...

OVERALL: <X.X>
SUMMARY: <2–3 sentences on the scenario's overall realism and attack coherence>
"""


def _compute_template_alignment_score(cfg: dict) -> dict:
    """Compute template_alignment score from hard-coded architectural assertions (D-P3).

    Returns the standard dimension dict with score, findings, and a rule summary.
    Replaces the circular LLM self-graded template_alignment dimension.
    """
    findings: List[dict] = []
    passed = 0
    total  = 0

    def _check(condition: bool, pass_msg: str, fail_msg: str) -> None:
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            findings.append(_finding("pass", pass_msg))
        else:
            findings.append(_finding("fail", fail_msg))

    services  = cfg.get("services", {})
    domains   = cfg.get("domains", [])
    solv      = cfg.get("solvability_vulnerabilities", {})
    attack_flow = cfg.get("attack_flow", [])
    settings  = cfg.get("config_settings", {})
    meta      = cfg.get("metadata", {})

    # R1 — metadata block present with agent field
    _check(bool(meta.get("agent")),
           "metadata.agent set",
           "metadata.agent missing — agent assignment required")

    # R2 — services block non-empty (≥ 2)
    _check(len(services) >= 2,
           f"{len(services)} services defined (≥ 2 required)",
           f"Only {len(services)} service(s) — config under-specified")

    # R3 — at least one goal service
    goal_svcs = [k for k, v in services.items() if v.get("is_goal")]
    _check(bool(goal_svcs),
           f"Goal service(s) defined: {goal_svcs}",
           "No service has is_goal: true — terminal condition missing")

    # R4 — goal services have value ≥ 1000 (DRL reward shaping)
    low_val = [k for k in goal_svcs if services[k].get("value", 0) < 1000]
    _check(not low_val,
           "All goal services have value ≥ 1000",
           f"Goal service(s) {low_val} have value < 1000 — reward signal too weak")

    # R5 — attack_flow has ≥ 3 entries (entry → intermediate → goal)
    _check(len(attack_flow) >= 3,
           f"attack_flow has {len(attack_flow)} entries (≥ 3 required)",
           f"attack_flow has only {len(attack_flow)} entries — path too shallow")

    # R6 — at least one domain defined
    _check(len(domains) >= 1,
           f"{len(domains)} domain(s) defined",
           "No domains defined — topology missing")

    # R7 — solvability_vulnerabilities has ≥ 2 non-empty categories
    nonempty_cats = [k for k, v in solv.items() if isinstance(v, list) and v]
    _check(len(nonempty_cats) >= 2,
           f"solvability_vulnerabilities has categories: {nonempty_cats}",
           f"Only {len(nonempty_cats)} non-empty solvability category — incomplete attack chain")

    # R8 — no ALL/* protocol on internal MUST_CONNECT constraints
    all_constraints = []
    for d in domains:
        all_constraints.extend(d.get("constraints", []))
    bad_proto = [
        c for c in all_constraints
        if isinstance(c, dict)
        and c.get("type") == "MUST_CONNECT"
        and str(c.get("protocol", "")).upper() in ("ALL", "*", "ANY", "")
    ]
    _check(not bad_proto,
           "All MUST_CONNECT constraints name a specific protocol",
           f"{len(bad_proto)} MUST_CONNECT constraint(s) use ALL/*/ANY protocol")

    # R9 — inter_domain_constraints defined if multi-domain
    if len(domains) > 1:
        idc = cfg.get("inter_domain_constraints", [])
        _check(bool(idc),
               f"inter_domain_constraints defined ({len(idc)} rules)",
               "Multi-domain config missing inter_domain_constraints")
    else:
        passed += 1
        total  += 1
        findings.append(_finding("pass", "Single-domain config — inter_domain_constraints N/A"))

    # R10 — start_node defined in config_settings
    _check(bool(settings.get("start_node")),
           "config_settings.start_node defined",
           "config_settings.start_node missing — breach entry undefined")

    score = round((passed / total) * 10) if total else 0
    return {
        "name":      "GLOBALTECH Template Alignment",
        "score":     score,
        "max_score": 10,
        "grade":     _grade(score),
        "findings":  findings,
        "_rule_summary": f"{passed}/{total} architectural assertions passed",
    }


def _parse_llm_scores(llm_response: str, config_name: str) -> dict:
    """Parse structured LLM output into the standard result dict."""
    dimensions = {
        k: {"name": v, "score": 7, "max_score": 10, "grade": "B", "findings": []}
        for k, v in DIMENSION_NAMES.items()
    }

    current_dim: Optional[str] = None
    in_findings = False

    for line in llm_response.splitlines():
        stripped = line.strip()

        m = re.match(r'^DIMENSION:\s*(\w+)', stripped, re.I)
        if m:
            current_dim = m.group(1).lower()
            in_findings = False
            continue

        if current_dim and re.match(r'^SCORE:\s*\d', stripped, re.I):
            m = re.match(r'^SCORE:\s*(\d+(?:\.\d+)?)', stripped, re.I)
            if m and current_dim in dimensions:
                score = max(0, min(10, round(float(m.group(1)))))
                dimensions[current_dim]["score"] = score
                dimensions[current_dim]["grade"] = _grade(score)
            continue

        if re.match(r'^FINDINGS:', stripped, re.I):
            in_findings = True
            continue

        if in_findings and current_dim:
            m = re.match(r'^\[(PASS|WARN|FAIL|CRITICAL|CRIT)\]\s+(.*)', stripped, re.I)
            if m and current_dim in dimensions:
                ftype_map = {
                    "PASS": "pass", "WARN": "warning",
                    "FAIL": "fail", "CRITICAL": "critical", "CRIT": "critical",
                }
                ftype = ftype_map.get(m.group(1).upper(), "warning")
                dimensions[current_dim]["findings"].append(
                    _finding(ftype, m.group(2).strip())
                )

    # Overall score — explicit OVERALL line, or mean of dimension scores
    m_overall = re.search(r'^OVERALL:\s*([\d.]+)', llm_response, re.M | re.I)
    if m_overall:
        overall = max(0.0, min(10.0, float(m_overall.group(1))))
    else:
        scores = [d["score"] for d in dimensions.values()]
        overall = round(sum(scores) / len(scores), 1)

    # Summary
    m_summary = re.search(r'^SUMMARY:\s*(.+)', llm_response, re.M | re.I)
    summary = m_summary.group(1).strip() if m_summary else f"Overall quality: {overall}/10 ({_grade(overall)})."

    # Top issues
    top_issues: List[dict] = []
    for dim_data in dimensions.values():
        for f in dim_data.get("findings", []):
            if f["type"] in ("critical", "fail"):
                top_issues.append({
                    "dimension": dim_data["name"],
                    "severity":  f["type"].upper(),
                    "message":   f["message"],
                    "ref":       f.get("ref", ""),
                })
    top_issues.sort(key=lambda x: (0 if x["severity"] == "CRITICAL" else 1, x["dimension"]))

    return {
        "config_name":   config_name,
        "overall_score": overall,
        "overall_grade": _grade(overall),
        "dimensions":    dimensions,
        "top_issues":    top_issues[:10],
        "summary":       summary,
    }


def _fallback_result(config_name: str, cfg: Optional[dict] = None) -> dict:
    """Neutral result returned when LLM is unavailable."""
    dimensions = {
        k: {"name": v, "score": 5, "max_score": 10, "grade": "D", "findings": [
            _finding("warning", "LLM evaluator unavailable — score defaulted to 5/10"),
        ]}
        for k, v in DIMENSION_NAMES.items()
    }
    # D-P3: still compute static template_alignment even without LLM
    dimensions["template_alignment"] = _compute_template_alignment_score(cfg or {})
    all_scores = [d["score"] for d in dimensions.values()]
    overall = round(sum(all_scores) / len(all_scores), 1)
    return {
        "config_name":   config_name,
        "overall_score": overall,
        "overall_grade": _grade(overall),
        "dimensions":    dimensions,
        "top_issues":    [],
        "summary":       "LLM evaluation unavailable. Check ANTHROPIC_API_KEY.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Evaluator class
# ─────────────────────────────────────────────────────────────────────────────

class ScenarioQualityEvaluator:
    """LLM-based quality evaluator for CyberBattleSim domain configs."""

    def __init__(self, config: dict, config_name: str = "unknown"):
        self.cfg  = config
        self.name = config_name

    # ── Primary entry point ───────────────────────────────────────────────────

    def evaluate_with_llm(
        self,
        graph_metrics: Optional[dict] = None,
        save_dir: Optional[str] = None,
        round_num: int = 1,
    ) -> dict:
        """Evaluate config quality via LLM across 7 dimensions.

        graph_metrics: aggregated runtime metrics from agent evaluation.
        save_dir: if provided, prompt and response are saved to
            {save_dir}/llm_prompt_r{round_num}.txt  and
            {save_dir}/llm_response_r{round_num}.txt
        """
        yaml_text = _yaml_to_str(self.cfg)
        prompt    = _build_llm_eval_prompt(yaml_text, self.name, graph_metrics)

        if save_dir:
            _sd = Path(save_dir)
            _sd.mkdir(parents=True, exist_ok=True)
            (_sd / f"llm_prompt_r{round_num}.txt").write_text(prompt, encoding="utf-8")

        llm_response = _call_llm_eval(prompt)

        if save_dir and llm_response:
            (_sd / f"llm_response_r{round_num}.txt").write_text(llm_response, encoding="utf-8")

        if not llm_response:
            return _fallback_result(self.name, cfg=self.cfg)

        result = _parse_llm_scores(llm_response, self.name)

        # ── D-P3: inject static template_alignment score ──────────────────────
        ta_dim = _compute_template_alignment_score(self.cfg)
        result["dimensions"]["template_alignment"] = ta_dim
        # Recompute overall as mean of all 7 dimensions (6 LLM + 1 static)
        all_scores = [d["score"] for d in result["dimensions"].values()]
        result["overall_score"] = round(sum(all_scores) / len(all_scores), 1)
        result["overall_grade"] = _grade(result["overall_score"])

        result["llm_assessment"] = llm_response
        result["cve_metrics"]    = self._extract_cve_metrics()
        return result

    # ── Backward-compatible aliases ───────────────────────────────────────────

    def evaluate(self) -> dict:
        """Alias for evaluate_with_llm() — kept for backward compatibility."""
        return self.evaluate_with_llm()

    def evaluate_with_graph_metrics(self, graph_metrics: dict) -> dict:
        """Alias for evaluate_with_llm(graph_metrics) — kept for backward compatibility."""
        return self.evaluate_with_llm(graph_metrics=graph_metrics)

    # ── CVE metrics for graph generation (unchanged) ─────────────────────────

    def _extract_cve_metrics(self) -> dict:
        solv = self.cfg.get("solvability_vulnerabilities", {})
        all_vulns: List[dict] = []
        if isinstance(solv, dict):
            for cat in ("remote_access", "credential_leak", "discovery", "goal_access"):
                for v in solv.get(cat, []) or []:
                    if isinstance(v, dict):
                        all_vulns.append({**v, "_category": cat})

        metrics: dict = {
            "total_vulns": len(all_vulns),
            "by_category": {},
            "success_rates": [],
            "exploit_costs": [],
            "implied_cvss": [],
            "match_properties_all": [],
            "cve_named_count": 0,
            "formula_rate_count": 0,
            "remote_count": 0,
            "local_count": 0,
            "windows_count": 0,
            "linux_count": 0,
        }

        for v in all_vulns:
            cat   = v["_category"]
            sr    = v.get("success_rate", 0.65)
            cost  = v.get("exploit_cost", 2.0)
            vtype = v.get("type", "LOCAL")
            props = v.get("match_properties", [])

            metrics["by_category"].setdefault(cat, []).append(sr)
            metrics["success_rates"].append({
                "name": v.get("name", "?"), "sr": sr,
                "category": cat, "type": vtype,
            })
            metrics["exploit_costs"].append(cost)
            metrics["implied_cvss"].append(round(min(10.0, sr * 10), 1))
            metrics["match_properties_all"].extend(props)

            if CVE_ID_RE.search(v.get("name", "") + v.get("description", "")):
                metrics["cve_named_count"] += 1

            def _is_formula(x: float) -> bool:
                return (round(x, 2) in FORMULA_FINGERPRINT_RATES
                        or abs(round(x / 0.05) * 0.05 - x) > 0.005)

            if _is_formula(sr):
                metrics["formula_rate_count"] += 1

            if vtype == "REMOTE":
                metrics["remote_count"] += 1
            else:
                metrics["local_count"] += 1

            if "Windows" in props:
                metrics["windows_count"] += 1
            if "Linux" in props:
                metrics["linux_count"] += 1

        metrics["property_freq"] = dict(
            Counter(metrics["match_properties_all"]).most_common(20)
        )
        metrics["cost_dist"] = dict(
            Counter(round(c, 1) for c in metrics["exploit_costs"])
        )
        return metrics


# ─────────────────────────────────────────────────────────────────────────────
# Formatting
# ─────────────────────────────────────────────────────────────────────────────

ICONS = {"pass": "✓", "warning": "⚠", "fail": "✗", "critical": "✗✗"}

GRADE_COLORS = {
    "A+": "EXCELLENT", "A": "GOOD", "B": "ABOVE AVERAGE",
    "C": "AVERAGE",    "D": "BELOW AVERAGE", "F": "POOR",
}


def format_report(result: dict) -> str:
    lines = []
    name    = result.get("config_name", "unknown")
    overall = result.get("overall_score", 0)
    grade   = result.get("overall_grade", "?")
    label   = GRADE_COLORS.get(grade, "")

    lines += [
        "╔══════════════════════════════════════════════════════════════╗",
        f"  SCENARIO QUALITY REPORT: {name}",
        f"  Overall Score: {overall}/10   Grade: {grade}  ({label})",
        "╚══════════════════════════════════════════════════════════════╝",
        "",
        "DIMENSION SCORES:",
        "─" * 62,
    ]

    for dim in result.get("dimensions", {}).values():
        score = dim["score"]
        bar   = "█" * score + "░" * (10 - score)
        lines.append(f"  {dim['name']:<40} {score:>2}/10 ({dim['grade']}) [{bar}]")

    lines += ["", "DETAILED FINDINGS:", "─" * 62]

    for dim in result.get("dimensions", {}).values():
        lines.append(f"\n  ── {dim['name']} ──")
        for f in dim.get("findings", []):
            icon    = ICONS.get(f["type"], "?")
            ref_str = f"  [→ {f['ref']}]" if f.get("ref") else ""
            ded_str = f"  (-{f['deduction']} pts)" if f.get("deduction", 0) > 0 else ""
            lines.append(f"    {icon}  {f['message']}{ref_str}{ded_str}")

    lines += ["", "TOP ISSUES:", "─" * 62]
    top = result.get("top_issues", [])
    if top:
        for i, issue in enumerate(top, 1):
            ref_str = f"  [{issue['ref']}]" if issue.get("ref") else ""
            lines.append(
                f"  {i}. [{issue['severity']}] {issue['dimension']}: "
                f"{issue['message']}{ref_str}"
            )
    else:
        lines.append("  No critical issues found — scenario looks realistic!")

    lines += ["", f"SUMMARY: {result.get('summary', '')}", ""]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_yaml_file(path: Path, graph_metrics: Optional[dict] = None) -> dict:
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not cfg:
        raise ValueError(f"Empty or invalid YAML: {path}")
    return ScenarioQualityEvaluator(cfg, config_name=path.stem).evaluate_with_llm(
        graph_metrics=graph_metrics
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Evaluate CyberBattleSim domain config quality via LLM"
    )
    parser.add_argument("config", help="Path to domain config YAML")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    print("  Running LLM quality evaluation...")
    result = evaluate_yaml_file(config_path)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(format_report(result))
        if result.get("llm_assessment"):
            print("\n══ LLM Assessment ══")
            print(result["llm_assessment"])
