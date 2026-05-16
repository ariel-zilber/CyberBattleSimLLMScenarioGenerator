#!/usr/bin/env python3
"""
tools/apply_critic_fixes.py
============================
Feedback-loop tool: reads the LLM critic response and quality evaluator
findings for a domain config, then asks Claude to produce a repaired YAML
that addresses the identified issues.

Workflow
--------
1. Load  data/<domain>.yaml                         (original config)
2. Run   ScenarioQualityEvaluator                   (structured findings)
3. Read  phase2/<domain>/llm_critic_response.json   (qualitative critique)
4. Build a repair prompt with all findings + schema docs
5. Call  Claude API → get fixed YAML
6. Validate fixed YAML with ScenarioQualityEvaluator
7. If score improves → save as data/<domain>_fixed.yaml (or overwrite if --inplace)
8. Print diff summary (score before/after, dimension changes)

Usage
-----
python tools/apply_critic_fixes.py data/enterprise_ad_v1.yaml
python tools/apply_critic_fixes.py data/enterprise_ad_v1.yaml --inplace
python tools/apply_critic_fixes.py data/enterprise_ad_v1.yaml --max-attempts 3
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path

import yaml

TOOLS_DIR  = Path(__file__).resolve().parent
REPO_ROOT  = TOOLS_DIR.parent
PROMPTS    = REPO_ROOT / "prompts"
DATA_DIR   = REPO_ROOT / "data"

sys.path.insert(0, str(TOOLS_DIR))
from scenario_quality_evaluator import ScenarioQualityEvaluator  # noqa: E402

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_doc(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _evaluate(cfg: dict, name: str) -> dict:
    return ScenarioQualityEvaluator(cfg, config_name=name).evaluate()


def _score_summary(result: dict) -> str:
    lines = [f"Overall: {result['overall_score']}/10 ({result['overall_grade']})"]
    for dim in result["dimensions"].values():
        lines.append(f"  {dim['name']}: {dim['score']}/10 ({dim['grade']})")
    return "\n".join(lines)


def _top_findings(result: dict, max_per_dim: int = 3) -> str:
    """Return a compact list of warning/fail/critical findings."""
    lines = []
    for dim in result["dimensions"].values():
        bad = [f for f in dim["findings"]
               if f["type"] in ("warning", "fail", "critical")][:max_per_dim]
        for f in bad:
            ded = f" [-{f['deduction']}]" if f.get("deduction") else ""
            lines.append(f"  [{f['type'].upper()}] {dim['name']}: {f['message']}{ded}")
    return "\n".join(lines) or "  (none)"


def _load_critic(domain_name: str) -> str:
    """Find llm_critic_response.json for the domain."""
    dataset_root_env = os.environ.get("DATASET_ROOT", "")
    candidates = []
    if dataset_root_env:
        candidates.append(Path(dataset_root_env) / "phase2" / domain_name / "llm_critic_response.json")
    candidates.append(REPO_ROOT / "phase2" / domain_name / "llm_critic_response.json")
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("DATASET_ROOT=") and not line.startswith("#"):
                root = line.split("=", 1)[1].strip().strip('"').strip("'")
                candidates.insert(0, Path(root) / "phase2" / domain_name / "llm_critic_response.json")
                break

    for p in candidates:
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data.get("critique", "")
            except Exception:
                pass
    return ""


def _load_phase2_artifacts(phase2_out: "Path | None") -> "tuple[dict, dict]":
    """Load bfs_metrics.json and quality_evaluation.json from phase2_out.

    Returns (bfs_metrics, quality_eval) — empty dicts if not found.
    """
    if phase2_out is None:
        return {}, {}
    bfs: dict = {}
    qual: dict = {}
    bfs_path  = phase2_out / "bfs_metrics.json"
    qual_path = phase2_out / "quality_evaluation.json"
    if bfs_path.exists():
        try:
            bfs = json.loads(bfs_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    if qual_path.exists():
        try:
            qual = json.loads(qual_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return bfs, qual


def _runtime_repair_rules(bfs: dict) -> str:
    """Generate targeted repair rules from runtime BFS metrics."""
    if not bfs:
        return ""

    rules: list[str] = []

    density  = bfs.get("mean_density",  bfs.get("graph", {}).get("mean_density",  0))
    diameter = bfs.get("mean_diameter", bfs.get("graph", {}).get("mean_diameter", 999))
    solve_rt = bfs.get("solve_rate", 0)
    n_scen   = bfs.get("n_scenarios", bfs.get("total", 0))
    solved   = bfs.get("solved", 0)
    mean_creds = bfs.get("mean_creds", 0)
    node_count = bfs.get("mean_node_count", bfs.get("graph", {}).get("mean_node_count", 0))

    rules.append(
        f"## RUNTIME METRICS (from {n_scen} agent-evaluated scenarios)\n"
        f"  Solved         : {solved}/{n_scen} ({solve_rt:.0%})\n"
        f"  Mean diameter  : {diameter:.1f}  (target > 3)\n"
        f"  Mean density   : {density:.3f}  (target 0.05–0.40)\n"
        f"  Mean creds     : {mean_creds}\n"
        f"  Mean nodes     : {node_count}"
    )

    if density > 0.40:
        cred_leak_nodes = round(node_count * bfs.get("mean_creds", 0) / max(node_count, 1), 1)
        rules.append(
            f"\n## HIGH DENSITY FIX REQUIRED (density={density:.3f} >> 0.40 target)\n"
            "The credential graph is saturated — too many nodes leak credentials to too many targets.\n"
            "**MANDATORY changes to reduce density:**\n"
            "1. Set `solvability_rules.lateral_movement_requirements.min_credential_leaking_nodes` to 0.10–0.12\n"
            "2. Set `constraint_vulnerabilities.leak_known_credentials.node_probability` to 0.15–0.20\n"
            "3. Set `constraint_vulnerabilities.leak_known_credentials.target_coverage`  to 0.12–0.15\n"
            "4. Set `constraint_vulnerabilities.leak_neighbors.node_probability` to 0.20–0.25\n"
            "5. Set `constraint_vulnerabilities.leak_neighbors.target_coverage`  to 0.15–0.20\n"
            "6. For any credential_leak solvability vuln that matches ALL DomainJoined nodes\n"
            "   (e.g. Mimikatz_NTLM, PassTheHash): set `target_coverage` to 0.15–0.20 max\n"
            "7. For discovery vulns (BloodHound, ShareEnum): set `probability` ≤ 0.35 and\n"
            "   `target_coverage` ≤ 0.20 — wide discovery spread inflates density"
        )

    if diameter <= 2:
        rules.append(
            f"\n## FLAT TOPOLOGY FIX REQUIRED (diameter={diameter:.1f} ≤ 2, target > 3)\n"
            "The attack graph collapses to ≤ 2 hops — agents reach goal nodes trivially.\n"
            "**MANDATORY changes to increase diameter:**\n"
            "1. Remove any MUST_CONNECT that creates a shortcut between non-adjacent tiers\n"
            "   (e.g. LegacyWorkstations→ModernWorkstations Kerberos is a peer-to-peer shortcut;\n"
            "    use Kerberos only from workstations→DomainControllers)\n"
            "2. Remove contradictory constraint pairs: if you have MUST_NOT_CONNECT(RDP) and\n"
            "   MUST_CONNECT(Kerberos) on the same source→target pair, drop the MUST_CONNECT\n"
            "3. Add MUST_NOT_CONNECT between non-adjacent tiers in inter_domain_constraints:\n"
            "   DMZTier→DataTier: MUST_NOT_CONNECT all groups except through AppTier gateway\n"
            "4. Reduce density (see above) — high edge density directly causes low diameter"
        )

    if solve_rt > 0.80:
        rules.append(
            f"\n## SOLVE RATE TOO HIGH ({solve_rt:.0%} > 80% target)\n"
            "Scenario is too easy. Increase difficulty:\n"
            "1. Reduce `start_node.leaked_node_coverage` to 0.05–0.10\n"
            "2. Reduce `solvability_vulnerabilities.remote_access[*].probability` to 0.40–0.55\n"
            "3. Increase `cost` on goal_access vulnerabilities to 2.0–3.0"
        )
    elif solve_rt < 0.75 and n_scen >= 3:
        severity = "CRITICALLY LOW" if solve_rt < 0.30 else "TOO LOW"
        rules.append(
            f"\n## SOLVE RATE {severity} ({solve_rt:.0%} — target ≥ 75%)\n"
            "Most scenarios are unsolvable for heuristic agents. Increase accessibility:\n"
            "1. Increase `solvability_rules.lateral_movement_requirements.min_credential_leaking_nodes` to 0.20–0.25\n"
            "2. Increase `solvability_rules.lateral_movement_requirements.max_credential_leaking_nodes` to 0.30\n"
            "3. Increase `constraint_vulnerabilities.leak_known_credentials.node_probability` to 0.25–0.30\n"
            "4. Increase `constraint_vulnerabilities.leak_known_credentials.target_coverage` to 0.25–0.30\n"
            "5. Ensure at least 1 remote_access vulnerability matches entry node properties\n"
            "6. Verify attack_flow has a complete unbroken path from entry to goal"
        )

    return "\n".join(rules)


def _get_env_key(key_name: str) -> str:
    key = os.environ.get(key_name, "")
    if key:
        return key
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
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
        print(f"  [WARN] Gemini repair failed: {exc}")
        return None


def _call_gemini_cli(prompt: str) -> Optional[str]:
    """Call the gemini CLI as an ultimate fallback."""
    import subprocess
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(prompt)
        temp_prompt_path = f.name
        
    try:
        print("  [INFO] Calling Gemini CLI for fallback repair...")
        result = subprocess.run(
            ["gemini", "-p", f"Please repair this CyberBattleSim YAML configuration based on the provided feedback and metrics. Output ONLY the repaired YAML in a code block.\n\nSOURCE PROMPT:\n{prompt}"],
            capture_output=True,
            text=True,
            timeout=300 # 5 minute timeout for repair as it's more complex
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


def _extract_yaml_block(text: str) -> str:
    """Extract the first ```yaml … ``` block from the LLM response."""
    import re
    m = re.search(r"```(?:yaml)?\s*\n(.*?)```", text, re.DOTALL)
    if m:
        return m.group(1).strip()
    # If no fences, try to find the start of YAML directly
    lines = text.splitlines()
    yaml_start = next((i for i, l in enumerate(lines) if l.startswith("config:") or l.startswith("# ")), None)
    if yaml_start is not None:
        return "\n".join(lines[yaml_start:])
    return text.strip()


# ─────────────────────────────────────────────────────────────────────────────
# Repair prompt builder
# ─────────────────────────────────────────────────────────────────────────────

_MULTI_DOMAIN_EXAMPLE = """
## CRITICAL: Multi-Domain Schema (REQUIRED when adding domains)

If you split into multiple domains you MUST include ALL of these:

### domains — each needs subnet, os_distribution, groups, constraints
```yaml
domains:
  - name: DMZTier
    subnet: 10.0.1.0/24
    os_distribution: {Linux: 0.8, Windows: 0.2}
    groups:
      - name: WebServers
        min_count: 1
        max_count: 3
        service_tier: DMZTier
    constraints:
      - {source: WebServers, target: AppServers, relation: MUST_CONNECT, protocol: HTTPS}
  - name: AppTier
    subnet: 10.0.2.0/24
    os_distribution: {Linux: 0.5, Windows: 0.5}
    groups:
      - name: AppServers
        min_count: 2
        max_count: 5
        service_tier: AppTier
    constraints:
      - {source: AppServers, target: DatabaseServers, relation: MUST_CONNECT, protocol: MySQL}
  - name: DataTier
    subnet: 10.0.3.0/24
    os_distribution: {Windows: 1.0}
    groups:
      - name: DatabaseServers
        min_count: 1
        max_count: 2
        service_tier: DataTier
    constraints: []
```

### inter_domain_constraints — MANDATORY for multi-domain (list, never empty!)
Each entry must have: source_domain, target_domain, constraints (list with protocol)
```yaml
inter_domain_constraints:
  - source_domain: DMZTier
    target_domain: AppTier
    constraints:
      - {source: WebServers, target: AppServers, relation: MUST_CONNECT, protocol: HTTPS}
  - source_domain: AppTier
    target_domain: DataTier
    constraints:
      - {source: AppServers, target: DatabaseServers, relation: MUST_CONNECT, protocol: MySQL}
```

FATAL MISTAKES to avoid:
- `inter_domain_constraints: []`  ← WRONG — evaluator gives -4 critical penalty
- `inter_domain_constraints: {}`  ← WRONG — must be a list
- protocol: ALL or protocol: ""   ← WRONG — always use specific protocol name
- No inter_domain_constraints key ← WRONG — must exist for multi-domain configs
"""


def _build_repair_prompt(
    original_yaml: str,
    findings_text: str,
    critic_text: str,
    allowed_props: str,
    vuln_catalog: str,
    previous_failures: "list[str] | None" = None,
    runtime_rules: str = "",
    llm_quality_summary: str = "",
) -> str:
    critic_section = textwrap.dedent(f"""
        ## LLM Critic Assessment
        {critic_text[:3000]}
    """).strip() if critic_text else ""

    failure_section = ""
    if previous_failures:
        failure_section = "## PREVIOUS ATTEMPT FAILURES (do NOT repeat these mistakes)\n\n"
        for msg in previous_failures:
            failure_section += f"  - {msg}\n"

    llm_quality_section = f"\n## LLM Quality Evaluation Summary\n{llm_quality_summary}\n" if llm_quality_summary else ""

    return textwrap.dedent(f"""
        You are a CyberBattleSim domain configuration repair specialist.
        Your task is to fix a YAML domain configuration based on quality evaluator
        findings, runtime agent metrics, and an LLM critic assessment.

        ## REPAIR RULES (MUST FOLLOW)

        1. **Preserve scenario identity** — keep the same domain theme, service names,
           group names, and vulnerability names. Do NOT rename or remove existing
           services or vulnerabilities.
        2. **Fix ALL flagged issues** — runtime issues (density, diameter) take HIGHEST
           priority because they reflect actual agent behaviour, not just YAML structure.
        3. **Use only allowed properties** from the Allowed Properties Dictionary.
        4. **Use only allowed exploits** from the Vulnerability Catalog.
        5. **Output ONLY valid YAML** inside a single ```yaml … ``` fenced block.
        6. **Schema compliance** — all properties registered in identifiers.base_properties.

        {runtime_rules}

        ## STATIC PRIORITY FIXES (when no runtime override above)

        **P1 — Network Segmentation (topology_realism)**
        - Split single domain into 2–3 named tiers: DMZTier / AppTier / DataTier
        - Each tier gets its own RFC 1918 /24 subnet
        - MANDATORY: add inter_domain_constraints between every adjacent tier pair

        **P2 — Constraint Coverage (firewall_realism)**
        - Add MUST_CONNECT constraints for ≥50% of directed group-pair flows
        - Add ≥1 MUST_NOT_CONNECT to enforce least-privilege

        **P3 — Attack Depth (scenario_difficulty)**
        - attack_flow must have ≥4 hops; goal must NOT be in the first hop targets

        {_MULTI_DOMAIN_EXAMPLE}

        {failure_section}

        ## QUALITY EVALUATOR FINDINGS (structured)

        {findings_text}

        {critic_section}
        {llm_quality_section}

        ## ALLOWED PROPERTIES (use ONLY these)

        {allowed_props[:4000]}

        ## VULNERABILITY CATALOG (use ONLY these exploits)

        {vuln_catalog[:3000]}

        ## ORIGINAL YAML CONFIG TO FIX

        ```yaml
        {original_yaml}
        ```

        Now produce the repaired YAML config. Output ONLY the ```yaml … ``` block.
    """).strip()


# ─────────────────────────────────────────────────────────────────────────────
# Main repair function
# ─────────────────────────────────────────────────────────────────────────────

def repair_config(
    config_path: Path,
    max_attempts: int = 2,
    inplace: bool = False,
    verbose: bool = True,
    phase2_out: "Path | None" = None,
) -> "Path | None":
    """Repair a domain config YAML using LLM critique feedback + runtime BFS metrics.

    phase2_out: directory containing bfs_metrics.json and quality_evaluation.json
                from the last Phase 2 run.  When provided the actor receives the
                actual agent-observed density / diameter / solve-rate and applies
                targeted structural fixes automatically.

    Returns the path to the fixed file, or None if repair failed/did not improve.
    """
    anthropic_key = _get_env_key("ANTHROPIC_API_KEY")
    google_key    = _get_env_key("GOOGLE_API_KEY")

    if not anthropic_key and not google_key:
        print("ERROR: Neither ANTHROPIC_API_KEY nor GOOGLE_API_KEY set in environment or .env file")
        return None

    domain_name   = config_path.stem
    original_yaml = config_path.read_text(encoding="utf-8")
    try:
        original_cfg  = yaml.safe_load(original_yaml)
    except Exception as exc:
        print(f"ERROR: Could not parse {config_path}: {exc}")
        return None

    # ── Load runtime artifacts ───────────────────────────────────────────────
    bfs_metrics, quality_eval = _load_phase2_artifacts(phase2_out)
    runtime_rules = _runtime_repair_rules(bfs_metrics)
    if runtime_rules and verbose:
        print("\n[ACTOR] Runtime-aware repair rules generated from BFS metrics:")
        density  = bfs_metrics.get("mean_density",  bfs_metrics.get("graph", {}).get("mean_density",  0))
        diameter = bfs_metrics.get("mean_diameter", bfs_metrics.get("graph", {}).get("mean_diameter", 0))
        print(f"  density={density:.3f}  diameter={diameter:.1f}")

    # LLM quality evaluation summary (from quality_evaluation.json)
    llm_quality_summary = ""
    if quality_eval:
        summary = quality_eval.get("summary", "")
        top_issues = quality_eval.get("top_issues", [])
        dim_lines = []
        for k, d in quality_eval.get("dimensions", {}).items():
            dim_lines.append(f"  {d.get('name', k)}: {d.get('score', '?')}/10 ({d.get('grade', '?')})")
        if dim_lines:
            llm_quality_summary = "\n".join(dim_lines)
            if top_issues:
                llm_quality_summary += "\n\nTop issues from last run:\n" + "\n".join(
                    f"  [{i.get('severity','?')}] {i.get('dimension','')}: {i.get('message','')} "
                    for i in top_issues
                )

    # ── Repair loop ──────────────────────────────────────────────────────────
    prompt = _build_repair_prompt(original_yaml, runtime_rules, llm_quality_summary)
    
    repaired_text = None
    
    # 1. Try Claude
    if anthropic_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=anthropic_key)
            if verbose: print(f"  [ACTOR] Calling Claude for repair (attempt 1/1) ...")
            msg = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            repaired_text = msg.content[0].text
        except Exception as exc:
            print(f"  [WARN] Claude repair failed: {exc}")

    # 2. Try Gemini API fallback
    if not repaired_text and google_key:
        if verbose: print(f"  [ACTOR] Calling Gemini API for repair fallback (attempt 1/1) ...")
        repaired_text = _call_gemini(prompt, google_key)

    # 3. Try Gemini CLI fallback
    if not repaired_text:
        if verbose: print(f"  [ACTOR] Calling Gemini CLI for repair fallback (attempt 1/1) ...")
        repaired_text = _call_gemini_cli(prompt)

    if not repaired_text:
        print("ERROR: All repair attempts (Claude, Gemini API, Gemini CLI) failed.")
        return None

    yaml_block = _extract_yaml_block(repaired_text)
                    for i in top_issues[:5]
                )
            if summary:
                llm_quality_summary += f"\n\nOverall summary: {summary}"

    # ── Evaluate original ───────────────────────────────────────────────────
    original_result  = _evaluate(original_cfg, domain_name)
    original_score   = original_result["overall_score"]
    findings_text    = _top_findings(original_result)
    critic_text      = _load_critic(domain_name)

    if verbose:
        print(f"\n{'='*60}")
        print(f"Domain: {domain_name}")
        print(f"{'='*60}")
        print(f"Original quality score:")
        print(_score_summary(original_result))
        print(f"\nTop findings to fix:")
        print(findings_text)
        if critic_text:
            print(f"\nLLM critic available ({len(critic_text)} chars)")
        else:
            print("\n[WARN] No LLM critic response found for this domain")

    # ── Load reference docs ─────────────────────────────────────────────────
    allowed_props = _load_doc(PROMPTS / "docs" / "reference" / "allowed_properties_dictionary.md")
    vuln_catalog  = _load_doc(PROMPTS / "docs" / "reference" / "vulnerability_catalog.md")

    # ── Attempt repair loop ─────────────────────────────────────────────────
    best_cfg     = None
    best_yaml    = None
    best_result  = None
    best_score   = original_score

    current_yaml    = original_yaml
    current_cfg     = original_cfg
    current_result  = original_result
    previous_failures: list = []

    for attempt in range(1, max_attempts + 1):
        findings_text = _top_findings(current_result)
        prompt = _build_repair_prompt(
            original_yaml=current_yaml,
            findings_text=findings_text,
            critic_text=critic_text,
            allowed_props=allowed_props,
            vuln_catalog=vuln_catalog,
            previous_failures=previous_failures if previous_failures else None,
            runtime_rules=runtime_rules,
            llm_quality_summary=llm_quality_summary,
        )

        if verbose:
            print(f"\n── Attempt {attempt}/{max_attempts} ──")
            print(f"  Sending {len(prompt)} chars to Claude...")

        try:
            response = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=8192,
                system=(
                    "You are a CyberBattleSim YAML config repair specialist. "
                    "You output ONLY valid YAML inside a single ```yaml block. "
                    "No prose, no explanation outside the block."
                ),
                messages=[{"role": "user", "content": prompt}],
            )
            raw_response = response.content[0].text if response.content else ""
            usage = {
                "input_tokens":  response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
        except Exception as exc:
            print(f"  [ERROR] API call failed: {exc}")
            break

        if verbose:
            print(f"  Tokens: {usage['input_tokens']} in / {usage['output_tokens']} out")

        # Extract YAML block
        fixed_yaml = _extract_yaml_block(raw_response)
        if not fixed_yaml:
            print("  [ERROR] Could not extract YAML from response")
            previous_failures.append("Previous attempt produced no YAML block")
            continue

        # Parse
        try:
            fixed_cfg = yaml.safe_load(fixed_yaml)
        except Exception as exc:
            print(f"  [ERROR] Fixed YAML parse error: {exc}")
            previous_failures.append(f"YAML parse error: {exc}")
            continue

        if not isinstance(fixed_cfg, dict):
            print("  [ERROR] Fixed YAML is not a dict")
            previous_failures.append("Fixed YAML was not a dict")
            continue

        # Evaluate
        fixed_result = _evaluate(fixed_cfg, domain_name)
        fixed_score  = fixed_result["overall_score"]

        if verbose:
            print(f"  Fixed quality score: {fixed_score}/10 ({fixed_result['overall_grade']})")

        # Check for catastrophic regressions: reject if any previously-passing
        # dimension now scores 0 or drops by more than 3 points
        regressions = []
        for key, dim in fixed_result["dimensions"].items():
            orig_s  = original_result["dimensions"][key]["score"]
            new_s   = dim["score"]
            delta   = new_s - orig_s
            arrow   = "↑" if delta > 0 else ("↓" if delta < 0 else "→")
            if verbose:
                print(f"    {arrow} {dim['name']}: {orig_s} → {new_s}")
            if orig_s >= 5 and new_s == 0:
                regressions.append(f"{dim['name']} crashed from {orig_s} to 0")
            elif delta <= -4:
                regressions.append(f"{dim['name']} dropped {abs(delta)} pts ({orig_s}→{new_s})")

        if regressions:
            msg = "Attempt caused regressions: " + "; ".join(regressions)
            print(f"  ✗ Rejected — {msg}")
            # Build specific fix guidance for next attempt
            crash_findings = ""
            for key, dim in fixed_result["dimensions"].items():
                if original_result["dimensions"][key]["score"] >= 5 and dim["score"] < original_result["dimensions"][key]["score"] - 2:
                    bad = [f for f in dim["findings"] if f["type"] in ("warning", "fail", "critical")]
                    for f in bad[:3]:
                        crash_findings += f"\n  [{f['type'].upper()}] {dim['name']}: {f['message'][:100]}"
            previous_failures.append(msg + crash_findings)
            # Don't update current — keep the last valid base
            continue

        # Accept this attempt if it's strictly better OR if we have nothing yet.
        # The pipeline calls the actor when the RUNTIME score is below target,
        # which may differ from the static score — so never discard a valid
        # (non-regressive) attempt just because it ties the static baseline.
        if fixed_score > best_score or best_yaml is None:
            if fixed_score > best_score:
                print(f"  ✓ Improvement: {original_score} → {fixed_score}")
            else:
                print(f"  ✓ Saved (ties static baseline at {fixed_score}; runtime BFS will verify)")
            best_score  = fixed_score
            best_cfg    = fixed_cfg
            best_yaml   = fixed_yaml
            best_result = fixed_result

        # Use fixed as base for next attempt
        current_yaml   = fixed_yaml
        current_cfg    = fixed_cfg
        current_result = fixed_result
        previous_failures = []  # reset on valid attempt

    # ── Save result ─────────────────────────────────────────────────────────
    if best_yaml is None:
        print(f"\n✗ No improvement found after {max_attempts} attempt(s). Original score: {original_score}/10")
        return None

    if inplace:
        output_path = config_path
    else:
        # Generate versioned output path: enterprise_ad_v1 → enterprise_ad_v2
        import re
        m = re.match(r"^(.*?)_v(\d+)$", domain_name)
        if m:
            base  = m.group(1)
            ver   = int(m.group(2)) + 1
            new_name = f"{base}_v{ver}"
        else:
            new_name = domain_name + "_fixed"
        output_path = config_path.parent / f"{new_name}.yaml"

    output_path.write_text(best_yaml, encoding="utf-8")

    # Save repair log
    repair_log = {
        "domain":          domain_name,
        "original_score":  original_score,
        "fixed_score":     best_score,
        "output_path":     str(output_path),
        "dimension_scores": {
            key: {
                "before": original_result["dimensions"][key]["score"],
                "after":  best_result["dimensions"][key]["score"],
            }
            for key in original_result["dimensions"]
        },
        "top_remaining_issues": _top_findings(best_result),
    }
    log_path = config_path.parent / f"{output_path.stem}_repair_log.json"
    log_path.write_text(json.dumps(repair_log, indent=2), encoding="utf-8")

    print(f"\n{'='*60}")
    print(f"✓ Repair complete: {original_score}/10 → {best_score}/10")
    print(f"  Fixed config: {output_path}")
    print(f"  Repair log:   {log_path}")
    print(f"  Score delta:  +{best_score - original_score:.1f} points")
    print(f"\nRemaining issues:")
    print(_top_findings(best_result))
    print(f"\nNext step: run the pipeline on the fixed config:")
    print(f"  python tools/run_full_pipeline.py {output_path}")

    return output_path


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Apply LLM-critic-guided fixes to a domain config YAML",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python tools/apply_critic_fixes.py data/enterprise_ad_v1.yaml
              python tools/apply_critic_fixes.py data/enterprise_ad_v1.yaml --inplace
              python tools/apply_critic_fixes.py data/enterprise_ad_v1.yaml --max-attempts 3

            The fixed config is saved as data/<domain>_v<N+1>.yaml by default.
            Use --inplace to overwrite the original file.
        """),
    )
    parser.add_argument("config", type=Path, help="Path to domain config YAML")
    parser.add_argument("--inplace", action="store_true",
                        help="Overwrite the original file instead of creating a new version")
    parser.add_argument("--max-attempts", type=int, default=2,
                        help="Maximum repair attempts (default: 2)")
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose output")
    parser.add_argument("--phase2-out", type=Path, default=None, metavar="DIR",
                        help="Phase 2 output directory containing bfs_metrics.json and "
                             "quality_evaluation.json (enables runtime-aware repair)")

    args = parser.parse_args()

    if not args.config.exists():
        print(f"ERROR: Config file not found: {args.config}")
        sys.exit(1)

    result = repair_config(
        config_path=args.config,
        max_attempts=args.max_attempts,
        inplace=args.inplace,
        verbose=not args.quiet,
        phase2_out=args.phase2_out,
    )
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
