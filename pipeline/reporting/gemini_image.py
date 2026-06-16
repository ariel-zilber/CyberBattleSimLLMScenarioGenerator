#!/usr/bin/env python3
"""Generate a representative scenario image with Gemini.

This module is intentionally dependency-light. It calls the Gemini REST API
directly so the reporting pipeline does not need a new SDK dependency.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import textwrap
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_MODEL = "gemini-3.1-flash-image-preview"


def _read_env_key(*names: str) -> str:
    for name in names:
        val = os.environ.get(name, "").strip()
        if val:
            return val

    env_file = REPO_ROOT / ".env"
    if not env_file.exists():
        return ""

    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        if key.strip() in names:
            return val.strip().strip('"').strip("'")
    return ""


def _extract_comment_section(lines: list[str], heading: str) -> list[str]:
    result: list[str] = []
    in_section = False
    for line in lines:
        stripped = line.strip()
        clean = stripped.lstrip("#").strip()
        if heading in clean:
            in_section = True
            continue
        if in_section:
            if stripped.startswith("config:"):
                break
            if clean.startswith("="):
                continue
            if clean.isupper() and clean.endswith(":"):
                break
            if clean:
                result.append(clean)
    return result


def _first_comment_value(lines: list[str], prefix: str) -> str:
    for line in lines[:40]:
        clean = line.strip().lstrip("#").strip()
        if clean.lower().startswith(prefix.lower()):
            return clean.split(":", 1)[1].strip() if ":" in clean else clean
    return ""


def _summarize_config(cfg: dict[str, Any]) -> dict[str, Any]:
    services = cfg.get("services", {}) or {}
    domains = cfg.get("domains", []) or []

    service_names = list(services.keys())[:12] if isinstance(services, dict) else []
    goal_services = [
        name for name, spec in services.items()
        if isinstance(spec, dict) and spec.get("is_goal")
    ][:6] if isinstance(services, dict) else []

    domain_names: list[str] = []
    group_names: list[str] = []
    for domain in domains:
        if not isinstance(domain, dict):
            continue
        if domain.get("name"):
            domain_names.append(str(domain["name"]))
        for group in domain.get("groups", []) or []:
            if isinstance(group, dict) and group.get("name"):
                group_names.append(str(group["name"]))

    return {
        "service_names": service_names,
        "goal_services": goal_services,
        "domain_names": domain_names[:8],
        "group_names": group_names[:14],
    }


_BG_ZONE_DESCRIPTIONS: dict[str, str] = {
    "Z4_InternetEdge":  "Internet Edge (Z4) — ISP routers, WAF appliances",
    "Z2_HQEdge":        "HQ Edge (Z2) — next-gen firewalls, core switches",
    "Z1_HQVLANs":       "Corporate VLANs (Z1) — domain-joined workstations",
    "Z1_ServerFarm":    "Server Farm (Z1) — file servers, print servers",
    "Z5_BranchOffice":  "Branch Office (Z5) — branch routers, SD-WAN",
    "Z6_AWSCloud":      "AWS Cloud (Z6) — web VMs, app servers",
}


def _build_background_section(config_path: Path) -> str:
    """Return a prompt section describing background zones for the full topology view."""
    try:
        sys.path.insert(0, str(REPO_ROOT))
        from pipeline.cbsim.scenario_expander import expansion_summary
        info = expansion_summary(config_path)
        bg_zones = info.get("will_add", [])
    except Exception:
        return ""

    if not bg_zones:
        return ""

    lines = [
        "",
        "Background infrastructure (draw these zones in the diagram but style them as",
        "inactive/neutral — light grey fill #f0f0f0, no attack arrows, node icons present",
        "but de-emphasised. They represent the full GLOBALTECH enterprise topology that",
        "surrounds the active attack scenario):",
    ]
    for zone in bg_zones:
        desc = _BG_ZONE_DESCRIPTIONS.get(zone, zone)
        lines.append(f"  - {desc}")
    lines += [
        "",
        "The contrast between coloured active zones and grey background zones is the",
        "key visual. All zones share the same diagram space — background zones are NOT",
        "omitted, they anchor the scenario in a realistic full enterprise topology.",
    ]
    return "\n".join(lines)


def build_image_prompt(config_path: Path, user_prompt: str = "") -> str:
    """Create the exact prompt sent to Gemini for a config YAML."""
    text = config_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    cfg = yaml.safe_load(text) or {}

    overview = " ".join(_extract_comment_section(lines, "SCENARIO OVERVIEW"))
    attack_path = _extract_comment_section(lines, "ATTACK PATH")
    progression = _extract_comment_section(lines, "ATTACKER PROGRESSION")
    path_lines = attack_path or progression

    agent = _first_comment_value(lines, "Agent") or cfg.get("metadata", {}).get("agent", "")
    zones = _first_comment_value(lines, "Zones") or cfg.get("metadata", {}).get("zones", "")
    terminal_goal = (
        _first_comment_value(lines, "Terminal goal")
        or cfg.get("metadata", {}).get("terminal_goal", "")
    )
    summary = _summarize_config(cfg)

    title = re.sub(r"_v\d+$", "", config_path.stem).replace("_", " ").title()
    path_text = "\n".join(f"- {line}" for line in path_lines[:8])
    background_section = _build_background_section(config_path)

    prompt = f"""
Create one professional representative image for a CyberBattleSim research scenario.

Scenario title: {title}
Specialist agent: {agent or "unspecified"}
Active zones: {zones or "unspecified"}
Terminal goal: {terminal_goal or ", ".join(summary["goal_services"]) or "terminal asset"}

Scenario overview:
{overview or "Synthetic enterprise cyber range scenario."}

Original generation request:
{user_prompt or "Not recorded."}

Representative attack progression:
{path_text or "- Initial foothold, lateral movement, credential discovery, and terminal goal compromise."}

Key service or host archetypes:
{", ".join(summary["service_names"] or summary["group_names"] or ["enterprise hosts"])}
{background_section}

Visual direction:
- Render a clean, high-fidelity cyber range architecture illustration, not a code screenshot.
- Active zones: coloured bounding boxes with labelled node clusters and a highlighted attack path.
- Background zones (if any): light grey (#f0f0f0) bounding boxes, nodes shown but de-emphasised, no attack arrows.
- Use a serious research-report style suitable for a thesis presentation.
- Avoid real company logos, exploit code, phishing pages, terminal commands, or instructions.
- Prefer readable abstract labels like Internet Edge, HQ VLANs, Server Farm, Cloud, Credentials, and Goal.
- Use a 16:9 composition with strong contrast and enough whitespace for inclusion in a PDF report.
""".strip()
    return textwrap.dedent(prompt)


def _gemini_generate_image(
    prompt: str,
    api_key: str,
    model: str,
    aspect_ratio: str,
    image_size: str,
) -> tuple[bytes, str]:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseModalities": ["TEXT", "IMAGE"],
            "responseFormat": {
                "image": {
                    "aspectRatio": aspect_ratio,
                    "imageSize": image_size,
                }
            },
        },
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    text_parts: list[str] = []
    for cand in body.get("candidates", []) or []:
        for part in cand.get("content", {}).get("parts", []) or []:
            if "text" in part:
                text_parts.append(str(part["text"]))
            inline = part.get("inlineData") or part.get("inline_data")
            if inline and inline.get("data"):
                return base64.b64decode(inline["data"]), "\n".join(text_parts).strip()

    raise RuntimeError("Gemini response did not contain image inlineData")


def generate_for_config(
    config_path: Path,
    output_dir: Path,
    user_prompt: str = "",
    model: str = DEFAULT_MODEL,
    aspect_ratio: str = "16:9",
    image_size: str = "1K",
    strict: bool = False,
) -> Path | None:
    output_dir.mkdir(parents=True, exist_ok=True)
    prompt = build_image_prompt(config_path, user_prompt=user_prompt)
    prompt_path = output_dir / "gemini_image_prompt.txt"
    image_path = output_dir / "gemini_representative_image.png"
    notes_path = output_dir / "gemini_image_notes.txt"
    prompt_path.write_text(prompt + "\n", encoding="utf-8")

    api_key = _read_env_key("GEMINI_API_KEY", "GOOGLE_API_KEY")
    if not api_key:
        msg = (
            "Gemini image generation skipped: set GEMINI_API_KEY or GOOGLE_API_KEY "
            "in the environment or .env."
        )
        notes_path.write_text(msg + "\n", encoding="utf-8")
        print(f"  [WARN] {msg}")
        if strict:
            raise RuntimeError(msg)
        return None

    try:
        image_bytes, notes = _gemini_generate_image(
            prompt=prompt,
            api_key=api_key,
            model=model,
            aspect_ratio=aspect_ratio,
            image_size=image_size,
        )
    except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError) as exc:
        msg = f"Gemini image generation failed: {exc}"
        notes_path.write_text(msg + "\n", encoding="utf-8")
        print(f"  [WARN] {msg}")
        if strict:
            raise RuntimeError(msg) from exc
        return None

    image_path.write_bytes(image_bytes)
    notes_path.write_text((notes or "Image generated successfully.") + "\n", encoding="utf-8")
    print(f"  Generated Gemini image: {image_path}")
    return image_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a Gemini representative image for a CyberBattleSim scenario config."
    )
    parser.add_argument("--config", required=True, help="Path to scenario config YAML")
    parser.add_argument("--output-dir", required=True, help="Directory for image and prompt artifacts")
    parser.add_argument("--user-prompt", default="", help="Original natural-language scenario request")
    parser.add_argument("--user-prompt-file", default="", help="File containing the original scenario request")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Gemini image model (default: {DEFAULT_MODEL})")
    parser.add_argument("--aspect-ratio", default="16:9", help="Output aspect ratio")
    parser.add_argument("--image-size", default="1K", help="Output image size, e.g. 512, 1K, 2K")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if API key or generation fails")
    args = parser.parse_args()

    try:
        user_prompt = args.user_prompt
        if args.user_prompt_file:
            p = Path(args.user_prompt_file)
            if p.exists():
                user_prompt = p.read_text(encoding="utf-8").strip()
        generate_for_config(
            Path(args.config),
            Path(args.output_dir),
            user_prompt=user_prompt,
            model=args.model,
            aspect_ratio=args.aspect_ratio,
            image_size=args.image_size,
            strict=args.strict,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
