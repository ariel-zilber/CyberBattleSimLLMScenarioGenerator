import shutil
from pathlib import Path
from ..latex_base import e

PROMPT_FILES = [
    ("prompt_01_system_prompt.md",               "prompts/llm_prompts/system_prompt_v2.md"),
    ("prompt_02_schema_definition.md",           "prompts/docs/schema/schema_definition.md"),
    ("prompt_03_domain_architecture_rules.md",   "prompts/docs/schema/domain_architecture_rules.md"),
    ("prompt_04_allowed_properties.md",          "prompts/docs/reference/allowed_properties_dictionary.md"),
    ("prompt_05_vulnerability_catalog.md",       "prompts/docs/reference/vulnerability_catalog.md"),
    ("prompt_06_anti_patterns.md",               "prompts/llm_prompts/anti_patterns.md"),
    ("prompt_07_golden_single_domain.yaml",      "prompts/examples/golden_single_domain.yaml"),
    ("prompt_08_golden_cross_domain.yaml",       "prompts/examples/golden_cross_domain.yaml"),
    ("prompt_09_validation_checklist.md",        "prompts/tools/validation_checklist.md"),
]

UNICODE_SUBS = str.maketrans({
    "\u2014": "--",   # em dash
    "\u2013": "-",    # en dash
    "\u2018": "'",    # left single quote
    "\u2019": "'",    # right single quote
    "\u201c": '"',    # left double quote
    "\u201d": '"',    # right double quote
    "\u2026": "...",  # ellipsis
    "\u00a0": " ",    # non-breaking space
})

def sanitize_for_listings(text: str) -> str:
    return text.translate(UNICODE_SUBS).encode("ascii", errors="replace").decode("ascii")

def llm_generation_prompt_appendix(repo_root: Path, workdir: Path) -> str:
    copied = []
    for dest_name, rel_path in PROMPT_FILES:
        src = repo_root / rel_path
        if src.exists():
            content = src.read_text(encoding="utf-8", errors="replace")
            (workdir / dest_name).write_text(
                sanitize_for_listings(content), encoding="ascii", errors="replace"
            )
            parts = dest_name.split("_", 2)
            clean = parts[2] if len(parts) == 3 else dest_name
            human = clean.replace("_", " ").replace(".md", "").replace(".yaml", "").title()
            copied.append((dest_name, human))
            
    if not copied:
        return ""
        
    prompt_sections = ""
    for dest_name, human_title in copied:
        prompt_sections += rf"\newpage\subsection*{{{e(human_title)}}}" + "\n" + rf"\lstinputlisting{{{dest_name}}}" + "\n\n"
        
    intro_tex = ""
    intro_src = repo_root / "tools" / "prompt_intro.tex"
    if intro_src.exists():
        shutil.copy(intro_src, workdir / "prompt_intro.tex")
        intro_tex = r"\input{prompt_intro.tex}" + "\n"
        
    return rf"""
\newpage
\section*{{Appendix: LLM Generation Prompt}}
\addcontentsline{{toc}}{{section}}{{Appendix: LLM Generation Prompt}}
{intro_tex}
{prompt_sections}
"""
