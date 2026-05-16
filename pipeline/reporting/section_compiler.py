"""
tools/reporting/section_compiler.py
====================================
Utilities for compiling individual LaTeX sections into standalone PDFs and
assembling the combined executive report.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

from .latex_base import PREAMBLE


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run_pdflatex(tex_path: Path, cwd: Path, label: str = "") -> bool:
    """Run pdflatex once in *cwd*.  Return True if successful."""
    result = subprocess.run(
        ["pdflatex", "-interaction=nonstopmode", "-halt-on-error",
         str(tex_path.name)],
        cwd=str(cwd),
        capture_output=True,
    )
    if result.returncode != 0:
        tag = f" [{label}]" if label else ""
        print(f"  [WARN] pdflatex failed{tag} (exit {result.returncode})")
        log_file = cwd / tex_path.with_suffix(".log").name
        if log_file.exists():
            lines = log_file.read_text(errors="replace").splitlines()
            print(f"  --- log tail ---")
            for ln in lines[-25:]:
                print("  " + ln)
    return result.returncode == 0


def _copy_assets_to_dir(workdir: Path, target_dir: Path) -> None:
    """
    Copy all .pdf, .png, .txt and .tex asset files from *workdir* into
    *target_dir* so that a LaTeX file compiled in *target_dir* can resolve
    \\includegraphics{} and \\lstinputlisting{} references by file name alone.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    for asset in workdir.iterdir():
        if asset.suffix.lower() in (".pdf", ".png", ".txt", ".tex", ".md", ".yaml") and asset.is_file():
            dst = target_dir / asset.name
            if not dst.exists() or asset.stat().st_mtime > dst.stat().st_mtime:
                shutil.copy2(asset, dst)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def compile_section(
    section_name: str,
    content: str,
    output_dir: Path,
    workdir: Path,
) -> "Path | None":
    """
    Wrap *content* in a standalone LaTeX document (PREAMBLE + document env),
    compile it in a temporary subdirectory that contains copies of all assets
    from *workdir*, then save both the .tex and .pdf to
    *output_dir/sections/<section_name>*.{tex,pdf}.

    Returns the destination PDF path on success, None on failure.
    """
    sections_dir = output_dir / "sections"
    sections_dir.mkdir(parents=True, exist_ok=True)

    # Build the full standalone document
    full_tex = (
        PREAMBLE
        + r"\begin{document}" + "\n"
        + content
        + "\n"
        + r"\end{document}" + "\n"
    )

    # Use a temp subdirectory so intermediate pdflatex files don't clutter workdir
    with tempfile.TemporaryDirectory() as _tmp:
        tmp_dir = Path(_tmp)

        # Copy all assets (figures, listings etc.) so the standalone can see them
        _copy_assets_to_dir(workdir, tmp_dir)

        tex_file = tmp_dir / f"{section_name}.tex"
        tex_file.write_text(full_tex, encoding="utf-8")

        # Two passes: second pass resolves any internal cross-references
        ok = _run_pdflatex(tex_file, tmp_dir, label=section_name)
        if ok:
            _run_pdflatex(tex_file, tmp_dir, label=f"{section_name} pass2")

        pdf_src = tmp_dir / f"{section_name}.pdf"
        if pdf_src.exists():
            dest_pdf = sections_dir / f"{section_name}.pdf"
            dest_tex = sections_dir / f"{section_name}.tex"
            shutil.copy(pdf_src, dest_pdf)
            # Save the bare content (no preamble wrapper) for inclusion in
            # the combined report
            dest_tex.write_text(content, encoding="utf-8")
            return dest_pdf
        else:
            print(f"  [WARN] No PDF produced for section '{section_name}'")
            # Still save the .tex even if compilation failed, for debugging
            dest_tex = sections_dir / f"{section_name}.tex"
            dest_tex.write_text(content, encoding="utf-8")
            return None


def compile_full_report(
    title: str,
    sections: list,
    output_path: Path,
    workdir: Path,
) -> "Path | None":
    """
    Assemble all sections into one combined LaTeX document and compile 3×
    so TOC page numbers and cross-references resolve correctly.

    Parameters
    ----------
    title:
        Report title — used only for a helpful print; the actual cover page
        content is expected to be the first entry in *sections*.
    sections:
        List of (name, content) tuples.  *name* is a short slug
        (e.g. "01_summary"); *content* is the LaTeX body fragment for that
        section (no preamble, no \\begin{document}).
    output_path:
        Final destination for the PDF.  Its parent is created if necessary.
    workdir:
        Directory containing figure PDFs / PNGs that the LaTeX can reference.

    Returns the output PDF path on success, None on failure.
    """
    print(f"  Assembling combined report '{title}' ({len(sections)} sections)...")

    # Write each section as a separate .tex file so \input{name.tex} works
    for name, content in sections:
        (workdir / f"{name}.tex").write_text(content, encoding="utf-8")

    # Build the combined document
    section_inputs = "\n".join(
        rf"\input{{{name}.tex}}" for name, _ in sections
    )
    main_tex_content = (
        PREAMBLE
        + r"\begin{document}" + "\n"
        + section_inputs + "\n"
        + r"\end{document}" + "\n"
    )

    main_tex = workdir / "main.tex"
    main_tex.write_text(main_tex_content, encoding="utf-8")

    # Three pdflatex passes: pass 1 builds the .aux/.toc, passes 2-3 resolve refs
    ok = True
    for pass_num in range(1, 4):
        print(f"    pdflatex pass {pass_num}/3 ...")
        ok = _run_pdflatex(main_tex, workdir, label=f"full report pass {pass_num}")
        if not ok:
            print(f"  [WARN] Full report compilation failed on pass {pass_num}")
            break

    main_pdf = workdir / "main.pdf"
    if main_pdf.exists():
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(main_pdf, output_path)
        # Also copy the .tex source for reference / debugging
        shutil.copy(main_tex, output_path.with_suffix(".tex"))
        print(f"    Combined report saved: {output_path}")
        return output_path
    else:
        print("  ERROR: pdflatex did not produce main.pdf for the combined report")
        return None
