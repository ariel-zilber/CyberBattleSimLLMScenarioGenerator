from ..latex_base import e

def cve_eda_section() -> str:
    try:
        from tools.generate_cve_eda_report import build_section as _eda_build_section
        _eda_body = _eda_build_section()
        return rf"""
\clearpage
\subsection{{Vulnerability Database EDA \& MITRE ATT\&CK Coverage}}
\label{{sec:cve_eda}}
{_eda_body}
"""
    except Exception as ex:
        print(f"  [WARN] CVE EDA section skipped: {ex}")
        return ""
