from pipeline.reporting.latex_base import e

def methodology_section() -> str:
    return rf"""
\newpage
\section{{How Scenarios Are Generated \& What They Represent}}
\label{{sec:generation}}

The dataset generation follows a two-phase stratified pipeline. Phase 1 employs an LLM-based 
generator that converts natural language scenario descriptions into structured YAML domain 
configurations, validated against a strictly-typed schema. Phase 2 performs stratified sampling 
to generate concrete network instances (Small, Medium, Large) which are then evaluated using 
a suite of heuristic BFS agents to verify solvability and quantify complexity.
"""

def reproducibility_section() -> str:
    return rf"""
\newpage
\section*{{Reproducibility Package}}
\addcontentsline{{toc}}{{section}}{{Reproducibility Package}}
All scenario configurations are versioned in YAML format. The generator uses fixed random seeds 
for topology generation (reproducible given the same configuration and generator version). 
Evaluation results include the full trace of heuristic agent actions.
"""

def ethics_section() -> str:
    return rf"""
\newpage
\section*{{Ethical Considerations}}
\addcontentsline{{toc}}{{section}}{{Ethical Considerations}}
This dataset is composed entirely of synthetic network configurations. No real-world infrastructure 
was scanned or accessed during the generation process. Vulnerability data is sourced from 
publicly available databases (NVD, Bitnami VulnDB) and mapped to synthetic nodes for 
educational and research purposes in the field of automated security testing.
"""

def open_source_section() -> str:
    return rf"""
\section*{{{e("Open Source & Availability")}}}
\addcontentsline{{toc}}{{section}}{{{e("Open Source & Availability")}}}
The Domain Generator and the resulting dataset are provided as open-source artefacts to 
encourage further research into Reinforcement Learning for cyber defence.
"""
