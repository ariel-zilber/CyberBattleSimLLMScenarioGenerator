"""
tools/reporting/sections/agent_design.py
=========================================
Section describing the 5 specialised lower-level DRL agents, their MITRE ATT&CK
focus, training scenarios, key vulnerabilities and properties, and the rationale
for this allocation.

NOTE: All LaTeX-building helpers use plain string concatenation (not rf-strings)
to avoid the Python <3.12 restriction on backslashes inside f-string expressions.
"""

import re as _re

from pipeline.reporting.latex_base import e

# ─────────────────────────────────────────────────────────────────────────────
# Agent specifications
# ─────────────────────────────────────────────────────────────────────────────

_AGENTS = [
    {
        "id":    1,
        "name":  "Scout",
        "role":  r"Initial Access \& Discovery Specialist",
        "color": "titleblue",
        "tactics": [
            ("TA0001", "Initial Access"),
            ("TA0043", "Reconnaissance"),
            ("TA0007", "Discovery"),
        ],
        "objective": (
            r"Identify exposed attack surfaces, map network topology, and establish "
            r"the first foothold in a target environment.  The Scout prioritises "
            r"\emph{exploration efficiency}: given a flat or lightly-segmented "
            r"network with 35--50 heterogeneous nodes, it must determine \emph{which} "
            r"of the many reachable nodes are actually vulnerable before attempting "
            r"any exploit."
        ),
        "scenarios": [
            (r"ta0001\_initial\_access\_v2",
             r"4-domain perimeter with VPN, RDP, IIS, PAN-OS -- maximal ingress-vector diversity"),
            (r"flat\_mixed\_os\_v1",
             r"Single flat subnet, 35--50 Windows/Linux/network-device nodes, SNMP/Telnet on 30\% -- maximum enumeration surface"),
            (r"network\_device\_infra\_v3",
             r"4-domain routed infrastructure; only probe vuln is \texttt{Remote.Probe.NetworkDevice} -- forces device-aware discovery"),
            (r"ta0007\_discovery\_v2",
             r"AD + SNMP monitoring + DNS -- mixed Windows/network discovery corpus"),
        ],
        "services": [
            "FortiGateVPN", "PanOSFirewall", "ExposedRDPServer", "IISWebServer",
            "WindowsDNSServer", "SNMPMonitoringServer", "CiscoAccessSwitch",
            "CiscoRouter", "JuniperRouter", "VPNConcentrator",
        ],
        "cves": [
            ("CVE-2019-0708", "BlueKeep",            "RDP pre-auth RCE",           "CVSS 9.8"),
            ("CVE-2020-0796", "SMBGhost",             "SMBv3 unauthenticated RCE",  "CVSS 10.0"),
            ("CVE-2019-1182", "DejaBlue",             "RDP RCE (Win 8/10/Server)",  "CVSS 9.8"),
            ("CVE-2022-0018", "PAN-OS GP Auth Leak",  "GlobalProtect cred leak",    "CVSS 8.2"),
            ("CVE-2018-13384","FortiGate SSL Redir",  "FortiSSL auth bypass",       "CVSS 6.8"),
            ("CVE-2020-3216", "Cisco IOS Auth Bypass","IOS privilege bypass",       "CVSS 7.4"),
        ],
        "vuln_types":  [r"discovery", r"leak\_neighbors",
                        r"Remote.Probe.NetworkDevice", r"Remote.Probe.Windows", r"Remote.Probe.Linux"],
        "properties":  ["AnonymousAccess", "SNMPEnabled", "TelnetEnabled",
                        "PublicFacingService", "OpenManagementPort"],
        "ports":       [22, 23, 53, 80, 161, 443, 1194, 3389],
        "rationale": (
            r"The Scout specialises in the most \emph{combinatorially explosive} "
            r"phase of a cyberattack: deciding which node to probe next when dozens "
            r"of potential targets are visible but only a handful carry exploitable "
            r"vulnerabilities.  Training on the flat mixed-OS corpus teaches the "
            r"agent to recognise OS fingerprints (SNMP community strings, Telnet "
            r"banners, Windows probe responses) as cheap signals that stratify the "
            r"action space.  The network-device corpus adds policy-aware routing "
            r"knowledge, essential for segmented enterprise networks."
        ),
    },
    {
        "id":    2,
        "name":  "Harvester",
        "role":  r"Credential Access, Execution \& Persistence Specialist",
        "color": "scoreA",
        "tactics": [
            ("TA0006", "Credential Access"),
            ("TA0002", "Execution"),
            ("TA0003", "Persistence"),
        ],
        "objective": (
            r"Extract, forge, and replay credentials; achieve code execution through "
            r"web applications and CI/CD pipelines; and maintain persistent access "
            r"for subsequent phases.  The Harvester operates after initial access "
            r"has been established and focuses on \emph{maximising the credential "
            r"footprint} so that downstream lateral-movement and escalation agents "
            r"have the widest possible key-ring."
        ),
        "scenarios": [
            (r"ta0006\_credential\_access\_v1",
             r"4-domain AD environment: DomainController, HashVault, FileServerWithCreds, LegacyWorkstation -- concentrated credential hierarchy"),
            (r"ta0002\_execution\_v2",
             r"4-domain CI/CD pipeline: JenkinsMaster, BuildAgent, ArtifactRegistry, KafkaBroker -- code-execution through build automation"),
            (r"ta0003\_persistence\_v1",
             r"3-domain web stack: Nginx--WordPress--MySQL--Redis--Drupal -- teaches persistence in web service chains"),
            (r"jenkins\_cicd\_v2",
             r"3-domain containerised CI/CD with OAuth, Grafana, PostgreSQL, Gitea -- credential exfiltration from secret stores"),
            (r"wordpress\_web\_stack\_v3",
             r"3-domain LAMP stack with Redis cache -- RCE-to-credential chain in a typical web environment"),
            (r"wordpress\_ad\_hybrid\_v3",
             r"4-domain hybrid: WordPress + AD DomainController -- bridges web and directory credential stores"),
        ],
        "services": [
            "DomainController", "HashVault", "FileServerWithCreds", "JenkinsMaster",
            "BuildAgent", "WordPressNode", "MySQLServer", "GiteaServer",
            "OAuthProxy", "LegacyWorkstation",
        ],
        "cves": [
            ("CVE-2021-36934", "HiveNightmare",      "SAM/SYSTEM dump without admin",   "CVSS 7.8"),
            ("CVE-2023-23397", "Outlook NTLM Relay", "Hash capture via calendar invite", "CVSS 9.8"),
            ("CVE-2021-26897", "Windows DNS RCE",    "Heap overflow pre-auth",           "CVSS 9.8"),
            ("CVE-2022-26904", "UserProfileSvc",     "Persistent service abuse",         "CVSS 7.0"),
            ("CVE-2021-41379", "MSI Always-Install", "Elevated MSI execution",           "CVSS 5.5"),
            ("CVE-2021-34473", "ProxyShell",         "Exchange RCE + privilege chain",   "CVSS 9.8"),
        ],
        "vuln_types": [r"credential\_leak", r"leak\_known\_credentials",
                       r"Remote.Probe.Container", r"Remote.Probe.Linux"],
        "properties": ["ServiceCredentials", "CredentialLeakage",
                       "WebApplicationExposed", "CIBuildAccess", "SecretStoreAccess"],
        "ports":      [22, 80, 88, 139, 389, 443, 445, 636, 3000, 3268, 3306, 8080, 8200, 50000],
        "rationale": (
            r"Credential access is the single highest-value action in CyberBattleSim: "
            r"a leaked credential can unlock an entire subnet of nodes that would "
            r"otherwise require individual exploits.  Training the Harvester across "
            r"both web-centric (WordPress, Jenkins) and directory-centric "
            r"(AD DomainController, HashVault) scenarios teaches it to model "
            r"\emph{credential dependency graphs} -- which service's secret "
            r"propagates to which downstream target.  The CI/CD scenarios add a "
            r"particularly realistic dimension: pipeline credentials often carry "
            r"deployment privileges far exceeding their apparent scope."
        ),
    },
    {
        "id":    3,
        "name":  "Pivot",
        "role":  "Lateral Movement Specialist",
        "color": "scoreB",
        "tactics": [
            ("TA0008", "Lateral Movement"),
            ("TA0005", "Defense Evasion"),
        ],
        "objective": (
            r"Navigate multi-tier and multi-domain topologies by chaining exploits "
            r"and credentials across subnet boundaries.  The Pivot agent specialises "
            r"in discovering \emph{non-obvious} paths -- shadow connections, hub "
            r"nodes reachable from multiple tiers, and cross-domain trust "
            r"relationships -- that reduce the hop count to the goal."
        ),
        "scenarios": [
            (r"ta0008\_lateral\_movement\_v1",
             r"4-domain hop-chain: ExternalWorkstation $\rightarrow$ JumpServer $\rightarrow$ FileShare $\rightarrow$ InternalWorkstation $\rightarrow$ MySQL"),
            (r"deep\_linux\_hub\_v1",
             r"5-tier Linux hub: shadow path WorkerTier $\rightarrow$ DataTier bypasses 4-hop canonical chain -- teaches shortcut discovery"),
            (r"bitnami\_cloud\_native\_v1",
             r"5-tier microservice stack: shadow RedisHub node reachable from AppTier and WorkerTier -- complex hub topology"),
            (r"meta\_ambiguous\_v1",
             r"4-domain ambiguous topology: multiple valid paths to DataVault -- forces route-cost comparison"),
            (r"meta\_multicluster\_xl\_v1",
             r"XL multi-cluster scenario: tests scalability of lateral traversal across 50+ nodes and 5 domains"),
        ],
        "services": [
            "AdminJumpServer", "FileShareServer", "InternalWorkstation",
            "RedisHubCache", "RedisHubNode", "NodeAppServer",
            "KafkaBroker", "NginxIngress", "DataVaultServer",
        ],
        "cves": [
            ("CVE-2020-0796", "SMBGhost",    "SMBv3 RCE -- cross-subnet pivot", "CVSS 10.0"),
            ("CVE-2008-4250", "MS08-067",    "SMBv1 RCE -- legacy node pivot",  "CVSS 10.0"),
            ("CVE-2022-26809", "RPC RCE 2",  "MSRPC heap overflow",             "CVSS 9.8"),
            ("CVE-2021-44548", "SMB Info",   "SMB information disclosure",      "CVSS 7.5"),
            ("CVE-2022-30221", "RPC RCE 1",  "Windows Graphics RPC RCE",        "CVSS 9.8"),
        ],
        "vuln_types": [r"credential\_leak", r"leak\_known\_credentials",
                       r"leak\_neighbors", r"Remote.Probe.LinuxAppServer",
                       r"Remote.Probe.LinuxWorker"],
        "properties": ["MustConnect", "SubnetBridgeNode", "HubNode",
                       "ShadowPath", "CrossDomainTrust"],
        "ports":      [22, 80, 139, 443, 445, 3389, 6379, 8080, 9092],
        "rationale": (
            r"Lateral movement is the phase where topology awareness matters most. "
            r"A naive agent exhaustively tries all visible nodes; a trained Pivot "
            r"agent learns to \emph{identify hub nodes} (nodes reachable from "
            r"multiple tiers) as high-leverage pivot points.  The hub scenarios "
            r"(deep\_linux\_hub and bitnami\_cloud\_native) provide the critical "
            r"training signal: both have a Redis hub node that reduces the optimal "
            r"path from 4 hops to 2 hops, but only if the agent discovers the "
            r"shadow connection.  The XL meta scenario stress-tests scalability "
            r"beyond the standard 10--20 node range."
        ),
    },
    {
        "id":    4,
        "name":  "Escalator",
        "role":  "Privilege Escalation Specialist",
        "color": "scoreC",
        "tactics": [
            ("TA0004", "Privilege Escalation"),
            ("TA0005", "Defense Evasion"),
        ],
        "objective": (
            r"On an already-owned node, identify and exploit misconfigurations or "
            r"vulnerabilities to elevate from a low-privilege shell to SYSTEM / "
            r"Domain Admin.  The Escalator must reason about \emph{local} "
            r"access-control structures: certificate templates, service accounts, "
            r"print spooler paths, and kernel exploits."
        ),
        "scenarios": [
            (r"ta0004\_privesc\_v1",
             r"4-domain AD privesc: DomainController, ADCertServer, PrintServer, ServiceAccountServer -- covers ADCS ESC1/ESC8 and PrintNightmare chains"),
            (r"windows\_privesc\_v1",
             r"3-domain heterogeneous Windows: Win7/Win10/Win2019/Win2022 -- teaches OS-version-aware exploit selection"),
            (r"scada\_ad\_hybrid\_v1",
             r"2-domain AD + SCADA: AD privesc leads to OT HMI/PLC access -- escalation opens entirely new attack surfaces"),
            (r"enterprise\_ad\_v6",
             r"3-domain AD production replica: DomainController, AppServer, FileServer, LegacyWorkstation -- general-purpose AD escalation curriculum"),
        ],
        "services": [
            "DomainController", "ADCertServer", "PrintServer",
            "ServiceAccountServer", "LowPrivWorkstation",
            "Win7Workstation", "Win10Workstation", "Win2019FileServer",
            "DomainControllerWin2022",
        ],
        "cves": [
            ("CVE-2022-26923", "Certifried",       "ADCS domain privesc via cert template",   "CVSS 8.8"),
            ("CVE-2022-34691", "ADCS CertSpoof",   "Certificate impersonation",               "CVSS 8.8"),
            ("CVE-2021-34527", "PrintNightmare",   "Print Spooler SYSTEM RCE",                "CVSS 8.8"),
            ("CVE-2023-21674", "ALPC EOP",         "Advanced LPC elevation of privilege",     "CVSS 8.8"),
            ("CVE-2021-34486", "Win32k EOP",       "Win32k kernel privilege escalation",      "CVSS 7.8"),
            ("CVE-2022-21857", "AD Services EOP",  "AD local escalation via services",        "CVSS 8.8"),
            ("CVE-2021-36934", "HiveNightmare",    "Unprivileged SAM/NTLM hash dump",         "CVSS 7.8"),
        ],
        "vuln_types": [r"credential\_leak", r"leak\_known\_credentials",
                       r"Remote.Probe.Windows", r"Remote.Probe.WindowsServer",
                       r"Remote.Probe.DomainController"],
        "properties": ["LowPrivilegeAccess", "ServiceAccountPresent",
                       "ADCSTemplateVulnerable", "PrintSpoolerEnabled",
                       "KernelUnpatched"],
        "ports":      [88, 135, 139, 389, 445, 631, 636, 3268, 3389, 9100],
        "rationale": (
            r"Privilege escalation in Windows/AD environments is highly version- "
            r"and configuration-dependent.  The Escalator must learn that "
            r"\texttt{ADCertServer} templates (ESC1/ESC8) are only exploitable "
            r"if the domain has a misconfigured CA, that PrintNightmare only "
            r"applies to specific patch levels, and that the Win7 legacy workstation "
            r"corpus opens kernel exploit paths unavailable on Win10+.  "
            r"The SCADA-AD hybrid scenario adds a key curriculum signal: "
            r"successfully escalating in the AD tier \emph{unlocks} the OT tier "
            r"goal nodes, teaching the agent that privilege escalation is not always "
            r"a terminal action but can open entirely new attack surfaces."
        ),
    },
    {
        "id":    5,
        "name":  "Endgame",
        "role":  r"Collection, Exfiltration \& Impact Specialist",
        "color": "scoreD",
        "tactics": [
            ("TA0009", "Collection"),
            ("TA0010", "Exfiltration"),
            ("TA0040", "Impact"),
        ],
        "objective": (
            r"Achieve the final mission objective: exfiltrate sensitive data from "
            r"IT systems \emph{and/or} disrupt operational technology (OT) "
            r"infrastructure.  The Endgame agent must navigate the IT/OT boundary "
            r"and operate ICS-protocol-aware exploits on PLCs, SCADA servers, "
            r"Historians, and HMIs."
        ),
        "scenarios": [
            (r"ta0009\_collection\_v1",
             r"3-domain DevSecOps stack: VaultServer, PostgreSQL, Gitea, Grafana, Jenkins -- aggregation from multiple secret and database sources"),
            (r"ta0040\_impact\_v1",
             r"3-domain Windows impact: DomainController, BackupServer, FinancialDatabase, ExposedWorkstation -- ransomware-style objective"),
            (r"scada\_ics\_v2",
             r"3-domain pure OT: ControlLogixPLC, ModiconPLC, SCADAServer, OPCServer, HistorianServer -- ICS protocol exploitation corpus"),
            (r"it\_ot\_dual\_goal\_v1",
             r"5-domain dual-goal: two simultaneous objectives (IT exfil \emph{and} OT disruption) -- teaches multi-goal reward balancing"),
            (r"meta\_it\_ot\_hybrid\_v1",
             r"5-domain Siemens S7 + WinCC Historian: cross-boundary scenario stressing the IT/OT gap"),
        ],
        "services": [
            "VaultServer", "PostgreSQLServer", "GiteaServer",
            "FinancialDatabase", "BackupServer",
            "ControlLogixPLC", "ModiconM340PLC", "SCADAServer",
            "OPCServer", "HistorianServer", "WinCCHistorianServer",
        ],
        "cves": [
            ("CVE-2023-21527", "iSCSI DataExfil",       "Windows iSCSI data exfiltration",      "CVSS 7.5"),
            ("CVE-2022-24472", "SharePoint DataExfil",  "SharePoint information disclosure",     "CVSS 5.7"),
            ("CVE-2017-12069", "Siemens WinCC OPC",     "WinCC OPC Server XML injection",        "CVSS 8.2"),
            ("CVE-2020-5653",  "OPC-UA Buffer Overflow","OPC-UA stack buffer overflow",          "CVSS 9.8"),
            ("CVE-2021-27460", "FactoryTalk RCE",       "Rockwell FactoryTalk remote code exec", "CVSS 9.8"),
            ("CVE-2018-7760",  "Schneider M340 RCE",    "Modicon M340 unauthenticated RCE",      "CVSS 9.8"),
            ("CVE-2022-35247", "RUGGEDCOM Exfil",       "Config read via unauthenticated API",   "CVSS 5.3"),
        ],
        "vuln_types": [r"goal\_access", r"Remote.Probe.Historian",
                       r"Remote.Probe.OTDevice", r"Remote.Probe.Windows"],
        "properties": ["SensitiveDataPresent", "GoalNode", "OTDevice",
                       "ICSProtocol", "BackupAccess", "VaultAccess"],
        "ports":      [22, 102, 139, 445, 502, 1433, 3000, 4840, 5432, 8200, 44818],
        "rationale": (
            r"The Endgame agent operates in the most \emph{heterogeneous} "
            r"environment in the dataset: it must reason simultaneously about "
            r"relational databases (PostgreSQL), secret vaults (HashiCorp Vault), "
            r"industrial PLCs (Rockwell, Schneider, Siemens), and legacy SCADA "
            r"historians.  The dual-goal scenario (\texttt{it\_ot\_dual\_goal}) "
            r"is especially important: it forces the agent to balance two "
            r"reward streams and discover that the OT disruption goal can only "
            r"be reached via the IT credential chain, mirroring the Industroyer/"
            r"TRITON attack pattern observed in real-world ICS incidents."
        ),
    },
]

# Meta scenario assignments
_META_ASSIGNMENTS = [
    (r"meta\_killchain\_v1",
     "All 5 agents",
     r"Full 5-domain IT kill chain: Apache $\rightarrow$ IIS $\rightarrow$ MSSQL $\rightarrow$ FileServer $\rightarrow$ DomainController. Shared benchmark measuring each agent's contribution to the complete attack chain."),
    (r"meta\_ambiguous\_v1",
     r"Agents 3 \& 4",
     r"4-domain ambiguous topology with multiple valid paths. Agent 3 (Pivot) learns route-comparison heuristics; Agent 4 (Escalator) practises recognising which paths require privilege escalation."),
    (r"meta\_it\_ot\_hybrid\_v1",
     r"Agents 4 \& 5",
     r"5-domain Siemens S7 + corporate AD hybrid. Agent 4 escalates in the IT tier; Agent 5 crosses the OT boundary to the Historian and PLC."),
    (r"meta\_deadend\_v1",
     r"Agents 1 \& 2",
     r"4-domain scenario with deliberately planted dead-end nodes. Trains the Scout and Harvester to recognise and abandon unproductive paths early."),
]


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def agent_design_section(entries: list = None) -> str:
    """Return full LaTeX for the 5-agent design section."""
    parts = [
        _intro(),
        _overview_table(),
    ]
    for ag in _AGENTS:
        parts.append(_agent_block(ag))
    parts += [
        _scenario_matrix(),
        _jaccard_matrix(),
        _jaccard_properties(),
        _jaccard_local_vulns(),
        _jaccard_remote_vulns(),
        _jaccard_ports(),
        _jaccard_combined(),
        _scenario_stats_page(entries or []),
        _meta_scenarios(),
        _synergy(),
    ]
    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Sub-section helpers (plain string concat — no rf-string backslash issues)
# ─────────────────────────────────────────────────────────────────────────────

def _tex(s: str) -> str:
    """Wrap in \texttt{}."""
    return "\\texttt{" + s + "}"


def _color(color: str, text: str) -> str:
    return "\\textcolor{" + color + "}{\\textbf{" + text + "}}"


def _intro() -> str:
    return r"""
\clearpage
\section{Specialised Agent Design}
\label{sec:agent_design}

\subsection{Motivation and Design Philosophy}

CyberBattleSim's action space grows combinatorially with network size: a 50-node
environment with 9 CVEs per node yields $O(450)$ candidate actions per step, but
fewer than 5\% are ever on an optimal attack path.  A single monolithic DRL agent
must simultaneously learn \emph{which nodes to probe}, \emph{which credentials
unlock which targets}, \emph{how to traverse multi-tier topologies}, \emph{how to
escalate privileges on a specific OS}, and \emph{how to reach OT-layer goals} -- a
curriculum too broad to converge reliably within academic episode budgets.

The solution adopted in this work is a \textbf{hierarchical ensemble of five
specialised lower-level agents}, each trained on a curated sub-corpus of scenarios
that maximises the training signal relevant to a single kill-chain phase.  A
higher-level coordinator routes execution to the appropriate specialist at each
phase transition.

The five phases map directly to MITRE ATT\&CK Enterprise:

\begin{center}
\begin{tabular}{clll}
\toprule
\textbf{\#} & \textbf{Agent} & \textbf{Kill-chain phase} & \textbf{Primary tactics} \\
\midrule
1 & Scout      & Reconnaissance \& Initial Access & TA0001, TA0043, TA0007 \\
2 & Harvester  & Credential Access \& Execution   & TA0006, TA0002, TA0003 \\
3 & Pivot      & Lateral Movement                 & TA0008, TA0005 \\
4 & Escalator  & Privilege Escalation              & TA0004, TA0005 \\
5 & Endgame    & Collection \& Impact              & TA0009, TA0010, TA0040 \\
\bottomrule
\end{tabular}
\end{center}
"""


def _overview_table() -> str:
    rows = ""
    for ag in _AGENTS:
        tactic_str = ", ".join(_tex(t[0]) for t in ag["tactics"])
        row = (
            "  " + str(ag["id"]) + " & "
            + _color(ag["color"], ag["name"]) + " & "
            + ag["role"] + " & "
            + tactic_str + " & "
            + str(len(ag["scenarios"])) + " \\\\\n"
        )
        rows += row

    return (
        "\n\\subsection{Agent Overview}\n\n"
        "\\noindent\n"
        "\\begin{tabular}{clp{4.5cm}p{4.5cm}c}\n"
        "\\toprule\n"
        "\\textbf{\\#} & \\textbf{Name} & \\textbf{Role} & "
        "\\textbf{MITRE Tactics} & \\textbf{Scenarios} \\\\\n"
        "\\midrule\n"
        + rows
        + "\\bottomrule\n\\end{tabular}\n"
    )


def _agent_block(ag: dict) -> str:
    agent_id   = str(ag["id"])
    agent_name = ag["name"]
    agent_role = ag["role"]

    # Tactic list
    tactic_items = "".join(
        "  \\item \\textbf{" + _tex(t[0]) + "} --- " + t[1] + "\n"
        for t in ag["tactics"]
    )

    # Training scenario table rows
    scen_rows = "".join(
        "  " + _tex(name) + " & " + reason + " \\\\\n"
        for name, reason in ag["scenarios"]
    )

    # CVE table rows
    cve_rows = "".join(
        "  " + _tex(cve_id) + " & " + label + " & " + e(desc) + " & " + cvss + " \\\\\n"
        for cve_id, label, desc, cvss in ag["cves"]
    )

    # Inline lists
    service_items = ", ".join(_tex(s) for s in ag["services"])
    vuln_items    = ", ".join(_tex(v) for v in ag["vuln_types"])
    prop_items    = ", ".join(_tex(p) for p in ag["properties"])

    obj = ag["objective"]
    rat = ag["rationale"]

    return (
        "\n\\clearpage\n"
        "\\subsection{Agent " + agent_id + ": " + agent_name + " --- " + agent_role + "}\n"
        "\\label{sec:agent" + agent_id + "}\n"
        "\n\\subsubsection*{Objective}\n"
        + obj + "\n"
        "\n\\subsubsection*{MITRE ATT\\&CK Tactics}\n"
        "\\begin{itemize}\n"
        + tactic_items
        + "\\end{itemize}\n"
        "\n\\subsubsection*{Training Scenarios}\n"
        "\\noindent\\begin{tabular}{p{4.5cm}p{11cm}}\n"
        "\\toprule\n"
        "\\textbf{Scenario} & \\textbf{Rationale for inclusion} \\\\\n"
        "\\midrule\n"
        + scen_rows
        + "\\bottomrule\n\\end{tabular}\n"
        "\n\\subsubsection*{Target Services}\n"
        "\\small " + service_items + "\n"
        "\n\\normalsize\n"
        "\\subsubsection*{Key Vulnerability CVEs}\n"
        "\\noindent\\begin{tabular}{llp{7cm}l}\n"
        "\\toprule\n"
        "\\textbf{CVE} & \\textbf{Label} & \\textbf{Description} & \\textbf{Severity} \\\\\n"
        "\\midrule\n"
        + cve_rows
        + "\\bottomrule\n\\end{tabular}\n"
        "\n\\subsubsection*{CBS Vulnerability Types}\n"
        "\\small " + vuln_items + "\n"
        "\n\\subsubsection*{Node Properties Leveraged}\n"
        "\\small " + prop_items + "\n"
        "\n\\normalsize\n"
        "\\subsubsection*{Allocation Rationale}\n"
        + rat + "\n"
    )


def _scenario_matrix() -> str:
    # Collect unique scenarios in order (across all agents)
    seen: set = set()
    all_scens = []
    for ag in _AGENTS:
        for name, _ in ag["scenarios"]:
            if name not in seen:
                seen.add(name)
                all_scens.append(name)

    # Rotated agent column headers
    header_cols = "".join(
        " & \\rotatebox{60}{" + _color(ag["color"], ag["name"]) + "}"
        for ag in _AGENTS
    )

    # Data rows: each scenario is a row, agents are columns
    rows = ""
    for scen in all_scens:
        row = "  \\small " + _tex(scen)
        for ag in _AGENTS:
            agent_scens = {n for n, _ in ag["scenarios"]}
            row += " & $\\bullet$" if scen in agent_scens else " &"
        rows += row + " \\\\\n"

    return (
        "\n\\clearpage\n"
        "\\subsection{Training Scenario Assignment Matrix}\n"
        "\\label{sec:scenario_matrix}\n\n"
        "Each row is a primary training scenario; a bullet indicates the agent trains on that scenario.  "
        "Meta-scenarios (shared across agents) are listed separately in Section~\\ref{sec:meta_scenarios}.\n\n"
        "\\vspace{0.4cm}\n"
        "\\noindent\n"
        "\\begin{tabular}{p{5.5cm}ccccc}\n"
        "\\toprule\n"
        "\\textbf{Scenario}" + header_cols + " \\\\\n"
        "\\midrule\n"
        + rows
        + "\\bottomrule\n\\end{tabular}\n"
        "\\normalsize\n"
    )


def _render_j_matrix(J: list, title: str, description: str, label: str) -> str:
    """Render a precomputed 5×5 Jaccard matrix as a LaTeX heatmap table."""
    n = len(_AGENTS)
    headers = " & ".join(
        "\\rotatebox{45}{" + _color(ag["color"], ag["name"]) + "}"
        for ag in _AGENTS
    )
    rows = ""
    for i, ag_i in enumerate(_AGENTS):
        row = _color(ag_i["color"], ag_i["name"])
        for j in range(n):
            val = J[i][j]
            if i == j:
                cell_bg  = "scoreA!50"
                cell_txt = "1.00"
            else:
                intensity = min(100, round(val * 100))
                cell_bg   = "titleblue!" + str(intensity)
                cell_txt  = "{:.2f}".format(val)
            row += " & \\cellcolor{" + cell_bg + "}" + cell_txt
        rows += row + " \\\\\n"

    return (
        "\n\\subsection{" + title + "}\n"
        "\\label{sec:" + label + "}\n\n"
        + description + "\n\n"
        "\\vspace{0.3cm}\n"
        "\\noindent\n"
        "\\begin{tabular}{lccccc}\n"
        "\\toprule\n"
        " & " + headers + " \\\\\n"
        "\\midrule\n"
        + rows
        + "\\bottomrule\n\\end{tabular}\n\n"
        "\\smallskip\n"
        "{\\small Colour scale: white $= 0.00$, full blue $= 1.00$; "
        "diagonal (self-similarity) highlighted green.}\n"
    )


def _jaccard_render(agent_sets: list, title: str, description: str, label: str) -> str:
    """Compute Jaccard from sets and delegate to _render_j_matrix."""
    n = len(_AGENTS)
    J: list = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            if i == j:
                J[i][j] = 1.0
            else:
                inter = len(agent_sets[i] & agent_sets[j])
                union = len(agent_sets[i] | agent_sets[j])
                J[i][j] = inter / union if union > 0 else 0.0
    return _render_j_matrix(J, title, description, label)


def _jaccard_matrix() -> str:
    # Build per-agent scenario sets (primary + meta assignments)
    agent_sets = [{name for name, _ in ag["scenarios"]} for ag in _AGENTS]
    for meta_name, agents_str, _ in _META_ASSIGNMENTS:
        if "All" in agents_str:
            for s in agent_sets:
                s.add(meta_name)
        else:
            nums = [int(x) for x in _re.findall(r'\d+', agents_str)]
            for idx in nums:
                agent_sets[idx - 1].add(meta_name)

    description = (
        "The Jaccard similarity $J(A,B) = |S_A \\cap S_B|\\,/\\,|S_A \\cup S_B|$ "
        "over training scenarios (primary $+$ meta assignments). "
        "Low off-diagonal values confirm largely disjoint corpora. "
        "The three highest pairwise values are intentional handoff-boundary overlaps: "
        "Scout--Harvester share \\texttt{meta\\_deadend\\_v1}; "
        "Pivot--Escalator share \\texttt{meta\\_ambiguous\\_v1}; "
        "Escalator--Endgame share \\texttt{meta\\_it\\_ot\\_hybrid\\_v1}."
    )
    return _jaccard_render(agent_sets,
                           "Agent Similarity: Training Scenarios",
                           description, "jaccard_scenarios")


def _jaccard_properties() -> str:
    agent_sets = [set(ag["properties"]) for ag in _AGENTS]
    description = (
        "Jaccard similarity over \\emph{node properties} leveraged by each agent. "
        "Node properties are the CBS flags that make a node actionable for a given tactic "
        "(e.g.\\ \\texttt{SNMPEnabled}, \\texttt{CredentialLeakage}, \\texttt{GoalNode}). "
        "Near-zero off-diagonal values confirm that each specialist targets a "
        "structurally distinct set of node characteristics with virtually no redundancy."
    )
    return _jaccard_render(agent_sets,
                           "Agent Similarity: Node Properties",
                           description, "jaccard_properties")


def _jaccard_local_vulns() -> str:
    agent_sets = [
        {v for v in ag["vuln_types"] if not v.startswith("Remote")}
        for ag in _AGENTS
    ]
    description = (
        "Jaccard similarity over \\emph{local vulnerability types} --- "
        "CBS actions executed \\emph{after} owning a node: "
        "credential leaks, neighbour discovery, and goal access. "
        "Harvester and Escalator show the highest overlap because both exploit "
        "\\texttt{credential\\_leak} and \\texttt{leak\\_known\\_credentials}: "
        "credential theft is a prerequisite for both execution/persistence "
        "\\emph{and} privilege-escalation chains. "
        "Pivot also shares these two types and additionally uses "
        "\\texttt{leak\\_neighbors} (shared with Scout), "
        "bridging the discovery and lateral-movement phases."
    )
    return _jaccard_render(agent_sets,
                           "Agent Similarity: Local Vulnerability Types",
                           description, "jaccard_local_vulns")


def _jaccard_remote_vulns() -> str:
    agent_sets = [
        {v for v in ag["vuln_types"] if v.startswith("Remote")}
        for ag in _AGENTS
    ]
    description = (
        "Jaccard similarity over \\emph{remote vulnerability types} "
        "(\\texttt{Remote.Probe.*} actions used to gain access to a node from the network). "
        "The Scout covers the broadest probe space (Windows, Linux, network devices). "
        "Scout--Harvester overlap on \\texttt{Remote.Probe.Linux}; "
        "Scout--Escalator and Scout--Endgame overlap on \\texttt{Remote.Probe.Windows}. "
        "Pivot probes only Linux application and worker tiers; "
        "zero overlap with Escalator (Windows-only) confirms platform-level separation."
    )
    return _jaccard_render(agent_sets,
                           "Agent Similarity: Remote Vulnerability Types",
                           description, "jaccard_remote_vulns")


def _jaccard_ports() -> str:
    agent_sets = [set(ag["ports"]) for ag in _AGENTS]
    description = (
        "Jaccard similarity over \\emph{target port numbers}. "
        "Common infrastructure ports (22/SSH, 139/NetBIOS, 445/SMB) "
        "appear across multiple agents but each specialist also carries a "
        "characteristic high-port fingerprint: "
        "Scout owns SNMP/161 and Telnet/23; "
        "Harvester owns Kerberos/88, MySQL/3306, Jenkins/8080; "
        "Pivot owns Redis/6379 and Kafka/9092; "
        "Escalator owns RPC/135 and raw-print/9100; "
        "Endgame owns Modbus/502, S7/102, OPC-UA/4840, and EtherNet\\/IP/44818."
    )
    return _jaccard_render(agent_sets,
                           "Agent Similarity: Target Ports",
                           description, "jaccard_ports")


def _jaccard_combined() -> str:
    """
    Weighted Jaccard aggregating all four feature dimensions with equal weights.
    J_w(A,B) = 0.25 * J_properties + 0.25 * J_local_vulns
             + 0.25 * J_remote_vulns + 0.25 * J_ports
    """
    _DIMS = [
        ("Properties",   [set(ag["properties"]) for ag in _AGENTS]),
        ("Local vulns",  [{v for v in ag["vuln_types"] if not v.startswith("Remote")} for ag in _AGENTS]),
        ("Remote vulns", [{v for v in ag["vuln_types"] if v.startswith("Remote")} for ag in _AGENTS]),
        ("Ports",        [set(ag["ports"]) for ag in _AGENTS]),
    ]
    w = 1.0 / len(_DIMS)

    n = len(_AGENTS)
    J: list = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            if i == j:
                J[i][j] = 1.0
            else:
                for _, sets in _DIMS:
                    inter = len(sets[i] & sets[j])
                    union = len(sets[i] | sets[j])
                    J[i][j] += w * (inter / union if union > 0 else 0.0)

    dim_list = ", ".join(d for d, _ in _DIMS)
    description = (
        "\\textbf{Weighted Jaccard} combining all four feature dimensions "
        "with equal weight $w = 1/4$ each:\n"
        "$$J_w(A,B) = \\frac{1}{4}\\bigl("
        "J_{\\text{prop}} + J_{\\text{local}} + J_{\\text{remote}} + J_{\\text{ports}}"
        "\\bigr)$$\n"
        "Dimensions: " + dim_list + ". "
        "A cell value $J_w$ means the two agents share, on average across all four "
        "feature vocabularies, $J_w \\times 100\\%$ of their elements. "
        "This composite view reveals the overall structural distance between specialists: "
        "adjacent kill-chain phases (Harvester--Escalator, Escalator--Endgame) "
        "score highest because they share both infrastructure ports and local "
        "vulnerability types, while non-adjacent pairs (Scout--Endgame, "
        "Harvester--Pivot) remain nearly orthogonal --- confirming that the "
        "five-agent partition minimises curriculum overlap."
    )
    return _render_j_matrix(J,
                            "Combined Weighted Jaccard (All Dimensions)",
                            description, "jaccard_combined")


def _scenario_stats_page(entries: list) -> str:
    """
    One-page statistical comparison of each agent's training corpus.
    Metrics come from the live entry dicts (agg + diversity sub-dicts).
    """
    if not entries:
        return ""

    entry_map = {e["name"]: e for e in entries}

    def _safe_float(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    # ── collect per-agent means ───────────────────────────────────────────────
    agent_rows = []
    for ag in _AGENTS:
        scen_entries = []
        for scen_name, _ in ag["scenarios"]:
            plain = scen_name.replace(r"\_", "_")
            if plain in entry_map:
                scen_entries.append(entry_map[plain])

        if not scen_entries:
            agent_rows.append(None)
            continue

        def mean_agg(key):
            vals = [_safe_float(e.get("agg", {}).get(key)) for e in scen_entries]
            vals = [v for v in vals if v is not None]
            return sum(vals) / len(vals) if vals else None

        def mean_div(key):
            vals = [_safe_float(e.get("diversity", {}).get(key)) for e in scen_entries]
            vals = [v for v in vals if v is not None]
            return sum(vals) / len(vals) if vals else None

        het_pct = (
            sum(1 for e in scen_entries if e.get("diversity", {}).get("heterogeneous_os"))
            / len(scen_entries) * 100
        )
        n_os_avg = sum(
            len(e.get("diversity", {}).get("os_types", []))
            for e in scen_entries
        ) / len(scen_entries)

        agent_rows.append({
            "n":            len(scen_entries),
            "nodes":        mean_agg("mean_nodes"),
            "density":      mean_agg("mean_density"),
            "diameter":     mean_agg("mean_diameter"),
            "tree_ratio":   mean_agg("tree_ratio"),
            "creds":        mean_agg("mean_creds"),
            "cred_paths":   mean_div("n_cred_paths"),
            "must_connect": mean_div("n_must_connect"),
            "solve_rate":   mean_agg("solve_rate"),
            "n_domains":    mean_div("n_domains"),
            "svc_types":    mean_div("n_service_types"),
            "het_os_pct":   het_pct,
            "n_os_avg":     n_os_avg,
        })

    # ── metric definitions: (key, label, format_fn, higher_is_notable) ───────
    # higher_is_notable=True  → darker = higher value
    # higher_is_notable=False → darker = lower value  (harder / more notable)
    # higher_is_notable=None  → no colour (plain count)
    _METRICS = [
        ("n",            r"\# Scenarios",         lambda v: str(int(round(v))),                       None),
        ("nodes",        "Avg nodes",              lambda v: "{:.1f}".format(v),                       True),
        ("density",      "Density",                lambda v: "{:.4f}".format(v),                       True),
        ("diameter",     "Diameter",               lambda v: "{:.1f}".format(v),                       True),
        ("tree_ratio",   "Tree ratio",             lambda v: "{:.2f}".format(v),                       False),
        ("creds",        "Avg credentials",        lambda v: "{:.1f}".format(v),                       True),
        ("cred_paths",   "Cred-leak edges",        lambda v: "{:.1f}".format(v),                       True),
        ("must_connect", "Must-connect edges",     lambda v: "{:.1f}".format(v),                       True),
        ("n_domains",    "Avg domains",            lambda v: "{:.1f}".format(v),                       True),
        ("svc_types",    "Service types",          lambda v: "{:.1f}".format(v),                       True),
        ("n_os_avg",     "Avg OS types",           lambda v: "{:.1f}".format(v),                       True),
        ("het_os_pct",   r"Het.\ OS (\%)",         lambda v: str(int(round(v))) + r"\%",               True),
        ("solve_rate",   "Solve rate",             lambda v: str(int(round(v * 100))) + r"\%",         False),
    ]

    # ── heatmap colouring helper ──────────────────────────────────────────────
    def _colour_row(vals, higher_notable):
        """Return list of (cell_colour, text) pairs for one metric row."""
        clean = [v for v in vals if v is not None]
        if not clean:
            return [("white", "---")] * len(vals)
        lo, hi = min(clean), max(clean)
        out = []
        for v in vals:
            if v is None:
                out.append(("white", "---"))
                continue
            if hi == lo:
                intensity = 20
            else:
                t = (v - lo) / (hi - lo)   # 0 = lowest, 1 = highest
                if higher_notable:
                    intensity = round(8 + t * 55)    # 8–63
                else:
                    intensity = round(8 + (1 - t) * 55)
            out.append(("titleblue!" + str(intensity), None))  # text filled below
        return out

    # ── build table rows ──────────────────────────────────────────────────────
    table_rows = ""
    for key, label, fmt, higher_notable in _METRICS:
        vals = [row[key] if row else None for row in agent_rows]
        colours = _colour_row(vals, higher_notable) if higher_notable is not None else None

        cells = []
        for idx, v in enumerate(vals):
            txt = fmt(v) if v is not None else "---"
            if colours is None or higher_notable is None:
                cells.append(txt)
            else:
                bg = colours[idx][0]
                cells.append("\\cellcolor{" + bg + "}" + txt)

        table_rows += "  " + label + " & " + " & ".join(cells) + " \\\\\n"
        # mid-rule separator after n_scenarios row
        if key == "n":
            table_rows += "  \\midrule\n"

    # ── column headers ────────────────────────────────────────────────────────
    headers = " & ".join(_color(ag["color"], ag["name"]) for ag in _AGENTS)

    return (
        "\n\\clearpage\n"
        "\\subsection{Training Corpus: Graph \& Scenario Statistics}\n"
        "\\label{sec:corpus_stats}\n\n"
        "Each cell is the mean of that metric across all primary training scenarios "
        "assigned to the agent.  Colour intensity within each row encodes relative "
        "rank: darker blue marks the agent most characterised by that property "
        "(or, for metrics where lower is harder, the agent facing the stiffest "
        "challenge).  The contrasting profiles confirm that the five specialists "
        "face structurally distinct learning problems.\n\n"
        "\\vspace{0.4cm}\n"
        "\\noindent\n"
        "\\small\n"
        "\\begin{tabular}{lp{2.6cm}p{2.6cm}p{2.6cm}p{2.6cm}p{2.6cm}}\n"
        "\\toprule\n"
        "\\textbf{Metric} & " + headers + " \\\\\n"
        "\\midrule\n"
        + table_rows
        + "\\bottomrule\n\\end{tabular}\n"
        "\\normalsize\n\n"
        "\\vspace{0.5cm}\n"
        "\\noindent\\textit{Interpretation highlights:}\n"
        "\\begin{itemize}\n"
        "  \\item \\textbf{Scout} trains on the largest, flattest networks "
        "(highest avg.\\ nodes, low diameter) --- the challenge is \\emph{breadth}: "
        "choosing which of 40+ reachable nodes to probe without exhaustive search.\n"
        "  \\item \\textbf{Harvester} scenarios have the highest credential density "
        "(avg.\\ credentials, cred-leak edges) --- directly supporting its mission of "
        "maximising the credential footprint for downstream agents.\n"
        "  \\item \\textbf{Pivot} exhibits the highest diameter and lowest tree ratio "
        "--- multi-hop, multi-path topologies that require explicit route-cost "
        "reasoning to find the shortest path to the goal.\n"
        "  \\item \\textbf{Escalator} trains on the smallest, most tightly-scoped "
        "Windows/AD environments: few nodes, many must-connect edges, and "
        "consistently high solve rates that provide a clean escalation curriculum.\n"
        "  \\item \\textbf{Endgame} has the highest service-type diversity and OS "
        "heterogeneity --- IT databases, secret vaults, and ICS devices coexist, "
        "demanding the most generalised feature representations of any specialist.\n"
        "\\end{itemize}\n"
    )


def _meta_scenarios() -> str:
    rows = "".join(
        "  " + _tex(name) + " & " + agents + " & " + rationale + " \\\\\n"
        for name, agents, rationale in _META_ASSIGNMENTS
    )
    return (
        "\n\\subsection{Meta-Scenario Assignments}\n"
        "\\label{sec:meta_scenarios}\n\n"
        "Four meta-scenarios serve specialised curriculum roles and are shared across "
        "multiple agents:\n\n"
        "\\noindent\\begin{tabular}{p{4cm}p{3cm}p{9cm}}\n"
        "\\toprule\n"
        "\\textbf{Scenario} & \\textbf{Agents} & \\textbf{Purpose} \\\\\n"
        "\\midrule\n"
        + rows
        + "\\bottomrule\n\\end{tabular}\n"
    )


def _synergy() -> str:
    return r"""
\subsection{Cross-Agent Synergy and Curriculum Design}
\label{sec:agent_synergy}

\subsubsection*{Why five agents and not three or seven?}
Five agents is the minimum partition that separates the five qualitatively
distinct sub-problems.  Merging Scout and Harvester into one agent conflates
\emph{topology exploration} (where the reward signal is sparse across many
nodes) with \emph{credential chain exploitation} (where the reward is dense
but requires sequence-level memory).  Similarly, merging Pivot and Escalator
would force a single policy to learn both \emph{graph-level} path-planning and
\emph{node-level} OS exploit selection -- tasks that benefit from different
network architectures (GNN vs.\ MLP).  Seven agents would over-specialise,
creating boundary cases where the coordinator must split a naturally unified
phase.

\subsubsection*{Scenario distribution strategy}
The training corpus for each agent was selected to satisfy three criteria:
\begin{enumerate}
  \item \textbf{Phase purity}: each scenario's primary challenge must lie within
    the agent's assigned kill-chain phase.  The ta0001 through ta0040 series
    provides the cleanest signal here, as each was generated with a single
    dominant MITRE tactic.
  \item \textbf{Environmental diversity}: the agent must see at least two
    distinct network archetypes (e.g., flat vs.\ segmented; Windows-only vs.\
    mixed OS) to prevent overfitting to a single topology.
  \item \textbf{Difficulty gradient}: the corpus must include both
    \emph{easy} instances (high solve rate $\geq 80\%$) for stable early
    learning and \emph{hard} instances (solve rate $40$--$60\%$) to push
    the policy beyond memorisation.
\end{enumerate}

\subsubsection*{Kill-chain handoff}
In the hierarchical system, the output of one agent seeds the input of the next.
The Scout's probed-node list becomes the Harvester's candidate target set.
The Harvester's credential footprint is passed as a starting condition to the
Pivot.  This chained curriculum mirrors the real-world attacker lifecycle and
ensures that each agent's training distribution reflects the states it will
actually encounter when deployed under the coordinator.

\subsubsection*{OT/ICS considerations}
The Endgame agent is the only specialist that encounters ICS protocols
(Modbus, DNP3, OPC-UA, EtherNet/IP).  This isolation is deliberate: ICS exploit
techniques are highly domain-specific, and contaminating other agents' training
corpora with OT scenarios would introduce spurious state features.
The Escalator's exposure to SCADA-AD hybrid scenarios is an exception -- but
there the OT layer is the \emph{reward}, not the \emph{mechanism}, so the
agent never needs to learn ICS protocol semantics.
"""
