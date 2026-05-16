from ..latex_base import e

def services_credentials_section(entries: list) -> str:
    domain_data = []
    all_protocols: set = set()

    for entry in entries:
        cfg = entry.get("_config", {})
        if not cfg: continue

        services = cfg.get("services", {})
        goal_svcs = [n for n, s in services.items() if s.get("is_goal")]
        protocols: set = set()
        os_families: set = set()
        prop_counts: list = []
        values: list = []

        for sdata in services.values():
            if sdata.get("port"): protocols.add(str(sdata["port"]))
            for p in sdata.get("default_properties", []):
                if p in ("Windows", "Linux", "MacOS"): os_families.add(p)
            prop_counts.append(len(sdata.get("default_properties", [])))
            if sdata.get("value"): values.append(sdata["value"])

        all_protocols.update(protocols)

        n_leak, n_knows, n_total = 0, 0, 0
        leak_flows = []
        for domain in cfg.get("domains", []):
            for c in domain.get("constraints", []):
                rel = c.get("relation", "").upper()
                n_total += 1
                if rel == "LEAK_KNOWN_CREDENTIALS":
                    n_leak += 1
                    leak_flows.append((c.get("source", "?"), c.get("target", "?"), c.get("protocol", "?")))
                elif rel == "KNOWS": n_knows += 1
        
        for idc in cfg.get("inter_domain_constraints", []):
            for c in idc.get("constraints", []):
                rel = c.get("relation", "").upper()
                n_total += 1
                if rel == "LEAK_KNOWN_CREDENTIALS":
                    n_leak += 1
                    leak_flows.append((c.get("source", "?"), c.get("target", "?"), c.get("protocol", "?")))
                elif rel == "KNOWS": n_knows += 1

        domain_data.append({
            "short": entry["short_name"],
            "n_svc": len(services),
            "protocols": protocols,
            "os_families": os_families,
            "goal_svcs": goal_svcs,
            "prop_mean": round(sum(prop_counts) / len(prop_counts), 1) if prop_counts else 0,
            "val_min": min(values) if values else 0,
            "val_max": max(values) if values else 0,
            "val_mean": round(sum(values) / len(values)) if values else 0,
            "n_leak": n_leak,
            "n_knows": n_knows,
            "n_total": n_total,
            "leak_flows": leak_flows,
        })

    svc_rows = []
    for d in domain_data:
        os_str = "/".join(sorted(d["os_families"])) or "—"
        goal_str = ", ".join(d["goal_svcs"]) if d["goal_svcs"] else "none"
        proto_str = ", ".join(sorted(d["protocols"]))
        svc_rows.append(f"  {e(d['short'])} & {d['n_svc']} & {d['prop_mean']} & "
                        f"\\texttt{{{e(proto_str)}}} & {e(os_str)} & {e(goal_str)} \\\\")
    
    val_rows = []
    for d in domain_data:
        val_rows.append(f"  {e(d['short'])} & {int(d['val_min']):,} & {int(d['val_max']):,} & "
                        f"{int(d['val_mean']):,} & {len(d['goal_svcs'])} \\\\")

    cred_rows = []
    for d in domain_data:
        density = f"{d['n_leak'] / d['n_total'] * 100:.0f}\\%" if d["n_total"] > 0 else "—"
        flow_parts = [f"{e(src)}$\\to${e(tgt)} (\\texttt{{{e(proto)}}})" for src, tgt, proto in d["leak_flows"][:3]]
        if len(d["leak_flows"]) > 3: flow_parts.append(f"\\ldots +{len(d['leak_flows']) - 3}")
        flow_str = "; ".join(flow_parts) if flow_parts else "—"
        cred_rows.append(f"  {e(d['short'])} & {d['n_leak']} & {d['n_knows']} & "
                         f"{d['n_total']} & {density} & {flow_str} \\\\")

    sorted_protos = sorted(all_protocols)
    proto_headers = " & ".join(r"\rotatebox{55}{\scriptsize\texttt{" + d["short"].replace("_", r"\_") + "}}" for d in domain_data)
    proto_rows = []
    for proto in sorted_protos:
        cells = [(r"\cellcolor{blue!20}$\bullet$" if proto in d["protocols"] else "") for d in domain_data]
        count = sum(1 for d in domain_data if proto in d["protocols"])
        proto_rows.append(f"  \\texttt{{{e(proto)}}} & {' & '.join(cells)} & {count}/{len(domain_data)} \\\\")

    col_proto = "p{2.8cm}" + "c" * len(domain_data) + "c"
    
    template = r"""
\newpage
\subsection{{Service Architecture \& Credential Flow Analysis}}

\subsubsection*{{Service Catalog Summary}}
\begin{{table}}[H]
\centering\small\setlength{{\tabcolsep}}{{4pt}}
\begin{{tabular}}{{p{{3.6cm}}ccp{{3.8cm}}cp{{3.4cm}}}}
\toprule
\textbf{{Domain}} & \textbf{{Svc Types}} & \textbf{{Avg Props}} & \textbf{{Protocols}} & \textbf{{OS Family}} & \textbf{{Goal Service(s)}} \\
\midrule
{svc_rows}
\bottomrule
\end{{tabular}}
\end{{table}}

\subsubsection*{{Service Value Distribution}}
\begin{{table}}[H]
\centering\small\setlength{{\tabcolsep}}{{5pt}}
\begin{{tabular}}{{lrrrr}}
\toprule
\textbf{{Domain}} & \textbf{{Min Value}} & \textbf{{Max Value}} & \textbf{{Mean Value}} & \textbf{{\# Goal Svcs}} \\
\midrule
{val_rows}
\bottomrule
\end{{tabular}}
\end{{table}}

\subsubsection*{{Credential Propagation Model}}
\begin{{table}}[H]
\centering\small\setlength{{\tabcolsep}}{{3pt}}
\begin{{tabular}}{{p{{3.2cm}}ccccp{{5.8cm}}}}
\toprule
\textbf{{Domain}} & \textbf{{Leak}} & \textbf{{Knows}} & \textbf{{Total}} & \textbf{{Density}} & \textbf{{Leak Flows}} \\
\midrule
{cred_rows}
\bottomrule
\end{{tabular}}
\end{{table}}

\subsubsection*{{Protocol $\times$ Domain Coverage}}
\begin{{table}}[H]
\centering\small\setlength{{\tabcolsep}}{{3pt}}
\begin{{tabular}}{{{col_proto}}}
\toprule
\textbf{{Protocol}} & {proto_headers} & \textbf{{Cov.}} \\
\midrule
{proto_rows}
\bottomrule
\end{{tabular}}
\end{{table}}
"""
    return template.format(
        svc_rows="\n".join(svc_rows),
        val_rows="\n".join(val_rows),
        cred_rows="\n".join(cred_rows),
        col_proto=col_proto,
        proto_headers=proto_headers,
        proto_rows="\n".join(proto_rows)
    )
