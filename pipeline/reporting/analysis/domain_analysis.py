import os
import yaml
import pandas as pd
import numpy as np
from collections import Counter
from typing import Dict, List
from tqdm.auto import tqdm

class DomainAnalysis:
    """
    Analyzes an entire domain of CyberBattleSim scenarios to generate aggregated 
    statistics on nodes, topology, vulnerabilities, and identifiers.
    """
    
    def __init__(self, domain_path: str):
        self.domain_path = domain_path
        self.domain_name = os.path.basename(os.path.normpath(domain_path))
        self.scenario_paths = self._find_scenarios()
        
        # Data storage
        self.raw_nodes_data = []      # List of dicts with raw node stats
        self.scenario_stats = []      # List of dicts with per-scenario stats
        self.domain_summary = {}      # Final aggregated domain stats
        
    def _find_scenarios(self) -> List[str]:
        """Finds all valid scenario subdirectories within the domain (recursive)."""
        scenarios = []
        for root, dirs, files in os.walk(self.domain_path):
            if 'nodes' in dirs:
                scenarios.append(root)
                dirs.clear()  # don't recurse into already-matched scenario dirs
        return sorted(scenarios)

    def process_domain(self):
        """Main execution method to read all files and calculate statistics."""
        if not self.scenario_paths:
            print(f"No valid scenarios found in {self.domain_path}")
            return
        
        print(f"Processing Domain: '{self.domain_name}' ({len(self.scenario_paths)} scenarios found)")
        
        for scenario_path in tqdm(self.scenario_paths, desc=f"Analyzing {self.domain_name}"):
            scenario_name = os.path.basename(scenario_path)
            self._process_scenario(scenario_path, scenario_name)
            
        self._aggregate_domain_statistics()
        return self.domain_summary

    def _process_scenario(self, scenario_path: str, scenario_name: str):
        """Processes a single scenario's nodes and identifiers."""
        nodes_dir = os.path.join(scenario_path, 'nodes')
        scenario_node_values = []
        local_vulns = 0
        remote_vulns = 0
        in_ports = 0
        out_ports = 0

        # Track per-scenario node-level stats for richer aggregation
        nodes_with_agent = 0
        nodes_reimagable = 0
        nodes_is_goal = 0
        nodes_with_any_vuln = 0
        nodes_with_properties = 0
        all_vuln_counts = []
        all_sla_weights = []
        all_privilege_levels = []

        # 1. Process Nodes
        node_files = [f for f in os.listdir(nodes_dir) if f.endswith('.yaml')]
        for node_file in node_files:
            with open(os.path.join(nodes_dir, node_file), 'r') as f:
                try:
                    node_data = yaml.safe_load(f) or {}
                except yaml.YAMLError:
                    continue

                # ── Basic parameters ──────────────────────────────────────────
                val            = node_data.get('value', 0)
                agent_installed= node_data.get('agent_installed', False)
                privilege_level= node_data.get('privilege_level', 0)
                reimagable     = node_data.get('reimagable', False)
                status         = node_data.get('status', 0)
                sla_weight     = node_data.get('sla_weight', 0.0)
                is_goal        = node_data.get('is_goal', False)
                image          = node_data.get('image', '')
                owned_string   = node_data.get('owned_string', '')

                # Deduplicate properties to avoid inflated counts
                raw_props  = node_data.get('properties', []) or []
                properties = list(dict.fromkeys(raw_props))   # preserves order, removes dupes
                num_duped_props = len(raw_props) - len(properties)

                scenario_node_values.append(val)
                all_sla_weights.append(sla_weight)
                all_privilege_levels.append(privilege_level)

                if agent_installed:   nodes_with_agent += 1
                if reimagable:        nodes_reimagable += 1
                if is_goal:           nodes_is_goal += 1
                if properties:        nodes_with_properties += 1

                # ── Services ──────────────────────────────────────────────────
                services = node_data.get('services', []) or []
                num_services         = len(services)
                num_running_services = sum(1 for s in services if isinstance(s, dict) and s.get('running', False))
                service_names        = [s.get('name', '') for s in services if isinstance(s, dict)]
                num_service_creds    = sum(
                    len(s.get('allowedCredentials', []) or [])
                    for s in services if isinstance(s, dict)
                )

                # ── Network info ──────────────────────────────────────────────
                net_info    = node_data.get('network_info', []) or []
                ip_addresses= [n.get('ip_address', '') for n in net_info if isinstance(n, dict)]
                subnets     = [
                    n.get('subnet', {}).get('network', '')
                    for n in net_info if isinstance(n, dict)
                ]

                # ── Vulnerabilities ───────────────────────────────────────────
                vulns = node_data.get('vulnerabilities', {}) or {}
                node_local_vulns  = 0
                node_remote_vulns = 0

                # Aggregated rates and costs across all vulns on this node
                success_rates        = []
                probing_detect_rates = []
                exploit_detect_rates = []
                vuln_costs           = []
                total_creds_leaked   = 0
                total_nodes_leaked   = 0
                outcome_type_counts  = Counter()  # probe_succeeded / leaked_credentials / leaked_nodes_id

                for v in vulns.values():
                    if not isinstance(v, dict):
                        continue

                    vtype = v.get('type')
                    if vtype == 2:
                        local_vulns      += 1
                        node_local_vulns += 1
                    elif vtype == 3:
                        remote_vulns      += 1
                        node_remote_vulns += 1

                    # Rates
                    rates = v.get('rates', {}) or {}
                    if 'successRate'        in rates: success_rates.append(rates['successRate'])
                    if 'probingDetectionRate' in rates: probing_detect_rates.append(rates['probingDetectionRate'])
                    if 'exploitDetectionRate' in rates: exploit_detect_rates.append(rates['exploitDetectionRate'])

                    # Cost
                    if 'cost' in v:
                        vuln_costs.append(v['cost'])

                    # Outcome
                    outcome = v.get('outcome', {}) or {}
                    otype   = outcome.get('type', '')
                    if otype:
                        outcome_type_counts[otype] += 1
                    kwargs = outcome.get('kwargs', {}) or {}
                    if otype == 'leaked_credentials':
                        total_creds_leaked += len(kwargs.get('credentials', []) or [])
                    elif otype == 'leaked_nodes_id':
                        total_nodes_leaked += len(kwargs.get('nodes', []) or [])

                node_total_vulns = node_local_vulns + node_remote_vulns
                all_vuln_counts.append(node_total_vulns)
                if node_total_vulns > 0:
                    nodes_with_any_vuln += 1

                # ── Firewall ──────────────────────────────────────────────────
                fw      = node_data.get('firewall', {}) or {}
                fw_in   = fw.get('incoming', []) or []
                fw_out  = fw.get('outgoing', []) or []
                in_ports  += len(fw_in)
                out_ports += len(fw_out)

                # Permission & priority breakdowns (0 = allow, 1 = deny assumed)
                fw_in_allow  = sum(1 for r in fw_in  if isinstance(r, dict) and r.get('permission', -1) == 0)
                fw_in_deny   = sum(1 for r in fw_in  if isinstance(r, dict) and r.get('permission', -1) == 1)
                fw_out_allow = sum(1 for r in fw_out if isinstance(r, dict) and r.get('permission', -1) == 0)
                fw_out_deny  = sum(1 for r in fw_out if isinstance(r, dict) and r.get('permission', -1) == 1)
                fw_priorities= [r.get('priority') for r in (fw_in + fw_out)
                                 if isinstance(r, dict) and r.get('priority') is not None]

                # ── Store raw node row ─────────────────────────────────────────
                self.raw_nodes_data.append({
                    # Identity
                    'scenario':               scenario_name,
                    'node_name':              node_file.replace('.yaml', ''),
                    'image':                  image,
                    'owned_string':           owned_string,

                    # Basic config
                    'value':                  val,
                    'agent_installed':        agent_installed,
                    'privilege_level':        privilege_level,
                    'reimagable':             reimagable,
                    'status':                 status,
                    'sla_weight':             sla_weight,
                    'is_goal':                is_goal,

                    # Properties (deduped)
                    'properties':             properties,
                    'num_properties':         len(properties),
                    'num_duplicate_properties': num_duped_props,

                    # Services
                    'num_services':           num_services,
                    'num_running_services':   num_running_services,
                    'service_names':          service_names,
                    'num_service_credentials':num_service_creds,

                    # Network
                    'ip_addresses':           ip_addresses,
                    'subnets':                subnets,
                    'num_interfaces':         len(net_info),

                    # Vulnerabilities
                    'local_vulnerabilities':  node_local_vulns,
                    'remote_vulnerabilities': node_remote_vulns,
                    'total_vulnerabilities':  node_total_vulns,
                    'avg_success_rate':       np.mean(success_rates)        if success_rates        else np.nan,
                    'avg_probing_detect_rate':np.mean(probing_detect_rates) if probing_detect_rates else np.nan,
                    'avg_exploit_detect_rate':np.mean(exploit_detect_rates) if exploit_detect_rates else np.nan,
                    'total_vuln_cost':        sum(vuln_costs),
                    'avg_vuln_cost':          np.mean(vuln_costs)           if vuln_costs           else np.nan,
                    'total_creds_leaked':     total_creds_leaked,
                    'total_nodes_leaked':     total_nodes_leaked,
                    'outcome_probe':          outcome_type_counts.get('probe_succeeded', 0),
                    'outcome_creds':          outcome_type_counts.get('leaked_credentials', 0),
                    'outcome_nodes':          outcome_type_counts.get('leaked_nodes_id', 0),

                    # Firewall
                    'firewall_incoming':      len(fw_in),
                    'firewall_outgoing':      len(fw_out),
                    'fw_in_allow':            fw_in_allow,
                    'fw_in_deny':             fw_in_deny,
                    'fw_out_allow':           fw_out_allow,
                    'fw_out_deny':            fw_out_deny,
                    'fw_avg_priority':        np.mean(fw_priorities) if fw_priorities else np.nan,
                })

        # 2. Process Identifiers
        identifiers_path = os.path.join(scenario_path, 'identifiers', 'identifiers.yaml')
        id_counts = {'properties': 0, 'ports': 0, 'local_vulnerabilities': 0, 'remote_vulnerabilities': 0}
        if os.path.exists(identifiers_path):
            with open(identifiers_path, 'r') as f:
                try:
                    id_data = yaml.safe_load(f) or {}
                    for key in id_counts.keys():
                        if key in id_data and isinstance(id_data[key], list):
                            id_counts[key] = len(id_data[key])
                except yaml.YAMLError:
                    pass

        n = max(len(node_files), 1)

        # Pull aggregated columns from raw_nodes_data for this scenario
        scen_nodes = [r for r in self.raw_nodes_data if r['scenario'] == scenario_name]
        _sr  = [r['avg_success_rate']        for r in scen_nodes if not (isinstance(r.get('avg_success_rate'), float) and np.isnan(r['avg_success_rate']))]
        _pdr = [r['avg_probing_detect_rate'] for r in scen_nodes if not (isinstance(r.get('avg_probing_detect_rate'), float) and np.isnan(r['avg_probing_detect_rate']))]
        _edr = [r['avg_exploit_detect_rate'] for r in scen_nodes if not (isinstance(r.get('avg_exploit_detect_rate'), float) and np.isnan(r['avg_exploit_detect_rate']))]

        # Append Scenario-level data
        self.scenario_stats.append({
            'scenario_name': scenario_name,
            'num_nodes':     len(node_files),

            # Value stats
            'avg_node_value':    np.mean(scenario_node_values)   if scenario_node_values else 0,
            'std_node_value':    np.std(scenario_node_values)    if scenario_node_values else 0,
            'max_node_value':    np.max(scenario_node_values)    if scenario_node_values else 0,
            'min_node_value':    np.min(scenario_node_values)    if scenario_node_values else 0,
            'median_node_value': np.median(scenario_node_values) if scenario_node_values else 0,
            'total_node_value':  np.sum(scenario_node_values)    if scenario_node_values else 0,

            # Node configuration
            'nodes_with_agent':      nodes_with_agent,
            'nodes_reimagable':      nodes_reimagable,
            'nodes_is_goal':         nodes_is_goal,
            'nodes_with_properties': nodes_with_properties,
            'nodes_with_any_vuln':   nodes_with_any_vuln,
            'agent_coverage_pct':    (nodes_with_agent  / n) * 100,
            'reimagable_pct':        (nodes_reimagable  / n) * 100,
            'goal_pct':              (nodes_is_goal     / n) * 100,

            # Privilege
            'avg_privilege_level': np.mean(all_privilege_levels) if all_privilege_levels else 0,
            'max_privilege_level': np.max(all_privilege_levels)  if all_privilege_levels else 0,

            # SLA
            'avg_sla_weight':   np.mean(all_sla_weights) if all_sla_weights else 0,
            'total_sla_weight': np.sum(all_sla_weights)  if all_sla_weights else 0,

            # Vulnerability counts
            'total_local_vulns':          local_vulns,
            'total_remote_vulns':         remote_vulns,
            'total_vulns':                local_vulns + remote_vulns,
            'avg_vulns_per_node':         np.mean(all_vuln_counts) if all_vuln_counts else 0,
            'std_vulns_per_node':         np.std(all_vuln_counts)  if all_vuln_counts else 0,
            'max_vulns_on_node':          np.max(all_vuln_counts)  if all_vuln_counts else 0,
            'vuln_coverage_pct':          (nodes_with_any_vuln / n) * 100,
            'local_to_remote_vuln_ratio': (local_vulns / remote_vulns) if remote_vulns > 0 else np.nan,

            # Vulnerability rates (averaged across all nodes in this scenario)
            'avg_success_rate':        np.mean(_sr)  if _sr  else np.nan,
            'avg_probing_detect_rate': np.mean(_pdr) if _pdr else np.nan,
            'avg_exploit_detect_rate': np.mean(_edr) if _edr else np.nan,

            # Vulnerability costs & outcomes
            'total_vuln_cost':     sum(r['total_vuln_cost']    for r in scen_nodes),
            'total_creds_leaked':  sum(r['total_creds_leaked'] for r in scen_nodes),
            'total_nodes_leaked':  sum(r['total_nodes_leaked'] for r in scen_nodes),
            'total_outcome_probe': sum(r['outcome_probe']      for r in scen_nodes),
            'total_outcome_creds': sum(r['outcome_creds']      for r in scen_nodes),
            'total_outcome_nodes': sum(r['outcome_nodes']      for r in scen_nodes),

            # Services
            'total_services':         sum(r['num_services']           for r in scen_nodes),
            'total_running_services': sum(r['num_running_services']   for r in scen_nodes),
            'total_service_creds':    sum(r['num_service_credentials']for r in scen_nodes),
            'avg_services_per_node':  np.mean([r['num_services'] for r in scen_nodes]) if scen_nodes else 0,

            # Network
            'total_interfaces': sum(r['num_interfaces'] for r in scen_nodes),
            'unique_subnets':   len({s for r in scen_nodes for s in r['subnets']}),

            # Firewall
            'firewall_incoming_rules':  in_ports,
            'firewall_outgoing_rules':  out_ports,
            'total_firewall_rules':     in_ports + out_ports,
            'avg_fw_incoming_per_node': in_ports  / n,
            'avg_fw_outgoing_per_node': out_ports / n,
            'fw_in_allow':  sum(r['fw_in_allow']  for r in scen_nodes),
            'fw_in_deny':   sum(r['fw_in_deny']   for r in scen_nodes),
            'fw_out_allow': sum(r['fw_out_allow'] for r in scen_nodes),
            'fw_out_deny':  sum(r['fw_out_deny']  for r in scen_nodes),

            **id_counts,

            # Identifier-derived ratios
            'vuln_identifier_coverage': (
                (local_vulns + remote_vulns) / max(id_counts['local_vulnerabilities'] + id_counts['remote_vulnerabilities'], 1)
            ),
        })

    def _aggregate_domain_statistics(self):
        """Calculates the final aggregated metrics for the entire domain."""
        df_scen  = pd.DataFrame(self.scenario_stats)
        df_nodes = pd.DataFrame(self.raw_nodes_data)

        if df_nodes.empty:
            self.domain_summary = {"Error": "No node data found."}
            return

        total_nodes     = max(1, df_nodes.shape[0])
        total_scenarios = len(df_scen)

        # ── Helpers ───────────────────────────────────────────────────────────
        def cv(series):
            s = series.dropna()
            m = s.mean()
            return (s.std() / m) if m != 0 else np.nan

        def pct(mask): return (mask.sum() / total_nodes) * 100

        # ── Properties (deduped counts already stored per node) ───────────────
        all_properties = [p for sublist in df_nodes['properties'].dropna() for p in sublist]
        prop_counter   = Counter(all_properties)
        top_properties = dict(prop_counter.most_common(5))

        # ── Services ──────────────────────────────────────────────────────────
        all_service_names = [s for sublist in df_nodes['service_names'].dropna() for s in sublist]
        top_services      = dict(Counter(all_service_names).most_common(5))
        nodes_with_services       = (df_nodes['num_services'] > 0).sum()
        nodes_all_services_running = (
            (df_nodes['num_services'] > 0) &
            (df_nodes['num_running_services'] == df_nodes['num_services'])
        ).sum()

        # ── Image types ───────────────────────────────────────────────────────
        image_distribution = df_nodes['image'].value_counts().to_dict()

        # ── Network ───────────────────────────────────────────────────────────
        all_subnets    = [s for sublist in df_nodes['subnets'].dropna() for s in sublist if s]
        unique_subnets = len(set(all_subnets))

        # ── Value buckets ─────────────────────────────────────────────────────
        value_mean       = df_nodes['value'].mean()
        value_p75        = df_nodes['value'].quantile(0.75)
        zero_value_nodes = (df_nodes['value'] == 0).sum()
        high_value_nodes = (df_nodes['value'] > value_mean).sum()

        # ── Vulnerability totals ──────────────────────────────────────────────
        total_local_vulns  = int(df_scen['total_local_vulns'].sum())
        total_remote_vulns = int(df_scen['total_remote_vulns'].sum())
        total_vulns        = total_local_vulns + total_remote_vulns
        vuln_exposure_score = (total_local_vulns * 1.0 + total_remote_vulns * 2.0) / total_nodes

        # ── Vulnerability rates (domain-wide, NaN-safe) ───────────────────────
        avg_success_rate        = df_nodes['avg_success_rate'].mean()
        avg_probing_detect_rate = df_nodes['avg_probing_detect_rate'].mean()
        avg_exploit_detect_rate = df_nodes['avg_exploit_detect_rate'].mean()
        stealth_score = 1.0 - np.nanmean([avg_probing_detect_rate, avg_exploit_detect_rate])

        # ── Vulnerability costs & outcomes ────────────────────────────────────
        total_vuln_cost      = df_scen['total_vuln_cost'].sum()
        avg_vuln_cost_per_node = df_nodes['avg_vuln_cost'].mean()
        total_creds_leaked   = int(df_scen['total_creds_leaked'].sum())
        total_nodes_leaked   = int(df_scen['total_nodes_leaked'].sum())
        total_outcome_probe  = int(df_scen['total_outcome_probe'].sum())
        total_outcome_creds  = int(df_scen['total_outcome_creds'].sum())
        total_outcome_nodes  = int(df_scen['total_outcome_nodes'].sum())
        nodes_leaking_creds  = (df_nodes['total_creds_leaked'] > 0).sum()
        nodes_leaking_nodes  = (df_nodes['total_nodes_leaked'] > 0).sum()

        # ── Firewall totals & permissions ─────────────────────────────────────
        total_fw_in        = int(df_scen['firewall_incoming_rules'].sum())
        total_fw_out       = int(df_scen['firewall_outgoing_rules'].sum())
        total_fw           = total_fw_in + total_fw_out
        fw_asymmetry       = (total_fw_in - total_fw_out) / max(total_fw, 1)
        total_fw_in_allow  = int(df_scen['fw_in_allow'].sum())
        total_fw_in_deny   = int(df_scen['fw_in_deny'].sum())
        total_fw_out_allow = int(df_scen['fw_out_allow'].sum())
        total_fw_out_deny  = int(df_scen['fw_out_deny'].sum())
        nodes_no_fw_in  = (df_nodes['firewall_incoming'] == 0).sum()
        nodes_no_fw_out = (df_nodes['firewall_outgoing'] == 0).sum()
        nodes_no_fw_any = ((df_nodes['firewall_incoming'] == 0) & (df_nodes['firewall_outgoing'] == 0)).sum()

        # ── Attack surface & risk ─────────────────────────────────────────────
        remote_exposed_nodes    = (df_nodes['remote_vulnerabilities'] > 0).sum()
        attack_surface_index    = remote_exposed_nodes / total_nodes
        df_nodes['_risk']       = df_nodes['value'] * df_nodes['remote_vulnerabilities']
        total_risk_score        = df_nodes['_risk'].sum()
        avg_risk_per_node       = df_nodes['_risk'].mean()
        df_nodes['_priv_risk']  = df_nodes['privilege_level'] * df_nodes['remote_vulnerabilities']
        privilege_weighted_risk = df_nodes['_priv_risk'].sum()

        # ── Goal & agent node breakdowns ──────────────────────────────────────
        goal_mask          = df_nodes['is_goal']
        agent_mask         = df_nodes['agent_installed']
        df_goals           = df_nodes[goal_mask]
        df_agents          = df_nodes[agent_mask]
        agent_goal_overlap = (goal_mask & agent_mask).sum()
        goal_avg_value     = df_goals['value'].mean()                if not df_goals.empty  else np.nan
        goal_avg_vulns     = df_goals['total_vulnerabilities'].mean()if not df_goals.empty  else np.nan
        goal_avg_sla       = df_goals['sla_weight'].mean()           if not df_goals.empty  else np.nan
        agent_avg_value    = df_agents['value'].mean()               if not df_agents.empty else np.nan

        # ── SLA-weighted metrics ──────────────────────────────────────────────
        sla_sum = df_nodes['sla_weight'].sum()
        if sla_sum > 0:
            sla_wtd_value     = (df_nodes['value']                * df_nodes['sla_weight']).sum() / sla_sum
            sla_wtd_vuln_exp  = (df_nodes['total_vulnerabilities'] * df_nodes['sla_weight']).sum() / sla_sum
            sla_wtd_privilege = (df_nodes['privilege_level']       * df_nodes['sla_weight']).sum() / sla_sum
        else:
            sla_wtd_value = sla_wtd_vuln_exp = sla_wtd_privilege = np.nan

        # ── Identifier totals ─────────────────────────────────────────────────
        total_id_props        = int(df_scen['properties'].sum())
        total_id_ports        = int(df_scen['ports'].sum())
        total_id_local_vulns  = int(df_scen['local_vulnerabilities'].sum())
        total_id_remote_vulns = int(df_scen['remote_vulnerabilities'].sum())

        self.domain_summary = {
            # ── Identity ──────────────────────────────────────────────────────
            'Domain Name':     self.domain_name,
            'Total Scenarios': total_scenarios,
            'Total Nodes':     total_nodes,

            # ── Scenario Size ─────────────────────────────────────────────────
            'Nodes per Scenario (Mean)': df_scen['num_nodes'].mean(),
            'Nodes per Scenario (Std)':  df_scen['num_nodes'].std(),
            'Nodes per Scenario (Min)':  df_scen['num_nodes'].min(),
            'Nodes per Scenario (Max)':  df_scen['num_nodes'].max(),
            'Nodes per Scenario (CV)':   cv(df_scen['num_nodes']),

            # ── Node Configuration ────────────────────────────────────────────
            'Nodes with Agent Installed (%)':       pct(agent_mask),
            'Reimagable Nodes (%)':                 pct(df_nodes['reimagable']),
            'Goal Nodes (%)':                       pct(goal_mask),
            'Agent-on-Goal Nodes':                  int(agent_goal_overlap),
            'Agent-on-Goal Nodes (%)':              (agent_goal_overlap / max(goal_mask.sum(), 1)) * 100,
            'Nodes with Any Property (%)':          pct(df_nodes['num_properties'].gt(0)),
            'Nodes with Any Vulnerability (%)':     pct(df_nodes['total_vulnerabilities'].gt(0)),
            'Nodes with No Firewall (Incoming, %)': (nodes_no_fw_in  / total_nodes) * 100,
            'Nodes with No Firewall (Outgoing, %)': (nodes_no_fw_out / total_nodes) * 100,
            'Nodes with No Firewall at All (%)':    (nodes_no_fw_any / total_nodes) * 100,
            'Average Properties per Node':          df_nodes['num_properties'].mean(),
            'Total Duplicate Properties Removed':   int(df_nodes['num_duplicate_properties'].sum()),
            'Image Type Distribution':              image_distribution,

            # ── Services ─────────────────────────────────────────────────────
            'Nodes with Services (%)':              (nodes_with_services / total_nodes) * 100,
            'Nodes with All Services Running (%)':  (nodes_all_services_running / total_nodes) * 100,
            'Avg Services per Node':                df_nodes['num_services'].mean(),
            'Avg Running Services per Node':        df_nodes['num_running_services'].mean(),
            'Total Service Credentials':            int(df_nodes['num_service_credentials'].sum()),
            'Top 5 Service Types':                  top_services,

            # ── Network ───────────────────────────────────────────────────────
            'Total Unique Subnets':                 unique_subnets,
            'Avg Interfaces per Node':              df_nodes['num_interfaces'].mean(),
            'Avg Unique Subnets per Scenario':      df_scen['unique_subnets'].mean(),

            # ── Privilege Levels ──────────────────────────────────────────────
            'Privilege Level Distribution':         df_nodes['privilege_level'].value_counts().to_dict(),
            'Average Privilege Level':              df_nodes['privilege_level'].mean(),
            'Max Privilege Level Seen':             int(df_nodes['privilege_level'].max()),
            'Std Privilege Level':                  df_nodes['privilege_level'].std(),

            # ── Node Status ───────────────────────────────────────────────────
            'Node Status Distribution':             df_nodes['status'].value_counts().to_dict(),

            # ── Node Value ────────────────────────────────────────────────────
            'Node Value (Mean)':                    value_mean,
            'Node Value (Median)':                  df_nodes['value'].median(),
            'Node Value (Std)':                     df_nodes['value'].std(),
            'Node Value (Min)':                     df_nodes['value'].min(),
            'Node Value (Max)':                     df_nodes['value'].max(),
            'Node Value (75th Percentile)':         value_p75,
            'Zero-Value Nodes (%)':                 (zero_value_nodes / total_nodes) * 100,
            'High-Value Nodes Above Mean (%)':      (high_value_nodes / total_nodes) * 100,
            'Total Cumulative Node Value':          df_nodes['value'].sum(),
            'Avg Total Scenario Value':             df_scen['total_node_value'].mean(),
            'Std Total Scenario Value':             df_scen['total_node_value'].std(),
            'CV: Total Scenario Value':             cv(df_scen['total_node_value']),

            # ── SLA ───────────────────────────────────────────────────────────
            'Average SLA Weight':                   df_nodes['sla_weight'].mean(),
            'Total Accumulated SLA Weight':         float(sla_sum),
            'SLA-Weighted Avg Node Value':          sla_wtd_value,
            'SLA-Weighted Avg Vulnerability Exposure': sla_wtd_vuln_exp,
            'SLA-Weighted Avg Privilege Level':     sla_wtd_privilege,

            # ── Goal & Agent Node Breakdown ───────────────────────────────────
            'Goal Node Avg Value':                  goal_avg_value,
            'Goal Node Avg Vulnerabilities':        goal_avg_vulns,
            'Goal Node Avg SLA Weight':             goal_avg_sla,
            'Agent Node Avg Value':                 agent_avg_value,

            # ── Vulnerabilities ───────────────────────────────────────────────
            'Total Local Vulnerabilities':          total_local_vulns,
            'Total Remote Vulnerabilities':         total_remote_vulns,
            'Total Vulnerabilities':                total_vulns,
            'Avg Vulnerabilities per Node':         df_nodes['total_vulnerabilities'].mean(),
            'Std Vulnerabilities per Node':         df_nodes['total_vulnerabilities'].std(),
            'Max Vulnerabilities on Single Node':   int(df_nodes['total_vulnerabilities'].max()),
            'Local vs Remote Vulnerability Ratio':  total_local_vulns / max(total_remote_vulns, 1),
            'Weighted Vulnerability Exposure Score':vuln_exposure_score,
            'Avg Vulnerability Coverage per Scenario (%)': df_scen['vuln_coverage_pct'].mean(),

            # ── Vulnerability Rates ───────────────────────────────────────────
            'Avg Exploit Success Rate':             avg_success_rate,
            'Avg Probing Detection Rate':           avg_probing_detect_rate,
            'Avg Exploit Detection Rate':           avg_exploit_detect_rate,
            'Domain Stealth Score (0=stealthy)':    stealth_score,
            'Total Vulnerability Cost':             total_vuln_cost,
            'Avg Vulnerability Cost per Node':      avg_vuln_cost_per_node,

            # ── Leakage & Outcomes ────────────────────────────────────────────
            'Total Credentials Leaked':             total_creds_leaked,
            'Total Nodes Leaked':                   total_nodes_leaked,
            'Nodes Leaking Credentials (%)':        (nodes_leaking_creds / total_nodes) * 100,
            'Nodes Leaking Node IDs (%)':           (nodes_leaking_nodes / total_nodes) * 100,
            'Total Probe Outcomes':                 total_outcome_probe,
            'Total Credential-Leak Outcomes':       total_outcome_creds,
            'Total Node-Leak Outcomes':             total_outcome_nodes,

            # ── Attack Surface & Risk ─────────────────────────────────────────
            'Remote-Exposed Nodes':                 int(remote_exposed_nodes),
            'Attack Surface Index (0–1)':           attack_surface_index,
            'Total Risk Score (Value × Remote Vulns)': total_risk_score,
            'Avg Risk Score per Node':              avg_risk_per_node,
            'Privilege-Weighted Remote Risk':       privilege_weighted_risk,

            # ── Firewall ──────────────────────────────────────────────────────
            'Total Firewall Incoming Rules':        total_fw_in,
            'Total Firewall Outgoing Rules':        total_fw_out,
            'Total Firewall Rules':                 total_fw,
            'Avg Firewall Incoming Rules per Node': total_fw_in  / total_nodes,
            'Avg Firewall Outgoing Rules per Node': total_fw_out / total_nodes,
            'Firewall Asymmetry (Inbound Bias)':    fw_asymmetry,
            'Firewall-to-Vulnerability Ratio':      total_fw / max(total_vulns, 1),
            'FW Incoming Allow Rules':              total_fw_in_allow,
            'FW Incoming Deny Rules':               total_fw_in_deny,
            'FW Outgoing Allow Rules':              total_fw_out_allow,
            'FW Outgoing Deny Rules':               total_fw_out_deny,
            'FW Allow Rate (%)':                    ((total_fw_in_allow + total_fw_out_allow) / max(total_fw, 1)) * 100,

            # ── Identifiers ───────────────────────────────────────────────────
            'Total Unique Property Identifiers':               total_id_props,
            'Total Unique Port Identifiers':                   total_id_ports,
            'Total Unique Local Vuln Identifiers':             total_id_local_vulns,
            'Total Unique Remote Vuln Identifiers':            total_id_remote_vulns,
            'Avg Unique Properties per Scenario':              df_scen['properties'].mean(),
            'Avg Unique Ports per Scenario':                   df_scen['ports'].mean(),
            'Avg Unique Local Vuln Identifiers per Scenario':  df_scen['local_vulnerabilities'].mean(),
            'Avg Unique Remote Vuln Identifiers per Scenario': df_scen['remote_vulnerabilities'].mean(),
            'Avg Vulnerability Identifier Coverage':           df_scen['vuln_identifier_coverage'].mean(),

            # ── Properties ────────────────────────────────────────────────────
            'Top 5 Most Common Node Properties': top_properties,
            'Total Unique Node Properties':      len(prop_counter),

            # ── Cross-Scenario Consistency (CV) ───────────────────────────────
            'CV: Nodes per Scenario':                cv(df_scen['num_nodes']),
            'CV: Total Vulnerabilities per Scenario':cv(df_scen['total_vulns']),
            'CV: Avg Node Value per Scenario':       cv(df_scen['avg_node_value']),
            'CV: Total Firewall Rules per Scenario': cv(df_scen['total_firewall_rules']),
            'CV: Agent Coverage per Scenario':       cv(df_scen['agent_coverage_pct']),
            'CV: Vuln Coverage per Scenario':        cv(df_scen['vuln_coverage_pct']),
            'CV: Avg SLA Weight per Scenario':       cv(df_scen['avg_sla_weight']),
            'CV: Avg Success Rate per Scenario':     cv(df_scen['avg_success_rate']),
            'CV: Total Services per Scenario':       cv(df_scen['total_services']),
        }

    def get_summary_dataframe(self) -> pd.DataFrame:
        """Returns the domain summary as a cleanly formatted Pandas DataFrame."""
        if not self.domain_summary:
            self.process_domain()
        return pd.DataFrame(list(self.domain_summary.items()), columns=['Metric', 'Value'])
        
    def get_node_dataframe(self) -> pd.DataFrame:
        """Returns the raw node data for deeper custom EDA."""
        return pd.DataFrame(self.raw_nodes_data)

    def get_scenario_dataframe(self) -> pd.DataFrame:
        """Returns the per-scenario aggregated data."""
        return pd.DataFrame(self.scenario_stats)

    # ──────────────────────────────────────────────────────────────────────────
    #  Global identifier comparison
    # ──────────────────────────────────────────────────────────────────────────

    def compare_with_global(self, global_ids: dict) -> dict:
        """
        Compare this domain's observed identifiers against the joint global
        identifier library.

        Parameters
        ----------
        global_ids : dict
            Parsed content of joint_identifiers.yaml, expected keys:
            'properties', 'ports', 'local_vulnerabilities', 'remote_vulnerabilities'

        Returns
        -------
        dict  — stored as self.global_comparison and also returned.
        """
        if not self.raw_nodes_data:
            raise RuntimeError("Run process_domain() before compare_with_global().")

        df_nodes = self.get_node_dataframe()
        df_scen  = self.get_scenario_dataframe()

        def _set(lst):
            return set(lst) if lst else set()

        # ── Global identifier sets ─────────────────────────────────────────────
        g_props       = _set(global_ids.get('properties', []))
        g_ports       = _set(str(p) for p in global_ids.get('ports', []))
        g_local_vulns = _set(global_ids.get('local_vulnerabilities', []))
        g_remote_vulns= _set(global_ids.get('remote_vulnerabilities', []))
        g_all         = g_props | g_ports | g_local_vulns | g_remote_vulns

        # ── Domain observed sets (deduped property lists, identifier columns) ──
        d_props       = _set(p for sublist in df_nodes['properties'].dropna() for p in sublist)

        # Ports seen in service_names and from identifiers file per scenario
        d_ports_svc   = _set(s for sublist in df_nodes['service_names'].dropna() for s in sublist)
        # Also collect from scenario-level identifier columns if populated
        d_local_vulns = set()
        d_remote_vulns= set()
        # Parse vulnerability names from scenario node YAML via raw_nodes_data
        # (vuln names are not stored explicitly — use identifier counts as proxy)
        # For exact name sets we rely on what's in the identifiers.yaml per scenario
        # which we don't re-read here; instead we derive from scenario stats ratios.

        # ── Per-category metrics ───────────────────────────────────────────────
        def _coverage(d_set, g_set):
            if not g_set: return np.nan
            return len(d_set & g_set) / len(g_set) * 100

        def _exclusivity(d_set, g_set):
            """% of domain identifiers NOT in global (unexpected/novel)."""
            if not d_set: return 0.0
            return len(d_set - g_set) / len(d_set) * 100

        def _unused(d_set, g_set):
            """Global identifiers not seen in this domain."""
            return sorted(g_set - d_set)

        prop_coverage      = _coverage(d_props,     g_props)
        prop_exclusivity   = _exclusivity(d_props,  g_props)
        prop_unused        = _unused(d_props,        g_props)
        prop_used          = sorted(d_props & g_props)
        prop_novel         = sorted(d_props - g_props)   # domain props not in global

        port_coverage      = _coverage(d_ports_svc, g_ports)
        port_unused        = _unused(d_ports_svc,   g_ports)

        # Vuln coverage: use scenario-level identifier counts vs global counts
        avg_local_id_ct  = df_scen['local_vulnerabilities'].mean()  if 'local_vulnerabilities'  in df_scen.columns else 0
        avg_remote_id_ct = df_scen['remote_vulnerabilities'].mean() if 'remote_vulnerabilities' in df_scen.columns else 0
        local_vuln_coverage  = min((avg_local_id_ct  / max(len(g_local_vulns),  1)) * 100, 100)
        remote_vuln_coverage = min((avg_remote_id_ct / max(len(g_remote_vulns), 1)) * 100, 100)

        # ── Overall utilization ────────────────────────────────────────────────
        # All unique identifiers "touched" by this domain (props + service port names)
        d_all_observed  = d_props | d_ports_svc
        overall_coverage = _coverage(d_all_observed, g_all)

        # ── Property specialization: how concentrated is usage ─────────────────
        # Entropy of property usage distribution vs uniform global distribution
        all_props_flat  = [p for sub in df_nodes['properties'].dropna() for p in sub]
        prop_freq       = Counter(all_props_flat)
        total_prop_uses = max(sum(prop_freq.values()), 1)
        prop_probs      = np.array([prop_freq[p] / total_prop_uses for p in g_props if p in prop_freq])
        if len(prop_probs) > 1:
            # Normalised entropy: 0 = fully concentrated, 1 = uniform across global
            entropy       = -np.sum(prop_probs * np.log2(prop_probs + 1e-12))
            max_entropy   = np.log2(len(g_props))
            norm_entropy  = entropy / max_entropy if max_entropy > 0 else 0.0
        else:
            norm_entropy  = 0.0

        # ── Top used / completely unused global properties ─────────────────────
        top_used_global_props   = dict(Counter({p: prop_freq[p] for p in g_props if p in prop_freq}).most_common(10))
        never_used_global_props = sorted(g_props - d_props)

        self.global_comparison = {
            # ── Global library sizes ───────────────────────────────────────────
            'Global: Total Properties':         len(g_props),
            'Global: Total Ports':              len(g_ports),
            'Global: Total Local Vulns':        len(g_local_vulns),
            'Global: Total Remote Vulns':       len(g_remote_vulns),
            'Global: Total Identifiers':        len(g_all),

            # ── Domain observed sizes ──────────────────────────────────────────
            'Domain: Unique Properties Observed':    len(d_props),
            'Domain: Unique Service Names Observed': len(d_ports_svc),

            # ── Coverage (% of global used by this domain) ────────────────────
            'Coverage: Properties vs Global (%)':     prop_coverage,
            'Coverage: Service Ports vs Global (%)':  port_coverage,
            'Coverage: Local Vulns vs Global (%)':    local_vuln_coverage,
            'Coverage: Remote Vulns vs Global (%)':   remote_vuln_coverage,
            'Coverage: Overall Identifiers (%)':      overall_coverage,

            # ── Exclusivity (domain-specific identifiers not in global) ────────
            'Exclusivity: Property Novelty (%)':      prop_exclusivity,
            'Novel Properties (not in global)':       prop_novel,
            'Novel Properties Count':                 len(prop_novel),

            # ── Unused global identifiers ──────────────────────────────────────
            'Unused Global Properties Count':         len(never_used_global_props),
            'Unused Global Properties (%)':           len(never_used_global_props) / max(len(g_props), 1) * 100,
            'Unused Global Ports Count':              len(port_unused),
            'Unused Global Ports (%)':                len(port_unused) / max(len(g_ports), 1) * 100,

            # ── Specialization ─────────────────────────────────────────────────
            'Property Usage Entropy (normalised)':    norm_entropy,
            # 0 = highly specialised (uses few properties heavily)
            # 1 = broad coverage (uses many properties evenly)

            # ── Lookup sets for plotting ───────────────────────────────────────
            'Top 10 Used Global Properties':          top_used_global_props,
            'Never-Used Global Properties':           never_used_global_props,
            'Used Global Properties':                 prop_used,
        }

        # Also inject key metrics into domain_summary for cross-domain comparison
        self.domain_summary.update({
            'Global Coverage: Properties (%)':    prop_coverage,
            'Global Coverage: Local Vulns (%)':   local_vuln_coverage,
            'Global Coverage: Remote Vulns (%)':  remote_vuln_coverage,
            'Global Coverage: Overall (%)':       overall_coverage,
            'Global: Unused Properties Count':    len(never_used_global_props),
            'Global: Unused Properties (%)':      len(never_used_global_props) / max(len(g_props), 1) * 100,
            'Global: Novel Properties Count':     len(prop_novel),
            'Property Usage Entropy (normalised)':norm_entropy,
        })

        return self.global_comparison

    def get_global_comparison_dataframe(self) -> pd.DataFrame:
        """Returns the global comparison results as a Pandas DataFrame."""
        if not hasattr(self, 'global_comparison') or not self.global_comparison:
            raise RuntimeError("Run compare_with_global(global_ids) first.")
        rows = [
            (k, v) for k, v in self.global_comparison.items()
            if not isinstance(v, (list, set, dict))
        ]
        return pd.DataFrame(rows, columns=['Metric', 'Value'])

    # ══════════════════════════════════════════════════════════════════════════
    #  DATA QUALITY
    # ══════════════════════════════════════════════════════════════════════════

    def analyze_data_quality(self) -> dict:
        """
        Assess dataset validity: null/missing rates, outliers (IQR), and
        normality tests (Shapiro-Wilk) on key continuous fields.
        """
        from scipy import stats as sp_stats

        df = self.get_node_dataframe()
        n  = max(len(df), 1)

        # ── Null / missing rates ──────────────────────────────────────────────
        EXPECTED_FIELDS = [
            'value', 'agent_installed', 'privilege_level', 'reimagable',
            'status', 'sla_weight', 'is_goal', 'image',
            'num_services', 'num_interfaces',
            'local_vulnerabilities', 'remote_vulnerabilities',
        ]
        null_rates = {}
        for col in EXPECTED_FIELDS:
            if col in df.columns:
                missing = df[col].isna().sum() + (
                    (df[col] == '').sum() if df[col].dtype == object else 0
                )
                null_rates[col] = (missing / n) * 100
            else:
                null_rates[col] = 100.0   # column entirely absent

        zero_image      = (df['image'].isin(['', None, np.nan]).sum()
                           if 'image' in df.columns else n)
        zero_sla        = (df['sla_weight'] == 0).sum() if 'sla_weight' in df.columns else 0
        status_zero_pct = ((df['status'] == 0).sum() / n) * 100 if 'status' in df.columns else 0.0

        # ── Outliers via IQR (1.5× rule) ─────────────────────────────────────
        def _iqr_outliers(series):
            s = series.dropna()
            if len(s) < 4:
                return 0, 0.0
            q1, q3 = s.quantile(0.25), s.quantile(0.75)
            iqr = q3 - q1
            mask = (s < q1 - 1.5 * iqr) | (s > q3 + 1.5 * iqr)
            return int(mask.sum()), (mask.sum() / len(s)) * 100

        outlier_results = {}
        for col in ['value', 'total_vulnerabilities', 'sla_weight',
                    'num_services', 'firewall_incoming', 'firewall_outgoing']:
            if col in df.columns:
                cnt, pct = _iqr_outliers(df[col])
                outlier_results[col] = {'count': cnt, 'pct': pct}

        # ── Normality tests (Shapiro-Wilk, max 5000 samples) ─────────────────
        normality_results = {}
        for col in ['value', 'total_vulnerabilities', 'sla_weight', 'num_services']:
            if col not in df.columns:
                continue
            s = df[col].dropna()
            s = s.sample(min(5000, len(s)), random_state=42) if len(s) > 5000 else s
            if len(s) < 8:
                continue
            stat, p = sp_stats.shapiro(s)
            normality_results[col] = {
                'statistic': round(float(stat), 4),
                'p_value':   round(float(p), 6),
                'normal':    bool(p > 0.05),
            }

        # ── Skewness & kurtosis ───────────────────────────────────────────────
        shape_stats = {}
        for col in ['value', 'total_vulnerabilities', 'sla_weight']:
            if col in df.columns:
                s = df[col].dropna()
                shape_stats[col] = {
                    'skewness': round(float(s.skew()), 4),
                    'kurtosis': round(float(s.kurtosis()), 4),
                }

        # ── Schema compliance: nodes missing any non-null expected field ───────
        required_cols = ['value', 'privilege_level', 'status', 'sla_weight']
        incomplete_nodes = int(df[required_cols].isna().any(axis=1).sum()) \
            if all(c in df.columns for c in required_cols) else -1

        self.data_quality = {
            'Null Rate per Field (%)':          null_rates,
            'Nodes with Zero SLA Weight':       int(zero_sla),
            'Nodes with Zero SLA Weight (%)':   (zero_sla / n) * 100,
            'Nodes with Empty Image Field (%)': (zero_image / n) * 100,
            'Nodes with Status=0 (%)':          status_zero_pct,
            'Incomplete Nodes (any null)':      incomplete_nodes,
            'Incomplete Nodes (%)':             (incomplete_nodes / n) * 100,
            'Outliers by Field':                outlier_results,
            'Normality Tests (Shapiro-Wilk)':   normality_results,
            'Shape Stats':                      shape_stats,
            # Flat summary metrics for cross-domain table
            'DQ: Avg Null Rate (%)':            np.mean(list(null_rates.values())),
            'DQ: Outlier Nodes % (value)':      outlier_results.get('value', {}).get('pct', 0),
            'DQ: Value Skewness':               shape_stats.get('value', {}).get('skewness', np.nan),
            'DQ: Value Kurtosis':               shape_stats.get('value', {}).get('kurtosis', np.nan),
            'DQ: Value is Normal':              normality_results.get('value', {}).get('normal', False),
        }
        self.domain_summary.update({k: v for k, v in self.data_quality.items()
                                     if not isinstance(v, dict)})
        return self.data_quality

    # ══════════════════════════════════════════════════════════════════════════
    #  SCENARIO DIVERSITY
    # ══════════════════════════════════════════════════════════════════════════

    def analyze_diversity(self) -> dict:
        """
        Measure scenario-level diversity: pairwise Jaccard similarity on
        property sets, diversity index, vocabulary coverage, and duplicate detection.
        """
        df      = self.get_node_dataframe()
        df_scen = self.get_scenario_dataframe()

        # Build per-scenario property sets
        scen_prop_sets = {}
        for scen, grp in df.groupby('scenario'):
            props = set(p for sublist in grp['properties'].dropna() for p in sublist)
            scen_prop_sets[scen] = props

        scenarios = list(scen_prop_sets.keys())
        n_scen    = max(len(scenarios), 1)

        # Domain-wide vocabulary
        domain_vocab = set(p for s in scen_prop_sets.values() for p in s)
        vocab_size   = max(len(domain_vocab), 1)

        # ── Pairwise Jaccard similarity matrix ────────────────────────────────
        def jaccard(a, b):
            u = len(a | b)
            return len(a & b) / u if u > 0 else 0.0

        sim_matrix = np.zeros((n_scen, n_scen))
        for i, s1 in enumerate(scenarios):
            for j, s2 in enumerate(scenarios):
                sim_matrix[i, j] = jaccard(scen_prop_sets[s1], scen_prop_sets[s2])

        # Off-diagonal mean = avg pairwise similarity; diversity = 1 - that
        mask = ~np.eye(n_scen, dtype=bool)
        avg_sim      = float(sim_matrix[mask].mean()) if n_scen > 1 else 1.0
        diversity_idx = 1.0 - avg_sim

        # ── Vocabulary coverage per scenario ──────────────────────────────────
        vocab_coverages = [
            len(scen_prop_sets[s]) / vocab_size for s in scenarios
        ]

        # ── Unique scenario fingerprints ──────────────────────────────────────
        # Fingerprint = (num_nodes, frozenset of properties)
        fingerprints = []
        for scen in scenarios:
            nn = df_scen[df_scen['scenario_name'] == scen]['num_nodes'].values
            nn = int(nn[0]) if len(nn) > 0 else 0
            fingerprints.append((nn, frozenset(scen_prop_sets[scen])))

        unique_fps   = len(set(fingerprints))
        duplicate_fps= n_scen - unique_fps

        self.diversity = {
            'Scenario Names':                   scenarios,
            'Jaccard Similarity Matrix':         sim_matrix,
            'Scenario Property Sets':            scen_prop_sets,
            'Avg Pairwise Jaccard Similarity':   avg_sim,
            'Scenario Diversity Index (0-1)':    diversity_idx,
            'Domain Vocabulary Size':            vocab_size,
            'Vocabulary Coverage per Scenario':  vocab_coverages,
            'Avg Vocabulary Coverage (%)':       np.mean(vocab_coverages) * 100,
            'Std Vocabulary Coverage (%)':       np.std(vocab_coverages) * 100,
            'Unique Scenario Fingerprints':      unique_fps,
            'Duplicate Scenario Fingerprints':   duplicate_fps,
            'Duplicate Scenarios (%)':           (duplicate_fps / n_scen) * 100,
        }
        self.domain_summary.update({
            'Diversity: Avg Jaccard Similarity':    avg_sim,
            'Diversity: Index (0=identical,1=unique)': diversity_idx,
            'Diversity: Vocabulary Size':           vocab_size,
            'Diversity: Avg Vocab Coverage (%)':   np.mean(vocab_coverages) * 100,
            'Diversity: Duplicate Scenarios (%)':  (duplicate_fps / n_scen) * 100,
        })
        return self.diversity

    # ══════════════════════════════════════════════════════════════════════════
    #  CLASS BALANCE & REPRESENTATION
    # ══════════════════════════════════════════════════════════════════════════

    def analyze_class_balance(self) -> dict:
        """
        Assess class balance relevant to RL/ML training:
        goal prevalence, vulnerability balance, property Gini,
        agent coverage, and statistical shape metrics.
        """
        df      = self.get_node_dataframe()
        df_scen = self.get_scenario_dataframe()
        n       = max(len(df), 1)

        # ── Goal node prevalence across scenarios ─────────────────────────────
        goal_prev = df_scen['goal_pct'] if 'goal_pct' in df_scen.columns \
                    else (df_scen['nodes_is_goal'] / df_scen['num_nodes'].replace(0,1) * 100)
        min_goal_prev  = float(goal_prev.min())
        max_goal_prev  = float(goal_prev.max())
        std_goal_prev  = float(goal_prev.std())
        zero_goal_scen = int((goal_prev == 0).sum())   # scenarios with no goal nodes

        # ── Vulnerability type balance across scenarios ───────────────────────
        vuln_ratio = df_scen['local_to_remote_vuln_ratio'].dropna()
        vuln_balance_cv = float(vuln_ratio.std() / vuln_ratio.mean()) \
            if vuln_ratio.mean() != 0 else np.nan

        # ── Gini coefficient on property frequency ────────────────────────────
        all_props = [p for sub in df['properties'].dropna() for p in sub]
        prop_freq = np.array(sorted(Counter(all_props).values()), dtype=float)
        def gini(arr):
            if len(arr) == 0: return np.nan
            arr = np.sort(arr)
            n   = len(arr)
            idx = np.arange(1, n+1)
            return float((2 * np.sum(idx * arr) / (n * arr.sum())) - (n+1)/n)
        prop_gini = gini(prop_freq) if len(prop_freq) > 0 else np.nan

        # ── Skewness & kurtosis on node value ────────────────────────────────
        val_skew = float(df['value'].skew())
        val_kurt = float(df['value'].kurtosis())

        # ── Degenerate scenario detection ────────────────────────────────────
        no_agent_scen  = int((df_scen['nodes_with_agent'] == 0).sum()) \
            if 'nodes_with_agent' in df_scen.columns else -1
        no_vuln_scen   = int((df_scen['total_vulns'] == 0).sum()) \
            if 'total_vulns' in df_scen.columns else -1
        no_remote_scen = int((df_scen['total_remote_vulns'] == 0).sum()) \
            if 'total_remote_vulns' in df_scen.columns else -1

        # ── Value concentration: top-10% nodes hold what % of total value ─────
        vals_sorted = df['value'].sort_values(ascending=False)
        top10_cut   = max(int(len(vals_sorted) * 0.1), 1)
        total_val   = vals_sorted.sum()
        top10_share = (vals_sorted.iloc[:top10_cut].sum() / total_val * 100) \
            if total_val > 0 else 0.0

        self.class_balance = {
            # Goal prevalence
            'Goal Prevalence per Scenario (Min %)':  min_goal_prev,
            'Goal Prevalence per Scenario (Max %)':  max_goal_prev,
            'Goal Prevalence per Scenario (Std)':    std_goal_prev,
            'Scenarios with Zero Goal Nodes':        zero_goal_scen,
            'Scenarios with Zero Goal Nodes (%)':    (zero_goal_scen / max(len(df_scen),1)) * 100,
            # Vulnerability balance
            'Vuln Local:Remote Ratio (CV)':          vuln_balance_cv,
            'Scenarios with Zero Remote Vulns':      no_remote_scen,
            # Property Gini
            'Property Frequency Gini':               prop_gini,
            # Value distribution
            'Node Value Skewness':                   val_skew,
            'Node Value Kurtosis':                   val_kurt,
            'Top-10% Nodes Value Share (%)':         top10_share,
            # Degenerate scenarios
            'Degenerate: No Agent Scenarios':        no_agent_scen,
            'Degenerate: No Vuln Scenarios':         no_vuln_scen,
            'Degenerate: No Remote Vuln Scenarios':  no_remote_scen,
        }
        self.domain_summary.update({
            k: v for k, v in self.class_balance.items()
            if not isinstance(v, (dict, list))
        })
        return self.class_balance

    # ══════════════════════════════════════════════════════════════════════════
    #  ATTACK SURFACE & LATERAL MOVEMENT
    # ══════════════════════════════════════════════════════════════════════════

    def analyze_attack_surface(self) -> dict:
        """
        Identify pivot nodes, credential chain potential, crown jewels,
        and goal node exposure.
        """
        df = self.get_node_dataframe()
        n  = max(len(df), 1)

        # ── Pivot nodes: remote-vulnerable AND leaks credentials ──────────────
        if 'remote_vulnerabilities' in df.columns and 'total_creds_leaked' in df.columns:
            pivot_mask = (df['remote_vulnerabilities'] > 0) & (df['total_creds_leaked'] > 0)
            pivot_nodes = int(pivot_mask.sum())
        else:
            pivot_nodes = 0

        # ── Crown jewels: top-value-quartile + remote-vulnerable ──────────────
        val_q75 = df['value'].quantile(0.75)
        if 'remote_vulnerabilities' in df.columns:
            crown_mask   = (df['value'] >= val_q75) & (df['remote_vulnerabilities'] > 0)
            crown_jewels = int(crown_mask.sum())
            crown_total_value = float(df[crown_mask]['value'].sum())
        else:
            crown_jewels, crown_total_value = 0, 0.0

        # ── Goal node exposure ────────────────────────────────────────────────
        goal_df = df[df['is_goal'] == True] if 'is_goal' in df.columns else pd.DataFrame()
        if not goal_df.empty and 'remote_vulnerabilities' in goal_df.columns:
            goal_exposed      = int((goal_df['remote_vulnerabilities'] > 0).sum())
            goal_exposed_pct  = (goal_exposed / max(len(goal_df), 1)) * 100
            goal_avg_fw_in    = float(goal_df['firewall_incoming'].mean()) \
                if 'firewall_incoming' in goal_df.columns else np.nan
            goal_avg_fw_out   = float(goal_df['firewall_outgoing'].mean()) \
                if 'firewall_outgoing' in goal_df.columns else np.nan
        else:
            goal_exposed = goal_exposed_pct = 0
            goal_avg_fw_in = goal_avg_fw_out = np.nan

        # ── Max credential chain depth (BFS on leakage graph) ────────────────
        # Build node-name → leakage list from raw_nodes_data
        leak_graph: dict = {}   # src_node -> set of reachable node names
        for row in self.raw_nodes_data:
            src = row['node_name']
            # total_nodes_leaked > 0 indicates this node's vulns leak node IDs
            # We use total_creds_leaked as a proxy for credential forwarding
            if row.get('total_creds_leaked', 0) > 0:
                leak_graph[src] = leak_graph.get(src, set())
                # Without the actual credential target lists we approximate:
                # nodes that have both remote entry + local cred-dump are
                # one hop from any remote-vulnerable node in the same scenario
                leak_graph[src].add('__any__')

        # Simple proxy metric: longest chain = max local-vuln-depth reachable
        # via scenarios that have at least one entry point + one cred leak
        df_scen = self.get_scenario_dataframe()
        has_chain = (
            (df_scen.get('total_remote_vulns', pd.Series([0])) > 0) &
            (df_scen.get('total_creds_leaked', pd.Series([0])) > 0)
        ) if 'total_remote_vulns' in df_scen.columns else pd.Series([False])
        chain_scenarios = int(has_chain.sum())
        chain_pct       = (chain_scenarios / max(len(df_scen), 1)) * 100

        # ── High-privilege remote-exposed nodes ───────────────────────────────
        if 'privilege_level' in df.columns and 'remote_vulnerabilities' in df.columns:
            hi_priv  = df['privilege_level'] >= df['privilege_level'].quantile(0.75)
            hi_priv_exposed = int((hi_priv & (df['remote_vulnerabilities'] > 0)).sum())
        else:
            hi_priv_exposed = 0

        self.attack_surface = {
            'Pivot Nodes (remote vuln + cred leak)':     pivot_nodes,
            'Pivot Nodes (%)':                           (pivot_nodes / n) * 100,
            'Crown Jewel Nodes (top-value + remote-exp)':crown_jewels,
            'Crown Jewels Total Value':                  crown_total_value,
            'Crown Jewels (%)':                          (crown_jewels / n) * 100,
            'Goal Nodes Directly Exposed (remote vuln)': goal_exposed,
            'Goal Nodes Exposed (%)':                    goal_exposed_pct,
            'Goal Node Avg Firewall Incoming':           goal_avg_fw_in,
            'Goal Node Avg Firewall Outgoing':           goal_avg_fw_out,
            'Scenarios with Full Attack Chain (%)':      chain_pct,
            'High-Privilege Remote-Exposed Nodes':       hi_priv_exposed,
            'High-Privilege Exposed (%)':                (hi_priv_exposed / n) * 100,
        }
        self.domain_summary.update({
            k: v for k, v in self.attack_surface.items()
            if not isinstance(v, (dict, list))
        })
        return self.attack_surface

    # ══════════════════════════════════════════════════════════════════════════
    #  REWARD SIGNAL QUALITY  (RL-specific)
    # ══════════════════════════════════════════════════════════════════════════

    def analyze_reward_signal(self) -> dict:
        """
        Assess the quality of the reward signal for RL training:
        reward density, reachable value, goal isolation, and solvability.
        """
        df      = self.get_node_dataframe()
        df_scen = self.get_scenario_dataframe()
        n       = max(len(df), 1)
        n_scen  = max(len(df_scen), 1)

        total_value = df['value'].sum()

        # ── Reward density: total value / node count ──────────────────────────
        reward_density = float(total_value / n)

        # ── Reachable value: value of remote-vulnerable nodes ────────────────
        if 'remote_vulnerabilities' in df.columns:
            reachable_mask  = df['remote_vulnerabilities'] > 0
            reachable_value = float(df[reachable_mask]['value'].sum())
            reachable_value_pct = (reachable_value / total_value * 100) if total_value > 0 else 0.0
        else:
            reachable_value = reachable_value_pct = 0.0

        # ── Goal isolation score ──────────────────────────────────────────────
        # Higher = better protected (more fw rules, lower remote vulns, higher privilege)
        goal_df = df[df['is_goal'] == True] if 'is_goal' in df.columns else pd.DataFrame()
        if not goal_df.empty:
            goal_avg_fw = float(
                (goal_df.get('firewall_incoming', pd.Series([0])) +
                 goal_df.get('firewall_outgoing', pd.Series([0]))).mean()
            )
            goal_avg_priv      = float(goal_df['privilege_level'].mean())
            goal_remote_exp_pct= float(
                (goal_df.get('remote_vulnerabilities', pd.Series([0])) > 0).mean() * 100
            )
            # Composite isolation: high fw + high priv + low exposure = well isolated
            # Normalised to 0-1 (higher = more isolated = harder for attacker)
            goal_isolation = min(
                (goal_avg_fw / max(df.get('firewall_incoming', pd.Series([1])).mean() +
                                   df.get('firewall_outgoing', pd.Series([1])).mean(), 1)) *
                (1 - goal_remote_exp_pct / 100),
                1.0
            )
        else:
            goal_avg_fw = goal_avg_priv = goal_isolation = np.nan
            goal_remote_exp_pct = 100.0

        # ── Per-scenario solvability score ────────────────────────────────────
        # A scenario is "solvable" if it has:
        #   1. At least one goal node
        #   2. At least one remote entry point
        #   3. At least one credential-leaking vulnerability
        has_goal   = df_scen.get('nodes_is_goal',    pd.Series([0])) > 0
        has_remote = df_scen.get('total_remote_vulns',pd.Series([0])) > 0
        has_creds  = df_scen.get('total_creds_leaked', pd.Series([0])) > 0
        solvable   = has_goal & has_remote & has_creds
        solvability_rate = float(solvable.mean() * 100)

        # Soft solvability: has goal + has remote (no cred requirement)
        soft_solvable     = has_goal & has_remote
        soft_solvability  = float(soft_solvable.mean() * 100)

        # ── Value-weighted reachability ───────────────────────────────────────
        # Mean value of remote-vulnerable nodes vs non-reachable
        if 'remote_vulnerabilities' in df.columns:
            reachable_mean_val   = float(df[df['remote_vulnerabilities'] > 0]['value'].mean()) \
                if reachable_mask.any() else 0.0
            unreachable_mean_val = float(df[df['remote_vulnerabilities'] == 0]['value'].mean())
        else:
            reachable_mean_val = unreachable_mean_val = float(df['value'].mean())

        self.reward_signal = {
            'Reward Density (total value / nodes)':     reward_density,
            'Reachable Value (remote-exp nodes)':        reachable_value,
            'Reachable Value (%)':                       reachable_value_pct,
            'Reachable Mean Node Value':                 reachable_mean_val,
            'Unreachable Mean Node Value':               unreachable_mean_val,
            'Goal Node Avg Firewall Rules':              goal_avg_fw,
            'Goal Node Avg Privilege':                   goal_avg_priv,
            'Goal Node Remote Exposure (%)':             goal_remote_exp_pct,
            'Goal Isolation Score (0-1)':                goal_isolation,
            'Solvability Rate (%)':                      solvability_rate,
            'Soft Solvability Rate (%)':                 soft_solvability,
        }
        self.domain_summary.update({
            k: v for k, v in self.reward_signal.items()
            if not isinstance(v, (dict, list))
        })
        return self.reward_signal

    def run_full_analysis(self, global_ids: dict = None) -> None:
        """
        Run all analysis modules in order. Call this instead of process_domain()
        to get the complete thesis-ready analysis.
        """
        self.process_domain()
        self.analyze_data_quality()
        self.analyze_diversity()
        self.analyze_class_balance()
        self.analyze_attack_surface()
        self.analyze_reward_signal()
        if global_ids is not None:
            self.compare_with_global(global_ids)