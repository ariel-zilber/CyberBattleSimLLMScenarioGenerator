import re as _re
from pathlib import Path
from ..latex_base import e
from ..data_utils import OUTCOME_KEYS, OUTCOME_SHORT
from ..visual_utils import save_outcome_chart, save_topology_radar

# ─────────────────────────────────────────────────────────────────────────────
# Large lookup tables (ported from monolithic generate_executive_report.py)
# ─────────────────────────────────────────────────────────────────────────────

_VULN_TO_CVE = {
    "Solvability.EternalBlue":          "CVE-2017-0144",
    "Solvability.BlueKeep":             "CVE-2019-0708",
    "Solvability.PrintNightmare":       "CVE-2021-34527",
    "Solvability.PetitPotam":           "CVE-2021-36942",
    "Solvability.noPac":                "CVE-2021-42287",
    "Solvability.IIS_RCE":              "CVE-2022-21907",
    "Solvability.ProxyLogon":           "CVE-2021-26855",
    "Solvability.Outlook_NTLM":         "CVE-2023-23397",
    "Solvability.Certifried":           "CVE-2022-26923",
    "Solvability.WP_TatsuBuilder_RCE":  "CVE-2021-25094",
    "Solvability.WP_ObjectInjection":   "CVE-2022-21663",
    "Solvability.Nginx_ResolverRCE":    "CVE-2021-23017",
    "Solvability.WordPress_ImageMagick":   "CVE-2026-22770",
    "Solvability.WordPress_ImageMagick_2": "CVE-2026-23876",
    "Solvability.Drupal_RCE":           "CVE-2024-55637",
    "Solvability.Nginx_LibCrypto_Critical": "CVE-2025-15467",
    "Solvability.Nginx_LibCrypto_High":     "CVE-2025-69421",
    "Solvability.Vault_GoStdlib":       "CVE-2024-41110",
    "Solvability.Vault_GoStdlib_2":     "CVE-2025-0377",
    "Solvability.Grafana_GoStdlib":     "CVE-2026-33186",
    "Solvability.OAuthProxy_RCE":       "CVE-2026-34457",
    "Solvability.Jenkins_RCE":          "CVE-2026-35414",
    "Solvability.Jenkins_High":         "CVE-2026-35385",
    "Solvability.Kafka_LibXML":         "CVE-2024-56171",
    "Solvability.Kafka_SQLite":         "CVE-2025-6965",
    "Solvability.Airflow_RCE":          "CVE-2024-12084",
    "Solvability.Airflow_RCE_2":        "CVE-2023-45853",
    "Solvability.Redis_GoStdlib":       "CVE-2023-24538",
    "Solvability.Redis_GoStdlib_2":     "CVE-2023-24540",
    "Solvability.MySQL_RCE":            "CVE-2022-21417",
    "Solvability.PanOS_CMDInject":      "CVE-2024-3400",
    "Solvability.FortiOS_SSLVPN_RCE":   "CVE-2023-27997",
    "Solvability.FortiOS_AuthBypass":   "CVE-2020-12812",
    "Solvability.CiscoNXOS_LLDP":       "CVE-2018-0395",
    "Solvability.CiscoNXOS_FCoE":       "CVE-2019-1595",
    "Solvability.PanOS_TOCTOU":         "CVE-2021-3054",
    "Solvability.CiscoASA_OSPF":        "CVE-2026-20020",
    "Solvability.CiscoNXOS_CMDInject":  "CVE-2017-12334",
    "Solvability.CiscoNXOS_CMDInject2": "CVE-2017-12341",
    "Solvability.FactoryTalk_Deser":    "CVE-2021-27462",
    "Solvability.FactoryTalk_CMDInject":"CVE-2021-27476",
    "Solvability.Rockwell_KeyReuse":    "CVE-2021-22681",
    "Solvability.OPC_UA_RCE":           "CVE-2023-32784",
    "Solvability.Modicon_AuthBypass":   "CVE-2018-7760",
    "Solvability.Modicon_HTTPInject":   "CVE-2018-7761",
    "Solvability.MicroLogix_BufferOverflow": "CVE-2017-16740",
    "Solvability.WinCC_HardcodedPwd":   "CVE-2010-2772",
    "Solvability.FactoryTalk_HardcodedKey": "CVE-2023-2637",
    "Solvability.FactoryTalk_RCE":      "CVE-2022-38766",
    "Solvability.OPCUA_BufferOverflow": "CVE-2023-27267",
    "Solvability.Modicon_StackOverflow":"CVE-2022-3977",
    "Solvability.IIS_HTTP_Stack":       "CVE-2021-31166",
    # Windows CVEs from windows_cves.json
    "Solvability.ADCS_CertSpoof":       "CVE-2022-34691",
    "Solvability.ADCS_EOP_1":           "CVE-2024-26212",
    "Solvability.ADCS_EOP_2":           "CVE-2024-26233",
    "Solvability.ADCS_EOP_3":           "CVE-2024-30082",
    "Solvability.ADCS_EOP_4":           "CVE-2022-26929",
    "Solvability.ADCS_InfDisc":         "CVE-2023-36368",
    "Solvability.AD_Services_EOP":      "CVE-2022-21857",
    "Solvability.ALPC_EOP":             "CVE-2023-21674",
    "Solvability.CLFS_EOP_1":           "CVE-2023-23376",
    "Solvability.CLFS_EOP_2":           "CVE-2023-28252",
    "Solvability.CLFS_EOP_3":           "CVE-2022-24521",
    "Solvability.CLFS_Privesc":         "CVE-2022-37969",
    "Solvability.CNG_EOP":              "CVE-2023-28229",
    "Solvability.CNG_EOP_2":            "CVE-2022-41125",
    "Solvability.CredSSP":              "CVE-2018-0886",
    "Solvability.DCOM_RCE_1":           "CVE-2022-30149",
    "Solvability.DNS_Client_RCE":       "CVE-2021-28470",
    "Solvability.DNS_EOP":              "CVE-2021-26898",
    "Solvability.DNS_RCE_1":            "CVE-2021-26897",
    "Solvability.DNS_RCE_2":            "CVE-2023-28254",
    "Solvability.DNS_RCE_3":            "CVE-2023-23400",
    "Solvability.DotNet_EOP":           "CVE-2023-28260",
    "Solvability.Edge_EOP":             "CVE-2022-22021",
    "Solvability.EternalRomance":       "CVE-2017-0147",
    "Solvability.Exchange_NTLM_Relay":  "CVE-2024-21410",
    "Solvability.Exchange_RCE_1":       "CVE-2023-21529",
    "Solvability.Exchange_RCE_2":       "CVE-2023-21706",
    "Solvability.Exchange_RCE_3":       "CVE-2023-21707",
    "Solvability.Exchange_RCE_4":       "CVE-2023-35368",
    "Solvability.Exchange_RCE_5":       "CVE-2024-26198",
    "Solvability.HTTP3_RCE":            "CVE-2023-23392",
    "Solvability.HyperV_EOP":           "CVE-2022-35795",
    "Solvability.HyperV_RCE":           "CVE-2021-28476",
    "Solvability.HyperV_RCE_2":         "CVE-2023-35628",
    "Solvability.IIS_EOP":              "CVE-2022-30209",
    "Solvability.IIS_EOP_2":            "CVE-2023-36393",
    "Solvability.IIS_RCE_2":            "CVE-2021-27085",
    "Solvability.IIS_Spoofing":         "CVE-2022-21983",
    "Solvability.Kernel_EOP_1":         "CVE-2021-31979",
    "Solvability.Kernel_EOP_2":         "CVE-2021-33771",
    "Solvability.Kernel_EOP_3":         "CVE-2024-21338",
    "Solvability.Kernel_EOP_4":         "CVE-2021-36955",
    "Solvability.Kernel_EOP_5":         "CVE-2022-37989",
    "Solvability.Kernel_EOP_6":         "CVE-2020-1027",
    "Solvability.Kerberos_EOP":         "CVE-2022-26931",
    "Solvability.Kerberos_EOP_2":       "CVE-2023-28244",
    "Solvability.Kerberos_EOP_3":       "CVE-2022-21896",
    "Solvability.LDAP_AuthBypass":      "CVE-2024-20674",
    "Solvability.LDAP_DoS":             "CVE-2023-21757",
    "Solvability.LDAP_EOP":             "CVE-2022-22031",
    "Solvability.LDAP_InfoDisc":        "CVE-2023-21676",
    "Solvability.LDAP_RCE_1":           "CVE-2022-26919",
    "Solvability.LDAP_RCE_2":           "CVE-2023-28283",
    "Solvability.LDAP_Spoof":           "CVE-2022-30216",
    "Solvability.LSASS_EOP":            "CVE-2023-21727",
    "Solvability.LSASS_EOP_AD":         "CVE-2023-21524",
    "Solvability.LSA_Spoofing":         "CVE-2022-26925",
    "Solvability.MS08_067":             "CVE-2008-4250",
    "Solvability.MSAA_Priv":            "CVE-2021-36949",
    "Solvability.MSHTML_RCE":           "CVE-2021-40444",
    "Solvability.MSMQ_EOP":             "CVE-2023-21537",
    "Solvability.MSSQL_InfoDisc":       "CVE-2024-28995",
    "Solvability.MSSQL_Privesc":        "CVE-2023-21688",
    "Solvability.MSSQL_RCE_1":          "CVE-2024-37338",
    "Solvability.MSSQL_RCE_2":          "CVE-2024-37340",
    "Solvability.MSSQL_RCE_3":          "CVE-2024-37342",
    "Solvability.NetNTLMv2_Downgrade":  "CVE-2022-37958",
    "Solvability.NFS_RCE":              "CVE-2022-24497",
    "Solvability.NFS_RCE_TCPIP":        "CVE-2022-34715",
    "Solvability.NTFS_RCE":             "CVE-2020-17096",
    "Solvability.NTLM_EOP":             "CVE-2023-21746",
    "Solvability.PPTP_RCE":             "CVE-2023-28243",
    "Solvability.PPTP_RCE_WinRM":       "CVE-2022-22035",
    "Solvability.ProxyNotShell_RCE":    "CVE-2022-41082",
    "Solvability.ProxyNotShell_SSRF":   "CVE-2022-41040",
    "Solvability.ProxyShell_Privesc":   "CVE-2021-34523",
    "Solvability.RD_Cert_Bypass":       "CVE-2023-35352",
    "Solvability.RDG_RCE":              "CVE-2020-0655",
    "Solvability.RDP_InfoDisc":         "CVE-2019-1225",
    "Solvability.RDP_RCE_0787":         "CVE-2019-0787",
    "Solvability.RDP_RCE_0788":         "CVE-2019-0788",
    "Solvability.RDP_RCE_1226":         "CVE-2019-1226",
    "Solvability.Remote_Registry":      "CVE-2023-36401",
    "Solvability.RPC_EOP":              "CVE-2023-21678",
    "Solvability.RPC_RCE_1":            "CVE-2022-30221",
    "Solvability.RPC_RCE_2":            "CVE-2022-26809",
    "Solvability.RPC_RCE_3":            "CVE-2023-23405",
    "Solvability.SIGRed":               "CVE-2020-1350",
    "Solvability.SMB_Client_RCE":       "CVE-2022-35804",
    "Solvability.SMB_InfDisc":          "CVE-2022-32230",
    "Solvability.Spooler_EOP_1":        "CVE-2022-30206",
    "Solvability.Spooler_EOP_2":        "CVE-2022-22022",
    "Solvability.Spooler_EOP_3":        "CVE-2021-34483",
    "Solvability.Spooler_EOP_4":        "CVE-2022-30226",
    "Solvability.Spooler_RCE":          "CVE-2021-36958",
    "Solvability.TCPIP_DoS":            "CVE-2021-24086",
    "Solvability.TCPIP_RCE_1":          "CVE-2021-24074",
    "Solvability.TCPIP_RCE_2":          "CVE-2021-24094",
    "Solvability.Win32k_EOP":           "CVE-2023-21822",
    "Solvability.Win32k_EOP_1":         "CVE-2021-34486",
    "Solvability.Win32k_EOP_2":         "CVE-2023-35359",
    "Solvability.Win32k_EOP_3":         "CVE-2021-26868",
    "Solvability.Win32k_EOP_4":         "CVE-2022-21999",
    "Solvability.Win_EOP_Cred":         "CVE-2022-24474",
    "Solvability.WSD_RCE":              "CVE-2023-28250",
    "Solvability.iSCSI_RCE":            "CVE-2023-21803",
    "Solvability.noPac_2":              "CVE-2021-42278",
}

_CVE_TACTICS = {
    "CVE-2017-0144": ["TA0001", "TA0008"],
    "CVE-2019-0708": ["TA0001", "TA0008"],
    "CVE-2021-34527": ["TA0004", "TA0001"],
    "CVE-2021-36942": ["TA0006", "TA0008"],
    "CVE-2021-42287": ["TA0004", "TA0006"],
    "CVE-2022-21907": ["TA0001"],
    "CVE-2021-26855": ["TA0001"],
    "CVE-2023-23397": ["TA0006", "TA0001"],
    "CVE-2022-26923": ["TA0004", "TA0006"],
    "CVE-2021-25094": ["TA0001"],
    "CVE-2022-21663": ["TA0001", "TA0002"],
    "CVE-2021-23017": ["TA0001"],
    "CVE-2026-22770": ["TA0001", "TA0003"],
    "CVE-2026-23876": ["TA0001", "TA0003"],
    "CVE-2024-55637": ["TA0001"],
    "CVE-2025-15467": ["TA0001"],
    "CVE-2025-69421": ["TA0001"],
    "CVE-2024-41110": ["TA0001"],
    "CVE-2025-0377":  ["TA0001"],
    "CVE-2026-33186": ["TA0001"],
    "CVE-2026-34457": ["TA0001"],
    "CVE-2026-35414": ["TA0002", "TA0001"],
    "CVE-2026-35385": ["TA0006", "TA0009"],
    "CVE-2024-56171": ["TA0002"],
    "CVE-2025-6965":  ["TA0002"],
    "CVE-2024-12084": ["TA0002"],
    "CVE-2023-45853": ["TA0002"],
    "CVE-2023-24538": ["TA0001"],
    "CVE-2023-24540": ["TA0001"],
    "CVE-2022-21417": ["TA0008"],
    "CVE-2024-3400":  ["TA0001"],
    "CVE-2023-27997": ["TA0001"],
    "CVE-2020-12812": ["TA0001", "TA0006"],
    "CVE-2018-0395":  ["TA0008"],
    "CVE-2019-1595":  ["TA0008"],
    "CVE-2021-3054":  ["TA0004"],
    "CVE-2026-20020": ["TA0008"],
    "CVE-2017-12334": ["TA0004", "TA0002"],
    "CVE-2017-12341": ["TA0004", "TA0002"],
    "CVE-2021-27462": ["ICS-IA", "TA0001"],
    "CVE-2021-27476": ["ICS-EX", "TA0002"],
    "CVE-2021-22681": ["ICS-LM", "ICS-IM"],
    "CVE-2023-32784": ["ICS-IA", "TA0001"],
    "CVE-2018-7760":  ["ICS-IA", "ICS-IM"],
    "CVE-2018-7761":  ["ICS-EX", "ICS-IM"],
    "CVE-2017-16740": ["ICS-IA", "ICS-IM"],
    "CVE-2010-2772":  ["TA0006"],
    "CVE-2023-2637":  ["TA0006"],
    "CVE-2022-38766": ["ICS-IA", "TA0001"],
    "CVE-2023-27267": ["ICS-LM", "TA0008"],
    "CVE-2022-3977":  ["ICS-IA", "ICS-IM"],
    "CVE-2021-31166": ["TA0001"],
    # Windows CVEs from windows_cves.json
    "CVE-2008-4250":  ["TA0001", "TA0008"],
    "CVE-2017-0147":  ["TA0001", "TA0008"],
    "CVE-2018-0886":  ["TA0001", "TA0008"],
    "CVE-2019-0787":  ["TA0001", "TA0008"],
    "CVE-2019-0788":  ["TA0001", "TA0008"],
    "CVE-2019-1225":  ["TA0001", "TA0008"],
    "CVE-2019-1226":  ["TA0001", "TA0008"],
    "CVE-2020-0655":  ["TA0001", "TA0008"],
    "CVE-2020-17096": ["TA0001", "TA0008"],
    "CVE-2020-1027":  ["TA0004"],
    "CVE-2020-1350":  ["TA0001", "TA0007"],
    "CVE-2021-24074": ["TA0001"],
    "CVE-2021-24086": ["TA0001"],
    "CVE-2021-24094": ["TA0001"],
    "CVE-2021-26868": ["TA0004"],
    "CVE-2021-26897": ["TA0001", "TA0007"],
    "CVE-2021-26898": ["TA0001", "TA0007"],
    "CVE-2021-27085": ["TA0001"],
    "CVE-2021-28470": ["TA0001", "TA0007"],
    "CVE-2021-28476": ["TA0001", "TA0008"],
    "CVE-2021-31979": ["TA0004"],
    "CVE-2021-33771": ["TA0004"],
    "CVE-2021-34486": ["TA0004"],
    "CVE-2021-34483": ["TA0004"],
    "CVE-2021-34523": ["TA0001"],
    "CVE-2021-36949": ["TA0004", "TA0006"],
    "CVE-2021-36955": ["TA0004"],
    "CVE-2021-36958": ["TA0004"],
    "CVE-2021-40444": ["TA0001"],
    "CVE-2021-42278": ["TA0004", "TA0006"],
    "CVE-2022-21857": ["TA0004", "TA0006"],
    "CVE-2022-21896": ["TA0004", "TA0006"],
    "CVE-2022-21983": ["TA0001"],
    "CVE-2022-21999": ["TA0004"],
    "CVE-2022-22021": ["TA0001", "TA0004"],
    "CVE-2022-22022": ["TA0004"],
    "CVE-2022-22031": ["TA0007", "TA0008"],
    "CVE-2022-22035": ["TA0008"],
    "CVE-2022-24474": ["TA0006"],
    "CVE-2022-24497": ["TA0006", "TA0008"],
    "CVE-2022-24521": ["TA0004"],
    "CVE-2022-26809": ["TA0001", "TA0008"],
    "CVE-2022-26919": ["TA0007", "TA0008"],
    "CVE-2022-26925": ["TA0006", "TA0008"],
    "CVE-2022-26929": ["TA0004", "TA0006"],
    "CVE-2022-26931": ["TA0004", "TA0006"],
    "CVE-2022-30149": ["TA0001", "TA0008"],
    "CVE-2022-30206": ["TA0004"],
    "CVE-2022-30209": ["TA0001"],
    "CVE-2022-30216": ["TA0007", "TA0008"],
    "CVE-2022-30221": ["TA0001", "TA0008"],
    "CVE-2022-30226": ["TA0004"],
    "CVE-2022-32230": ["TA0001", "TA0008"],
    "CVE-2022-34691": ["TA0004", "TA0006"],
    "CVE-2022-34715": ["TA0001"],
    "CVE-2022-35795": ["TA0001", "TA0008"],
    "CVE-2022-35804": ["TA0001"],
    "CVE-2022-37958": ["TA0004", "TA0006"],
    "CVE-2022-37969": ["TA0006"],
    "CVE-2022-41040": ["TA0001"],
    "CVE-2022-41082": ["TA0001"],
    "CVE-2022-41125": ["TA0004"],
    "CVE-2023-21524": ["TA0004", "TA0006"],
    "CVE-2023-21537": ["TA0001", "TA0004"],
    "CVE-2023-21674": ["TA0004"],
    "CVE-2023-21676": ["TA0007", "TA0008"],
    "CVE-2023-21678": ["TA0001", "TA0008"],
    "CVE-2023-21688": ["TA0008", "TA0002"],
    "CVE-2023-21727": ["TA0006"],
    "CVE-2023-21746": ["TA0006", "TA0008"],
    "CVE-2023-21757": ["TA0007", "TA0008"],
    "CVE-2023-21803": ["TA0001", "TA0004"],
    "CVE-2023-21822": ["TA0001", "TA0004"],
    "CVE-2023-23376": ["TA0004"],
    "CVE-2023-23392": ["TA0001"],
    "CVE-2023-23400": ["TA0001", "TA0007"],
    "CVE-2023-23405": ["TA0001", "TA0008"],
    "CVE-2023-28243": ["TA0001"],
    "CVE-2023-28244": ["TA0004", "TA0006"],
    "CVE-2023-28250": ["TA0001", "TA0004"],
    "CVE-2023-28252": ["TA0004"],
    "CVE-2023-28254": ["TA0001", "TA0007"],
    "CVE-2023-28260": ["TA0001", "TA0004"],
    "CVE-2023-28283": ["TA0007", "TA0008"],
    "CVE-2023-28229": ["TA0006"],
    "CVE-2023-35359": ["TA0004"],
    "CVE-2023-35368": ["TA0001"],
    "CVE-2023-35628": ["TA0001", "TA0008"],
    "CVE-2023-35352": ["TA0001", "TA0008"],
    "CVE-2023-36368": ["TA0004", "TA0006"],
    "CVE-2023-36393": ["TA0001"],
    "CVE-2023-36401": ["TA0008"],
    "CVE-2024-20674": ["TA0007", "TA0008"],
    "CVE-2024-21338": ["TA0004"],
    "CVE-2024-21410": ["TA0001"],
    "CVE-2024-26198": ["TA0001"],
    "CVE-2024-26212": ["TA0004", "TA0006"],
    "CVE-2024-26233": ["TA0004", "TA0006"],
    "CVE-2024-28995": ["TA0008", "TA0002"],
    "CVE-2024-30082": ["TA0004", "TA0006"],
    "CVE-2024-37338": ["TA0008", "TA0002"],
    "CVE-2024-37340": ["TA0008", "TA0002"],
    "CVE-2024-37342": ["TA0008", "TA0002"],
}

# Enterprise tactics in kill-chain order (ICS appended at end)
_TACTIC_ORDER = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0040", "Impact"),
    ("ICS-IA", "ICS Initial Access"),
    ("ICS-EX", "ICS Execution"),
    ("ICS-LM", "ICS Lateral Move"),
    ("ICS-IM", "ICS Impair Process"),
]


def _domain_tactics_detail(cfg: dict) -> tuple:
    """Return (tactic_set, tactic_to_cves dict) for a domain config."""
    tactics: set = set()
    tactic_cves: dict = {}   # tactic_code -> set of CVE IDs

    def _add(tac, cve=None):
        tactics.add(tac)
        tactic_cves.setdefault(tac, set())
        if cve:
            tactic_cves[tac].add(cve)

    solv = cfg.get("solvability_vulnerabilities", {})
    if "discovery" in solv and solv["discovery"]:
        _add("TA0007")
    for entry in solv.get("goal_access", []):
        gc = entry.get("goal_category", "")
        if gc in ("dump", "partial_dump"):
            _add("TA0009")
    for _cat, elist in solv.items():
        if not isinstance(elist, list):
            continue
        for entry in elist:
            name = entry.get("name", "")
            cve  = _VULN_TO_CVE.get(name)
            if not cve:
                desc = entry.get("description", "")
                m    = _re.search(r"CVE-\d{4}-\d+", desc)
                cve  = m.group(0) if m else None
            if cve and cve in _CVE_TACTICS:
                for tac in _CVE_TACTICS[cve]:
                    _add(tac, cve)
    return tactics, tactic_cves


def outcomes_and_topology_section(entries: list, workdir: Path) -> str:
    """Generate LaTeX for outcome distribution and network structure sections."""
    outcome_pdf  = workdir / "outcome_distribution.pdf"
    topology_pdf = workdir / "topology_radar.pdf"

    save_outcome_chart(entries, outcome_pdf)
    save_topology_radar(entries, topology_pdf)

    def _inc(p: Path, w: str) -> str:
        return rf"\includegraphics[width={w}]{{{p.name}}}" if p.exists() else ""

    out_inc  = _inc(outcome_pdf,  r"0.55\linewidth")
    topo_inc = _inc(topology_pdf, r"0.40\linewidth")

    # Per-domain outcome table
    rows = ""
    for entry in entries:
        totals = entry["agg"].get("outcome_totals", {})
        if not totals:
            continue
        cells = " & ".join(str(totals.get(k, 0)) for k in OUTCOME_KEYS)
        rows += rf"  {e(entry['short_name'])} & {cells} \\" + "\n"

    headers = " & ".join(rf"\textbf{{{e(OUTCOME_SHORT.get(k,k))}}}"
                          for k in OUTCOME_KEYS)

    # Network structure table
    topo_rows = ""
    for entry in entries:
        agg = entry["agg"]
        topology_type = "mesh" if agg.get("tree_ratio", 0) > 10 else (
            "hierarchical" if agg.get("tree_ratio", 0) > 3 else "tree-like"
        )
        topo_rows += (
            rf"  {e(entry['short_name'])} & {agg.get('mean_node_count',0):.0f} & "
            rf"{agg.get('mean_density',0):.3f} & "
            rf"{agg.get('mean_diameter',0):.1f} & "
            rf"{agg.get('tree_ratio',0):.1f} & "
            rf"\textit{{{e(topology_type)}}} \\" + "\n"
        )

    return rf"""
\newpage
\subsection{{Attack Outcome Distribution \& Network Structure}}

\subsubsection*{{Vulnerability Outcome Distribution}}

Outcome events recorded by the BFS planner agent across all evaluation episodes.
Each bar shows aggregated counts summed over all scenarios in a domain.

\begin{{center}}
{out_inc}
\end{{center}}

\begin{{center}}
\begin{{tabular}}{{l{"r" * len(OUTCOME_KEYS)}}}
\toprule
\textbf{{Domain}} & {headers} \\
\midrule
{rows}\bottomrule
\end{{tabular}}
\end{{center}}

\textit{{\footnotesize
  CredLeak=LeakedCredentials, NodeDisc=LeakedNodesId, Lateral=LateralMove,
  PrivEsc=PrivilegeEscalation, AdminEsc/SysEsc=escalation variants,
  Probe\checkmark=ProbeSucceeded, ExploitFail=ExploitFailed.}}

\subsubsection*{{Network Structure Analysis}}

\textbf{{Tree Ratio}} $= \text{{density}} \times n$: values near~1 indicate
tree-like topology; values~$>10$ indicate dense mesh.

\begin{{center}}
{topo_inc}
\end{{center}}

\begin{{center}}
\begin{{tabular}}{{lrrrrr}}
\toprule
\textbf{{Domain}} & \textbf{{Nodes}} & \textbf{{Density}} & \textbf{{Diameter}} & \textbf{{Tree Ratio}} & \textbf{{Type}} \\
\midrule
{topo_rows}\bottomrule
\end{{tabular}}
\end{{center}}
"""


def diversity_metrics_section(entries: list) -> str:
    # Compute pairwise Jaccard distance between property sets across domains
    prop_sets = []
    for entry in entries:
        top_props = entry.get("agg", {}).get("payloads", {}).get("top_properties", {})
        if not top_props:
            div   = entry.get("diversity", {})
            props = set(div.get("os_types", []) + div.get("node_roles", []))
        else:
            props = set(top_props.keys())
        prop_sets.append((entry["short_name"], props))

    jaccard_pairs = []
    for i in range(len(prop_sets)):
        for j in range(i + 1, len(prop_sets)):
            a, b = prop_sets[i][1], prop_sets[j][1]
            if a | b:
                jac = len(a & b) / len(a | b)
                jaccard_pairs.append((prop_sets[i][0], prop_sets[j][0], jac))

    if jaccard_pairs:
        avg_jac  = sum(j for _, _, j in jaccard_pairs) / len(jaccard_pairs)
        min_pair = min(jaccard_pairs, key=lambda x: x[2])
        max_pair = max(jaccard_pairs, key=lambda x: x[2])
    else:
        avg_jac, min_pair, max_pair = 0.0, ("---", "---", 0.0), ("---", "---", 0.0)

    # Per-domain diversity summary table
    div_rows = ""
    for entry in entries:
        div = entry.get("diversity", {})
        agg = entry.get("agg", {})
        n_domains  = div.get("n_domains", 1)
        n_roles    = len(div.get("node_roles", []))
        n_svc      = div.get("n_service_types", 0)
        n_connect  = div.get("n_must_connect", 0)
        n_cve      = 0
        cfg = entry.get("_config", {})
        if cfg:
            cve_text = str(cfg.get("solvability_vulnerabilities", {}))
            n_cve    = len(set(_re.findall(r'CVE-\d{4}-\d+', cve_text)))
        mean_nodes = agg.get("mean_node_count", "---")
        mean_nodes_str = f"{mean_nodes:.0f}" if isinstance(mean_nodes, float) else str(mean_nodes)
        div_rows += (f"  {entry['short_name']} & {n_domains} & {n_roles} & "
                     f"{n_svc} & {n_connect} & {n_cve} & {mean_nodes_str} \\\\\n")

    # Collect per-entry tactics, CVE counts, and per-tactic CVE mapping
    entry_tactic_data = []
    for entry in entries:
        cfg = entry.get("_config", {})
        if cfg:
            tacs, tac_cves = _domain_tactics_detail(cfg)
        else:
            tacs, tac_cves = set(), {}
        solv_text = str(cfg.get("solvability_vulnerabilities", {})) if cfg else ""
        cves_in_domain = set(_re.findall(r"CVE-\d{4}-\d+", solv_text))
        entry_tactic_data.append({
            "short":    entry["short_name"],
            "tactics":  tacs,
            "tac_cves": tac_cves,
            "n_cve":    len(cves_in_domain),
            "all_cves": cves_in_domain,
        })

    all_tactics_seen = {t for d in entry_tactic_data for t in d["tactics"]}
    ordered_tactics  = [(code, name) for code, name in _TACTIC_ORDER
                        if code in all_tactics_seen]
    n_dom = len(entry_tactic_data)

    # Build heatmap rows
    heatmap_rows = ""
    for tac_code, tac_name in ordered_tactics:
        is_ics     = tac_code.startswith("ICS")
        row_prefix = (r"\rowcolor{gray!12}" if is_ics else "")
        cells = []
        count = 0
        for d in entry_tactic_data:
            if tac_code in d["tactics"]:
                cells.append(r"\cellcolor{green!35}$\checkmark$")
                count += 1
            else:
                cells.append(r"\cellcolor{red!18}$\times$")
        coverage_pct = f"{count}/{n_dom}"
        tac_label    = f"\\texttt{{{tac_code}}} {tac_name}"
        heatmap_rows += (row_prefix + tac_label + " & " +
                         " & ".join(cells) + f" & {coverage_pct} \\\\\n")

    # Short domain column headers (rotated)
    domain_headers = " & ".join(
        r"\rotatebox{55}{\scriptsize\texttt{" + d["short"].replace("_", r"\_") + "}}"
        for d in entry_tactic_data
    )
    n_covered = len(ordered_tactics)
    n_ics     = sum(1 for c, _ in ordered_tactics if c.startswith("ICS"))
    n_ent     = n_covered - n_ics
    col_spec  = "p{4.8cm}" + "c" * n_dom + "c"

    # Per-domain tactic statistics table (CVE count per tactic per domain)
    tac_count_rows = ""
    for tac_code, tac_name in ordered_tactics:
        is_ics     = tac_code.startswith("ICS")
        row_prefix = (r"\rowcolor{gray!12}" if is_ics else "")
        cells = []
        total_across = 0
        for d in entry_tactic_data:
            cnt = len(d["tac_cves"].get(tac_code, set()))
            if cnt > 0:
                shade = min(60, max(15, cnt * 12))
                cells.append(rf"\cellcolor{{blue!{shade}}}{cnt}")
                total_across += cnt
            else:
                cells.append("---")
        tac_label = f"\\texttt{{{tac_code}}} {tac_name}"
        tac_count_rows += (row_prefix + tac_label + " & " +
                           " & ".join(cells) + f" & {total_across} \\\\\n")

    # Per-domain narrative: one mini-table per domain
    per_domain_tables = ""
    for d in entry_tactic_data:
        if not d["tactics"]:
            continue
        domain_tac_rows = ""
        for tac_code, tac_name in ordered_tactics:
            if tac_code not in d["tactics"]:
                continue
            cve_set = sorted(d["tac_cves"].get(tac_code, set()))
            cve_str = ", ".join(r"\texttt{" + c + "}" for c in cve_set[:6])
            if len(cve_set) > 6:
                cve_str += rf" \ldots +{len(cve_set)-6}"
            if not cve_str:
                cve_str = r"\textit{(technique)}"
            domain_tac_rows += (
                rf"  \texttt{{{tac_code}}} & {tac_name} & {len(cve_set)} & {cve_str} \\\\" + "\n"
            )
        short_escaped = e(d["short"])
        per_domain_tables += rf"""
\noindent\textbf{{{short_escaped}}} \hfill {d['n_cve']} unique CVE(s) / {len(d['tactics'])} tactic(s)

\begin{{tabular}}{{p{{1.6cm}}p{{3.5cm}}cp{{7.5cm}}}}
\toprule
\textbf{{Code}} & \textbf{{Tactic}} & \textbf{{\#CVE}} & \textbf{{Contributing CVEs}} \\
\midrule
{domain_tac_rows}\bottomrule
\end{{tabular}}

\smallskip
"""

    return r"""
\clearpage
\subsection{Dataset Diversity Analysis}

Diversity is a core claimed advantage of LLM-driven generation over parametric
randomisation.  This section quantifies diversity at three levels: (1)
per-domain structural variety, (2) cross-domain property-space dissimilarity,
and (3) MITRE ATT\&CK tactic coverage.

% Per-domain diversity
\subsubsection*{Per-Domain Structural Diversity}
\begin{table}[H]
\centering\small
\setlength{\tabcolsep}{5pt}
\begin{tabular}{lcccccc}
\toprule
\textbf{Domain} & \textbf{Tiers} & \textbf{Node Roles} & \textbf{Service Types} & \textbf{Firewall Edges} & \textbf{Unique CVEs} & \textbf{Mean Nodes} \\
\midrule
""" + div_rows + r"""\bottomrule
\end{tabular}
\caption*{Structural diversity per domain configuration.
Tiers = number of distinct network domains; Node Roles = distinct service-role properties;
Firewall Edges = MUST\_CONNECT + CLIENT\_OF intra/inter-domain constraints.}
\end{table}

% Cross-domain Jaccard
\subsubsection*{Cross-Domain Property-Space Dissimilarity (Jaccard Distance)}

Average pairwise Jaccard \emph{similarity} between the property sets of
distinct domain configurations:

\begin{center}
\begin{tabular}{lll}
\toprule
\textbf{Metric} & \textbf{Value} & \textbf{Interpretation} \\
\midrule
Mean pairwise Jaccard similarity & """ + f"{avg_jac:.3f}" + r""" & 0 = fully disjoint, 1 = identical \\
Most similar pair & """ + f"{e(max_pair[0])} / {e(max_pair[1])}" + r""" & """ + f"{max_pair[2]:.3f}" + r""" \\
Most distinct pair & """ + f"{e(min_pair[0])} / {e(min_pair[1])}" + r""" & """ + f"{min_pair[2]:.3f}" + r""" \\
\bottomrule
\end{tabular}
\end{center}

A mean Jaccard similarity below 0.4 indicates that the domain configurations
occupy substantially different regions of the property space, validating the
diversity of the generated dataset.

% MITRE ATT&CK heatmap
\subsubsection*{MITRE ATT\&CK Tactic $\times$ Domain Coverage}

Each CVE in the dataset has been classified against MITRE ATT\&CK Enterprise
and the MITRE ATT\&CK for ICS framework.
The heatmap below shows which tactics are exercised by each domain.
\textit{Shaded rows} are ICS-specific tactics absent from purely IT domains.

\begin{table}[H]
\centering\small\setlength{\tabcolsep}{3pt}
\begin{tabular}{""" + col_spec + r"""}
\toprule
\textbf{Tactic} & """ + domain_headers + r""" & \textbf{Cov.} \\
\midrule
""" + heatmap_rows + r"""\bottomrule
\end{tabular}
\caption*{MITRE ATT\&CK tactic $\times$ domain coverage.
\colorbox{green!35}{$\checkmark$}~tactic is exercised; \colorbox{red!18}{$\times$}~not exercised.
Grey rows = ICS-framework tactics.
""" + str(n_ent) + r""" Enterprise + """ + str(n_ics) + r""" ICS tactics covered across the dataset.}
\end{table}

% Per-domain tactic CVE count table
\subsubsection*{Per-Domain Tactic Statistics (CVE Count per Tactic)}

The table below shows, for each domain, \emph{how many CVEs} are mapped to
each MITRE tactic.  Cell shading is proportional to count;
\textbf{---} indicates the tactic is not exercised by that domain.

\begin{table}[H]
\centering\small\setlength{\tabcolsep}{3pt}
\begin{tabular}{""" + col_spec + r"""}
\toprule
\textbf{Tactic} & """ + domain_headers + r""" & \textbf{Total} \\
\midrule
""" + tac_count_rows + r"""\bottomrule
\end{tabular}
\caption*{Number of CVEs per tactic per domain.  Blue shading intensity $\propto$ count.
Grey rows = ICS tactics.}
\end{table}

% Per-domain tactic detail (narrative)
\subsubsection*{Per-Domain Tactic Breakdown}

For each domain the table lists every covered tactic together with the specific
CVEs that drive the classification.

""" + per_domain_tables + r"""
"""
