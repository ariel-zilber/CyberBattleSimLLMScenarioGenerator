#!/usr/bin/env python3
"""Add CVE entries to domain configs to equalize CVE counts to the target (9).

Uses catalog CVEs appropriate for each domain type, appended to
solvability_vulnerabilities.remote_access.
"""

import re
import sys
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"

# Format: yaml text block to insert (will be appended into remote_access section)
# Using 4-space indentation for items under remote_access.
def _entry(name, cve, description, cost, sr, reward, match_props, prob):
    props_yaml = "\n".join(f"        - {p}" for p in match_props)
    return f"""
    - name: Solvability.{name}
      type: REMOTE
      description: "{cve} — {description}"
      cost: {cost}
      success_rate: {sr}
      reward: "{reward}"
      match_properties:
{props_yaml}
      probability: {prob}
"""


ADDITIONS = {
    "wordpress_web_stack_v3.yaml": [
        _entry(
            "Nginx_LibCrypto_High",
            "CVE-2025-69421",
            "libcrypto3 HIGH severity heap UAF in Nginx Bitnami chart. CVSS 7.5, AC=LOW.",
            1.5, 0.75,
            "Nginx LibCrypto High RCE achieved — secondary shell path on reverse proxy node",
            ["Linux", "WebServer", "LibCrypto"],
            0.45,
        ),
        _entry(
            "Redis_GoStdlib_2",
            "CVE-2023-24540",
            "Go stdlib text/template injection (critical) in Redis Bitnami chart. CVSS 9.8.",
            1.0, 0.90,
            "Redis GoStdlib RCE (CVE-2023-24540) achieved — alternate lateral movement via cache tier",
            ["Linux", "CacheServer", "RedisServer", "GoRuntime"],
            0.38,
        ),
        _entry(
            "Vault_GoStdlib_2",
            "CVE-2025-0377",
            "Go stdlib net/http CRITICAL unauthenticated RCE in HashiCorp Vault Bitnami chart. CVSS 9.1.",
            1.0, 0.90,
            "Vault GoStdlib RCE (CVE-2025-0377) achieved — secrets management node compromised",
            ["Linux", "AppServer", "GoRuntime"],
            0.40,
        ),
        _entry(
            "Drupal_RCE",
            "CVE-2024-55637",
            "Drupal core CRITICAL unauthenticated PHP RCE via crafted request. CVSS 9.8.",
            1.0, 0.90,
            "Drupal PHP RCE achieved — shell on PHP application tier",
            ["Linux", "PHP", "WebServer"],
            0.38,
        ),
    ],

    "enterprise_ad_v6.yaml": [
        _entry(
            "PetitPotam",
            "CVE-2021-36942",
            "Windows LSA forced NTLM authentication relay via EfsRpcOpenFileRaw. CVSS 7.5.",
            1.5, 0.75,
            "PetitPotam NTLM relay achieved — domain controller coerced authentication captured",
            ["Windows", "DomainController"],
            0.50,
        ),
        _entry(
            "ProxyLogon",
            "CVE-2021-26855",
            "Microsoft Exchange Server SSRF allowing pre-auth RCE (ProxyLogon). CVSS 9.1.",
            1.0, 0.90,
            "ProxyLogon SSRF achieved — Exchange mail server shell obtained",
            ["Windows", "MailServer"],
            0.55,
        ),
        _entry(
            "Outlook_NTLM",
            "CVE-2023-23397",
            "Microsoft Outlook zero-click NTLM hash theft via crafted calendar invitation. CVSS 9.8.",
            1.0, 0.90,
            "Outlook NTLM relay achieved — domain user NTLM hash captured and relayed",
            ["Windows", "DomainJoined"],
            0.55,
        ),
    ],

    "jenkins_cicd_v2.yaml": [
        _entry(
            "Airflow_RCE_2",
            "CVE-2023-45853",
            "Python zlib/minizip heap overflow CRITICAL in Apache Airflow runtime. CVSS 9.8.",
            1.0, 0.90,
            "Airflow Python RCE (CVE-2023-45853) achieved — alternate shell on CI worker node",
            ["Linux", "WorkerNode", "Python"],
            0.40,
        ),
        _entry(
            "Kafka_SQLite",
            "CVE-2025-6965",
            "SQLite libs CRITICAL integer overflow in Kafka Bitnami chart. CVSS 9.8.",
            1.0, 0.90,
            "Kafka SQLite RCE (CVE-2025-6965) achieved — message broker node compromised",
            ["Linux", "WorkerNode", "Java"],
            0.38,
        ),
    ],

    "network_device_infra_v3.yaml": [
        _entry(
            "CiscoNXOS_FCoE",
            "CVE-2019-1595",
            "Cisco NX-OS FCoE unauthenticated protocol processing vulnerability. CVSS 7.4.",
            1.5, 0.65,
            "CiscoNXOS FCoE exploit achieved — data-center switch session obtained",
            ["Switch", "CiscoNXOS", "NetworkDevice"],
            0.45,
        ),
        _entry(
            "PanOS_TOCTOU",
            "CVE-2021-3054",
            "Palo Alto PAN-OS Web UI TOCTOU race condition allowing privilege escalation. CVSS 7.2.",
            1.5, 0.85,
            "PAN-OS TOCTOU race exploit achieved — firewall management plane access obtained",
            ["Firewall", "PaloAlto", "PANOS"],
            0.48,
        ),
        _entry(
            "CiscoASA_OSPF",
            "CVE-2026-20020",
            "Cisco ASA OSPF unauthenticated flooding vulnerability. CVSS 6.8.",
            1.5, 0.85,
            "Cisco ASA OSPF exploit achieved — perimeter firewall routing tables accessible",
            ["Firewall", "NetworkDevice"],
            0.45,
        ),
    ],

    "scada_ics_v2.yaml": [
        _entry(
            "MicroLogix_BufferOverflow",
            "CVE-2017-16740",
            "Allen-Bradley MicroLogix 1400 buffer overflow via EtherNet/IP unauthenticated. CVSS 10.0.",
            1.0, 0.85,
            "MicroLogix 1400 buffer overflow achieved — PLC process control access obtained",
            ["PLC", "Rockwell", "AllenBradley", "ICS", "Unpatched"],
            0.50,
        ),
    ],

    "scada_ad_hybrid_v1.yaml": [
        _entry(
            "Rockwell_KeyReuse",
            "CVE-2021-22681",
            "Studio 5000 / RSLogix cryptographic key reuse allows forging messages to Rockwell PLC. CVSS 10.0.",
            1.0, 0.90,
            "Rockwell key reuse exploit achieved — forged EtherNet/IP messages sent to ControlLogix PLC",
            ["PLC", "Rockwell", "ControlLogix", "EtherNetIP", "ICS"],
            0.52,
        ),
    ],

    "wordpress_ad_hybrid_v3.yaml": [
        _entry(
            "WordPress_ImageMagick",
            "CVE-2026-22770",
            "imagemagick-7-common CRITICAL RCE in WordPress Bitnami chart. CVSS 9.8.",
            1.0, 0.90,
            "WordPress ImageMagick RCE achieved — web tier PHP shell via media upload pipeline",
            ["Linux", "PHP", "WebServer", "ImageMagick"],
            0.50,
        ),
        _entry(
            "Nginx_LibCrypto_Critical",
            "CVE-2025-15467",
            "libcrypto3 CRITICAL unauthenticated RCE in Nginx Bitnami chart. CVSS 9.8.",
            1.0, 0.90,
            "Nginx LibCrypto RCE achieved — reverse proxy shell obtained",
            ["Linux", "WebServer", "LibCrypto"],
            0.50,
        ),
        _entry(
            "noPac",
            "CVE-2021-42287",
            "Active Directory SAM Account Name spoofing privilege escalation (noPac). CVSS 7.5.",
            1.5, 0.75,
            "noPac AD privilege escalation achieved — domain administrator Kerberos ticket obtained",
            ["Windows", "DomainController", "DomainJoined"],
            0.48,
        ),
    ],
}


def _insert_into_remote_access(text: str, new_entries: str) -> str:
    """Insert YAML entries at end of remote_access block, just before credential_leak."""
    # Find the credential_leak section inside solvability_vulnerabilities
    # Pattern: "  credential_leak:" that follows the remote_access block
    pattern = r'(\n  credential_leak:)'
    match = re.search(pattern, text)
    if not match:
        # Try end of file or goal_access
        pattern = r'(\n  goal_access:)'
        match = re.search(pattern, text)
    if not match:
        print("  WARNING: could not find insertion point, appending at end of file")
        return text + new_entries
    pos = match.start()
    return text[:pos] + new_entries + text[pos:]


def main():
    target_count = 9
    changed = []

    for filename, entries in ADDITIONS.items():
        path = DATA_DIR / filename
        if not path.exists():
            print(f"SKIP (not found): {filename}")
            continue

        text = path.read_text()

        # Count existing unique CVEs
        existing_cves = set(re.findall(r'CVE-\d{4}-\d+', text))
        print(f"{filename}: {len(existing_cves)} CVEs → adding {len(entries)}")

        combined = "".join(entries)
        new_text = _insert_into_remote_access(text, combined)

        # Verify new CVE count
        new_cves = set(re.findall(r'CVE-\d{4}-\d+', new_text))
        print(f"  → {len(new_cves)} CVEs after addition")

        path.write_text(new_text)
        changed.append(filename)

    print(f"\nUpdated {len(changed)} files: {changed}")

    # Final report
    print("\n=== Final CVE counts ===")
    for fname in sorted(DATA_DIR.glob("*.yaml")):
        if fname.name == "domains.yaml":
            continue
        content = fname.read_text()
        cves = set(re.findall(r'CVE-\d{4}-\d+', content))
        tag = " ✓" if len(cves) >= target_count else f" (need {target_count - len(cves)} more)"
        print(f"  {len(cves):3d}  {fname.name}{tag}")


if __name__ == "__main__":
    main()
