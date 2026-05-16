#!/usr/bin/env python3
"""
Fetch and process the official Bitnami vulnerability database.
https://github.com/bitnami/vulndb

Steps:
  1. Clone (or update) bitnami/vulndb to a local cache directory
  2. Parse all OSV-1.5.0 JSON files under data/
  3. Compute CVSS v3.1 base score from vector string
  4. Filter to severity HIGH or CRITICAL (configurable)
  5. Derive CBS parameters using the project formula
  6. Map components to CBS chart properties
  7. Add MITRE ATT&CK tactic labels
  8. Save to data/vulnerability_db/bitnami_vulndb_cves.json

Usage:
    python tools/fetch_bitnami_vulndb.py [--cache-dir DIR] [--min-severity HIGH]
                                         [--output PATH] [--no-clone]
"""
import argparse
import collections
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

# ─── Paths ───────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parent.parent
VULNDB_URL  = "https://github.com/bitnami/vulndb.git"
DEFAULT_CACHE  = REPO_ROOT / ".cache" / "bitnami-vulndb"
DEFAULT_OUTPUT = REPO_ROOT / "data/vulnerability_db/bitnami_vulndb_cves.json"

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# ─── CVSS v3.1 base score calculator ─────────────────────────────────────────

_AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC  = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope Changed
_UI  = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    """CVSS 3.1 roundup: round to nearest 0.1 ceiling."""
    return math.ceil(x * 10) / 10


def cvss_vector_to_score(vector: str) -> tuple[float, dict]:
    """
    Parse a CVSS v3.x vector string and return (base_score, metrics_dict).
    Returns (0.0, {}) if parsing fails.
    """
    try:
        # strip prefix e.g. "CVSS:3.1/"
        v = re.sub(r"^CVSS:\d+\.\d+/", "", vector.strip())
        parts = dict(kv.split(":") for kv in v.split("/"))
        av  = _AV[parts["AV"]]
        ac  = _AC[parts["AC"]]
        s   = parts["S"]   # U or C
        pr  = (_PR_C if s == "C" else _PR_U)[parts["PR"]]
        ui  = _UI[parts["UI"]]
        c   = _CIA[parts["C"]]
        i_  = _CIA[parts["I"]]
        a   = _CIA[parts["A"]]

        iss = 1 - (1 - c) * (1 - i_) * (1 - a)
        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            score = 0.0
        elif s == "U":
            score = _roundup(min(impact + exploitability, 10.0))
        else:
            score = _roundup(min(1.08 * (impact + exploitability), 10.0))

        metrics = {
            "attack_vector":      parts["AV"],
            "attack_complexity":  parts["AC"],
            "privileges_required": parts["PR"],
            "user_interaction":   parts["UI"],
            "scope":              s,
            "confidentiality":    parts["C"],
            "integrity":          parts["I"],
            "availability":       parts["A"],
        }
        return score, metrics
    except Exception:
        return 0.0, {}


def score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "UNKNOWN"


def av_long(code: str) -> str:
    return {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}.get(code, "UNKNOWN")


# ─── CBS parameter derivation (same formula as generate_bitnami_report.py) ──

def derive_cbs_params(score: float, metrics: dict) -> dict:
    base = score / 10.0
    if metrics.get("attack_complexity") == "H":
        base *= 0.70
    if metrics.get("user_interaction") == "R":
        base *= 0.85
    sr = round(max(0.30, min(0.90, base)), 2)

    if score >= 9.0:
        cost = 1.0
    elif score >= 7.0:
        cost = 1.5
    elif score >= 5.0:
        cost = 2.0
    else:
        cost = 3.0

    sev = score_to_severity(score)
    prob = {"CRITICAL": 0.85, "HIGH": 0.65, "MEDIUM": 0.45}.get(sev, 0.45)

    return {"success_rate": sr, "exploit_cost": cost, "probability": prob}


# ─── Component → CBS properties mapping ──────────────────────────────────────

# keyword patterns matched against the component name (lowercase)
_PROP_RULES = [
    # Web / proxy
    (r"nginx|apache|httpd|haproxy|caddy|traefik|envoy|kong|apisix",
     ["WebServer", "Linux"]),
    (r"wordpress|drupal|joomla|magento|moodle|mediawiki|dokuwiki|opencart|ghost|matomo",
     ["WebServer", "PHP", "Linux"]),
    (r"discourse|mastodon",
     ["WebServer", "Ruby", "Linux"]),
    # Auth / identity
    (r"keycloak",
     ["AuthServer", "KeycloakService", "Java", "Linux"]),
    (r"oauth2.proxy",
     ["AuthServer", "GoRuntime", "Linux"]),
    (r"vault",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"cert.manager|ejbca|step.ca",
     ["AuthServer", "Java", "Linux"]),
    # Data stores
    (r"postgresql|postgres",
     ["DatabaseServer", "PostgreSQLServer", "Linux"]),
    (r"mysql|mariadb|percona",
     ["DatabaseServer", "MySQL", "MySQLServer", "Linux"]),
    (r"mongodb",
     ["DatabaseServer", "MongoDB", "GoRuntime", "Linux"]),
    (r"redis(?!.cluster)|keydb",
     ["DatabaseServer", "Redis", "GoRuntime", "LibCrypto", "Linux"]),
    (r"redis.cluster",
     ["DatabaseServer", "Redis", "GoRuntime", "Linux"]),
    (r"elasticsearch|opensearch",
     ["DatabaseServer", "ElasticsearchServer", "Java", "Linux"]),
    (r"cassandra",
     ["DatabaseServer", "Java", "Linux"]),
    (r"influxdb",
     ["DatabaseServer", "GoRuntime", "Linux"]),
    (r"clickhouse|druid|dremio",
     ["DatabaseServer", "Java", "Linux"]),
    (r"milvus",
     ["DatabaseServer", "GoRuntime", "Linux"]),
    (r"janusgraph|neo4j|arangodb",
     ["DatabaseServer", "Java", "Linux"]),
    # CI/CD / DevOps
    (r"jenkins",
     ["AppServer", "Java", "Linux"]),
    (r"argo",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"gitlab|gitea|forgejo",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"concourse",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"harbor",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"chainloop",
     ["AppServer", "GoRuntime", "Linux"]),
    # Monitoring / observability
    (r"grafana(?!.loki|.mimir|.tempo|.alloy)",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"grafana.loki|grafana.mimir|grafana.tempo|grafana.alloy",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"prometheus|thanos|cortex|victoriametrics",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"jaeger|zipkin|opentelemetry|grafana.k6",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"kibana",
     ["AppServer", "Java", "Linux"]),
    (r"cadvisor|node.exporter",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"fluentd",
     ["AppServer", "Ruby", "Linux"]),
    (r"fluent.bit",
     ["AppServer", "Linux"]),
    (r"logstash",
     ["AppServer", "Java", "Linux"]),
    # Workflow / message
    (r"kafka",
     ["WorkerNode", "MessageBroker", "Java", "Linux"]),
    (r"rabbitmq",
     ["WorkerNode", "MessageBroker", "Linux"]),
    (r"nats",
     ["WorkerNode", "MessageBroker", "GoRuntime", "Linux"]),
    (r"airflow",
     ["WorkerNode", "Python", "Linux"]),
    (r"flink",
     ["WorkerNode", "Java", "Linux"]),
    (r"spark",
     ["WorkerNode", "Java", "Linux"]),
    (r"celery|prefect",
     ["WorkerNode", "Python", "Linux"]),
    # Kubernetes / infrastructure
    (r"etcd",
     ["AppServer", "GoRuntime", "K8sCluster", "Linux"]),
    (r"coredns",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"cilium|calico|flannel",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"external.dns|cert.manager|nginx.ingress",
     ["AppServer", "GoRuntime", "Linux"]),
    (r"metrics.server",
     ["AppServer", "GoRuntime", "Linux"]),
    # Misc app servers
    (r"node(?:js)?",
     ["AppServer", "Linux"]),
    (r"tomcat|jetty",
     ["AppServer", "Java", "Linux"]),
    (r"aspnet",
     ["AppServer", "Linux"]),
    (r"php.?fpm",
     ["AppServer", "PHP", "Linux"]),
    (r"jupyterhub|jupyter",
     ["AppServer", "Python", "Linux"]),
    (r"mlflow|kubeflow|ray|pytorch|tensorflow",
     ["AppServer", "Python", "Linux"]),
    (r"minio|seaweedfs",
     ["DatabaseServer", "GoRuntime", "Linux"]),
    (r"memcached",
     ["DatabaseServer", "Linux"]),
    # API gateways
    (r"kong|krakend|tyk",
     ["APIGateway", "Linux"]),
    # Bitnami-specific utilities
    (r"bndiagnostic|bitnami",
     ["AppServer", "Linux"]),
]


def component_to_properties(name: str) -> list[str]:
    n = name.lower().replace("_", "-").replace(" ", "-")
    for pattern, props in _PROP_RULES:
        if re.search(pattern, n):
            return sorted(set(props))
    # default fallback
    return ["AppServer", "Linux"]


# ─── MITRE ATT&CK tactic classifier ──────────────────────────────────────────

def classify_tactics(score: float, metrics: dict, description: str, component: str) -> list[str]:
    """Return list of tactic IDs (primary first)."""
    av  = metrics.get("attack_vector", "N")
    ac  = metrics.get("attack_complexity", "L")
    c   = metrics.get("confidentiality", "N")
    i_  = metrics.get("integrity", "N")
    a   = metrics.get("availability", "N")
    desc = (description or "").lower()
    comp = component.lower()

    tactics = []

    # Primary tactic: Initial Access (network RCE / auth bypass)
    if av == "N" and (c in ("H",) or i_ in ("H",)):
        tactics.append("TA0001")

    # Execution (code execution mentioned)
    exec_kw = ["code execution", "rce", "remote code", "execute", "command injection",
                "arbitrary command", "os command"]
    if any(kw in desc for kw in exec_kw):
        if "TA0002" not in tactics:
            tactics.append("TA0002")

    # Credential Access
    cred_kw = ["password", "credential", "token", "secret", "key", "auth", "session",
               "bypass authentication", "unauthenticated"]
    if any(kw in desc for kw in cred_kw) and av == "N":
        if "TA0006" not in tactics:
            tactics.append("TA0006")

    # Privilege Escalation
    privesc_kw = ["privilege escalation", "privilege", "root", "admin", "escalat",
                  "elevation", "sudo"]
    if any(kw in desc for kw in privesc_kw):
        if "TA0004" not in tactics:
            tactics.append("TA0004")

    # Discovery
    disc_kw = ["information disclosure", "path traversal", "directory traversal",
               "enumerat", "expose", "leak", "read file", "read arbitrary"]
    if any(kw in desc for kw in disc_kw):
        if "TA0007" not in tactics:
            tactics.append("TA0007")

    # Impact (DoS / availability)
    dos_kw = ["denial of service", "dos", "crash", "memory exhaustion", "null pointer",
              "infinite loop", "resource exhaustion", "availability"]
    if a == "H" or any(kw in desc for kw in dos_kw):
        if "TA0040" not in tactics:
            tactics.append("TA0040")

    # Lateral movement (SQL injection, SSRF)
    lat_kw = ["sql injection", "ssrf", "server-side request", "lateral"]
    if any(kw in desc for kw in lat_kw):
        if "TA0008" not in tactics:
            tactics.append("TA0008")

    # Collection
    coll_kw = ["exfiltrat", "data exposure", "sensitive data", "read.*data",
               "arbitrary file read"]
    if any(kw in desc for kw in coll_kw):
        if "TA0009" not in tactics:
            tactics.append("TA0009")

    # Ensure at least one tactic
    if not tactics:
        if av == "N":
            tactics.append("TA0001")
        elif a == "H":
            tactics.append("TA0040")
        else:
            tactics.append("TA0001")

    return tactics


# ─── Deployment frequency weight (from Docker Hub chart_stats) ───────────────

def load_pull_counts() -> dict[str, int]:
    """Load pull counts from existing bitnami_cves.json chart_stats."""
    path = REPO_ROOT / "data/vulnerability_db/bitnami_cves.json"
    if not path.exists():
        return {}
    with open(path) as f:
        d = json.load(f)
    cs = d.get("chart_stats", {})
    return {k: v.get("pull_count", 0) for k, v in cs.items() if v.get("pull_count")}


def compute_deployment_weight(component: str, pull_counts: dict) -> float:
    if not pull_counts:
        return 0.5
    max_pulls = max(pull_counts.values()) if pull_counts else 1
    # fuzzy match component name to chart_stats key
    name = component.lower().replace("_", "-")
    pulls = pull_counts.get(name, pull_counts.get(name.split("-")[0], 0))
    if pulls == 0:
        return 0.0
    return round(math.log1p(pulls) / math.log1p(max_pulls), 4)


# ─── Git clone / update ───────────────────────────────────────────────────────

def clone_or_update(cache_dir: Path) -> bool:
    if (cache_dir / ".git").exists():
        print(f"Updating vulndb cache at {cache_dir}...")
        result = subprocess.run(
            ["git", "-C", str(cache_dir), "pull", "--ff-only", "--quiet"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"  git pull warning: {result.stderr.strip()}", file=sys.stderr)
        else:
            print("  ✓ cache up-to-date")
        return True
    else:
        print(f"Cloning bitnami/vulndb to {cache_dir}...")
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth=1", "--quiet", VULNDB_URL, str(cache_dir)],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"  git clone failed: {result.stderr.strip()}", file=sys.stderr)
            return False
        print("  ✓ cloned")
        return True


# ─── Parser ───────────────────────────────────────────────────────────────────

def parse_osv_file(path: Path, pull_counts: dict) -> dict | None:
    """Parse one BIT-*.json file and return a normalised CVE record or None."""
    try:
        with open(path) as f:
            entry = json.load(f)
    except Exception:
        return None

    # BIT-<component>-<year>-<number>
    bit_id = entry.get("id", "")
    aliases = entry.get("aliases", [])
    cve_id  = next((a for a in aliases if a.startswith("CVE-")), None)
    if not cve_id:
        return None   # skip entries without a CVE ID

    summary = entry.get("summary", "")
    details = entry.get("details", "")
    description = f"{summary}. {details}".strip(". ")

    published = entry.get("published", "")[:10]
    modified  = entry.get("modified", "")[:10]

    affected_list = entry.get("affected", [])
    if not affected_list:
        return None

    aff = affected_list[0]
    component = aff.get("package", {}).get("name", path.parent.name)
    purl      = aff.get("package", {}).get("purl", f"pkg:bitnami/{component}")

    # severity / CVSS from affected[0].severity
    severity_entries = aff.get("severity", [])
    cvss_vector = None
    for se in severity_entries:
        if se.get("type") in ("CVSS_V3", "CVSS_V3.1", "CVSS_V3.0"):
            cvss_vector = se.get("score", "")
            break

    cvss_score = 0.0
    metrics    = {}
    if cvss_vector:
        cvss_score, metrics = cvss_vector_to_score(cvss_vector)

    # fallback: use database_specific severity to estimate score
    db_sev = entry.get("database_specific", {}).get("severity", "").upper()
    if cvss_score == 0.0 and db_sev:
        cvss_score = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.0}.get(db_sev, 0.0)

    if cvss_score == 0.0:
        return None

    severity = score_to_severity(cvss_score)

    # version ranges
    ranges     = aff.get("ranges", [])
    introduced = []
    fixed      = []
    for rng in ranges:
        for evt in rng.get("events", []):
            if "introduced" in evt:
                introduced.append(evt["introduced"])
            elif "fixed" in evt:
                fixed.append(evt["fixed"])
    has_fix = bool(fixed)

    # CPEs
    cpes = entry.get("database_specific", {}).get("cpes", [])

    # CVE year
    try:
        year = int(cve_id.split("-")[1])
    except Exception:
        year = 0

    # CBS properties
    chart_properties = component_to_properties(component)

    # MITRE tactics
    tactic_ids = classify_tactics(cvss_score, metrics, description, component)
    tactic_map = {
        "TA0001": "Initial Access", "TA0002": "Execution",
        "TA0004": "Privilege Escalation", "TA0006": "Credential Access",
        "TA0007": "Discovery", "TA0008": "Lateral Movement",
        "TA0009": "Collection", "TA0040": "Impact",
    }
    mitre_tactics = [
        {"tactic_id": tid, "tactic_name": tactic_map.get(tid, tid), "techniques": []}
        for tid in tactic_ids
    ]

    # CBS parameters
    cbs = derive_cbs_params(cvss_score, metrics)

    # deployment weight
    dw = compute_deployment_weight(component, pull_counts)

    # frequency tier from deployment weight
    if dw >= 0.70:   freq_tier = "high"
    elif dw >= 0.40: freq_tier = "medium"
    elif dw >= 0.10: freq_tier = "low"
    else:             freq_tier = "minimal"

    return {
        "cve_id":           cve_id,
        "bit_id":           bit_id,
        "pkg_name":         component,
        "purl":             purl,
        "cpes":             cpes,
        "severity":         severity,
        "cvss_score":       round(cvss_score, 1),
        "cvss_vector":      cvss_vector or "",
        "attack_vector":    av_long(metrics.get("attack_vector", "N")),
        "attack_complexity": {"L": "LOW", "H": "HIGH"}.get(
                                metrics.get("attack_complexity", "L"), "LOW"),
        "privileges_required": metrics.get("privileges_required", "N"),
        "user_interaction":    metrics.get("user_interaction", "N"),
        "scope":               metrics.get("scope", "U"),
        "description":         description[:400],
        "affected_versions":   introduced,
        "fixed_versions":      fixed,
        "has_fix":             has_fix,
        "published":           published,
        "modified":            modified,
        "year":                year,
        "chart":               component,
        "chart_properties":    chart_properties,
        "mitre_tactics":       mitre_tactics,
        "mitre_primary":       tactic_ids[0] if tactic_ids else "TA0001",
        "success_rate":        cbs["success_rate"],
        "exploit_cost":        cbs["exploit_cost"],
        "probability":         cbs["probability"],
        "deployment_weight":   dw,
        "frequency_tier":      freq_tier,
        "source":              "bitnami/vulndb",
    }


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache-dir",    type=Path, default=DEFAULT_CACHE,
                        help="Local cache for bitnami/vulndb clone")
    parser.add_argument("--output",       type=Path, default=DEFAULT_OUTPUT,
                        help="Output JSON path")
    parser.add_argument("--min-severity", default="HIGH",
                        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Minimum severity to include (default: HIGH)")
    parser.add_argument("--no-clone",     action="store_true",
                        help="Skip git clone/update (use existing cache)")
    parser.add_argument("--components",   nargs="*",
                        help="Limit to specific component names (default: all)")
    args = parser.parse_args()

    min_sev_rank = SEVERITY_ORDER[args.min_severity]

    # 1. Clone / update
    if not args.no_clone:
        ok = clone_or_update(args.cache_dir)
        if not ok:
            sys.exit(1)
    elif not args.cache_dir.exists():
        print(f"Cache dir {args.cache_dir} does not exist. Run without --no-clone first.",
              file=sys.stderr)
        sys.exit(1)

    # 2. Discover all JSON files
    data_dir = args.cache_dir / "data"
    if not data_dir.exists():
        print(f"ERROR: {data_dir} not found. Clone may have failed.", file=sys.stderr)
        sys.exit(1)

    all_files = sorted(data_dir.rglob("BIT-*.json"))
    print(f"Found {len(all_files):,} BIT-*.json files")

    # filter to requested components
    if args.components:
        wanted = {c.lower() for c in args.components}
        all_files = [f for f in all_files if f.parent.name.lower() in wanted]
        print(f"  → filtered to {len(all_files):,} files for components: {wanted}")

    # 3. Load pull counts for deployment weights
    pull_counts = load_pull_counts()
    print(f"Loaded pull counts for {len(pull_counts)} charts")

    # 4. Parse all files
    records      = []
    skipped_sev  = 0
    skipped_no_cve = 0
    errors       = 0
    component_stats: dict[str, int] = collections.Counter()

    for i, path in enumerate(all_files):
        if i % 500 == 0 and i > 0:
            print(f"  ... {i:,}/{len(all_files):,} processed "
                  f"({len(records):,} kept, {skipped_sev:,} below severity)", end="\r")
        rec = parse_osv_file(path, pull_counts)
        if rec is None:
            skipped_no_cve += 1
            continue
        if SEVERITY_ORDER.get(rec["severity"], 0) < min_sev_rank:
            skipped_sev += 1
            continue
        records.append(rec)
        component_stats[rec["chart"]] += 1

    print(f"\n  → Parsed:  {len(records):,} records kept")
    print(f"     Skipped (below {args.min_severity}): {skipped_sev:,}")
    print(f"     Skipped (no CVE ID): {skipped_no_cve:,}")

    # 5. Deduplicate by (cve_id, component) — keep highest CVSS
    deduped: dict[tuple, dict] = {}
    for rec in records:
        key = (rec["cve_id"], rec["chart"])
        existing = deduped.get(key)
        if existing is None or rec["cvss_score"] > existing["cvss_score"]:
            deduped[key] = rec
    records = list(deduped.values())
    print(f"  → After deduplication: {len(records):,} records")

    # 6. Sort by component then CVE id
    records.sort(key=lambda r: (r["chart"], r["cve_id"]))

    # 7. Summary stats
    unique_cves   = len({r["cve_id"] for r in records})
    unique_comps  = len({r["chart"] for r in records})
    sev_dist      = collections.Counter(r["severity"] for r in records)
    av_dist       = collections.Counter(r["attack_vector"] for r in records)
    top10_charts  = collections.Counter(r["chart"] for r in records).most_common(10)
    network_pct   = round(100 * av_dist.get("NETWORK", 0) / max(len(records), 1), 1)

    print(f"\nDataset summary:")
    print(f"  Total records:    {len(records):,}")
    print(f"  Unique CVEs:      {unique_cves:,}")
    print(f"  Unique components:{unique_comps:,}")
    print(f"  Severity:         {dict(sev_dist)}")
    print(f"  Attack vector:    {dict(av_dist)}  ({network_pct}% NETWORK)")
    print(f"  Top-10 charts:    {top10_charts}")

    # 8. Build output document
    output = {
        "source":        "bitnami/vulndb (OSV format, parsed by fetch_bitnami_vulndb.py)",
        "schema":        "OSV 1.5.0 → enriched with CBS parameters",
        "generated":     __import__("datetime").datetime.utcnow().isoformat()[:16] + "Z",
        "cache_dir":     str(args.cache_dir),
        "min_severity":  args.min_severity,
        "total_records": len(records),
        "unique_cves":   unique_cves,
        "unique_components": unique_comps,
        "severity_dist": dict(sev_dist),
        "av_dist":       dict(av_dist),
        "top_components": dict(top10_charts),
        "cves":          records,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    size_kb = args.output.stat().st_size // 1024
    print(f"\n✓ Saved {len(records):,} records → {args.output} ({size_kb:,} KB)")


if __name__ == "__main__":
    main()
