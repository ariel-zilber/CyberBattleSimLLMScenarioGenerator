"""
tools/scan_bitnami_images.py
============================
Scan Bitnami Docker images with `trivy image` using the correct versioned tags
from bitnami_chart_analysis.json, then merge results into bitnami_cves.json.

Usage:
    python3 tools/scan_bitnami_images.py                        # scan all mapped charts
    python3 tools/scan_bitnami_images.py --charts nginx,redis   # specific charts
    python3 tools/scan_bitnami_images.py --list                 # list available charts
    python3 tools/scan_bitnami_images.py --dry-run              # show images without scanning
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────

REPO_ROOT      = Path(__file__).resolve().parent.parent
VULN_DB        = REPO_ROOT / "data" / "vulnerability_db" / "bitnami_cves.json"
CHART_ANALYSIS = REPO_ROOT / "data" / "vulnerability_db" / "bitnami_chart_analysis.json"

# ── Chart → CBS property mapping ───────────────────────────────────────────────
# Defines which charts to scan and what CBS properties to associate with each.
# Image tag is resolved from bitnami_chart_analysis.json at runtime.

CHART_MAP: dict[str, list[str]] = {
    # Web / proxy
    "nginx":        ["WebServer",  "Linux", "NginxServer", "LibCrypto"],
    "wordpress":    ["WebServer",  "Linux", "PHP", "WordPressInstall", "ImageMagick"],
    "drupal":       ["WebServer",  "Linux", "PHP"],
    "phpmyadmin":   ["WebServer",  "Linux", "PHP", "AnonymousAuth"],
    "kong":         ["WebServer",  "Linux", "GoRuntime"],
    # Auth / identity
    "keycloak":     ["AuthServer", "Linux", "Java", "KeycloakService"],
    "oauth2-proxy": ["AuthServer", "Linux", "GoRuntime"],
    # App servers
    "jenkins":      ["AppServer",  "Linux", "Java", "WebServer"],
    "grafana":      ["AppServer",  "Linux", "GoRuntime"],
    "vault":        ["AppServer",  "Linux", "GoRuntime"],
    "prometheus":   ["AppServer",  "Linux", "GoRuntime"],
    "kibana":       ["AppServer",  "Linux", "Java", "WebServer"],
    "minio":        ["AppServer",  "Linux", "GoRuntime", "DatabaseServer"],
    "sonarqube":    ["AppServer",  "Linux", "Java"],
    "gitea":        ["AppServer",  "Linux", "GoRuntime"],
    "jupyterhub":   ["AppServer",  "Linux", "Python"],
    # Message brokers / workers
    "kafka":        ["WorkerNode", "Linux", "Java"],
    "airflow":      ["WorkerNode", "Linux", "Python", "Java"],
    "rabbitmq":     ["WorkerNode", "Linux", "Java"],
    "logstash":     ["WorkerNode", "Linux", "Java"],
    "fluentd":      ["WorkerNode", "Linux", "Python"],
    "spark":        ["WorkerNode", "Linux", "Java", "Python"],
    # Databases
    "mongodb":      ["DatabaseServer", "Linux", "MongoDB", "GoRuntime"],
    "redis":        ["DatabaseServer", "Linux", "Redis", "GoRuntime"],
    "mysql":        ["DatabaseServer", "Linux", "MySQLServer", "MySQL"],
    "postgresql":   ["DatabaseServer", "Linux"],
    "elasticsearch":["DatabaseServer", "Linux", "Java"],
    "cassandra":    ["DatabaseServer", "Linux", "Java"],
    # K8s infrastructure
    "etcd":         ["Kubernetes",  "Linux", "GoRuntime", "K8sCluster"],
}

# ── CVSS helpers ───────────────────────────────────────────────────────────────

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

def _parse_cvss(vuln: dict) -> tuple[float, str, str]:
    cvss_block = vuln.get("CVSS") or {}
    for source in ("nvd", "redhat", "ghsa", "bitnami"):
        blk = cvss_block.get(source, {})
        score = blk.get("V3Score") or blk.get("V2Score")
        vec   = blk.get("V3Vector") or blk.get("V2Vector") or ""
        if score is not None:
            return float(score), *_parse_vector(vec)
    return 5.0, "UNKNOWN", "LOW"

def _parse_vector(vec: str) -> tuple[str, str]:
    AV_MAP = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
    AC_MAP = {"L": "LOW", "H": "HIGH"}
    av, ac = "UNKNOWN", "LOW"
    for part in vec.split("/"):
        if part.startswith("AV:"):
            av = AV_MAP.get(part[3:], "UNKNOWN")
        elif part.startswith("AC:"):
            ac = AC_MAP.get(part[3:], "LOW")
    return av, ac

def _success_rate(cvss: float, ac: str) -> float:
    base = max(0.0, min(1.0, cvss / 10.0))
    if ac == "HIGH":
        base *= 0.7
    return round(max(0.30, min(0.90, base)), 2)

def _exploit_cost(cvss: float) -> float:
    if cvss >= 9.0: return 1.0
    if cvss >= 7.0: return 1.5
    if cvss >= 5.0: return 2.0
    return 3.0

# ── Chart analysis loader ──────────────────────────────────────────────────────

def load_chart_images() -> dict[str, str]:
    """
    Return chart_name → first_image_reference from bitnami_chart_analysis.json.
    E.g., 'nginx' → 'docker.io/bitnami/nginx:1.29.1-debian-12-r0'
    """
    if not CHART_ANALYSIS.exists():
        return {}
    data = json.loads(CHART_ANALYSIS.read_text())
    result: dict[str, str] = {}
    for hc in data.get("helm_charts", []):
        name   = hc.get("name", "")
        images = hc.get("images", [])
        if name and images:
            result[name] = images[0]  # first image = main service image
    return result

# ── Scanner ────────────────────────────────────────────────────────────────────

def scan_image(
    image_ref: str,
    chart_key: str,
    chart_properties: list[str],
    severity: str = "HIGH",
) -> list[dict]:
    """Run trivy image on `image_ref` and return CVE dicts."""
    print(f"  Scanning {image_ref} ...", flush=True)

    result = subprocess.run(
        [
            "trivy", "image",
            "--format", "json",
            "--scanners", "vuln",
            "--severity", severity,
            "--skip-version-check",
            "--quiet",
            image_ref,
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )

    if result.returncode not in (0, 1):
        stderr = result.stderr[:300]
        print(f"  WARN: trivy exit {result.returncode}: {stderr}", file=sys.stderr)
        return []

    if not result.stdout.strip():
        print(f"  WARN: no output (image may not be locally cached — run: docker pull {image_ref})", file=sys.stderr)
        return []

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"  WARN: JSON parse error: {e}", file=sys.stderr)
        return []

    cves: list[dict] = []
    for res in raw.get("Results", []):
        target = res.get("Target", image_ref)
        for v in res.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            if SEVERITY_RANK.get(sev, 0) < SEVERITY_RANK.get(severity, 3):
                continue
            score, av, ac = _parse_cvss(v)
            cves.append({
                "cve_id":            v.get("VulnerabilityID", ""),
                "pkg_name":          v.get("PkgName", ""),
                "installed_version": v.get("InstalledVersion", ""),
                "fixed_version":     v.get("FixedVersion", ""),
                "severity":          sev,
                "cvss_score":        score,
                "attack_vector":     av,
                "attack_complexity": ac,
                "success_rate":      _success_rate(score, ac),
                "exploit_cost":      _exploit_cost(score),
                "description":       (v.get("Description") or "")[:350],
                "chart":             chart_key,
                "app_version":       "",
                "chart_properties":  chart_properties,
                "target":            target,
            })

    # Deduplicate by CVE ID within this image
    seen: dict[str, dict] = {}
    for c in cves:
        cid = c["cve_id"]
        if cid not in seen or c["cvss_score"] > seen[cid]["cvss_score"]:
            seen[cid] = c

    result_list = list(seen.values())
    crit = sum(1 for c in result_list if c["severity"] == "CRITICAL")
    high = sum(1 for c in result_list if c["severity"] == "HIGH")
    print(f"  → {len(result_list)} unique CVEs ({crit} CRITICAL, {high} HIGH)", flush=True)
    return result_list


def merge_into_db(db_path: Path, new_cves: list[dict], chart_key: str, chart_name: str) -> dict:
    """Load DB, replace CVEs for chart_key, rebuild stats, write back."""
    if db_path.exists():
        data = json.loads(db_path.read_text())
    else:
        data = {
            "source": "bitnami images via trivy image scan",
            "charts_scanned": [],
            "unique_cve_count": 0,
            "cves": [],
            "service_vuln_map": {},
        }

    # Remove stale entries for this chart
    kept = [c for c in data.get("cves", []) if c.get("chart") != chart_key]
    merged = kept + new_cves

    # Global dedup by (cve_id, chart)
    seen: dict[tuple, dict] = {}
    for c in merged:
        key = (c["cve_id"], c["chart"])
        if key not in seen or c["cvss_score"] > seen[key]["cvss_score"]:
            seen[key] = c

    final_cves = list(seen.values())

    # Rebuild service_vuln_map
    svm: dict[str, int] = {}
    for c in final_cves:
        ch = c.get("chart", "")
        svm[ch] = svm.get(ch, 0) + 1

    charts_set = set(data.get("charts_scanned", []))
    charts_set.add(chart_name)

    data["cves"] = final_cves
    data["unique_cve_count"] = len({c["cve_id"] for c in final_cves})
    data["charts_scanned"] = sorted(charts_set)
    data["service_vuln_map"] = dict(sorted(svm.items()))
    return data


# ── Pull helper ────────────────────────────────────────────────────────────────

def docker_pull(image_ref: str) -> bool:
    """Pull image with docker. Returns True on success."""
    r = subprocess.run(
        ["docker", "pull", "--quiet", image_ref],
        capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0:
        print(f"  WARN: docker pull failed: {r.stderr[:150]}", file=sys.stderr)
        return False
    return True


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan Bitnami images with Trivy and update bitnami_cves.json"
    )
    parser.add_argument("--charts",   default="", help="Comma-separated chart names (default: all)")
    parser.add_argument("--severity", default="HIGH", help="Min severity (default: HIGH → HIGH+CRITICAL)")
    parser.add_argument("--out",      default="", help="Output path (default: data/vulnerability_db/bitnami_cves.json)")
    parser.add_argument("--pull",     action="store_true", help="Run docker pull before scanning")
    parser.add_argument("--list",     action="store_true", help="List available charts and exit")
    parser.add_argument("--dry-run",  action="store_true", help="Print images to scan without running trivy")
    args = parser.parse_args()

    out_path    = Path(args.out) if args.out else VULN_DB
    chart_imgs  = load_chart_images()

    if args.charts:
        targets = [n.strip() for n in args.charts.split(",") if n.strip()]
        unknown = [t for t in targets if t not in CHART_MAP]
        if unknown:
            print(f"Unknown charts: {unknown}\nAvailable: {sorted(CHART_MAP.keys())}", file=sys.stderr)
            sys.exit(1)
    else:
        targets = list(CHART_MAP.keys())

    if args.list or args.dry_run:
        print(f"Charts to scan ({len(targets)}):")
        for name in targets:
            img = chart_imgs.get(name, f"docker.io/bitnami/{name}:latest  ← NOT in chart analysis")
            props = CHART_MAP[name]
            print(f"  {name:20} {img}")
            print(f"  {'':20} props={props}")
        return

    print(f"Scanning {len(targets)} Bitnami charts (severity≥{args.severity})")
    print(f"Output: {out_path}\n")

    for i, chart_name in enumerate(targets, 1):
        props     = CHART_MAP[chart_name]
        image_ref = chart_imgs.get(chart_name)

        if not image_ref:
            print(f"[{i}/{len(targets)}] {chart_name} — SKIP (not in chart analysis)")
            continue

        print(f"[{i}/{len(targets)}] {chart_name}")

        if args.pull:
            print(f"  Pulling {image_ref} ...", flush=True)
            docker_pull(image_ref)

        new_cves = scan_image(image_ref, chart_name, props, severity=args.severity)
        data = merge_into_db(out_path, new_cves, chart_name, chart_name)
        out_path.write_text(json.dumps(data, indent=2))
        print(f"  Saved — DB: {data['unique_cve_count']} unique CVEs, "
              f"{len(data['charts_scanned'])} charts\n")

    print("Done.")
    data = json.loads(out_path.read_text())
    print(f"Final: {data['unique_cve_count']} unique CVEs across {len(data['charts_scanned'])} charts")
    print(f"Service map: { {k:v for k,v in data['service_vuln_map'].items()} }")


if __name__ == "__main__":
    main()
