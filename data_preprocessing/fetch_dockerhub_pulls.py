#!/usr/bin/env python3
"""
tools/fetch_dockerhub_pulls.py
==============================
Fetch Docker Hub pull counts for every bitnami chart and write deployment
frequency weights back into data/vulnerability_db/bitnami_cves.json.

What gets added
---------------
Top-level key  `chart_stats`  — per-chart dict:
    {
      "pull_count":        3338504627,
      "star_count":        364,
      "last_updated":      "2025-04-01T...",
      "hub_name":          "redis",        # actual Docker Hub repo queried
      "frequency_weight":  1.0,            # log-normalised 0–1
      "frequency_tier":    "high"          # high / medium / low / minimal
    }

Per-CVE field  `deployment_weight`  — float 0–1 copied from the chart entry.

Usage
-----
  python tools/fetch_dockerhub_pulls.py            # fetch + save
  python tools/fetch_dockerhub_pulls.py --dry-run  # print table, no save
  python tools/fetch_dockerhub_pulls.py --force    # re-fetch even if cached
"""

from __future__ import annotations

import argparse
import json
import math
import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parent.parent
BITNAMI_DB  = REPO_ROOT / "data" / "vulnerability_db" / "bitnami_cves.json"

# ── Docker Hub API ────────────────────────────────────────────────────────────
HUB_API     = "https://hub.docker.com/v2/repositories/bitnami/{name}/"
RATE_DELAY  = 0.35   # seconds between requests (polite rate limit)
TIMEOUT     = 12

# ── Name fallbacks ────────────────────────────────────────────────────────────
# Some Helm chart names differ from their Docker Hub image name.
# Map chart_name → hub_image_name (tried after exact-name 404).
FALLBACKS: dict[str, str] = {
    "postgresql-ha":               "postgresql",
    "mariadb-galera":              "mariadb",
    "mongodb-sharded":             "mongodb",
    "redis-cluster":               "redis",
    "valkey-cluster":              "valkey",
    "minio-operator":              "minio",
    "nginx-ingress-controller":    "nginx",
    "grafana-alloy":               "grafana",
    "grafana-loki":                "grafana",
    "grafana-mimir":               "grafana",
    "grafana-operator":            "grafana",
    "grafana-tempo":               "grafana",
    "grafana-k6-operator":         "grafana",
    "kube-prometheus":             "kube-state-metrics",
    "kube-arangodb":               "arangodb",
    "kube-state-metrics":          "kube-state-metrics",
    "kubernetes-event-exporter":   "kubernetes-event-exporter",
    "argo-cd":                     "argo-cd",
    "aspnet-core":                 "aspnet-core",
    "cert-manager":                "cert-manager",
    "cloudnative-pg":              "cloudnative-pg",
    "envoy-gateway":               "envoy",
    "external-dns":                "external-dns",
    "fluent-bit":                  "fluent-bit",
    "gitlab-runner":               "gitlab-runner",
    "multus-cni":                  "multus-cni",
    "node-exporter":               "node-exporter",
    "oauth2-proxy":                "oauth2-proxy",
    "metrics-server":              "metrics-server",
    "neo4j":                       "neo4j",
}


# ── Frequency tier thresholds (pull count) ────────────────────────────────────
TIER_THRESHOLDS = [
    (100_000_000,  "high"),      # > 100M  pulls
    (10_000_000,   "medium"),    # > 10M   pulls
    (1_000_000,    "low"),       # > 1M    pulls
    (0,            "minimal"),   # ≤ 1M    pulls
]


def _tier(pull_count: int) -> str:
    for threshold, name in TIER_THRESHOLDS:
        if pull_count > threshold:
            return name
    return "minimal"


# ── Docker Hub fetch ──────────────────────────────────────────────────────────

def fetch_hub(hub_name: str) -> dict | None:
    """Return {pull_count, star_count, last_updated} or None on 404."""
    url = HUB_API.format(name=hub_name)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.loads(r.read())
            return {
                "pull_count":   int(data.get("pull_count", 0)),
                "star_count":   int(data.get("star_count", 0)),
                "last_updated": data.get("last_updated", ""),
            }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    except Exception:
        return None


def resolve_chart(chart: str) -> tuple[str, dict | None]:
    """
    Try exact name, then fallback name.
    Returns (hub_name_used, result_dict | None).
    """
    result = fetch_hub(chart)
    if result is not None:
        return chart, result

    fallback = FALLBACKS.get(chart)
    if fallback and fallback != chart:
        time.sleep(RATE_DELAY)
        result = fetch_hub(fallback)
        if result is not None:
            return fallback, result

    return chart, None


# ── Log-normalised weight ─────────────────────────────────────────────────────

def log_weight(pull_count: int, max_pulls: int) -> float:
    """Scale pull_count logarithmically to [0, 1]."""
    if max_pulls <= 0 or pull_count <= 0:
        return 0.0
    return round(math.log1p(pull_count) / math.log1p(max_pulls), 4)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch Docker Hub pull counts for bitnami charts")
    parser.add_argument("--dry-run", action="store_true", help="Print results without saving")
    parser.add_argument("--force",   action="store_true", help="Re-fetch even if chart_stats already exist")
    args = parser.parse_args()

    data = json.loads(BITNAMI_DB.read_text(encoding="utf-8"))
    cves: list[dict] = data.get("cves", [])

    existing: dict[str, dict] = data.get("chart_stats", {})
    charts = sorted(set(c["chart"] for c in cves))

    to_fetch = [ch for ch in charts if args.force or ch not in existing]

    print(f"{'=' * 62}")
    print(f"  Docker Hub Pull Fetcher — bitnami ({len(charts)} charts)")
    print(f"  Fetching : {len(to_fetch)}   Cached: {len(charts) - len(to_fetch)}")
    print(f"  Mode     : {'DRY RUN' if args.dry_run else 'LIVE'}")
    print(f"{'=' * 62}\n")

    results: dict[str, dict] = dict(existing)  # start with cached values

    for i, chart in enumerate(to_fetch, 1):
        hub_name, raw = resolve_chart(chart)
        if raw:
            results[chart] = {
                "pull_count":   raw["pull_count"],
                "star_count":   raw["star_count"],
                "last_updated": raw["last_updated"],
                "hub_name":     hub_name,
            }
            pulls = raw["pull_count"]
            print(f"  [{i:>2}/{len(to_fetch)}] {chart:<35} {pulls:>14,}  pulls  "
                  f"({'✓' if hub_name == chart else f'→ {hub_name}'})")
        else:
            results[chart] = {
                "pull_count":   0,
                "star_count":   0,
                "last_updated": "",
                "hub_name":     hub_name,
            }
            print(f"  [{i:>2}/{len(to_fetch)}] {chart:<35}  NOT FOUND on Docker Hub")

        time.sleep(RATE_DELAY)

    # ── Compute log-normalised weights ────────────────────────────────────────
    max_pulls = max((v["pull_count"] for v in results.values()), default=1)

    for chart, stat in results.items():
        stat["frequency_weight"] = log_weight(stat["pull_count"], max_pulls)
        stat["frequency_tier"]   = _tier(stat["pull_count"])

    # ── Print summary table ───────────────────────────────────────────────────
    print(f"\n{'─' * 62}")
    print(f"  {'Chart':<35} {'Pulls':>15}  {'Weight':>7}  Tier")
    print(f"{'─' * 62}")
    for chart in sorted(results, key=lambda c: -results[c]["pull_count"]):
        s = results[chart]
        bar_len = int(s["frequency_weight"] * 20)
        bar = "█" * bar_len
        print(f"  {chart:<35} {s['pull_count']:>15,}  {s['frequency_weight']:>7.4f}  "
              f"{s['frequency_tier']:<8}  {bar}")

    # ── Tier breakdown ────────────────────────────────────────────────────────
    from collections import Counter
    tier_counts = Counter(s["frequency_tier"] for s in results.values())
    print(f"\n  Tier breakdown:")
    for tier in ["high", "medium", "low", "minimal"]:
        n = tier_counts.get(tier, 0)
        print(f"    {tier:<10} {n:>3} charts")

    if args.dry_run:
        print("\n  [dry-run] No files written.")
        return

    # ── Write chart_stats back to bitnami_cves.json ───────────────────────────
    data["chart_stats"] = results

    # Add deployment_weight to every CVE entry
    for cve in cves:
        chart  = cve.get("chart", "")
        stat   = results.get(chart, {})
        cve["deployment_weight"] = stat.get("frequency_weight", 0.0)
        cve["frequency_tier"]    = stat.get("frequency_tier", "minimal")

    # Backup + save
    bak = BITNAMI_DB.with_suffix(".json.bak")
    if BITNAMI_DB.exists() and not bak.exists():
        shutil.copy(BITNAMI_DB, bak)

    BITNAMI_DB.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"\n  Saved → {BITNAMI_DB.name}")
    print(f"  chart_stats : {len(results)} entries")
    print(f"  CVE entries updated with deployment_weight: {len(cves)}")


if __name__ == "__main__":
    main()
