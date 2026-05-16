#!/usr/bin/env python3
"""
Merge Trivy image-scan data (bitnami_cves.json) with the official Bitnami
vulnerability database (bitnami_vulndb_cves.json) into a single enriched
combined dataset.

Merge strategy:
  - Start with all Trivy records (ground truth for specific image versions)
  - Enrich each Trivy record with vulndb data where CVE ID and component overlap:
      adds: cvss_vector, affected_versions, fixed_versions, bit_id, cpes
      updates: cvss_score to the higher of the two (vulndb has more complete vectors)
  - Append vulndb-only records (CVE IDs not in Trivy) for all overlapping components
  - Optionally include vulndb-only records for new components

Outputs:
  data/vulnerability_db/bitnami_combined_cves.json

Usage:
    python tools/merge_bitnami_datasets.py [--include-new-components]
                                           [--output PATH]
"""
import argparse
import collections
import json
import statistics
from pathlib import Path

REPO_ROOT   = Path(__file__).resolve().parent.parent
TRIVY_PATH  = REPO_ROOT / "data/vulnerability_db/bitnami_cves.json"
VULNDB_PATH = REPO_ROOT / "data/vulnerability_db/bitnami_vulndb_cves.json"
DEFAULT_OUT = REPO_ROOT / "data/vulnerability_db/bitnami_combined_cves.json"


def load(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def build_vulndb_index(vdb_records: list[dict]) -> dict:
    """Build lookup: (cve_id, component) → record, and cve_id → [records]."""
    by_key    = {}   # (cve_id, chart) → record
    by_cve_id = collections.defaultdict(list)
    for rec in vdb_records:
        key = (rec["cve_id"], rec["chart"])
        if key not in by_key or rec["cvss_score"] > by_key[key]["cvss_score"]:
            by_key[key] = rec
        by_cve_id[rec["cve_id"]].append(rec)
    return by_key, dict(by_cve_id)


def enrich_trivy_with_vulndb(trivy_rec: dict, vdb_rec: dict) -> dict:
    """Merge vulndb fields into a Trivy record (non-destructive)."""
    r = dict(trivy_rec)
    # add vulndb-specific fields that Trivy doesn't have
    r["bit_id"]            = vdb_rec.get("bit_id", "")
    r["cvss_vector"]       = vdb_rec.get("cvss_vector", "")
    r["affected_versions"] = vdb_rec.get("affected_versions", [])
    r["fixed_versions"]    = vdb_rec.get("fixed_versions", [])
    r["cpes"]              = vdb_rec.get("cpes", [])
    r["purl"]              = vdb_rec.get("purl", f"pkg:bitnami/{r['chart']}")
    r["privileges_required"] = vdb_rec.get("privileges_required", "N")
    r["user_interaction"]    = vdb_rec.get("user_interaction", "N")
    r["scope"]               = vdb_rec.get("scope", "U")
    r["published"]           = vdb_rec.get("published", "")
    r["modified"]            = vdb_rec.get("modified", "")
    r["vulndb_source"]       = True

    # prefer vulndb CVSS score if it's higher (more complete vector)
    if vdb_rec.get("cvss_score", 0.0) > r.get("cvss_score", 0.0):
        r["cvss_score"] = vdb_rec["cvss_score"]
        # recalculate CBS params with the updated score
        r["success_rate"] = vdb_rec["success_rate"]
        r["exploit_cost"] = vdb_rec["exploit_cost"]
        r["probability"]  = vdb_rec["probability"]

    return r


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--include-new-components", action="store_true",
                        help="Include vulndb components not present in Trivy scan")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    print("Loading datasets...")
    trivy_d = load(TRIVY_PATH)
    vdb_d   = load(VULNDB_PATH)

    trivy_records = trivy_d["cves"]
    vdb_records   = vdb_d["cves"]

    trivy_charts = {r["chart"] for r in trivy_records}
    vdb_charts   = {r["chart"] for r in vdb_records}
    chart_overlap = trivy_charts & vdb_charts

    print(f"  Trivy records:      {len(trivy_records):,} ({len(trivy_charts)} charts)")
    print(f"  Vulndb records:     {len(vdb_records):,} ({len(vdb_charts)} components)")
    print(f"  Chart overlap:      {len(chart_overlap)} components")

    vdb_index, vdb_by_cve = build_vulndb_index(vdb_records)

    # ── Step 1: enrich Trivy records ─────────────────────────────────────────
    enriched_count = 0
    merged: list[dict] = []
    for rec in trivy_records:
        key = (rec["cve_id"], rec["chart"])
        if key in vdb_index:
            rec = enrich_trivy_with_vulndb(rec, vdb_index[key])
            enriched_count += 1
        else:
            rec = dict(rec)
            rec["vulndb_source"] = False
        rec["data_source"] = "trivy"
        merged.append(rec)

    print(f"  Trivy records enriched with vulndb: {enriched_count:,}")

    # ── Step 2: add vulndb-only records for overlapping components ────────────
    trivy_keys = {(r["cve_id"], r["chart"]) for r in merged}
    added_overlap = 0
    added_new = 0

    for rec in vdb_records:
        key = (rec["cve_id"], rec["chart"])
        if key in trivy_keys:
            continue   # already in merged (from Trivy)
        in_overlap = rec["chart"] in trivy_charts
        if in_overlap or args.include_new_components:
            r = dict(rec)
            r["data_source"]   = "vulndb"
            r["vulndb_source"] = True
            r["target"]        = f"bitnami/{rec['chart']}"  # Trivy-compat field
            merged.append(r)
            if in_overlap:
                added_overlap += 1
            else:
                added_new += 1

    print(f"  Vulndb-only (overlapping components): {added_overlap:,}")
    if args.include_new_components:
        print(f"  Vulndb-only (new components):         {added_new:,}")

    total = len(merged)
    print(f"  → Combined total: {total:,} records")

    # ── Step 3: deduplication: keep highest CVSS per (cve_id, chart) ─────────
    dedup: dict[tuple, dict] = {}
    for rec in merged:
        key = (rec["cve_id"], rec["chart"])
        existing = dedup.get(key)
        if existing is None or rec["cvss_score"] > existing["cvss_score"]:
            dedup[key] = rec
    merged = sorted(dedup.values(), key=lambda r: (r["chart"], r["cve_id"]))
    print(f"  → After dedup:    {len(merged):,} records")

    # ── Step 4: summary stats ─────────────────────────────────────────────────
    unique_cves  = len({r["cve_id"] for r in merged})
    unique_comps = len({r["chart"] for r in merged})
    sev_cnt      = collections.Counter(r["severity"] for r in merged)
    av_cnt       = collections.Counter(r["attack_vector"] for r in merged)
    source_cnt   = collections.Counter(r["data_source"] for r in merged)
    scores       = [r["cvss_score"] for r in merged if r.get("cvss_score")]

    print(f"\nCombined dataset summary:")
    print(f"  Total records:     {len(merged):,}")
    print(f"  Unique CVE IDs:    {unique_cves:,}")
    print(f"  Unique components: {unique_comps}")
    print(f"  Severity:          {dict(sev_cnt)}")
    print(f"  Attack vector:     {dict(av_cnt)}")
    print(f"  Source:            {dict(source_cnt)}")
    print(f"  CVSS mean:         {statistics.mean(scores):.2f}  "
          f"median: {statistics.median(scores):.2f}  "
          f"std: {statistics.stdev(scores):.2f}")

    # ── Step 5: write output ──────────────────────────────────────────────────
    output_doc = {
        "source": "Merged: bitnami Trivy scan + bitnami/vulndb official advisory database",
        "components": {
            "trivy": str(TRIVY_PATH.name),
            "vulndb": str(VULNDB_PATH.name),
        },
        "generated": __import__("datetime").datetime.utcnow().isoformat()[:16] + "Z",
        "total_records":       len(merged),
        "unique_cves":         unique_cves,
        "unique_components":   unique_comps,
        "trivy_records":       source_cnt.get("trivy", 0),
        "vulndb_only_records": source_cnt.get("vulndb", 0),
        "enriched_trivy":      enriched_count,
        "severity_dist":       dict(sev_cnt),
        "av_dist":             dict(av_cnt),
        "cvss_mean":           round(statistics.mean(scores), 3),
        "cvss_median":         round(statistics.median(scores), 3),
        "cvss_std":            round(statistics.stdev(scores), 3),
        # pass through chart_stats from trivy for deployment weights in report
        "chart_stats":         trivy_d.get("chart_stats", {}),
        "cves":                merged,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output_doc, f, indent=2)

    size_kb = args.output.stat().st_size // 1024
    print(f"\n✓ Saved → {args.output} ({size_kb:,} KB)")


if __name__ == "__main__":
    main()
