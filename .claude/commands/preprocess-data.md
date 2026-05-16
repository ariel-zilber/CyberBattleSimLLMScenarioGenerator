# Data Preprocessing — Fetch, Enrich, and Curate CVE Databases

Run the one-time data preparation pipeline that builds the CVE reference databases used by
the generation pipeline. Re-run whenever you want to refresh CVE data from upstream sources.

**Output:** `data/vulnerability_db/*.json` + updated `prompts/reference/vulnerability_catalog.md`
and `prompts/reference/allowed_properties.md`.

---

## Arguments

```
/preprocess-data                        # full pipeline (fetch + enrich + curate)
/preprocess-data --fetch-only           # stop after fetching raw CVEs
/preprocess-data --enrich-only          # skip fetch, re-run enrichment on existing data
/preprocess-data --domain windows       # only refresh windows_cves.json
/preprocess-data --domain network       # only refresh network_devices_cves.json
/preprocess-data --domain bitnami       # only refresh bitnami_combined_cves.json
/preprocess-data --skip-curate          # fetch + enrich but skip LLM catalog curation
```

---

## Step 1 — Fetch raw CVEs

Run the relevant fetch scripts based on `$ARGUMENTS` (all by default):

**Windows CVEs (NVD API v2):**
```bash
python pipeline/data_preprocessing/nvd_scraper.py
```

**Network device CVEs (NVD + EPSS + CISA KEV):**
```bash
python pipeline/data_preprocessing/scrape_domain_cves.py
```

**Bitnami CVEs (Trivy image scans + official vulndb + DockerHub weights):**
```bash
python pipeline/data_preprocessing/scan_bitnami_images.py
python pipeline/data_preprocessing/fetch_bitnami_vulndb.py
python pipeline/data_preprocessing/fetch_dockerhub_pulls.py
```

Report counts after each script: `N CVEs written to data/vulnerability_db/<file>.json`.

---

## Step 2 — Enrich

Run in order (each script reads and overwrites the JSON in-place):

```bash
python pipeline/data_preprocessing/merge_bitnami_datasets.py
python pipeline/data_preprocessing/tag_mitre_tactics.py
python pipeline/data_preprocessing/add_missing_tactic_cves.py
python pipeline/data_preprocessing/equalize_cves.py
```

After each script report: script name + records before → after.

---

## Step 3 — MITRE analysis report (optional)

```bash
python pipeline/data_preprocessing/mitre_attack_analysis.py
```

Prints a per-tactic CVE coverage table. Use this to verify enrichment quality.

---

## Step 4 — Catalog Curation (LLM)

**Skip if `--skip-curate` was passed.**

For each CVE database that was updated, use the LLM to map CVEs into CBS vocabulary and
update `prompts/reference/vulnerability_catalog.md` and `prompts/reference/allowed_properties.md`.

Load context:
- `prompts/system_prompt.md`
- `prompts/schema/definition.md`
- The updated `data/vulnerability_db/*.json`

For each new or changed CVE entry, confirm it maps to:
- A valid CBS service name
- Valid node property tokens
- A `success_rate` in 0.40–0.90
- The correct vulnerability type (REMOTE / LOCAL)
- At least one `match_properties` token

**Do NOT add CVEs to the catalog that lack a real CVE ID or verified CVSS score.**

---

## Step 5 — Summary

Report:
```
DATA PREPROCESSING COMPLETE
════════════════════════════════════
  windows_cves.json        : N entries  (N new)
  network_devices_cves.json: N entries  (N new)
  bitnami_combined_cves.json: N entries (N new)

  vulnerability_catalog.md : N entries  (N added / N updated)
  allowed_properties.md    : N tokens

  MITRE tactic coverage    : TA0001 N · TA0002 N · TA0003 N ...
════════════════════════════════════
```

---

## Arguments

$ARGUMENTS
