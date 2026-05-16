# Bitnami CVE EDA Report Generator

Generate (or regenerate) the full Bitnami Helm chart vulnerability analysis report:
figures + LaTeX source + compiled PDF.

Output is written to `/content/drive/MyDrive/thesis/code/datasets/poc/claude/`.

---

## Usage

```
/bitnami-report                         # regenerate everything (figures + tex + PDF)
/bitnami-report --no-compile            # skip pdflatex (useful in headless environments)
/bitnami-report --out-dir PATH          # override output directory
/bitnami-report --dataset trivy         # use Trivy-only dataset (693 records)
/bitnami-report --dataset vulndb        # use official Bitnami/vulndb dataset (2813 records)
/bitnami-report --dataset combined      # use merged dataset (1634 records) [default]
```

---

## What it does

1. **Loads** the selected dataset (default: `bitnami_combined_cves.json`, 1634 records, 94 charts).
2. **Loads all three datasets** for the source comparison figure (Trivy / vulndb / Combined).
3. **Generates 11 publication-quality figures** (PDF format) in `figures/bitnami/`:
   - CVSS score distribution
   - Severity × Attack Complexity breakdown
   - Top-18 charts by CVE count
   - Primary MITRE ATT&CK tactic distribution
   - Supply-chain CVE propagation (top 12)
   - Deployment frequency tiers + pull-count ranking
   - CBS node property frequency
   - CVE year distribution
   - Success rate + exploit cost distributions
   - Application tier overview (CVEs + chart counts)
   - **Source comparison** (Trivy vs. vulndb vs. Combined — record counts, component coverage, CVSS & network %)
4. **Writes** `bitnami_analysis.tex` — a full two-column conference-style paper
   with all statistics computed from the live JSON (no hard-coded numbers).
   Includes an "Extended Dataset: Bitnami/vulndb Integration" section with
   a three-source comparison table and the source comparison figure.
5. **Compiles** with `pdflatex` (two passes) → `bitnami_analysis.pdf`.

---

## Datasets

| Flag | File | Records | Unique CVEs | Charts | CVSS mean |
|------|------|---------|-------------|--------|-----------|
| `trivy` | `bitnami_cves.json` | 693 | 163 | 94 | 8.22 |
| `vulndb` | `bitnami_vulndb_cves.json` | 2,813 | 2,284 | 155 | 8.08 |
| `combined` | `bitnami_combined_cves.json` | 1,634 | 1,042 | 94 | 8.20 |

To regenerate datasets:
- `python pipeline/data/fetch_bitnami_vulndb.py` — fetch/update official vulndb → `bitnami_vulndb_cves.json`
- `python pipeline/data/merge_bitnami_datasets.py` — merge Trivy + vulndb → `bitnami_combined_cves.json`

---

## Instructions

Run the report generation script, then verify the PDF was created:

```bash
cd /home/ariel/Documents/thesis/CyberBattleSimDomainGenerator
python pipeline/reporting/bitnami.py $ARGUMENTS
```

After the script completes:
- Confirm `bitnami_analysis.pdf` exists at the output path.
- If compilation fails, show the last 40 lines of the `.log` file.
- Report the final file sizes of the `.tex` and `.pdf`.

If `$ARGUMENTS` contains `--no-compile`, skip the PDF verification step.
