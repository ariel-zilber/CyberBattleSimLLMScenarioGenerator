"""
tools/trivy_scanner.py
======================
Clone a git repository and run Trivy filesystem scan to extract real CVE data.

Usage (standalone):
    python tools/trivy_scanner.py --repo https://github.com/org/repo --out /tmp/scan.json

Requires: trivy on PATH  (https://github.com/aquasecurity/trivy#installation)
          git on PATH
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ── Constants ─────────────────────────────────────────────────────────────────

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0,
}
DEFAULT_MIN_SEVERITY = "MEDIUM"

# git clone flags: shallow + no history, much faster
GIT_CLONE_FLAGS = ["--depth=1", "--single-branch", "--quiet"]


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class TrivyCVE:
    cve_id:            str
    pkg_name:          str
    installed_version: str
    fixed_version:     str
    severity:          str          # CRITICAL | HIGH | MEDIUM | LOW
    cvss_score:        float        # 0.0–10.0
    attack_vector:     str          # NETWORK | ADJACENT | LOCAL | PHYSICAL | UNKNOWN
    attack_complexity: str          # LOW | HIGH
    privileges_required: str        # NONE | LOW | HIGH
    description:       str
    target_file:       str          # originating package manifest
    references:        List[str] = field(default_factory=list)

    @property
    def is_network_exploitable(self) -> bool:
        return self.attack_vector in ("NETWORK", "ADJACENT")

    @property
    def normalised_success_rate(self) -> float:
        """Map CVSS 0–10 to a plausible CyberBattleSim success_rate (0.30–0.90)."""
        base = max(0.0, min(1.0, self.cvss_score / 10.0))
        # complexity penalty: HIGH complexity → harder to exploit
        if self.attack_complexity == "HIGH":
            base *= 0.7
        return round(max(0.30, min(0.90, base)), 2)

    @property
    def exploit_cost(self) -> float:
        """Higher CVSS + lower complexity → lower cost for attacker."""
        if self.cvss_score >= 9.0:
            return 1.0
        if self.cvss_score >= 7.0:
            return 1.5
        if self.cvss_score >= 5.0:
            return 2.0
        return 3.0


@dataclass
class TrivyScanResult:
    repo_url:     str
    repo_dir:     str
    cves:         List[TrivyCVE] = field(default_factory=list)
    targets:      List[str]      = field(default_factory=list)
    pkg_managers: List[str]      = field(default_factory=list)
    error:        Optional[str]  = None

    @property
    def critical_cves(self) -> List[TrivyCVE]:
        return [c for c in self.cves if c.severity == "CRITICAL"]

    @property
    def high_cves(self) -> List[TrivyCVE]:
        return [c for c in self.cves if c.severity == "HIGH"]

    @property
    def network_exploitable(self) -> List[TrivyCVE]:
        return [c for c in self.cves if c.is_network_exploitable]

    def top_by_cvss(self, n: int = 15) -> List[TrivyCVE]:
        return sorted(self.cves, key=lambda c: c.cvss_score, reverse=True)[:n]


# ── Main scanner class ────────────────────────────────────────────────────────

class TrivyScanner:
    """Clone a git repo and run Trivy to extract CVE findings."""

    def __init__(
        self,
        work_dir: Optional[Path] = None,
        keep_clone: bool = False,
    ):
        self.work_dir   = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="trivy_"))
        self.keep_clone = keep_clone

    # ── public ────────────────────────────────────────────────────────────────

    def scan(
        self,
        repo_url: str,
        min_severity: str = DEFAULT_MIN_SEVERITY,
    ) -> TrivyScanResult:
        """
        Full pipeline: clone → trivy → parse → return.
        Cleans up the clone unless keep_clone=True.
        """
        repo_dir = self.work_dir / _repo_dirname(repo_url)
        try:
            self._check_dependencies()
            self._clone(repo_url, repo_dir)
            raw = self._run_trivy(repo_dir)
            return self._parse(raw, repo_url, repo_dir, min_severity)
        except Exception as exc:
            return TrivyScanResult(
                repo_url=repo_url,
                repo_dir=str(repo_dir),
                error=str(exc),
            )
        finally:
            if not self.keep_clone and repo_dir.exists():
                shutil.rmtree(repo_dir, ignore_errors=True)

    # ── internals ─────────────────────────────────────────────────────────────

    def _check_dependencies(self):
        missing = [t for t in ("git", "trivy") if not shutil.which(t)]
        if missing:
            raise RuntimeError(
                f"Missing required tools: {missing}. "
                "Install trivy: https://github.com/aquasecurity/trivy#installation"
            )

    def _clone(self, url: str, dest: Path):
        dest.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", *GIT_CLONE_FLAGS, url, str(dest)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr[:400]}")

    def _run_trivy(self, repo_dir: Path) -> dict:
        result = subprocess.run(
            [
                "trivy", "fs",
                "--format",   "json",
                "--scanners", "vuln",
                "--quiet",
                str(repo_dir),
            ],
            capture_output=True, text=True,
        )
        # trivy exits 1 when vulnerabilities are found — that is expected
        if result.returncode not in (0, 1):
            raise RuntimeError(f"trivy scan failed (exit {result.returncode}): {result.stderr[:400]}")
        if not result.stdout.strip():
            return {}
        return json.loads(result.stdout)

    def _parse(
        self,
        raw: dict,
        repo_url: str,
        repo_dir: Path,
        min_severity: str,
    ) -> TrivyScanResult:
        threshold    = SEVERITY_RANK.get(min_severity.upper(), 0)
        cves:         list[TrivyCVE] = []
        targets:      list[str]      = []
        pkg_managers: set[str]       = set()

        for result in raw.get("Results", []):
            target = result.get("Target", "")
            targets.append(target)
            pkg_managers.add(result.get("Type", "unknown"))

            for v in result.get("Vulnerabilities") or []:
                sev = (v.get("Severity") or "UNKNOWN").upper()
                if SEVERITY_RANK.get(sev, 0) < threshold:
                    continue

                score, av, ac, pr = _parse_cvss(v)
                cves.append(TrivyCVE(
                    cve_id             = v.get("VulnerabilityID", ""),
                    pkg_name           = v.get("PkgName", ""),
                    installed_version  = v.get("InstalledVersion", ""),
                    fixed_version      = v.get("FixedVersion", ""),
                    severity           = sev,
                    cvss_score         = score,
                    attack_vector      = av,
                    attack_complexity  = ac,
                    privileges_required= pr,
                    description        = (v.get("Description") or "")[:350],
                    target_file        = target,
                    references         = (v.get("References") or [])[:4],
                ))

        # deduplicate by CVE ID (keep highest-scored duplicate)
        seen: dict[str, TrivyCVE] = {}
        for c in cves:
            if c.cve_id not in seen or c.cvss_score > seen[c.cve_id].cvss_score:
                seen[c.cve_id] = c

        return TrivyScanResult(
            repo_url     = repo_url,
            repo_dir     = str(repo_dir),
            cves         = list(seen.values()),
            targets      = targets,
            pkg_managers = sorted(pkg_managers),
        )


# ── CVSS parsing helpers ──────────────────────────────────────────────────────

def _parse_cvss(vuln: dict) -> tuple[float, str, str, str]:
    """Return (score, attack_vector, attack_complexity, privileges_required)."""
    cvss_block = vuln.get("CVSS") or {}
    for source in ("nvd", "redhat", "ghsa", "bitnami"):
        blk = cvss_block.get(source, {})
        score = blk.get("V3Score") or blk.get("V2Score")
        vec   = blk.get("V3Vector") or blk.get("V2Vector") or ""
        if score is not None:
            return float(score), *_parse_vector(vec)
    return 5.0, "UNKNOWN", "LOW", "NONE"


def _parse_vector(vec: str) -> tuple[str, str, str]:
    """Extract AV, AC, PR from CVSS vector string."""
    AV_MAP = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
    AC_MAP = {"L": "LOW", "H": "HIGH"}
    PR_MAP = {"N": "NONE", "L": "LOW", "H": "HIGH"}
    av, ac, pr = "UNKNOWN", "LOW", "NONE"
    for part in vec.split("/"):
        if part.startswith("AV:"):
            av = AV_MAP.get(part[3:], "UNKNOWN")
        elif part.startswith("AC:"):
            ac = AC_MAP.get(part[3:], "LOW")
        elif part.startswith("PR:"):
            pr = PR_MAP.get(part[3:], "NONE")
    return av, ac, pr


# ── Serialisation ─────────────────────────────────────────────────────────────

def scan_result_to_dict(r: TrivyScanResult) -> dict:
    """Convert TrivyScanResult to a JSON-serialisable dict for MCP."""
    return {
        "repo_url":     r.repo_url,
        "repo_dir":     r.repo_dir,
        "error":        r.error,
        "cve_count":    len(r.cves),
        "critical":     len(r.critical_cves),
        "high":         len(r.high_cves),
        "network_exploitable": len(r.network_exploitable),
        "pkg_managers": r.pkg_managers,
        "top_cves": [
            {
                "cve_id":             c.cve_id,
                "pkg_name":           c.pkg_name,
                "installed_version":  c.installed_version,
                "fixed_version":      c.fixed_version,
                "severity":           c.severity,
                "cvss_score":         c.cvss_score,
                "attack_vector":      c.attack_vector,
                "attack_complexity":  c.attack_complexity,
                "privileges_required":c.privileges_required,
                "description":        c.description,
                "target_file":        c.target_file,
                "success_rate":       c.normalised_success_rate,
                "exploit_cost":       c.exploit_cost,
                "references":         c.references,
            }
            for c in r.top_by_cvss(20)
        ],
    }


# ── Utilities ─────────────────────────────────────────────────────────────────

def _repo_dirname(url: str) -> str:
    name = url.rstrip("/").split("/")[-1]
    return name[:-4] if name.endswith(".git") else (name or "repo")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scan a git repo with Trivy")
    parser.add_argument("--repo",     required=True, help="Git repo URL")
    parser.add_argument("--out",      default="",    help="Save JSON to file (default: stdout)")
    parser.add_argument("--severity", default=DEFAULT_MIN_SEVERITY,
                        help="Minimum severity (default: MEDIUM)")
    parser.add_argument("--keep",     action="store_true", help="Keep cloned repo")
    args = parser.parse_args()

    scanner = TrivyScanner(keep_clone=args.keep)
    result  = scanner.scan(args.repo, min_severity=args.severity)
    data    = scan_result_to_dict(result)

    if args.out:
        Path(args.out).write_text(json.dumps(data, indent=2))
        print(f"Saved to {args.out}")
    else:
        print(json.dumps(data, indent=2))
