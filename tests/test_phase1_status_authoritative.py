"""Regression test: Phase 1's human-readable status must never contradict the
machine-readable validation verdict.

Bug: pipeline/phase1/pipeline.py's step_check_config() correctly writes
{"valid": false} to 03_validation.json whenever the static config checker
finds real errors (config_checker.py exits non-zero). But step_report()'s
status label was computed purely from the dynamic BFS solve rate, never
consulting check_data["valid"] -- so a config with real static errors could
still produce a report reading "SUCCESS" or "PARTIAL", and main() printed an
unconditional green "Pipeline complete" regardless. The text report and the
JSON verdict could disagree about whether the run actually passed.

Run:
    pytest tests/test_phase1_status_authoritative.py -x -q
"""
import tempfile
from pathlib import Path

import pytest

from pipeline.phase1.pipeline import step_report


def _report_status(tmp_path, check_data, eval_data=None):
    out_dir = Path(tmp_path)
    status = step_report(
        out_dir=out_dir,
        domain="test_domain",
        eval_data=eval_data,
        check_data=check_data,
        train_count=5,
        test_count=2,
        fetch_ok=True,
        vulns_added=0,
        start_ts=0.0,
    )
    report_text = (out_dir / "reports" / "phase1_summary.txt").read_text()
    return status, report_text


def test_static_errors_force_failed_status_regardless_of_solve_rate(tmp_path):
    """A config with real static validation errors must report FAILED, even
    if the dynamic evaluator somehow reports a perfect solve rate -- static
    correctness is a prerequisite the dynamic result cannot override."""
    check_data = {"valid": False, "errors": ["some static error"], "warnings": []}
    eval_data = {"aggregate": {"solve_rate": 1.0}}  # perfect solve rate

    status, report_text = _report_status(tmp_path, check_data, eval_data)

    assert status == "FAILED", (
        f"expected FAILED when check_data['valid'] is False, got {status!r} -- "
        f"the report ignored the static validation verdict"
    )
    assert "FAILED" in report_text
    assert "Config Valid : False" in report_text


def test_valid_config_with_good_solve_rate_reports_success(tmp_path):
    check_data = {"valid": True, "errors": [], "warnings": []}
    eval_data = {"aggregate": {"solve_rate": 0.9}}

    status, report_text = _report_status(tmp_path, check_data, eval_data)

    assert status == "SUCCESS"
    assert "Config Valid : True" in report_text


def test_valid_config_with_low_solve_rate_reports_partial_not_failed(tmp_path):
    """A low solve rate is a quality problem, not an invalidity problem --
    it must stay PARTIAL, not be conflated with a real static FAILED."""
    check_data = {"valid": True, "errors": [], "warnings": []}
    eval_data = {"aggregate": {"solve_rate": 0.1}}

    status, _ = _report_status(tmp_path, check_data, eval_data)

    assert status == "PARTIAL"


def test_no_eval_data_and_valid_config_reports_partial(tmp_path):
    check_data = {"valid": True, "errors": [], "warnings": []}
    status, _ = _report_status(tmp_path, check_data, eval_data=None)
    assert status == "PARTIAL"
