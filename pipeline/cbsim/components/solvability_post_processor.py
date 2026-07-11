"""
Backward-compatible re-export shim.

The actual implementation moved to
pipeline/cbsim/components/solvability/post_processor/ (split into small,
single-concern submodules to reduce file size and eliminate the duplicate
logic that used to drift out of sync with SolvabilityConstraintProcessor).

Existing imports of `pipeline.cbsim.components.solvability_post_processor`
keep working unchanged.
"""

from pipeline.cbsim.components.solvability.post_processor.core import (
    SolvabilityPostProcessor,
    _collect_planned_vuln_names,
)

__all__ = ["SolvabilityPostProcessor", "_collect_planned_vuln_names"]
