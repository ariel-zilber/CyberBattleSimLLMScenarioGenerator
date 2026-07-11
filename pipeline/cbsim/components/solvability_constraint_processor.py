"""
Backward-compatible re-export shim.

The actual implementation moved to
pipeline/cbsim/components/solvability/constraint_processor/ (split into
small, single-concern submodules to reduce file size and eliminate the
duplicate logic that used to drift out of sync with SolvabilityPostProcessor).

Existing imports of `pipeline.cbsim.components.solvability_constraint_processor`
keep working unchanged.
"""

from pipeline.cbsim.components.solvability.constraint_processor.core import (
    SolvabilityConstraintProcessor,
)

__all__ = ["SolvabilityConstraintProcessor"]
