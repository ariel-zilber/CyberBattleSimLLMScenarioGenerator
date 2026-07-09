# components/precondition_utils.py
"""Shared helper for turning a template's match_properties into a real
runtime Precondition, instead of every generated VulnerabilityInfo defaulting
to Precondition("true") (CyberBattleSim's own default when none is passed).

CyberBattleSim's actions.py:_check_prerequisites evaluates
`vulnerability.precondition.expression` against the target node's current
properties before allowing an exploit to succeed — this is the real runtime
gate, separate from the generator's placement-time property matching.
"""
from typing import Iterable, Optional

from cyberbattle.simulation.vulenrabilites import Precondition


def precondition_from_properties(
    any_of: Optional[Iterable[str]] = None,
    all_of: Optional[Iterable[str]] = None,
) -> Precondition:
    """Build a Precondition gating an exploit on node properties.

    `any_of` uses OR semantics (any one suffices) to match the placement-time
    check already used everywhere in this codebase
    (`any(p in node_properties for p in match_properties)`), so this cannot
    make anything that's solvable today become unsolvable — it only replaces
    the always-true default with a real, inspectable gate. `all_of` uses AND
    semantics for callers that separately track a strict "must have all of
    these" requirement (e.g. `properties_all` match rules).

    Falls back to Precondition("true") when neither is given.
    """
    clauses = []
    any_props = [p for p in (any_of or []) if p]
    if any_props:
        clauses.append("|".join(any_props) if len(any_props) == 1 else f"({'|'.join(any_props)})")
    all_props = [p for p in (all_of or []) if p]
    if all_props:
        clauses.append("&".join(all_props) if len(all_props) == 1 else f"({'&'.join(all_props)})")

    if not clauses:
        return Precondition("true")
    return Precondition("&".join(clauses))
