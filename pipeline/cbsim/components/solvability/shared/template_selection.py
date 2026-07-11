"""
YAML vulnerability-template selection, shared by SolvabilityPostProcessor
and SolvabilityConstraintProcessor. Plain functions — no class/self state.

get_cred_leak_template/get_discovery_template are intentionally still
blind-index-[0] here, matching current main behavior exactly. Property-aware
selection is a deliberate follow-up change (see task tracker), not part of
this refactor.
"""

from typing import Dict, List, Optional


def pick_remote_template(templates: List[Dict], node_properties: set) -> Optional[Dict]:
    fallback = None
    for tmpl in templates:
        match_props = tmpl.get('match_properties', [])
        if not match_props:
            fallback = tmpl
            continue
        if any(p in node_properties for p in match_props):
            return tmpl
    return fallback


def pick_goal_template(templates: List[Dict], node_properties: set, category) -> Optional[Dict]:
    """Return the best-matching goal template for the given category.

    category=None means "accept any category" (used as a cross-category fallback).
    """
    fallback = None
    for tmpl in templates:
        tmpl_category = tmpl.get('goal_category', '')
        if category is not None and tmpl_category and tmpl_category != category:
            continue

        match_props = tmpl.get('match_properties', [])
        if not match_props:
            fallback = tmpl
            continue
        if any(p in node_properties for p in match_props):
            return tmpl
    return fallback


def get_cred_leak_template(templates: List[Dict]) -> Optional[Dict]:
    return templates[0] if templates else None


def get_discovery_template(templates: List[Dict]) -> Optional[Dict]:
    return templates[0] if templates else None
