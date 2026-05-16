"""
pipeline/constants.py
=====================
Single source of truth for all pipeline thresholds and defaults.
Import from here instead of using inline literals.
"""

# ── Actor-critic loop ─────────────────────────────────────────────────────────

MAX_BFS_ROUNDS: int = 2
# Maximum number of Phase 2 BFS-eval → LLM-repair iterations per config.
# Raising this improves output quality but multiplies wall-clock time linearly.

MAX_REPAIR_ATTEMPTS: int = 2
# Maximum LLM repair attempts inside a single _05_apply_critic_fixes.py call.
# Each attempt sends one API request and validates the returned YAML.

TARGET_SCORE: float = 8.0
# Default LLM quality score threshold (out of 10) for the actor-critic loop to
# declare success. Can be overridden via --target-score CLI flag.

# ── Solve-rate thresholds ─────────────────────────────────────────────────────

MIN_SOLVE_RATE: float = 0.50
# Minimum fraction of generated scenarios that must be BFS-solvable for a
# config to be accepted. Below this, the actor-critic loop triggers repair.

SOLVE_RATE_DESIGN_THRESHOLD: float = 0.40
# Dividing line between "broken YAML design" and "bad random seeds."
#   solve_rate <  0.40 → YAML has a structural reachability gap → invoke LLM repair
#   solve_rate >= 0.40 → design is sound but some seeds failed → replace scenarios
# Empirically derived from observing the bimodal distribution of failure modes.

# ── Scenario replacement ──────────────────────────────────────────────────────

REPLACEMENT_MAX_ATTEMPTS: int = 3
# Maximum seed-replacement iterations before giving up on unsolved scenarios.
# Each iteration deletes unsolved scenario dirs and regenerates with new seeds.

# ── BFS evaluation (values passed to 02_test_env_integration.py) ──────────────

BFS_MAX_STEPS: int = 5000
# Maximum CBS environment steps per BFS episode. Larger values allow BFS to
# solve harder configs but slow down evaluation proportionally.

BFS_NUM_AGENTS: int = 3
# Number of cooperative BFS agents run in parallel per scenario. Higher counts
# improve coverage of branchy topologies at the cost of memory.

BFS_EPISODES: int = 3
# Number of independent BFS episodes per scenario. Averaging across episodes
# smooths out stochastic SR variance in success_rate values.

BFS_MAX_CREDS_PER_ACTION: int = 5000
# CBS environment cap on credentials discoverable per action step.
# Set high to avoid artificially constraining credential-heavy scenarios.

# ── Graph quality thresholds ──────────────────────────────────────────────────

MIN_DIAMETER_TARGET: int = 3
# Attack-path diameter below which a scenario is considered "too easy."
# Triggers the domain-fragmentation fix in the Actor repair prompt.

FLAT_TOPOLOGY_DIAMETER: int = 2
# Diameter at or below which the Actor prompt switches to MANDATORY structural
# fixes (add domains, add IDC) rather than optional SR adjustments.

MAX_DENSITY_TARGET: float = 0.40
# Graph density above which the scenario is over-connected; forces the Actor to
# remove direct shortcuts between non-adjacent tiers.

SOLVABILITY_PROB_RANGE: tuple[float, float] = (0.40, 0.55)
# Recommended probability range for solvability_vulnerabilities entries when
# the Actor is instructed to reduce density via probability reduction.

# ── Agent-category allowlist (used by 02_config_checker.py) ──────────────────

AGENT_CATEGORY_ALLOWLIST: dict[str, list[str]] = {
    "S_Network":  ["remote_access", "credential_leak"],
    "S_Linux":    ["remote_access", "credential_leak"],
    "S_Windows":  ["remote_access"],
    "S_Identity": ["remote_access", "goal_access"],
    "S_Lateral":  ["lateral_movement", "credential_leak"],
    "Meta":       ["remote_access", "credential_leak", "lateral_movement",
                   "discovery", "goal_access"],
}
# Maps metadata.agent values to the solvability categories that config is
# allowed to contain. Any entry outside the allowlist is a validation error.
# Enforces the S_Identity / S_Lateral technique partition (Decision D-A5).

# ── Solvability constraints defaults ───────────────────────────────────────────

DEFAULT_MIN_CREDENTIAL_LEAKING_NODES_RATIO: float = 0.5
# Default minimum ratio of nodes that must leak credentials for lateral movement.

DEFAULT_MAX_CREDENTIAL_LEAKING_NODES_MULTIPLIER: float = 1.5
# Default multiplier for the maximum credential leaking nodes ratio based on the minimum.

DEFAULT_CREDENTIAL_REUSE_PROBABILITY: float = 0.8
# Default probability that a credential is reused across groups in credential flows.

DEFAULT_MIN_REMOTE_VULNERABILITIES: int = 1
# Default minimum number of remote vulnerabilities required at entry points.

DEFAULT_MIN_CREDENTIAL_LEAKING_VULNERABILITIES: int = 1
# Default minimum number of credential leaking vulnerabilities required at entry points.

# ── Technique Cost Normalization (Q10) ───────────────────────────────────────

ENABLE_TECHNIQUE_COST_SCALING: bool = True
# If True, AD techniques (non-CVE exploits) are assigned a higher cost to
# prevent agent spamming and reflect protocol-level complexity.

DEFAULT_TECHNIQUE_COST: float = 2.0
# The cost assigned to AD techniques when scaling is enabled.

DEFAULT_CVE_COST: float = 1.0
# The standard cost assigned to CVE-backed exploits.

# ── Credential & Vulnerability Defaults ──────────────────────────────────────

DEFAULT_CREDENTIAL_PROBABILITY: float = 0.5
# Default probability for credential selection in banks (replaces legacy 0.7).

VULN_COST_TIER_LOW: float = 3.0
VULN_COST_TIER_MEDIUM: float = 7.0
VULN_COST_TIER_HIGH: float = 10.0
# Hardcoded cost boundaries used by VulnerabilityLibraryManager.

# ── Evaluator Thresholds & Retries ───────────────────────────────────────────

MAX_BFS_RETRIES: int = 8
# Max retries for agent actions during runtime evaluation.

STEALTH_DETECTION_THRESHOLD: float = 10.0
# Global threshold for stealth detection metrics.

RATING_EXTREME: float = 8.0
RATING_HARD: float = 6.0
RATING_MODERATE: float = 4.0
RATING_EASY: float = 2.0
# Difficulty rating thresholds used by the test environment integrator.
