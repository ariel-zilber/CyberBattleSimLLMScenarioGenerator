"""Re-export shim: allows 'from quality_evaluator import ScenarioQualityEvaluator'
when pipeline/ is on sys.path (as run.py arranges via sys.path.insert)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "phase2"))
from _04_quality_evaluator import ScenarioQualityEvaluator  # noqa: F401
from _04_quality_evaluator import *  # noqa: F401, F403
