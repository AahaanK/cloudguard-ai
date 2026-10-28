"""
CloudGuardAI - Risk Scoring & Multi-Dimensional Aggregator
Calculates deterministic risk scores (0-100), risk letter grades (A-F),
and sub-scores for each of the 7 Well-Architected dimensions.
"""

from typing import List, Dict, Any, Tuple
from ..db.models import Finding

DIMENSIONS = ["SECURITY", "IAM", "NETWORK", "CONFIGURATION", "RELIABILITY", "PERFORMANCE", "COST"]

SEVERITY_WEIGHTS = {
    "CRITICAL": 25.0,
    "HIGH": 15.0,
    "MEDIUM": 8.0,
    "LOW": 3.0
}

class RiskScorer:

    @staticmethod
    def calculate_score(findings: List[Finding]) -> Tuple[float, str, Dict[str, float], Dict[str, int]]:
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": len(findings)
        }
        dim_raw: Dict[str, float] = {d: 0.0 for d in DIMENSIONS}

        for f in findings:
            sev = f.severity.upper()
            dim = f.dimension.upper()
            weight = SEVERITY_WEIGHTS.get(sev, 5.0)

            if sev == "CRITICAL":
                counts["critical"] += 1
            elif sev == "HIGH":
                counts["high"] += 1
            elif sev == "MEDIUM":
                counts["medium"] += 1
            elif sev == "LOW":
                counts["low"] += 1

            if dim in dim_raw:
                dim_raw[dim] += weight

        # Total raw score
        total_raw = sum(dim_raw.values())
        # Non-linear normalization curve: 100 * (1 - e^(-raw / 50))
        # Or simple proportional capped score:
        overall_score = min(100.0, round(total_raw, 1))

        # Risk Grade (A = lowest risk / cleanest, F = extreme risk)
        if overall_score <= 20.0:
            grade = "A"
        elif overall_score <= 40.0:
            grade = "B"
        elif overall_score <= 60.0:
            grade = "C"
        elif overall_score <= 80.0:
            grade = "D"
        else:
            grade = "F"

        # Normalize dimension scores to 0-100
        dimension_scores = {d.lower(): min(100.0, round(dim_raw[d], 1)) for d in DIMENSIONS}

        return overall_score, grade, dimension_scores, counts
