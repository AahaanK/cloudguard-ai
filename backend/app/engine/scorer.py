"""
CloudGuardAI - Risk Scoring & Multi-Dimensional Aggregator
Calculates deterministic risk scores (0-100), risk letter grades (A-F),
and sub-scores for each of the 7 Well-Architected dimensions with confidence weighting,
deduplication, critical floor protection, and transparent mathematical explanation.
"""

from typing import List, Dict, Any, Tuple, Optional
from ..db.models import Finding

DIMENSIONS = ["SECURITY", "IAM", "NETWORK", "CONFIGURATION", "RELIABILITY", "PERFORMANCE", "COST"]

SEVERITY_WEIGHTS = {
    "CRITICAL": 25.0,
    "HIGH": 15.0,
    "MEDIUM": 8.0,
    "LOW": 3.0
}

STATUS_MULTIPLIERS = {
    "CONFIRMED": 1.0,
    "POTENTIAL": 0.65,
    "REQUIRES_VERIFICATION": 0.35
}

class RiskScorer:

    @staticmethod
    def calculate_score(findings: List[Finding]) -> Tuple[float, str, Dict[str, float], Dict[str, int]]:
        """
        Backwards-compatible calculation interface returning:
        (overall_score, grade, dimension_scores, counts)
        """
        score, grade, dim_scores, counts, _ = RiskScorer.calculate_score_detailed(findings)
        return score, grade, dim_scores, counts

    @staticmethod
    def calculate_score_detailed(
        findings: List[Finding],
        check_stats: Optional[Dict[str, Any]] = None
    ) -> Tuple[float, str, Dict[str, float], Dict[str, int], Dict[str, Any]]:
        """
        Comprehensive calculation factoring in:
        1. Exact severity base weights (CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3).
        2. Status weighting (CONFIRMED=1.0, POTENTIAL=0.65, REQUIRES_VERIFICATION=0.35).
        3. Deduplication across resource_id + rule_id.
        4. Critical floor protection (CONFIRMED critical ensures minimum 70.0 / Grade D or F).
        5. Zero-risk baseline for clean architecture (0.0 / Grade A).
        """
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0,
            "confirmed": 0,
            "potential": 0,
            "requires_verification": 0
        }
        dim_raw: Dict[str, float] = {d: 0.0 for d in DIMENSIONS}

        # Deduplicate findings on the same resource and same rule_id
        seen_keys = set()
        deduped_findings: List[Finding] = []
        dedup_count = 0

        for f in findings:
            attr = ""
            if isinstance(f.evidence, dict):
                attr = f.evidence.get("attribute", "")
            dedup_key = f"{f.resource_id}::{f.rule_id}::{attr}"
            if dedup_key in seen_keys:
                dedup_count += 1
                continue
            seen_keys.add(dedup_key)
            deduped_findings.append(f)

        counts["total"] = len(deduped_findings)

        has_confirmed_critical = False
        raw_weighted_points = 0.0

        for f in deduped_findings:
            sev = (f.severity or "LOW").upper()
            dim = (f.dimension or "CONFIGURATION").upper()
            status = (getattr(f, "finding_status", None) or "CONFIRMED").upper()
            if status not in STATUS_MULTIPLIERS:
                status = "CONFIRMED"

            if sev == "CRITICAL":
                counts["critical"] += 1
                if status == "CONFIRMED":
                    has_confirmed_critical = True
            elif sev == "HIGH":
                counts["high"] += 1
            elif sev == "MEDIUM":
                counts["medium"] += 1
            elif sev == "LOW":
                counts["low"] += 1

            if status == "CONFIRMED":
                counts["confirmed"] += 1
            elif status == "POTENTIAL":
                counts["potential"] += 1
            elif status == "REQUIRES_VERIFICATION":
                counts["requires_verification"] += 1

            base_weight = SEVERITY_WEIGHTS.get(sev, 3.0)
            status_multiplier = STATUS_MULTIPLIERS.get(status, 1.0)
            weighted_points = base_weight * status_multiplier
            raw_weighted_points += weighted_points

            if dim in dim_raw:
                dim_raw[dim] += weighted_points

        # Calculate final overall score (0.0 to 100.0)
        if counts["total"] == 0:
            overall_score = 0.0
            grade = "A"
            critical_override_applied = False
        else:
            overall_score = min(100.0, round(raw_weighted_points, 1))

            # Critical override: if confirmed critical vulnerability exists, risk score cannot be below 70.0
            critical_override_applied = False
            if has_confirmed_critical and overall_score < 70.0:
                overall_score = 70.0
                critical_override_applied = True

            # Risk Grade (A = 0-20, B = 21-40, C = 41-60, D = 61-80, F = 81-100)
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

        dimension_scores = {d.lower(): min(100.0, round(dim_raw[d], 1)) for d in DIMENSIONS}

        score_explanation = {
            "formula": "Sum of (Severity Weight x Finding Status Multiplier) with Deduplication & Critical Floor Protection",
            "severity_weights": SEVERITY_WEIGHTS,
            "status_multipliers": STATUS_MULTIPLIERS,
            "raw_weighted_points": round(raw_weighted_points, 1),
            "final_score": overall_score,
            "risk_grade": grade,
            "has_confirmed_critical": has_confirmed_critical,
            "critical_override_applied": critical_override_applied,
            "deduplicated_findings_count": dedup_count,
            "status_breakdown": {
                "CONFIRMED": counts["confirmed"],
                "POTENTIAL": counts["potential"],
                "REQUIRES_VERIFICATION": counts["requires_verification"]
            },
            "severity_breakdown": {
                "CRITICAL": counts["critical"],
                "HIGH": counts["high"],
                "MEDIUM": counts["medium"],
                "LOW": counts["low"]
            },
            "check_statistics": check_stats or {}
        }

        return overall_score, grade, dimension_scores, counts, score_explanation
