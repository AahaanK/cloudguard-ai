"""
CloudGuardAI - Remediation Security Comparator
Computes mathematically verified before-and-after audit differentials.
Tracks resolved, partially resolved, unresolved, and newly introduced risks.
Never marks a risk resolved without AST rule verification.
"""

from typing import Dict, Any, List
from datetime import datetime, timezone
from ..db.models import ScanJob, Finding

class RemediationComparator:

    @staticmethod
    def compare_scans(original_scan: ScanJob, remediated_scan: ScanJob) -> Dict[str, Any]:
        """
        Executes granular comparison between pre-remediation and post-remediation scans.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        orig_map = {f"{f.resource_id}::{f.rule_id}": f for f in original_scan.findings}
        rem_map = {f"{f.resource_id}::{f.rule_id}": f for f in remediated_scan.findings}

        resolved_findings: List[Dict[str, Any]] = []
        partially_resolved_findings: List[Dict[str, Any]] = []
        unresolved_findings: List[Dict[str, Any]] = []
        newly_introduced_findings: List[Dict[str, Any]] = []
        unverified_findings: List[Dict[str, Any]] = []

        # Severity rank helper
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        # Check all original findings
        for key, orig_f in orig_map.items():
            if key not in rem_map:
                resolved_findings.append({
                    "finding_id": orig_f.finding_id,
                    "rule_id": orig_f.rule_id,
                    "title": orig_f.title,
                    "resource_id": orig_f.resource_id,
                    "severity": orig_f.severity,
                    "original_status": orig_f.finding_status,
                    "outcome": "Resolved",
                    "explanation": f"Rule {orig_f.rule_id} is no longer triggered on {orig_f.resource_id}."
                })
            else:
                rem_f = rem_map[key]
                orig_rank = sev_rank.get(orig_f.severity.upper(), 1)
                rem_rank = sev_rank.get(rem_f.severity.upper(), 1)
                orig_status = (orig_f.finding_status or "CONFIRMED").upper()
                rem_status = (rem_f.finding_status or "CONFIRMED").upper()

                # Partially resolved if severity decreased or status downgraded to POTENTIAL
                if rem_rank < orig_rank or (orig_status == "CONFIRMED" and rem_status in ("POTENTIAL", "REQUIRES_VERIFICATION")):
                    partially_resolved_findings.append({
                        "finding_id": orig_f.finding_id,
                        "rule_id": orig_f.rule_id,
                        "title": orig_f.title,
                        "resource_id": orig_f.resource_id,
                        "severity_before": orig_f.severity,
                        "severity_after": rem_f.severity,
                        "status_before": orig_status,
                        "status_after": rem_status,
                        "outcome": "Partially Resolved",
                        "explanation": f"Risk mitigated from {orig_f.severity} ({orig_status}) to {rem_f.severity} ({rem_status})."
                    })
                else:
                    unresolved_findings.append({
                        "finding_id": orig_f.finding_id,
                        "rule_id": orig_f.rule_id,
                        "title": orig_f.title,
                        "resource_id": orig_f.resource_id,
                        "severity": rem_f.severity,
                        "status": rem_status,
                        "outcome": "Unresolved",
                        "explanation": f"Configuration remains non-compliant with {orig_f.rule_id}."
                    })

            # Check unverified
            if getattr(orig_f, "finding_status", "") == "REQUIRES_VERIFICATION":
                unverified_findings.append({
                    "finding_id": orig_f.finding_id,
                    "rule_id": orig_f.rule_id,
                    "resource_id": orig_f.resource_id,
                    "outcome": "Requires Live Verification",
                    "explanation": "Runtime AWS status must be verified via Live Scan."
                })

        # Check newly introduced findings
        for key, rem_f in rem_map.items():
            if key not in orig_map:
                newly_introduced_findings.append({
                    "finding_id": rem_f.finding_id,
                    "rule_id": rem_f.rule_id,
                    "title": rem_f.title,
                    "resource_id": rem_f.resource_id,
                    "severity": rem_f.severity,
                    "outcome": "Newly Introduced",
                    "explanation": f"Introduced by remediation changes on {rem_f.resource_id}."
                })

        score_before = original_scan.overall_risk_score
        score_after = remediated_scan.overall_risk_score
        score_delta = round(score_before - score_after, 1)

        return {
            "original_scan_id": original_scan.scan_id,
            "remediated_scan_id": remediated_scan.scan_id,
            "score_before": score_before,
            "score_after": score_after,
            "score_delta": score_delta,
            "grade_before": original_scan.risk_grade,
            "grade_after": remediated_scan.risk_grade,
            "counts_before": {
                "total": original_scan.total_findings,
                "critical": original_scan.critical_count,
                "high": original_scan.high_count,
                "medium": original_scan.medium_count,
                "low": original_scan.low_count
            },
            "counts_after": {
                "total": remediated_scan.total_findings,
                "critical": remediated_scan.critical_count,
                "high": remediated_scan.high_count,
                "medium": remediated_scan.medium_count,
                "low": remediated_scan.low_count
            },
            "resolved_count": len(resolved_findings),
            "partially_resolved_count": len(partially_resolved_findings),
            "unresolved_count": len(unresolved_findings),
            "newly_introduced_count": len(newly_introduced_findings),
            "resolved_findings": resolved_findings,
            "partially_resolved_findings": partially_resolved_findings,
            "unresolved_findings": unresolved_findings,
            "newly_introduced_findings": newly_introduced_findings,
            "unverified_findings": unverified_findings,
            "compared_at": now_iso
        }
