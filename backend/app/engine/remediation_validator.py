"""
CloudGuardAI - Pre-Application Remediation Validator
Rigorous dual-stage validator ensuring both syntactic validity and security correctness.
Never claims a fix is safe merely because the code parses; verifies that target vulnerabilities
are eliminated and zero regressions or new attack surfaces are introduced.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from .parser import IaCParser
from .rules import RuleEvaluator
from .scorer import RiskScorer
from ..db.models import Finding

class RemediationValidator:

    @staticmethod
    def validate_remediation(
        candidate_blueprint: str,
        filename: str,
        target_finding: Finding,
        original_findings: List[Finding]
    ) -> Dict[str, Any]:
        """
        Executes comprehensive dual-phase validation:
          Phase 1: Syntactic AST verification and reference integrity.
          Phase 2: Security rule re-evaluation and regression detection.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        validation_errors: List[str] = []
        warnings: List[str] = []
        candidate_bytes = candidate_blueprint.encode("utf-8")

        # -------------------------------------------------------------
        # PHASE 1: Syntactic AST Parsing & Structural Integrity
        # -------------------------------------------------------------
        try:
            resources, unsupported = IaCParser.parse(candidate_bytes, filename)
        except Exception as e:
            return {
                "syntactic_validity": False,
                "security_correctness": False,
                "target_finding_resolved": False,
                "new_findings_introduced": [],
                "remaining_findings_count": len(original_findings),
                "candidate_risk_score": 100.0,
                "candidate_risk_grade": "F",
                "validation_errors": [f"Syntactic parsing failure: {str(e)}"],
                "warnings": [],
                "validated_at": now_iso
            }

        malformed = [u for u in unsupported if "MALFORMED" in str(u.get("type", ""))]
        if malformed:
            for m in malformed:
                validation_errors.append(f"Syntax error: {m.get('message')}")
            return {
                "syntactic_validity": False,
                "security_correctness": False,
                "target_finding_resolved": False,
                "new_findings_introduced": [],
                "remaining_findings_count": len(original_findings),
                "candidate_risk_score": 100.0,
                "candidate_risk_grade": "F",
                "validation_errors": validation_errors,
                "warnings": [],
                "validated_at": now_iso
            }

        if not resources:
            validation_errors.append("Candidate blueprint contains no valid resources after applying remediation.")
            return {
                "syntactic_validity": False,
                "security_correctness": False,
                "target_finding_resolved": False,
                "new_findings_introduced": [],
                "remaining_findings_count": len(original_findings),
                "candidate_risk_score": 0.0,
                "candidate_risk_grade": "A",
                "validation_errors": validation_errors,
                "warnings": [],
                "validated_at": now_iso
            }

        # Reference and dependency check
        res_ids = {r.resource_id for r in resources}
        for r in resources:
            for rel in r.relationships:
                # E.g. PublicAccessBlock:aws_s3_bucket.pab
                if ":" in rel:
                    target_ref = rel.split(":", 1)[-1]
                    if target_ref and target_ref not in res_ids and "." in target_ref:
                        warnings.append(f"Referenced companion resource '{target_ref}' declared dynamically.")

        syntactic_validity = True

        # -------------------------------------------------------------
        # PHASE 2: Security Correctness & Regression Detection
        # -------------------------------------------------------------
        new_findings, discovered, summary = RuleEvaluator.evaluate_blueprint(
            resources=resources,
            scan_id="validation_sandbox",
            unsupported=unsupported,
            filename=filename,
            file_size=len(candidate_bytes)
        )

        new_score, new_grade, _, counts, _ = RiskScorer.calculate_score_detailed(
            new_findings, summary.get("check_statistics")
        )

        # Check if the targeted finding was resolved
        target_rule = target_finding.rule_id
        target_res = target_finding.resource_id

        target_still_present = any(
            f.rule_id == target_rule and f.resource_id == target_res
            for f in new_findings
        )
        target_finding_resolved = not target_still_present

        # Detect any regressions or newly introduced findings
        orig_finding_keys = {f"{f.resource_id}::{f.rule_id}" for f in original_findings}
        new_finding_keys = {f"{f.resource_id}::{f.rule_id}" for f in new_findings}

        introduced_keys = list(new_finding_keys - orig_finding_keys)

        if not target_finding_resolved:
            validation_errors.append(
                f"Security Verification Failed: Rule [{target_rule}] was not resolved on {target_res}."
            )

        if introduced_keys:
            validation_errors.append(
                f"Security Regression Detected: Proposed modification introduced {len(introduced_keys)} new issue(s): {', '.join(introduced_keys)}."
            )

        security_correctness = (
            syntactic_validity and
            target_finding_resolved and
            len(introduced_keys) == 0
        )

        return {
            "syntactic_validity": syntactic_validity,
            "security_correctness": security_correctness,
            "target_finding_resolved": target_finding_resolved,
            "new_findings_introduced": introduced_keys,
            "remaining_findings_count": len(new_findings),
            "candidate_risk_score": new_score,
            "candidate_risk_grade": new_grade,
            "validation_errors": validation_errors,
            "warnings": warnings,
            "validated_at": now_iso
        }
