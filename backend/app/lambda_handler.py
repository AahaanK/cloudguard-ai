"""
CloudGuardAI - AWS Lambda Asynchronous Analysis Worker
Handles event-driven and direct asynchronous risk analysis jobs.
Features:
  - S3 Event Trigger support (s3:ObjectCreated:* on uploads/ prefix)
  - Direct JSON invocation support ({ analysis_id, file_key, bucket })
  - Recursive trigger prevention (strictly rejects/ignores reports/ prefix)
  - Idempotency & state machine updates (PENDING -> PROCESSING -> COMPLETED/FAILED)
  - Structured CloudWatch JSON logging
  - Reuses core IaC parser, 7-dimension rules engine, and persistence layer
"""

import json
import time
import logging
from typing import Dict, Any, Optional

from .storage.manager import storage_manager
from .engine.parser import IaCParser
from .engine.rules import RuleEvaluator
from .engine.scorer import RiskScorer
from .db.repository import repository
from .db.models import ScanJob

logger = logging.getLogger("cloudguard.lambda")
logger.setLevel(logging.INFO)

def log_event(level: str, message: str, **kwargs):
    """Emits structured JSON logs to CloudWatch."""
    payload = {
        "timestamp": time.time(),
        "service": "cloudguard-worker",
        "level": level,
        "message": message,
        **kwargs
    }
    print(json.dumps(payload))

def process_analysis_job(file_key: str, analysis_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Core idempotent analysis routine reused across AWS Lambda and local async workers.
    """
    start_time = time.time()
    clean_key = file_key.replace("\\", "/").lstrip("/")

    # 1. Recursive Trigger Prevention
    if clean_key.startswith("reports/"):
        log_event("WARNING", "Recursive trigger blocked. Output prefix ignored.", file_key=clean_key)
        return {
            "status": "SKIPPED",
            "message": "Recursive trigger blocked: Output reports prefix ignored."
        }

    parts = clean_key.split("/")
    if len(parts) >= 3 and parts[0] == "uploads":
        analysis_id = analysis_id or parts[1]
        filename = parts[2]
    else:
        analysis_id = analysis_id or f"scan_{int(time.time())}"
        filename = clean_key.split("/")[-1]

    log_event("INFO", "Starting asynchronous analysis", analysis_id=analysis_id, file_key=clean_key)

    # 2. Idempotency Check
    existing = repository.get_scan(analysis_id)
    if existing and existing.status == "COMPLETED":
        log_event("INFO", "Job already completed (idempotent return)", analysis_id=analysis_id)
        return {
            "status": "ALREADY_COMPLETED",
            "analysis_id": analysis_id,
            "overall_risk_score": existing.overall_risk_score,
            "findings_count": existing.total_findings
        }

    # Mark as PROCESSING
    initial_job = ScanJob(
        scan_id=analysis_id,
        scan_type="IAC_STATIC",
        target_name=filename,
        status="PROCESSING",
        file_key=clean_key,
        storage_backend="s3" if storage_manager.prefer_s3 else "local"
    )
    repository.save_scan(initial_job)

    try:
        # 3. Retrieve verified content from storage layer
        content, _ = storage_manager.retrieve_file(clean_key)

        # 4. Parse Normalized Resources
        resources, unsupported = IaCParser.parse(content, filename)

        # 5. Evaluate 7-Dimension Rules & Build Inspection Telemetry
        findings, discovered_resources, discovery_summary = RuleEvaluator.evaluate_blueprint(
            resources=resources,
            scan_id=analysis_id,
            unsupported=unsupported,
            filename=filename,
            file_size=len(content)
        )

        # 6. Compute Scores
        score, grade, dim_scores, counts = RiskScorer.calculate_score(findings)

        # 7. Persist COMPLETED ScanJob
        duration_ms = round((time.time() - start_time) * 1000, 2)
        completed_job = ScanJob(
            scan_id=analysis_id,
            scan_type="IAC_STATIC",
            target_name=filename,
            status="COMPLETED",
            overall_risk_score=score,
            risk_grade=grade,
            total_findings=counts["total"],
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            dimension_scores=dim_scores,
            unsupported_constructs=unsupported,
            discovered_resources=discovered_resources,
            discovery_summary=discovery_summary,
            file_key=clean_key,
            storage_backend="s3" if storage_manager.prefer_s3 else "local",
            findings=findings
        )
        repository.save_scan(completed_job)

        log_event(
            "INFO", "Analysis completed successfully",
            analysis_id=analysis_id,
            risk_score=score,
            findings_count=counts["total"],
            critical_count=counts["critical"],
            duration_ms=duration_ms
        )

        return {
            "status": "SUCCESS",
            "analysis_id": analysis_id,
            "overall_risk_score": score,
            "risk_grade": grade,
            "findings_count": counts["total"],
            "duration_ms": duration_ms
        }

    except Exception as e:
        log_event("ERROR", "Analysis failed", analysis_id=analysis_id, error=str(e))
        failed_job = ScanJob(
            scan_id=analysis_id,
            scan_type="IAC_STATIC",
            target_name=filename,
            status="FAILED",
            file_key=clean_key,
            error_message=str(e)
        )
        repository.save_scan(failed_job)
        return {
            "status": "FAILED",
            "analysis_id": analysis_id,
            "error": str(e)
        }

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Standard AWS Lambda entry point.
    Dispatches S3 Event Notifications or direct JSON invocations.
    """
    log_event("INFO", "Lambda execution invoked", event_keys=list(event.keys()) if isinstance(event, dict) else [])

    # Case A: S3 Event Trigger (s3:ObjectCreated:*)
    if "Records" in event and isinstance(event["Records"], list):
        results = []
        for record in event["Records"]:
            s3_data = record.get("s3", {})
            object_key = s3_data.get("object", {}).get("key")
            if object_key:
                res = process_analysis_job(file_key=object_key)
                results.append(res)
        return {
            "statusCode": 200,
            "body": json.dumps({"mode": "S3_EVENT", "results": results})
        }

    # Case B: Direct JSON Invocation Payload
    file_key = event.get("file_key")
    analysis_id = event.get("analysis_id")
    if file_key:
        res = process_analysis_job(file_key=file_key, analysis_id=analysis_id)
        return {
            "statusCode": 200 if res["status"] != "FAILED" else 500,
            "body": json.dumps(res)
        }

    return {
        "statusCode": 400,
        "body": json.dumps({"error": "Invalid event payload. Must contain 'Records' (S3 Event) or 'file_key'."})
    }
