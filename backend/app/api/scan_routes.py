"""
CloudGuardAI - Core Risk Analysis & Scanning REST API Endpoints
Connects IaC Parser, 7-Dimension Rule Engine, Live Scanner, Repository, and Async Lambda Worker.
"""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query, Response, BackgroundTasks
import uuid
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from ..storage.manager import storage_manager
from ..engine.parser import IaCParser, NormalizedResource
from ..engine.rules import RuleEvaluator
from ..engine.scorer import RiskScorer
from ..engine.remediation_engine import RemediationEngine
from ..engine.remediation_validator import RemediationValidator
from ..engine.remediation_comparator import RemediationComparator
from ..scanner.live_scanner import live_scanner
from ..reports.exporter import ReportExporter
from ..db.repository import repository
from ..db.models import ScanJob, Finding
from ..lambda_handler import process_analysis_job
from ..ai.bedrock_service import bedrock_service
from ..aws.cloudwatch_logger import cloudwatch_logger

router = APIRouter(prefix="/api/v1/scan", tags=["Risk Analysis & Assessment"])

SAMPLE_TERRAFORM_BLUEPRINT = '''# Safe Enterprise Production Infrastructure Stack
# CloudGuardAI Deterministic Risk Analysis & Posture Assessment Template

resource "aws_vpc" "production_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name        = "production-vpc"
    Environment = "production"
  }
}

resource "aws_subnet" "public_subnet_a" {
  vpc_id            = aws_vpc.production_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Tier = "public"
  }
}

resource "aws_security_group" "web_tier_sg" {
  name        = "production-web-sg"
  description = "Public web ingress and administration security group"
  vpc_id      = aws_vpc.production_vpc.id

  # HTTPS Ingress
  ingress {
    description = "Allow HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Insecure administration port open to 0.0.0.0/0
  ingress {
    description = "SSH Administration Ingress"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_subnet_a.id
  vpc_security_group_ids = [aws_security_group.web_tier_sg.id]
  monitoring             = true
  tags = {
    Name = "prod-app-worker"
  }
}

resource "aws_s3_bucket" "public_customer_media" {
  bucket = "prod-customer-media-public"
  acl    = "public-read"
}

resource "aws_s3_bucket" "audit_vault" {
  bucket = "prod-immutable-audit-records"
  acl    = "private"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_db_instance" "primary_database" {
  identifier          = "production-db-instance"
  allocated_storage   = 50
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = false
  deletion_protection = false
  multi_az            = false
}

resource "aws_iam_role" "application_worker_role" {
  name = "production-app-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}
'''

@router.get("/sample-blueprint")
async def get_sample_blueprint():
    """Provides a safe, multi-tier enterprise Terraform template for 1-click verification."""
    return {
        "success": True,
        "filename": "production_cloud_stack.tf",
        "content": SAMPLE_TERRAFORM_BLUEPRINT,
        "format": "hcl",
        "size_bytes": len(SAMPLE_TERRAFORM_BLUEPRINT.encode("utf-8")),
        "description": "Safe multi-tier AWS blueprint comprising VPC, Subnet, Security Group, EC2, S3, RDS, and IAM."
    }

@router.post("/upload")
async def scan_uploaded_infrastructure(
    file: UploadFile = File(...),
    template_type: str = Form(default="auto")
):
    """
    Synchronous analysis: Ingests blueprint, stores it, parses untrusted content,
    evaluates 7-dimension rules, computes scores, and saves to DB.
    """
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    filename = file.filename or "template.tf"

    try:
        raw_bytes = await file.read()
        if len(raw_bytes) == 0:
            raise ValueError("Uploaded file is empty (0 bytes).")

        # 1. Store in configured storage layer
        store_res = storage_manager.store_file(
            content=raw_bytes,
            filename=filename,
            analysis_id=scan_id,
            is_report=False
        )

        # 2. Retrieve verified content from the storage layer (round-trip integrity)
        stored_content, _ = storage_manager.retrieve_file(store_res["file_key"])

        # 3. Parse Normalized Resources & Detect Unsupported Constructs
        resources, unsupported = IaCParser.parse(stored_content, filename)

        # 4. Evaluate 7-Dimension Rules & Build Inspection Queue Telemetry
        findings, discovered_resources, discovery_summary = RuleEvaluator.evaluate_blueprint(
            resources=resources,
            scan_id=scan_id,
            unsupported=unsupported,
            filename=filename,
            file_size=len(raw_bytes)
        )

        # 5. Compute Scores & Subtotals with Detailed Explanation
        score, grade, dim_scores, counts, score_explanation = RiskScorer.calculate_score_detailed(
            findings, discovery_summary.get("check_statistics")
        )

        # 6. Build and Persist ScanJob
        job = ScanJob(
            scan_id=scan_id,
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
            score_explanation=score_explanation,
            check_statistics=discovery_summary.get("check_statistics", {}),
            compound_risks=discovery_summary.get("compound_risks", []),
            file_key=store_res["file_key"],
            storage_backend=store_res["storage_backend"],
            findings=findings
        )
        saved_job = repository.save_scan(job)

        cloudwatch_logger.log_audit_event(
            event_type="IAC_SCAN_COMPLETED",
            scan_id=scan_id,
            details={
                "target_name": filename,
                "overall_risk_score": score,
                "risk_grade": grade,
                "total_findings": counts["total"],
                "critical_count": counts["critical"],
                "high_count": counts["high"],
                "resources_parsed": len(resources),
                "unsupported_skipped": len(unsupported)
            }
        )

        msg = (
            f"Evaluated {len(resources)} resources across 7 Well-Architected dimensions."
            if not unsupported else
            f"Evaluated {len(resources)} resources across 7 dimensions ({len(unsupported)} unsupported constructs skipped)."
        )

        return {
            "success": True,
            "message": msg,
            "data": saved_job.model_dump()
        }

    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis engine error: {str(e)}")

@router.post("/async")
async def trigger_async_analysis(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    Asynchronous analysis: Accepts file, stores it, queues background processing
    via the Lambda worker routine, and returns immediately with HTTP 202 Accepted.
    """
    scan_id = f"scan_async_{uuid.uuid4().hex[:10]}"
    filename = file.filename or "template.tf"

    try:
        raw_bytes = await file.read()
        store_res = storage_manager.store_file(
            content=raw_bytes,
            filename=filename,
            analysis_id=scan_id,
            is_report=False
        )
        file_key = store_res["file_key"]

        # Register initial PENDING record
        pending_job = ScanJob(
            scan_id=scan_id,
            scan_type="IAC_STATIC",
            target_name=filename,
            status="PENDING",
            file_key=file_key,
            storage_backend=store_res["storage_backend"]
        )
        repository.save_scan(pending_job)

        # Offload execution to asynchronous background worker (mirrors Lambda execution)
        background_tasks.add_task(process_analysis_job, file_key, scan_id)

        return Response(
            status_code=202,
            content=ScanJob.model_dump_json(pending_job),
            media_type="application/json"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Async queue error: {str(e)}")

@router.post("/analyze-stored")
async def analyze_stored_infrastructure(
    file_key: str = Form(...)
):
    """
    Retrieves an existing blueprint directly from S3 or local storage by file_key
    and executes the full risk-analysis pipeline.
    """
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    filename = file_key.split("/")[-1]

    try:
        content, _ = storage_manager.retrieve_file(file_key)
        resources, unsupported = IaCParser.parse(content, filename)
        findings, discovered_resources, discovery_summary = RuleEvaluator.evaluate_blueprint(
            resources=resources,
            scan_id=scan_id,
            unsupported=unsupported,
            filename=filename,
            file_size=len(content)
        )
        score, grade, dim_scores, counts, score_explanation = RiskScorer.calculate_score_detailed(
            findings, discovery_summary.get("check_statistics")
        )

        job = ScanJob(
            scan_id=scan_id,
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
            score_explanation=score_explanation,
            check_statistics=discovery_summary.get("check_statistics", {}),
            compound_risks=discovery_summary.get("compound_risks", []),
            file_key=file_key,
            storage_backend="s3" if storage_manager.prefer_s3 else "local",
            findings=findings
        )
        saved = repository.save_scan(job)

        cloudwatch_logger.log_audit_event(
            event_type="LIVE_AWS_SCAN_COMPLETED",
            scan_id=scan_id,
            details={
                "target_name": job.target_name,
                "overall_risk_score": job.overall_risk_score,
                "risk_grade": job.risk_grade,
                "total_findings": job.total_findings,
                "critical_count": job.critical_count,
                "resources_discovered": len(job.discovered_resources)
            }
        )
        return {
            "success": True,
            "message": f"Retrieved from storage ({file_key}) and evaluated successfully.",
            "data": saved.model_dump()
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File key '{file_key}' not found in storage.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze stored file: {str(e)}")

@router.post("/live")
async def scan_live_aws(region: Optional[str] = Form(default=None)):
    """Triggers an authentic read-only live scan of configured AWS resources."""
    scan_id = f"scan_live_{uuid.uuid4().hex[:10]}"
    try:
        job = live_scanner.scan_environment(scan_id=scan_id, region=region)
        saved = repository.save_scan(job)

        cloudwatch_logger.log_audit_event(
            event_type="LIVE_AWS_SCAN_COMPLETED",
            scan_id=scan_id,
            details={
                "target_name": job.target_name,
                "overall_risk_score": job.overall_risk_score,
                "risk_grade": job.risk_grade,
                "total_findings": job.total_findings,
                "critical_count": job.critical_count,
                "resources_discovered": len(job.discovered_resources)
            }
        )
        return {
            "success": True,
            "message": "Live AWS security scan completed.",
            "data": saved.model_dump()
        }
    except RuntimeError as re:
        raise HTTPException(status_code=400, detail=str(re))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Live scan failed: {str(e)}")

@router.get("/metrics/summary")
async def get_summary_metrics():
    """Returns aggregated risk metrics across all historical scans."""
    return repository.get_summary_metrics()

@router.get("/scans")
async def list_historical_scans(limit: int = Query(default=20), offset: int = Query(default=0)):
    """Lists historical scans with summary statistics."""
    scans = repository.list_scans(limit=limit, offset=offset)
    return {
        "success": True,
        "count": len(scans),
        "scans": [s.model_dump() for s in scans]
    }

@router.get("/{scan_id}")
async def get_scan_details(scan_id: str):
    """Retrieves full scan details including all findings and remediations."""
    job = repository.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return {
        "success": True,
        "data": job.model_dump()
    }

@router.get("/{scan_id}/report")
async def export_audit_report(scan_id: str, format: str = Query(default="markdown")):
    """Exports an audit report in markdown, json, or html/pdf."""
    job = repository.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    fmt = format.lower()
    if fmt == "json":
        return Response(content=ReportExporter.export_json(job), media_type="application/json", headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.json"})
    elif fmt == "html":
        return Response(content=ReportExporter.export_html(job), media_type="text/html", headers={"Content-Disposition": f"inline; filename=report_{scan_id}.html"})
    else:
        return Response(content=ReportExporter.export_markdown(job), media_type="text/markdown", headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.md"})

@router.get("/{scan_id}/report/url")
async def get_authorized_report_url(
    scan_id: str,
    format: str = Query(default="markdown"),
    expires_in: int = Query(default=900)
):
    """
    Generates a private, authorized short-lived presigned download URL for the requested report.
    Persists the generated report to Amazon S3 (with AES256 server-side encryption) or local storage.
    """
    job = repository.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    try:
        report_data = ReportExporter.export_and_persist(job, format_type=format, expires_in=expires_in)
        return {
            "success": True,
            "message": "Authorized presigned report download URL generated successfully.",
            "data": report_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report URL: {str(e)}")

@router.post("/{scan_id}/findings/{finding_id}/ai-remediation")
async def generate_finding_ai_remediation(scan_id: str, finding_id: str):
    """
    Synthesizes contextual LLM remediation for a specific finding using Amazon Bedrock.
    If Bedrock is unavailable or restricted by IAM LabRole, falls back to deterministic rule baseline.
    """
    job = repository.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    target_finding = next((f for f in job.findings if f.finding_id == finding_id), None)
    if not target_finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found in scan '{scan_id}'.")

    # Generate AI Remediation with automatic deterministic fallback
    result = bedrock_service.generate_remediation(target_finding)

    # If successful, update the finding in the scan record
    if result["status"] == "SUCCESS":
        target_finding.ai_remediation = result["content"]
        target_finding.remediation_source = "BEDROCK_AI"
        repository.save_scan(job)

    return {
        "success": True,
        "scan_id": scan_id,
        "finding_id": finding_id,
        "remediation": result
    }

@router.post("/{scan_id}/findings/{finding_id}/verify")
def verify_individual_finding(scan_id: str, finding_id: str):
    """
    Evidence-based finding verification action:
    Re-examines resource and graph context in the blueprint AST.
    Detects whether compensating controls or overriding policies exist.
    Clearly distinguishes static blueprint verification from live AWS verification.
    Updates the finding status, confidence, and verification details in persistence.
    """
    job = repository.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    target_finding = next((f for f in job.findings if f.finding_id == finding_id), None)
    if not target_finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found in scan '{scan_id}'.")

    # Reconstruct or parse resources from stored blueprint
    resources: List[NormalizedResource] = []
    if job.file_key:
        try:
            stored_content, _ = storage_manager.retrieve_file(job.file_key)
            parsed_res, _ = IaCParser.parse(stored_content, job.target_name)
            resources = parsed_res
        except Exception:
            pass

    if not resources and job.discovered_resources:
        for dr in job.discovered_resources:
            resources.append(NormalizedResource(
                resource_id=dr["resource_id"],
                resource_type=dr["resource_type"],
                service=dr["service"],
                properties=dr.get("properties", {}),
                line_number=dr.get("line_number", 1),
                relationships=dr.get("relationships", [])
            ))

    verification_result = RuleEvaluator.verify_finding(target_finding, resources)

    # Update finding fields
    target_finding.verification_method = verification_result.get("verification_method", "STATIC_BLUEPRINT_VERIFICATION")
    target_finding.verification_details = verification_result
    if verification_result.get("status"):
        target_finding.finding_status = verification_result["status"]
    if verification_result.get("confidence"):
        target_finding.confidence = verification_result["confidence"]

    # Re-calculate score with updated finding statuses
    score, grade, dim_scores, counts, score_explanation = RiskScorer.calculate_score_detailed(
        job.findings, job.check_statistics
    )
    job.overall_risk_score = score
    job.risk_grade = grade
    job.dimension_scores = dim_scores
    job.score_explanation = score_explanation
    job.critical_count = counts["critical"]
    job.high_count = counts["high"]
    job.medium_count = counts["medium"]
    job.low_count = counts["low"]

    repository.save_scan(job)

    cloudwatch_logger.log_audit_event(
        event_type="FINDING_VERIFIED",
        scan_id=scan_id,
        details={
            "finding_id": finding_id,
            "rule_id": target_finding.rule_id,
            "verification_status": verification_result.get("status"),
            "confidence": verification_result.get("confidence")
        }
    )

    return {
        "success": True,
        "scan_id": scan_id,
        "finding_id": finding_id,
        "verification": verification_result,
        "updated_finding": target_finding.model_dump(),
        "updated_score": score,
        "updated_grade": grade
    }

@router.post("/{scan_id}/findings/{finding_id}/remediation/preview")
def preview_finding_remediation(scan_id: str, finding_id: str):
    """
    Intelligent Remediation Engine:
    Generates a contextual, surgically targeted IaC code correction for the affected finding.
    Performs pre-application validation (syntactic validity + security correctness check).
    Displays original config, proposed config, unified diff, explanation, security benefit, and side-effects.
    Does NOT overwrite original file.
    """
    job = repository.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    target_finding = next((f for f in job.findings if f.finding_id == finding_id), None)
    if not target_finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found in scan '{scan_id}'.")

    # Retrieve current base blueprint text
    content_str = ""
    if job.file_key:
        try:
            content_bytes, _ = storage_manager.retrieve_file(job.file_key)
            content_str = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass

    if not content_str:
        content_str = target_finding.actual_config or (target_finding.remediation_code or "")

    # Generate precision remediation
    rem_preview = RemediationEngine.generate_remediation(
        finding=target_finding,
        blueprint_content=content_str,
        filename=job.target_name
    )

    # Apply fix to candidate content in memory to validate
    candidate_content = RemediationEngine.apply_staged_remediations(
        original_blueprint=content_str,
        staged_remediations={finding_id: rem_preview},
        filename=job.target_name
    )

    # Validate candidate fix
    validation = RemediationValidator.validate_remediation(
        candidate_blueprint=candidate_content,
        filename=job.target_name,
        target_finding=target_finding,
        original_findings=job.findings
    )
    rem_preview["validation"] = validation

    # Update finding status & preview
    if validation["security_correctness"]:
        target_finding.remediation_status = "Validated"
    else:
        target_finding.remediation_status = "Fix Generated"

    target_finding.remediation_preview = rem_preview
    repository.save_scan(job)

    cloudwatch_logger.log_audit_event(
        event_type="REMEDIATION_PREVIEW_GENERATED",
        scan_id=scan_id,
        details={
            "finding_id": finding_id,
            "rule_id": target_finding.rule_id,
            "security_correctness": validation["security_correctness"],
            "candidate_score": validation["candidate_risk_score"]
        }
    )

    return {
        "success": True,
        "scan_id": scan_id,
        "finding_id": finding_id,
        "preview": rem_preview,
        "validation": validation,
        "remediation_status": target_finding.remediation_status
    }

@router.post("/{scan_id}/findings/{finding_id}/remediation/approve")
def approve_finding_remediation(scan_id: str, finding_id: str):
    """
    User-Approved Repair Workflow:
    Explicit user approval action to stage an approved fix into the working corrected blueprint.
    Updates finding status to 'Awaiting Approval' / 'Validated' and updates audit history.
    """
    job = repository.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    target_finding = next((f for f in job.findings if f.finding_id == finding_id), None)
    if not target_finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found in scan '{scan_id}'.")

    # If preview hasn't been generated, generate it now
    if not target_finding.remediation_preview:
        content_str = ""
        if job.file_key:
            try:
                content_bytes, _ = storage_manager.retrieve_file(job.file_key)
                content_str = content_bytes.decode("utf-8", errors="replace")
            except Exception:
                pass
        target_finding.remediation_preview = RemediationEngine.generate_remediation(
            finding=target_finding,
            blueprint_content=content_str,
            filename=job.target_name
        )

    # Stage the fix
    if not isinstance(job.staged_remediations, dict):
        job.staged_remediations = {}
    job.staged_remediations[finding_id] = target_finding.remediation_preview

    # Apply all staged remediations to update job.corrected_content
    original_content = ""
    if job.file_key:
        try:
            content_bytes, _ = storage_manager.retrieve_file(job.file_key)
            original_content = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass

    job.corrected_content = RemediationEngine.apply_staged_remediations(
        original_blueprint=original_content,
        staged_remediations=job.staged_remediations,
        filename=job.target_name
    )

    target_finding.remediation_status = "Validated"
    target_finding.remediation_history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "APPROVED_BY_USER",
        "change": target_finding.remediation_preview.get("change_description", "Fix approved")
    })

    repository.save_scan(job)

    cloudwatch_logger.log_audit_event(
        event_type="REMEDIATION_FIX_APPROVED",
        scan_id=scan_id,
        details={
            "finding_id": finding_id,
            "rule_id": target_finding.rule_id,
            "staged_count": len(job.staged_remediations)
        }
    )

    return {
        "success": True,
        "message": f"Remediation for '{target_finding.rule_id}' approved and staged into corrected blueprint.",
        "staged_count": len(job.staged_remediations),
        "remediation_status": target_finding.remediation_status
    }

@router.get("/{scan_id}/remediation/candidate")
def get_candidate_remediated_blueprint(scan_id: str):
    """
    Retrieves the current in-memory candidate corrected blueprint with all approved remediations.
    """
    job = repository.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    original_content = ""
    if job.file_key:
        try:
            content_bytes, _ = storage_manager.retrieve_file(job.file_key)
            original_content = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass

    corrected_text = job.corrected_content or RemediationEngine.apply_staged_remediations(
        original_blueprint=original_content,
        staged_remediations=job.staged_remediations or {},
        filename=job.target_name
    )

    return {
        "success": True,
        "scan_id": scan_id,
        "target_name": job.target_name,
        "staged_count": len(job.staged_remediations or {}),
        "candidate_blueprint": corrected_text
    }

@router.get("/{scan_id}/remediation/export")
def export_remediated_blueprint(scan_id: str, download: bool = Query(default=False)):
    """
    User-Approved Export Action:
    Generates the final corrected blueprint incorporating all staged fixes,
    stores it securely in the storage backend, and marks status as 'Exported'.
    Returns downloadable file stream or JSON metadata.
    """
    job = repository.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    original_content = ""
    if job.file_key:
        try:
            content_bytes, _ = storage_manager.retrieve_file(job.file_key)
            original_content = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass

    clean_name = re.sub(r'^(?:remediated_)+', '', job.target_name)
    corrected_filename = f"remediated_{clean_name}"

    if job.corrected_content:
        corrected_text = job.corrected_content
    elif job.staged_remediations:
        corrected_text = RemediationEngine.apply_staged_remediations(
            original_blueprint=original_content,
            staged_remediations=job.staged_remediations or {},
            filename=clean_name
        )
    else:
        corrected_text = original_content or ""

    content_bytes = corrected_text.encode("utf-8")

    # Store in configured storage layer
    store_res = storage_manager.store_file(
        content=content_bytes,
        filename=corrected_filename,
        analysis_id=f"rem_{scan_id}",
        is_report=False
    )
    job.corrected_file_key = store_res["file_key"]
    job.corrected_content = corrected_text

    # Update status for all staged findings
    for finding_id in (job.staged_remediations or {}):
        f = next((item for item in job.findings if item.finding_id == finding_id), None)
        if f:
            f.remediation_status = "Exported"
            f.remediation_history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "EXPORTED",
                "file_key": store_res["file_key"]
            })

    repository.save_scan(job)

    cloudwatch_logger.log_audit_event(
        event_type="CORRECTED_BLUEPRINT_EXPORTED",
        scan_id=scan_id,
        details={
            "corrected_filename": corrected_filename,
            "staged_count": len(job.staged_remediations or {})
        }
    )

    if download:
        return Response(
            content=corrected_text,
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename={corrected_filename}"}
        )

    return {
        "success": True,
        "scan_id": scan_id,
        "filename": corrected_filename,
        "file_key": store_res["file_key"],
        "storage_backend": store_res["storage_backend"],
        "byte_size": len(content_bytes),
        "staged_count": len(job.staged_remediations or {}),
        "content": corrected_text
    }

@router.post("/{scan_id}/remediation/verify-rescan")
def verify_and_rescan_remediation(scan_id: str):
    """
    Before-and-After Security Verification Lifecycle:
    Re-analyses the corrected blueprint using the identical 7-dimension rule evaluator and risk scorer.
    Computes mathematically verified before-and-after comparison.
    Updates original finding statuses to 'Resolved', 'Partially Resolved', or 'Unresolved'.
    Never marks a risk resolved without passing full AST inspection.
    """
    job = repository.get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    # Get corrected blueprint
    corrected_text = job.corrected_content
    if not corrected_text:
        original_content = ""
        if job.file_key:
            try:
                content_bytes, _ = storage_manager.retrieve_file(job.file_key)
                original_content = content_bytes.decode("utf-8", errors="replace")
            except Exception:
                pass
        corrected_text = RemediationEngine.apply_staged_remediations(
            original_blueprint=original_content,
            staged_remediations=job.staged_remediations or {},
            filename=job.target_name
        )

    if not corrected_text:
        raise HTTPException(status_code=400, detail="No corrected blueprint available to rescan.")

    corrected_bytes = corrected_text.encode("utf-8")
    new_scan_id = f"scan_rem_{uuid.uuid4().hex[:10]}"
    clean_name = re.sub(r'^(?:remediated_)+', '', job.target_name)
    new_target_name = f"remediated_{clean_name}"

    # Store corrected blueprint
    store_res = storage_manager.store_file(
        content=corrected_bytes,
        filename=new_target_name,
        analysis_id=new_scan_id,
        is_report=False
    )

    # Full authentic analysis of corrected blueprint
    resources, unsupported = IaCParser.parse(corrected_bytes, new_target_name)
    new_findings, discovered, summary = RuleEvaluator.evaluate_blueprint(
        resources=resources,
        scan_id=new_scan_id,
        unsupported=unsupported,
        filename=new_target_name,
        file_size=len(corrected_bytes)
    )

    new_score, new_grade, new_dim_scores, new_counts, new_explanation = RiskScorer.calculate_score_detailed(
        new_findings, summary.get("check_statistics")
    )

    remediated_job = ScanJob(
        scan_id=new_scan_id,
        scan_type="IAC_STATIC",
        target_name=new_target_name,
        status="COMPLETED",
        overall_risk_score=new_score,
        risk_grade=new_grade,
        total_findings=new_counts["total"],
        critical_count=new_counts["critical"],
        high_count=new_counts["high"],
        medium_count=new_counts["medium"],
        low_count=new_counts["low"],
        dimension_scores=new_dim_scores,
        unsupported_constructs=unsupported,
        discovered_resources=discovered,
        discovery_summary=summary,
        score_explanation=new_explanation,
        check_statistics=summary.get("check_statistics", {}),
        compound_risks=summary.get("compound_risks", []),
        file_key=store_res["file_key"],
        storage_backend=store_res["storage_backend"],
        parent_scan_id=scan_id,
        findings=new_findings
    )

    # Compute comparison
    comparison = RemediationComparator.compare_scans(original_scan=job, remediated_scan=remediated_job)

    # Update original findings based on comparison
    resolved_ids = {item["finding_id"] for item in comparison["resolved_findings"]}
    partially_ids = {item["finding_id"] for item in comparison["partially_resolved_findings"]}
    unresolved_ids = {item["finding_id"] for item in comparison["unresolved_findings"]}

    for f in job.findings:
        if f.finding_id in resolved_ids:
            f.remediation_status = "Resolved"
        elif f.finding_id in partially_ids:
            f.remediation_status = "Partially Resolved"
        elif f.finding_id in unresolved_ids:
            if f.finding_id in (job.staged_remediations or {}):
                f.remediation_status = "Verification Failed"
            else:
                f.remediation_status = "Unresolved"

        f.remediation_history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "RESCAN_VERIFICATION",
            "status": f.remediation_status,
            "remediated_scan_id": new_scan_id
        })

    job.comparison_data = comparison
    remediated_job.comparison_data = comparison
    remediated_job.corrected_content = corrected_text

    # Attach verified resolved findings for comprehensive audit visibility
    display_findings = list(new_findings)
    for f in job.findings:
        if f.finding_id in resolved_ids:
            resolved_copy = Finding(
                finding_id=f.finding_id,
                scan_id=new_scan_id,
                rule_id=f.rule_id,
                rule_name=f.rule_name,
                dimension=f.dimension,
                severity=f.severity,
                resource_id=f.resource_id,
                resource_type=f.resource_type,
                file_name=new_target_name,
                line_number=f.line_number,
                confidence=f.confidence,
                finding_status=f.finding_status,
                verification_method="RESCAN_VERIFIED",
                actual_config=f.actual_config,
                expected_config=f.expected_config,
                evidence=f.evidence,
                title=f.title,
                description=f.description,
                impact=f.impact,
                remediation_summary="Remediation applied and verified resolved by AST inspection.",
                remediation_code=f.remediation_code,
                cli_command=f.cli_command,
                remediation_status="Resolved",
                remediation_history=f.remediation_history,
                related_resources=f.related_resources
            )
            display_findings.append(resolved_copy)

    remediated_job.findings = display_findings

    repository.save_scan(job)
    repository.save_scan(remediated_job)

    cloudwatch_logger.log_audit_event(
        event_type="REMEDIATION_RESCAN_COMPLETED",
        scan_id=scan_id,
        details={
            "remediated_scan_id": new_scan_id,
            "score_before": comparison["score_before"],
            "score_after": comparison["score_after"],
            "resolved_count": comparison["resolved_count"]
        }
    )

    return {
        "success": True,
        "message": f"Remediated blueprint rescanned. Score improved from {comparison['score_before']} (Grade {comparison['grade_before']}) to {comparison['score_after']} (Grade {comparison['grade_after']}).",
        "comparison": comparison,
        "original_scan": job.model_dump(),
        "remediated_scan": remediated_job.model_dump()
    }
