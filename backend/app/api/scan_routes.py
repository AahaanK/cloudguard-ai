"""
CloudGuardAI - Core Risk Analysis & Scanning REST API Endpoints
Connects IaC Parser, 7-Dimension Rule Engine, Live Scanner, Repository, and Async Lambda Worker.
"""

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query, Response, BackgroundTasks
import uuid
from typing import Optional, List

from ..storage.manager import storage_manager
from ..engine.parser import IaCParser
from ..engine.rules import RuleEvaluator
from ..engine.scorer import RiskScorer
from ..scanner.live_scanner import live_scanner
from ..reports.exporter import ReportExporter
from ..db.repository import repository
from ..db.models import ScanJob
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

        # 5. Compute Scores & Subtotals
        score, grade, dim_scores, counts = RiskScorer.calculate_score(findings)

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
        findings = RuleEvaluator.evaluate(resources, scan_id)
        score, grade, dim_scores, counts = RiskScorer.calculate_score(findings)

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
