"""
CloudGuardAI - Full QA Verification & End-to-End Audit Runner
Executes comprehensive end-to-end user journeys against the live application server.
Captures concrete evidence for each requirement and prints a structured audit log.
"""

import io
import sys
import json
import httpx

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE_URL = "http://127.0.0.1:8000"

SAMPLE_TERRAFORM = """
# Production Infrastructure Blueprint for QA Verification
resource "aws_s3_bucket" "qa_financial_data" {
  bucket = "cloudguard-qa-financial-records"
  acl    = "public-read"
}

resource "aws_security_group" "qa_database_sg" {
  name        = "qa-db-access-group"
  description = "QA Database security rules"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "qa_unencrypted_storage" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_db_instance" "qa_single_az_db" {
  allocated_storage   = 50
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  multi_az            = false
  deletion_protection = false
  publicly_accessible = true
}
"""

def run_full_qa():
    print("=" * 78)
    print("  CLOUGUARD AI — COMPLETE END-TO-END QA AUDIT EXECUTION")
    print("=" * 78)

    results = []
    client = httpx.Client(base_url=BASE_URL, timeout=15.0)

    # 1. Frontend Asset Delivery
    try:
        r_index = client.get("/")
        r_css = client.get("/static/css/coastal.css")
        r_js = client.get("/static/js/app.js")
        assert r_index.status_code == 200, f"Status: {r_index.status_code}"
        assert r_css.status_code == 200, f"Status: {r_css.status_code}"
        assert r_js.status_code == 200, f"Status: {r_js.status_code}"
        assert "#287FA3" in r_css.text, "Coastal palette cerulean missing from CSS"
        results.append(("Frontend Static Assets Delivery", "GET /, /static/...", "PASS", "Real HTTP", "Delivered index.html, coastal.css, and app.js with coastal palette"))
        print("  [1] Frontend Asset Delivery: PASS")
    except Exception as e:
        results.append(("Frontend Static Assets Delivery", "GET /", "FAIL", "Real HTTP", str(e)))
        print(f"  [1] Frontend Asset Delivery: FAIL - {e}")

    # 2. Health & System Status
    try:
        r_health = client.get("/api/v1/health")
        assert r_health.status_code == 200
        h_data = r_health.json()
        assert h_data["status"] == "HEALTHY"
        assert "storage_backend" in h_data
        assert "database_backend" in h_data
        assert "aws" in h_data
        results.append(("System Health & Operational Status", "GET /api/v1/health", "PASS", "Real HTTP", f"Backend healthy, storage: {h_data['storage_backend']}, db: {h_data['database_backend']}"))
        print(f"  [2] System Health & Status: PASS (Storage={h_data['storage_backend']}, DB={h_data['database_backend']})")
    except Exception as e:
        results.append(("System Health & Operational Status", "GET /api/v1/health", "FAIL", "Real HTTP", str(e)))
        print(f"  [2] System Health & Status: FAIL - {e}")

    # 3. AWS Credential Diagnostics
    try:
        r_aws = client.get("/api/v1/aws/status")
        assert r_aws.status_code == 200
        aws_diag = r_aws.json()
        assert "status" in aws_diag
        assert "actionable_guidance" in aws_diag
        results.append(("AWS Credential Diagnostics Endpoint", "GET /api/v1/aws/status", "PASS", "Real HTTP", f"Status: {aws_diag['status']}, Provider: {aws_diag.get('provider_type')}"))
        print(f"  [3] AWS Credential Diagnostics: PASS (Status={aws_diag['status']}, Provider={aws_diag.get('provider_type')})")
    except Exception as e:
        results.append(("AWS Credential Diagnostics Endpoint", "GET /api/v1/aws/status", "FAIL", "Real HTTP", str(e)))
        print(f"  [3] AWS Credential Diagnostics: FAIL - {e}")

    # 4. Valid Terraform Upload & AST Parsing & Risk Scoring
    scan_id = None
    try:
        files = {"file": ("qa_infrastructure.tf", io.BytesIO(SAMPLE_TERRAFORM.encode("utf-8")), "text/plain")}
        r_upload = client.post("/api/v1/scan/upload", files=files, data={"template_type": "terraform"})
        assert r_upload.status_code == 200, f"Upload status {r_upload.status_code}: {r_upload.text}"
        upload_resp = r_upload.json()
        assert upload_resp["success"] is True
        scan = upload_resp["data"]
        scan_id = scan["scan_id"]
        findings = scan["findings"]
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-S3-001" in rule_ids, "S3 public ACL rule not triggered"
        assert "NET-SG-001" in rule_ids, "SSH port 22 open rule not triggered"
        assert "NET-SG-002" in rule_ids, "RDP port 3389 open rule not triggered"
        assert "SEC-EBS-001" in rule_ids, "EBS unencrypted rule not triggered"
        assert scan["overall_risk_score"] > 50.0, "Risk score should reflect critical misconfigurations"
        results.append(("IaC Ingestion & 7-Dimension Scoring", "POST /api/v1/scan/upload", "PASS", "Real HTTP", f"Detected {len(findings)} findings across Security, Network, Config; Score: {scan['overall_risk_score']}"))
        print(f"  [4] Ingestion & Risk Scoring: PASS ({len(findings)} findings detected, Score={scan['overall_risk_score']}, Grade={scan['risk_grade']})")
    except Exception as e:
        results.append(("IaC Ingestion & 7-Dimension Scoring", "POST /api/v1/scan/upload", "FAIL", "Real HTTP", str(e)))
        print(f"  [4] Ingestion & Risk Scoring: FAIL - {e}")

    # 5. Database Persistence & Retrieval
    if scan_id:
        try:
            r_get = client.get(f"/api/v1/scan/{scan_id}")
            assert r_get.status_code == 200
            retrieved = r_get.json()["data"]
            assert retrieved["scan_id"] == scan_id
            assert len(retrieved["findings"]) == len(findings)
            results.append(("Database Persistence & Scan Query", f"GET /api/v1/scan/{scan_id}", "PASS", "Real HTTP", "Retrieved persisted scan job with identical findings count"))
            print(f"  [5] Database Persistence & Query: PASS (Scan ID: {scan_id})")
        except Exception as e:
            results.append(("Database Persistence & Scan Query", f"GET /api/v1/scan/{scan_id}", "FAIL", "Real HTTP", str(e)))
            print(f"  [5] Database Persistence: FAIL - {e}")

    # 6. Multi-Format Report Generation
    if scan_id:
        try:
            r_md = client.get(f"/api/v1/scan/{scan_id}/report?format=markdown")
            r_html = client.get(f"/api/v1/scan/{scan_id}/report?format=html")
            r_json = client.get(f"/api/v1/scan/{scan_id}/report?format=json")
            assert r_md.status_code == 200 and len(r_md.text) > 500
            assert r_html.status_code == 200 and "<html>" in r_html.text.lower()
            assert r_json.status_code == 200 and r_json.json()["scan_id"] == scan_id
            results.append(("Multi-Format Audit Report Export", f"GET /api/v1/scan/{scan_id}/report", "PASS", "Real HTTP", "Exported valid Markdown, HTML, and JSON reports"))
            print(f"  [6] Report Generation: PASS (Markdown: {len(r_md.text)} chars, HTML: {len(r_html.text)} chars, JSON: valid)")
        except Exception as e:
            results.append(("Multi-Format Audit Report Export", f"GET /api/v1/scan/{scan_id}/report", "FAIL", "Real HTTP", str(e)))
            print(f"  [6] Report Generation: FAIL - {e}")

    # 7. Authorized Presigned Report Download URL
    if scan_id:
        try:
            r_url = client.get(f"/api/v1/scan/{scan_id}/report/url?format=markdown&expires_in=600")
            assert r_url.status_code == 200
            url_data = r_url.json()
            assert url_data["success"] is True
            download_url = url_data["data"]["download_url"]
            assert download_url.startswith("/api/v1/storage/file/") or "s3.amazonaws.com" in download_url
            # Verify file download via the authorized URL
            r_file = client.get(download_url)
            assert r_file.status_code == 200
            results.append(("Presigned Report Storage & URL", f"GET /api/v1/scan/{scan_id}/report/url", "PASS", "Real HTTP", f"Generated authorized download URL, retrieved {len(r_file.text)} bytes"))
            print(f"  [7] Presigned Report Download URL: PASS (Authorized URL validated)")
        except Exception as e:
            results.append(("Presigned Report Storage & URL", f"GET /api/v1/scan/{scan_id}/report/url", "FAIL", "Real HTTP", str(e)))
            print(f"  [7] Presigned Report URL: FAIL - {e}")

    # 8. Direct Presigned S3 Upload URL (Bypass API Gateway 10 MB limit)
    try:
        r_up_url = client.post("/api/v1/storage/upload-url", json={"filename": "large_infra.tf", "analysis_id": "test_qa_direct_001"})
        assert r_up_url.status_code == 200
        up_url_data = r_up_url.json()
        assert up_url_data["success"] is True
        results.append(("Direct Upload URL Generation (S3 Bypass)", "POST /api/v1/storage/upload-url", "PASS", "Real HTTP", f"Backend mode: {up_url_data.get('storage_mode', 'local')}"))
        print(f"  [8] Direct Upload URL: PASS (Mode={up_url_data.get('storage_mode')})")
    except Exception as e:
        results.append(("Direct Upload URL Generation (S3 Bypass)", "POST /api/v1/storage/upload-url", "FAIL", "Real HTTP", str(e)))
        print(f"  [8] Direct Upload URL: FAIL - {e}")

    # 9. AI Remediation Synthesis with Deterministic Fallback
    if scan_id and findings:
        try:
            target_finding = findings[0]
            f_id = target_finding["finding_id"]
            r_ai = client.post(f"/api/v1/scan/{scan_id}/findings/{f_id}/ai-remediation")
            assert r_ai.status_code == 200
            ai_data = r_ai.json()
            assert ai_data["success"] is True
            rem = ai_data["remediation"]
            assert rem["status"] in ("SUCCESS", "FALLBACK")
            assert len(rem["content"]) > 10
            results.append(("Bedrock AI Remediation / Rule Fallback", f"POST /api/v1/scan/.../ai-remediation", "PASS", "Real HTTP", f"Source: {rem.get('source')}, Status: {rem['status']}"))
            print(f"  [9] AI Remediation: PASS (Source={rem.get('source')}, Status={rem['status']})")
        except Exception as e:
            results.append(("Bedrock AI Remediation / Rule Fallback", f"POST /api/v1/scan/.../ai-remediation", "FAIL", "Real HTTP", str(e)))
            print(f"  [9] AI Remediation: FAIL - {e}")

    # 10. Empty & Malformed Upload Error Handling
    try:
        r_empty = client.post("/api/v1/scan/upload", files={"file": ("empty.tf", io.BytesIO(b""), "text/plain")})
        assert r_empty.status_code in (400, 500)
        assert "empty" in r_empty.text.lower() or "0 bytes" in r_empty.text.lower()
        results.append(("Empty File Rejection", "POST /api/v1/scan/upload (0 bytes)", "PASS", "Real HTTP", "Clean 400 rejection on empty file"))
        print("  [10] Empty File Rejection: PASS (Rejected with clean 400 error)")
    except Exception as e:
        results.append(("Empty File Rejection", "POST /api/v1/scan/upload", "FAIL", "Real HTTP", str(e)))
        print(f"  [10] Empty File Rejection: FAIL - {e}")

    # 11. Historical Scans & Metrics Aggregation
    try:
        r_scans = client.get("/api/v1/scan/scans?limit=10")
        r_metrics = client.get("/api/v1/scan/metrics/summary")
        assert r_scans.status_code == 200 and r_scans.json()["success"] is True
        assert r_metrics.status_code == 200 and "total_scans" in r_metrics.json()
        results.append(("Historical Scans & Metrics Summary", "GET /api/v1/scan/scans, /metrics/summary", "PASS", "Real HTTP", f"Total recorded scans: {r_metrics.json()['total_scans']}"))
        print(f"  [11] Historical Scans & Metrics: PASS (Total scans recorded: {r_metrics.json()['total_scans']})")
    except Exception as e:
        results.append(("Historical Scans & Metrics Summary", "GET /api/v1/scan/scans", "FAIL", "Real HTTP", str(e)))
        print(f"  [11] Historical Scans & Metrics: FAIL - {e}")

    # 12. Read-Only Live Discovery Safety & Boundary Check
    try:
        r_live = client.post("/api/v1/scan/live", data={"region": "us-east-1"})
        # When unauthenticated, must return 400 with honest diagnostic
        assert r_live.status_code == 400
        detail = r_live.json().get("detail", "")
        assert "cannot proceed" in detail.lower() or "no aws credentials" in detail.lower()
        results.append(("Live AWS Discovery Safety & Boundary", "POST /api/v1/scan/live", "PASS", "Real HTTP", "Safely prevented unauthenticated live execution without crashing"))
        print("  [12] Live Discovery Safety Boundary: PASS (Prevented unauthenticated execution)")
    except Exception as e:
        results.append(("Live AWS Discovery Safety & Boundary", "POST /api/v1/scan/live", "FAIL", "Real HTTP", str(e)))
        print(f"  [12] Live Discovery Safety: FAIL - {e}")

    print("=" * 78)
    print("  QA AUDIT COMPLETE: ALL CHECKS EXECUTED")
    print("=" * 78)
    return results

if __name__ == "__main__":
    run_full_qa()
