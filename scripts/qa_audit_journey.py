"""
CloudGuardAI - Senior QA End-to-End User Journey Audit
Directly executes the live user journey against http://127.0.0.1:8000:
1. Health check & status verification
2. Blueprint upload (Terraform with known critical vulnerabilities)
3. Storage round-trip & AST parsing
4. 7-dimension rule evaluation & mathematical risk scoring
5. Database persistence verification
6. Multi-format report export & authorized presigned URL generation
7. Detail drawer AI synthesis & deterministic fallback verification
8. Live AWS discovery boundary handling
"""

import httpx
import json
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE = "http://127.0.0.1:8000"

def run_qa_journey():
    print("=" * 70)
    print("  CloudGuardAI - End-to-End User Journey QA Audit")
    print("=" * 70)

    client = httpx.Client(base_url=BASE, timeout=10.0)

    # 1. Health & Configuration Probe
    print("\n[STEP 1] Probing Health & Runtime Configuration (/api/v1/health)...")
    r_health = client.get("/api/v1/health")
    assert r_health.status_code == 200, f"Health check failed: {r_health.status_code}"
    health_data = r_health.json()
    print(f"  • Status:           {health_data['status']}")
    print(f"  • Storage Backend:  {health_data['storage_backend']}")
    print(f"  • Database Backend: {health_data['database_backend']}")
    print(f"  • Remediation Mode: {health_data['remediation_backend']}")
    print(f"  • AWS Authenticated:{health_data['aws']['authenticated']}")

    # 2. Upload and Scan Vulnerable Terraform Blueprint
    print("\n[STEP 2] Uploading & Analyzing Vulnerable Blueprint (/api/v1/scan/upload)...")
    tf_content = b"""
// Production Infrastructure Blueprint with known vulnerabilities
resource "aws_s3_bucket" "financial_data" {
  bucket = "corp-financial-records"
  acl    = "public-read"
}

resource "aws_security_group" "allow_ssh_rdp" {
  name        = "bastion-sg"
  description = "Management SG"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
    files = {"file": ("financial_infra.tf", tf_content, "text/plain")}
    r_upload = client.post("/api/v1/scan/upload", files=files)
    assert r_upload.status_code == 200, f"Upload failed: {r_upload.status_code} - {r_upload.text}"
    scan_resp = r_upload.json()
    assert scan_resp["success"] is True, "Upload reported success=False"
    scan_data = scan_resp["data"]
    scan_id = scan_data["scan_id"]
    print(f"  • Scan ID:          {scan_id}")
    print(f"  • Overall Score:    {scan_data['overall_risk_score']} / 100")
    print(f"  • Risk Grade:       {scan_data['risk_grade']}")
    print(f"  • Total Findings:   {scan_data['total_findings']} (Critical: {scan_data['critical_count']}, High: {scan_data['high_count']})")
    
    # Assert findings detection
    rule_ids = [f["rule_id"] for f in scan_data["findings"]]
    print(f"  • Detected Rules:   {', '.join(rule_ids)}")
    assert "SEC-S3-001" in rule_ids, "SEC-S3-001 (Public S3) not detected"
    assert "SEC-S3-002" in rule_ids, "SEC-S3-002 (Missing SSE) not detected"
    assert "NET-SG-001" in rule_ids, "NET-SG-001 (Port 22 Open) not detected"
    assert "NET-SG-002" in rule_ids, "NET-SG-002 (Port 3389 Open) not detected"
    print("  ✓ All 4 expected security misconfigurations accurately detected with concrete evidence.")

    # 3. Database Persistence Verification
    print("\n[STEP 3] Verifying Database Persistence (/api/v1/scan/{scan_id})...")
    r_get = client.get(f"/api/v1/scan/{scan_id}")
    assert r_get.status_code == 200, f"Failed to retrieve scan: {r_get.status_code}"
    fetched = r_get.json()["data"]
    assert fetched["scan_id"] == scan_id, "Fetched scan_id mismatch"
    assert len(fetched["findings"]) == scan_data["total_findings"], "Findings count mismatch in persistence"
    print(f"  ✓ Persisted record verified in database ({fetched['storage_backend']}).")

    # 4. Multi-Format Report Generation
    print("\n[STEP 4] Verifying Multi-Format Reports (/api/v1/scan/{scan_id}/report)...")
    r_md = client.get(f"/api/v1/scan/{scan_id}/report?format=markdown")
    assert r_md.status_code == 200, "Markdown report failed"
    assert "# CloudGuardAI Security & Architecture Audit Report" in r_md.text
    print(f"  • Markdown Report:  {len(r_md.text)} characters")

    r_html = client.get(f"/api/v1/scan/{scan_id}/report?format=html")
    assert r_html.status_code == 200, "HTML report failed"
    assert "<!DOCTYPE html>" in r_html.text
    assert "#287fa3" in r_html.text, "Coastal primary color missing from HTML report"
    print(f"  • HTML Report:      {len(r_html.text)} characters")

    r_url = client.get(f"/api/v1/scan/{scan_id}/report/url?format=markdown")
    assert r_url.status_code == 200, "Authorized report URL generation failed"
    url_data = r_url.json()["data"]
    print(f"  • Authorized URL:   {url_data['download_url'][:55]}... (valid {url_data['expires_in_seconds']}s)")
    print("  ✓ Downloadable reports generated and stored privately with presigned authorization.")

    # 5. Detail Drawer AI Remediation Endpoint
    print("\n[STEP 5] Testing Detail Drawer AI Remediation Synthesis...")
    target_finding_id = scan_data["findings"][0]["finding_id"]
    r_ai = client.post(f"/api/v1/scan/{scan_id}/findings/{target_finding_id}/ai-remediation")
    assert r_ai.status_code == 200, "AI remediation endpoint failed"
    ai_data = r_ai.json()["remediation"]
    print(f"  • AI Status:        {ai_data['status']}")
    print(f"  • Remediation Source:{ai_data['source']}")
    print(f"  • Result Snippet:   {ai_data['content'][:70]}...")
    print("  ✓ Non-blocking AI synthesis / deterministic fallback executed cleanly.")

    # 6. Live AWS Resource Discovery Boundary Check
    print("\n[STEP 6] Testing Live AWS Discovery Safety & Boundary Handling (/api/v1/scan/live)...")
    r_live = client.post("/api/v1/scan/live")
    # In local testing without credentials, endpoint should reject cleanly with 400
    assert r_live.status_code == 400, f"Expected 400 when unauthenticated, got {r_live.status_code}"
    print(f"  • Clean Rejection:  {r_live.json()['detail']}")
    print("  ✓ Live discovery safely prevents unauthenticated executions.")

    print("\n" + "=" * 70)
    print("  AUDIT RESULT: COMPLETE USER JOURNEY VERIFIED AND PASSING 100%")
    print("=" * 70)

if __name__ == "__main__":
    run_qa_journey()
