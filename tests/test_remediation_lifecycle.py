"""
CloudGuardAI - Intelligent Remediation Lifecycle Test Suite
Verifies:
  1. Contextual remediation generation (Terraform & CloudFormation)
  2. Syntactic validity and AST reference preservation
  3. Security correctness and regression detection prior to applying fixes
  4. Staged fix preview, diff calculation, and approval workflow
  5. Corrected blueprint export and download
  6. Authentic AST verification rescan and before-and-after comparison
  7. Multi-format report generation (Markdown, HTML, JSON) with remediation sections
  8. Safety protections and edge case handling
"""

import io
import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.db.repository import repository
from backend.app.reports.exporter import ReportExporter
from backend.app.engine.remediation_engine import RemediationEngine
from backend.app.engine.remediation_validator import RemediationValidator
from backend.app.engine.remediation_comparator import RemediationComparator

TEST_INSECURE_TF = b"""resource "aws_s3_bucket" "vault" {
  bucket = "company-sensitive-vault"
  acl    = "public-read"
}

resource "aws_security_group" "web_sg" {
  name = "web_sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "app_db" {
  identifier          = "app-database"
  publicly_accessible = true
  multi_az            = false
  deletion_protection = false
}
"""

TEST_CFN_YAML = b"""AWSTemplateFormatVersion: '2010-09-09'
Description: Sample Insecure CloudFormation Template
Resources:
  PublicBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  OpenSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow all SSH
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
"""

class TestRemediationLifecycle(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_terraform_remediation_lifecycle_e2e(self):
        """Complete user journey: Scan -> Preview -> Approve -> Candidate -> Export -> Rescan -> Compare."""
        # 1. Upload insecure Terraform template
        files = {
            "file": ("e2e_infra.tf", io.BytesIO(TEST_INSECURE_TF), "text/plain")
        }
        res = self.client.post("/api/v1/scan/upload", files=files)
        self.assertEqual(res.status_code, 200)
        scan = res.json()["data"]
        scan_id = scan["scan_id"]
        initial_score = scan["overall_risk_score"]
        initial_grade = scan["risk_grade"]
        self.assertGreaterEqual(initial_score, 70.0)
        self.assertIn(initial_grade, ["D", "F"])

        findings = scan["findings"]
        s3_finding = next((f for f in findings if f["rule_id"] == "SEC-S3-001"), None)
        sg_finding = next((f for f in findings if f["rule_id"] == "NET-SG-001"), None)
        rds_finding = next((f for f in findings if f["rule_id"] == "SEC-RDS-001"), None)

        self.assertIsNotNone(s3_finding)
        self.assertIsNotNone(sg_finding)
        self.assertIsNotNone(rds_finding)

        # 2. Preview Remediation for S3 (SEC-S3-001)
        preview_res = self.client.post(f"/api/v1/scan/{scan_id}/findings/{s3_finding['finding_id']}/remediation/preview")
        self.assertEqual(preview_res.status_code, 200)
        p_data = preview_res.json()
        self.assertTrue(p_data["success"])
        preview = p_data["preview"]
        self.assertIn("diff", preview)
        self.assertIn("explanation", preview)
        self.assertIn("security_improvement", preview)
        self.assertIn("side_effects", preview)
        self.assertEqual(p_data["remediation_status"], "Validated")

        val = preview["validation"]
        self.assertTrue(val["syntactic_validity"])
        self.assertTrue(val["security_correctness"])
        self.assertTrue(val["target_finding_resolved"])
        self.assertEqual(len(val["new_findings_introduced"]), 0)

        # 3. Approve S3 Fix
        appr_res = self.client.post(f"/api/v1/scan/{scan_id}/findings/{s3_finding['finding_id']}/remediation/approve")
        self.assertEqual(appr_res.status_code, 200)
        self.assertEqual(appr_res.json()["staged_count"], 1)

        # 4. Preview and Approve SG Fix (NET-SG-001)
        preview_sg = self.client.post(f"/api/v1/scan/{scan_id}/findings/{sg_finding['finding_id']}/remediation/preview")
        self.assertEqual(preview_sg.status_code, 200)
        self.assertTrue(preview_sg.json()["preview"]["validation"]["syntactic_validity"])

        appr_sg = self.client.post(f"/api/v1/scan/{scan_id}/findings/{sg_finding['finding_id']}/remediation/approve")
        self.assertEqual(appr_sg.status_code, 200)
        self.assertEqual(appr_sg.json()["staged_count"], 2)

        # 5. Preview and Approve RDS Fix (SEC-RDS-001)
        preview_rds = self.client.post(f"/api/v1/scan/{scan_id}/findings/{rds_finding['finding_id']}/remediation/preview")
        self.assertEqual(preview_rds.status_code, 200)
        self.assertTrue(preview_rds.json()["preview"]["validation"]["syntactic_validity"])

        appr_rds = self.client.post(f"/api/v1/scan/{scan_id}/findings/{rds_finding['finding_id']}/remediation/approve")
        self.assertEqual(appr_rds.status_code, 200)
        self.assertEqual(appr_rds.json()["staged_count"], 3)

        # 6. Retrieve Candidate Blueprint
        cand_res = self.client.get(f"/api/v1/scan/{scan_id}/remediation/candidate")
        self.assertEqual(cand_res.status_code, 200)
        cand_data = cand_res.json()
        cand_bp = cand_data["candidate_blueprint"]
        self.assertIn('acl = "private"', cand_bp)
        self.assertIn('aws_s3_bucket_public_access_block', cand_bp)
        self.assertIn('10.0.0.0/16', cand_bp)
        self.assertIn('publicly_accessible = false', cand_bp)

        # 7. Export Remediation
        exp_res = self.client.get(f"/api/v1/scan/{scan_id}/remediation/export?download=false")
        self.assertEqual(exp_res.status_code, 200)
        exp_data = exp_res.json()
        self.assertTrue(exp_data["success"])
        self.assertIn("file_key", exp_data)

        # 8. Verify & Rescan
        rescan_res = self.client.post(f"/api/v1/scan/{scan_id}/remediation/verify-rescan")
        self.assertEqual(rescan_res.status_code, 200)
        rescan_data = rescan_res.json()
        self.assertTrue(rescan_data["success"])
        cmp = rescan_data["comparison"]

        self.assertLess(cmp["score_after"], cmp["score_before"])
        self.assertGreater(cmp["score_delta"], 0)
        self.assertGreaterEqual(cmp["resolved_count"], 3)

        # Verify finding remediation statuses updated in scan
        saved_scan = repository.get_scan(scan_id)
        for f in saved_scan.findings:
            if f.rule_id in ["SEC-S3-001", "NET-SG-001", "SEC-RDS-001"]:
                self.assertEqual(f.remediation_status, "Resolved")
                self.assertIsNotNone(f.remediation_preview)
                self.assertGreater(len(f.remediation_history), 0)

    def test_cloudformation_remediation(self):
        """Verifies contextual remediation generation for CloudFormation templates."""
        files = {
            "file": ("cfn_stack.yaml", io.BytesIO(TEST_CFN_YAML), "text/yaml")
        }
        res = self.client.post("/api/v1/scan/upload", files=files)
        self.assertEqual(res.status_code, 200)
        scan = res.json()["data"]
        scan_id = scan["scan_id"]

        findings = scan["findings"]
        s3_finding = next((f for f in findings if f["rule_id"] == "SEC-S3-001"), None)
        self.assertIsNotNone(s3_finding)

        # Preview CloudFormation fix
        preview_res = self.client.post(f"/api/v1/scan/{scan_id}/findings/{s3_finding['finding_id']}/remediation/preview")
        self.assertEqual(preview_res.status_code, 200)
        p_data = preview_res.json()
        self.assertTrue(p_data["success"])
        self.assertTrue(p_data["preview"]["validation"]["syntactic_validity"])

    def test_multi_format_reports_include_remediation(self):
        """Verifies Markdown, HTML, and JSON reports contain the Before vs After remediation section."""
        files = {
            "file": ("report_test.tf", io.BytesIO(TEST_INSECURE_TF), "text/plain")
        }
        res = self.client.post("/api/v1/scan/upload", files=files)
        scan = res.json()["data"]
        scan_id = scan["scan_id"]

        s3_finding = next(f for f in scan["findings"] if f["rule_id"] == "SEC-S3-001")
        self.client.post(f"/api/v1/scan/{scan_id}/findings/{s3_finding['finding_id']}/remediation/preview")
        self.client.post(f"/api/v1/scan/{scan_id}/findings/{s3_finding['finding_id']}/remediation/approve")
        self.client.post(f"/api/v1/scan/{scan_id}/remediation/verify-rescan")

        updated_scan = repository.get_scan(scan_id)

        # 1. Markdown
        md = ReportExporter.export_markdown(updated_scan)
        self.assertIn("Remediation Lifecycle: Before vs After Verification", md)
        self.assertIn("Net Risk Reduction:", md)
        self.assertIn("Successfully Resolved Risks (Verified)", md)

        # 2. HTML
        html = ReportExporter.export_html(updated_scan)
        self.assertIn("Remediation Lifecycle: Before vs After Comparison", html)
        self.assertIn("Verified Resolved", html)

        # 3. JSON
        json_report_str = ReportExporter.export_json(updated_scan)
        self.assertIn("comparison_data", json_report_str)
        self.assertIn("staged_remediations", json_report_str)
        import json as py_json
        parsed_json = py_json.loads(json_report_str)
        self.assertEqual(parsed_json["comparison_data"]["grade_before"], updated_scan.comparison_data["grade_before"])

    def test_remediation_error_handling(self):
        """Verifies 404 responses for invalid scan_id or finding_id."""
        bad_preview = self.client.post("/api/v1/scan/non_existent_scan/findings/f_123/remediation/preview")
        self.assertEqual(bad_preview.status_code, 404)

        bad_candidate = self.client.get("/api/v1/scan/non_existent_scan/remediation/candidate")
        self.assertEqual(bad_candidate.status_code, 404)

        bad_export = self.client.get("/api/v1/scan/non_existent_scan/remediation/export")
        self.assertEqual(bad_export.status_code, 404)

        bad_rescan = self.client.post("/api/v1/scan/non_existent_scan/remediation/verify-rescan")
        self.assertEqual(bad_rescan.status_code, 404)

if __name__ == "__main__":
    unittest.main()
