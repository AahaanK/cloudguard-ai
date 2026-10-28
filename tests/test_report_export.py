"""
CloudGuardAI - Multi-Format Audit Report Tests
Verifies Markdown, JSON, and clean printable HTML report generation,
confirming strict adherence to the coastal enterprise design system.
"""

import unittest
import json
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.db.models import Finding, ScanJob
from backend.app.db.repository import repository
from backend.app.reports.exporter import ReportExporter

client = TestClient(app)

class TestReportExport(unittest.TestCase):

    def setUp(self):
        self.finding = Finding(
            finding_id="find_rep_001",
            scan_id="scan_rep_100",
            rule_id="SEC-S3-001",
            rule_name="S3 Bucket Public Read/Write Access",
            dimension="SECURITY",
            severity="CRITICAL",
            resource_id="audit_bucket",
            resource_type="aws_s3_bucket",
            evidence={"attribute": "acl", "detected_value": "public-read", "expected_value": "private"},
            title="Public access granted on S3 bucket",
            description="Bucket specifies public-read ACL.",
            impact="Unauthorized public data exposure.",
            remediation_summary="Set bucket ACL to private and enable Block Public Access.",
            remediation_code='resource "aws_s3_bucket_public_access_block" "block" {\n  bucket = audit_bucket.id\n}',
            cli_command="aws s3api put-public-access-block --bucket audit_bucket"
        )
        self.scan = ScanJob(
            scan_id="scan_rep_100",
            scan_type="IAC_STATIC",
            target_name="production_main.tf",
            status="COMPLETED",
            overall_risk_score=78.5,
            risk_grade="D",
            total_findings=1,
            critical_count=1,
            high_count=0,
            medium_count=0,
            low_count=0,
            dimension_scores={"security": 78.5, "iam": 0.0, "network": 0.0},
            findings=[self.finding]
        )
        repository.save_scan(self.scan)

    def test_export_markdown(self):
        """Markdown export should contain all headers, metrics, and code blocks."""
        md = ReportExporter.export_markdown(self.scan)
        self.assertIn("# CloudGuardAI Security & Architecture Audit Report", md)
        self.assertIn("production_main.tf", md)
        self.assertIn("scan_rep_100", md)
        self.assertIn("78.5 / 100", md)
        self.assertIn("Grade **D**", md)
        self.assertIn("SEC-S3-001", md)
        self.assertIn("```terraform", md)
        self.assertIn("```bash", md)

    def test_export_json(self):
        """JSON export should serialize full scan model."""
        json_str = ReportExporter.export_json(self.scan)
        data = json.loads(json_str)
        self.assertEqual(data["scan_id"], "scan_rep_100")
        self.assertEqual(data["overall_risk_score"], 78.5)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["rule_id"], "SEC-S3-001")

    def test_export_html_coastal_theme(self):
        """HTML export should adhere to the coastal palette (#287fa3, #f3f1eb, #202a30)."""
        html = ReportExporter.export_html(self.scan)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("production_main.tf", html)
        self.assertIn("#287fa3", html)   # Cerulean
        self.assertIn("#f3f1eb", html)   # Warm off-white
        self.assertIn("#202a30", html)   # Charcoal
        self.assertIn("audit_bucket", html)

    def test_api_report_endpoint_markdown(self):
        """GET /api/v1/scan/{scan_id}/report?format=markdown"""
        res = client.get("/api/v1/scan/scan_rep_100/report?format=markdown")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "text/markdown; charset=utf-8")
        self.assertIn("# CloudGuardAI Security & Architecture Audit Report", res.text)

    def test_api_report_endpoint_html(self):
        """GET /api/v1/scan/{scan_id}/report?format=html"""
        res = client.get("/api/v1/scan/scan_rep_100/report?format=html")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "text/html; charset=utf-8")
        self.assertIn("<!DOCTYPE html>", res.text)

    def test_api_report_endpoint_json(self):
        """GET /api/v1/scan/{scan_id}/report?format=json"""
        res = client.get("/api/v1/scan/scan_rep_100/report?format=json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "application/json")
        data = res.json()
        self.assertEqual(data["scan_id"], "scan_rep_100")

    def test_export_and_persist_private_storage(self):
        """Verify export_and_persist stores private report and returns valid presigned download URL metadata."""
        meta = ReportExporter.export_and_persist(self.scan, format_type="markdown", expires_in=900)
        self.assertEqual(meta["scan_id"], "scan_rep_100")
        self.assertEqual(meta["format"], "markdown")
        self.assertTrue(meta["file_key"].startswith("reports/scan_rep_100/"))
        self.assertIn("download_url", meta)
        self.assertEqual(meta["expires_in_seconds"], 900)
        self.assertGreater(meta["byte_size"], 0)

    def test_api_authorized_report_url_endpoint(self):
        """GET /api/v1/scan/{scan_id}/report/url?format=markdown"""
        res = client.get("/api/v1/scan/scan_rep_100/report/url?format=markdown&expires_in=600")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertIn("data", data)
        self.assertEqual(data["data"]["scan_id"], "scan_rep_100")
        self.assertIn("download_url", data["data"])


if __name__ == "__main__":
    unittest.main()
