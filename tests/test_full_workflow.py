"""
CloudGuardAI - End-to-End Workflow & Integration Tests
Tests full blueprint upload -> IaC parsing -> 7-dimension rule evaluation -> scoring -> DB persistence -> report export.
"""

import unittest
from fastapi.testclient import TestClient
import io

from backend.app.main import app

VULNERABLE_TERRAFORM = b"""
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "company-sensitive-data"
  acl    = "public-read"
}

resource "aws_security_group" "allow_ssh_world" {
  name        = "allow_ssh"
  description = "Allow SSH from world"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "prod_database" {
  identifier          = "production-db"
  instance_class      = "db.t3.medium"
  publicly_accessible = true
  multi_az            = false
  deletion_protection = false
}

resource "aws_instance" "large_web_server" {
  instance_type = "c5.8xlarge"
  ami           = "ami-0c55b159cbfafe1f0"
}
"""

class TestFullWorkflow(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_full_analysis_workflow(self):
        # 1. Upload & Analyze Blueprint
        files = {
            "file": ("vulnerable_infra.tf", io.BytesIO(VULNERABLE_TERRAFORM), "text/plain")
        }
        res = self.client.post("/api/v1/scan/upload", files=files)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        scan = data["data"]

        scan_id = scan["scan_id"]
        self.assertTrue(scan["overall_risk_score"] > 50.0)
        self.assertIn(scan["risk_grade"], ["C", "D", "F"])
        self.assertTrue(scan["critical_count"] >= 2) # S3 public + SG SSH open + RDS public
        self.assertTrue(len(scan["findings"]) >= 4)

        # 2. Retrieve Specific Scan Details
        detail_res = self.client.get(f"/api/v1/scan/{scan_id}")
        self.assertEqual(detail_res.status_code, 200)
        detail_data = detail_res.json()["data"]
        self.assertEqual(detail_data["scan_id"], scan_id)
        
        # Check that remediation code exists on findings
        has_remediation = any(f["remediation_summary"] for f in detail_data["findings"])
        self.assertTrue(has_remediation)

        # 3. Check Global Summary Metrics
        metrics_res = self.client.get("/api/v1/scan/metrics/summary")
        self.assertEqual(metrics_res.status_code, 200)
        m = metrics_res.json()
        self.assertTrue(m["total_scans"] >= 1)
        self.assertTrue(m["total_critical"] >= 2)

        # 4. Check Historical Listing
        history_res = self.client.get("/api/v1/scan/scans")
        self.assertEqual(history_res.status_code, 200)
        hist_list = history_res.json()["scans"]
        self.assertTrue(any(s["scan_id"] == scan_id for s in hist_list))

        # 5. Export Report (Markdown, JSON, HTML)
        md_res = self.client.get(f"/api/v1/scan/{scan_id}/report?format=markdown")
        self.assertEqual(md_res.status_code, 200)
        self.assertIn("CloudGuardAI Security & Architecture Audit Report", md_res.text)

        html_res = self.client.get(f"/api/v1/scan/{scan_id}/report?format=html")
        self.assertEqual(html_res.status_code, 200)
        self.assertIn("<!DOCTYPE html>", html_res.text)

        json_res = self.client.get(f"/api/v1/scan/{scan_id}/report?format=json")
        self.assertEqual(json_res.status_code, 200)
        self.assertIn("scan_id", json_res.json())

if __name__ == "__main__":
    unittest.main()
