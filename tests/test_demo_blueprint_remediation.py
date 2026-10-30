import unittest
from fastapi.testclient import TestClient
from backend.app.main import app

BLUEPRINT_FIXTURE = """# CloudGuardAI Moderate-to-High Risk Test Blueprint
terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}

resource "aws_s3_bucket" "demo_data_bucket" {
  bucket = "cloudguardai-demo-risk-bucket-change-me"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "demo_data_bucket_encryption" {
  bucket = aws_s3_bucket.demo_data_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "demo_data_bucket_public_access" {
  bucket = aws_s3_bucket.demo_data_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "demo_public_read_policy" {
  bucket = aws_s3_bucket.demo_data_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadForRiskDemo"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.demo_data_bucket.arn}/*"
    }]
  })
}

resource "aws_iam_policy" "demo_overly_broad_policy" {
  name        = "cloudguardai-demo-overly-broad-policy"
  description = "INSECURE TEST FIXTURE ONLY - do not attach or deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_security_group" "demo_open_admin_access" {
  name        = "cloudguardai-demo-open-admin-access"
  description = "INSECURE TEST FIXTURE ONLY - unrestricted SSH"

  ingress {
    description = "Intentionally unrestricted SSH for static-analysis testing"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

class TestDemoBlueprintRemediation(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_moderate_high_risk_blueprint_full_lifecycle(self):
        # 1. Upload blueprint
        resp = self.client.post(
            "/api/v1/scan/upload",
            files={"file": ("cloudguardai_moderate_high_risk_blueprint.tf", BLUEPRINT_FIXTURE.encode("utf-8"), "text/plain")}
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()["data"]
        scan_id = data["scan_id"]
        self.assertEqual(data["overall_risk_score"], 70.0)
        self.assertEqual(data["risk_grade"], "D")
        self.assertEqual(len(data["findings"]), 2)

        finding_rules = {f["rule_id"]: f["finding_id"] for f in data["findings"]}
        self.assertIn("NET-SG-001", finding_rules)
        self.assertIn("IAM-POL-001", finding_rules)

        # 2. Preview and approve NET-SG-001
        sg_fid = finding_rules["NET-SG-001"]
        prev_sg = self.client.post(f"/api/v1/scan/{scan_id}/findings/{sg_fid}/remediation/preview")
        self.assertEqual(prev_sg.status_code, 200, prev_sg.text)
        self.assertTrue(prev_sg.json()["validation"]["target_finding_resolved"])

        app_sg = self.client.post(f"/api/v1/scan/{scan_id}/findings/{sg_fid}/remediation/approve")
        self.assertEqual(app_sg.status_code, 200)

        # 3. Preview and approve IAM-POL-001
        iam_fid = finding_rules["IAM-POL-001"]
        prev_iam = self.client.post(f"/api/v1/scan/{scan_id}/findings/{iam_fid}/remediation/preview")
        self.assertEqual(prev_iam.status_code, 200, prev_iam.text)
        self.assertTrue(prev_iam.json()["validation"]["target_finding_resolved"])

        app_iam = self.client.post(f"/api/v1/scan/{scan_id}/findings/{iam_fid}/remediation/approve")
        self.assertEqual(app_iam.status_code, 200)

        # 4. Trigger Rescan & Verification
        rescan = self.client.post(f"/api/v1/scan/{scan_id}/remediation/verify-rescan")
        self.assertEqual(rescan.status_code, 200, rescan.text)
        rescan_data = rescan.json()
        self.assertTrue(rescan_data["success"])

        cmp = rescan_data["comparison"]
        self.assertEqual(cmp["score_before"], 70.0)
        self.assertEqual(cmp["score_after"], 0.0)
        self.assertEqual(cmp["grade_after"], "A")
        self.assertEqual(cmp["resolved_count"], 2)
        self.assertEqual(cmp["unresolved_count"], 0)

        rem_scan = rescan_data["remediated_scan"]
        self.assertEqual(rem_scan["overall_risk_score"], 0.0)
        self.assertEqual(rem_scan["risk_grade"], "A")
        self.assertEqual(rem_scan["total_findings"], 0)
        self.assertEqual(rem_scan["target_name"], "remediated_cloudguardai_moderate_high_risk_blueprint.tf")

        # 5. Export corrected blueprint
        export = self.client.get(f"/api/v1/scan/{scan_id}/remediation/export?download=true")
        self.assertEqual(export.status_code, 200)
        exported_text = export.text
        self.assertIn("10.0.0.0/16", exported_text)
        self.assertNotIn('Action   = "*"', exported_text)

        # 6. Check that rescanning the remediated scan does not duplicate target_name
        rescan_again = self.client.post(f"/api/v1/scan/{rem_scan['scan_id']}/remediation/verify-rescan")
        self.assertEqual(rescan_again.status_code, 200)
        self.assertEqual(
            rescan_again.json()["remediated_scan"]["target_name"],
            "remediated_cloudguardai_moderate_high_risk_blueprint.tf"
        )

if __name__ == "__main__":
    unittest.main()
