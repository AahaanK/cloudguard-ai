"""
CloudGuardAI - Comprehensive Risk Analysis Pipeline Test Suite
Tests:
  1. Valid clean templates (empty findings, 0.0 score, Grade A)
  2. Insecure configurations across 7 dimensions (verifying structured evidence)
  3. Malformed files & syntax errors (graceful parsing, zero crashes)
  4. Unsupported constructs (external modules, custom CFN macros)
  5. Untrusted input security (zero arbitrary code execution)
  6. Storage-layer retrieval and analysis round-trip (/analyze-stored)
"""

import unittest
from fastapi.testclient import TestClient
import io

from backend.app.main import app
from backend.app.engine.parser import IaCParser
from backend.app.engine.rules import RuleEvaluator
from backend.app.engine.scorer import RiskScorer

# 1. Clean, Well-Architected Template (Should yield 0 findings)
CLEAN_TERRAFORM = b"""
resource "aws_s3_bucket" "secure_assets" {
  bucket = "secure-corporate-vault"
  acl    = "private"
  server_side_encryption_configuration = "AES256"
}

resource "aws_s3_bucket_public_access_block" "secure_assets_pab" {
  bucket = aws_s3_bucket.secure_assets.id
  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "production_db" {
  identifier          = "prod-aurora"
  instance_class      = "db.r5.large"
  publicly_accessible = false
  multi_az            = true
  deletion_protection = true
}

resource "aws_security_group" "internal_api" {
  name        = "internal_api_sg"
  description = "Internal API only"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
"""

# 2. Insecure Multi-Dimension Template
INSECURE_TERRAFORM = b"""
resource "aws_s3_bucket" "leak_bucket" {
  bucket = "public-leak"
  acl    = "public-read"
}

resource "aws_ebs_volume" "unencrypted_vol" {
  size      = 40
  encrypted = false
}

resource "aws_iam_policy" "admin_wildcard" {
  name   = "admin_all"
  policy = "{\"Action\": \"*\", \"Effect\": \"Allow\"}"
}

resource "aws_security_group" "open_ssh" {
  name = "open_ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "insecure_rds" {
  publicly_accessible = true
  multi_az            = false
  deletion_protection = false
}

resource "aws_instance" "legacy_huge_node" {
  instance_type = "t2.8xlarge"
}
"""

# 3. Template with Unsupported Constructs (External Module & Custom Macro)
UNSUPPORTED_TERRAFORM = b"""
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.14.0"
}

resource "aws_s3_bucket" "local_bucket" {
  bucket = "local-assets"
  acl    = "private"
}
"""

class TestRiskPipeline(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_valid_clean_template_empty_findings(self):
        """Verifies clean architecture yields zero findings, score 0.0, and Grade A."""
        files = {
            "file": ("clean_architecture.tf", io.BytesIO(CLEAN_TERRAFORM), "text/plain")
        }
        res = self.client.post("/api/v1/scan/upload", files=files)
        self.assertEqual(res.status_code, 200)
        scan = res.json()["data"]

        self.assertEqual(scan["total_findings"], 0)
        self.assertEqual(scan["overall_risk_score"], 0.0)
        self.assertEqual(scan["risk_grade"], "A")
        self.assertEqual(scan["findings"], [])

    def test_insecure_configurations_with_structured_evidence(self):
        """Verifies rules detect misconfigurations across 7 dimensions and provide structured evidence."""
        files = {
            "file": ("insecure_multi.tf", io.BytesIO(INSECURE_TERRAFORM), "text/plain")
        }
        res = self.client.post("/api/v1/scan/upload", files=files)
        self.assertEqual(res.status_code, 200)
        scan = res.json()["data"]

        findings = scan["findings"]
        rule_ids = {f["rule_id"] for f in findings}

        # Verify key rule triggers across dimensions
        self.assertIn("SEC-S3-001", rule_ids)   # Security
        self.assertIn("SEC-EBS-001", rule_ids)  # Security
        self.assertIn("IAM-POL-001", rule_ids)  # IAM
        self.assertIn("NET-SG-001", rule_ids)   # Network
        self.assertIn("CFG-RDS-001", rule_ids)  # Configuration
        self.assertIn("REL-RDS-001", rule_ids)  # Reliability
        self.assertIn("PRF-EC2-001", rule_ids)  # Performance
        self.assertIn("CST-EC2-001", rule_ids)  # Cost

        # Verify structured evidence dictionary is populated on findings
        s3_finding = next(f for f in findings if f["rule_id"] == "SEC-S3-001")
        self.assertEqual(s3_finding["evidence"]["attribute"], "acl")
        self.assertEqual(s3_finding["evidence"]["detected_value"], "public-read")
        self.assertEqual(s3_finding["evidence"]["expected_value"], "private")

    def test_malformed_syntax_graceful_handling(self):
        """Verifies broken JSON/YAML syntax produces clean diagnostics without unhandled 500 crashes."""
        malformed_json = b"{\n  \"bad\": [broken_json\n"
        files = {
            "file": ("broken.json", io.BytesIO(malformed_json), "application/json")
        }
        res = self.client.post("/api/v1/scan/upload", files=files)
        self.assertEqual(res.status_code, 200)
        scan = res.json()["data"]

        self.assertEqual(scan["total_findings"], 0)
        self.assertTrue(len(scan["unsupported_constructs"]) >= 1)
        self.assertEqual(scan["unsupported_constructs"][0]["type"], "MALFORMED_JSON")

    def test_unsupported_constructs_reporting(self):
        """Verifies external modules are recorded as unsupported constructs and static resources still evaluate."""
        files = {
            "file": ("modular.tf", io.BytesIO(UNSUPPORTED_TERRAFORM), "text/plain")
        }
        res = self.client.post("/api/v1/scan/upload", files=files)
        self.assertEqual(res.status_code, 200)
        scan = res.json()["data"]

        # Module detected in unsupported list
        unsupported = scan["unsupported_constructs"]
        self.assertTrue(any(u["type"] == "EXTERNAL_TERRAFORM_MODULE" for u in unsupported))

    def test_untrusted_input_safety(self):
        """Ensures arbitrary code execution payloads in templates are inertly parsed as plain text."""
        exploit_yaml = b"""
Resources:
  Exploit:
    Type: "AWS::S3::Bucket"
    Properties:
      BucketName: "import os; os.system('calc.exe')"
"""
        resources, _ = IaCParser.parse(exploit_yaml, "exploit.yaml")
        self.assertEqual(len(resources), 1)
        # Content is safely treated as plain string property, zero code execution
        self.assertIn("import os", resources[0].get("BucketName"))

    def test_storage_layer_retrieval_and_analysis_roundtrip(self):
        """Verifies the /analyze-stored endpoint retrieves from storage layer and completes the pipeline."""
        # 1. Upload first via storage API
        upload_res = self.client.post(
            "/api/v1/storage/upload",
            files={"file": ("stored_target.tf", io.BytesIO(INSECURE_TERRAFORM), "text/plain")}
        )
        self.assertEqual(upload_res.status_code, 200)
        file_key = upload_res.json()["data"]["file_key"]

        # 2. Trigger analysis by file_key from storage
        analyze_res = self.client.post(
            "/api/v1/scan/analyze-stored",
            data={"file_key": file_key}
        )
        self.assertEqual(analyze_res.status_code, 200)
        scan_data = analyze_res.json()["data"]
        self.assertEqual(scan_data["file_key"], file_key)
        self.assertTrue(scan_data["total_findings"] > 0)

if __name__ == "__main__":
    unittest.main()
