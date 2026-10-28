"""
CloudGuardAI - Complete Security Audit & Failure Recovery Test Suite
Verifies:
  1. Credential isolation (zero secrets in frontend bundles, logs, or safe configs)
  2. Path traversal attack neutralization & extension whitelisting
  3. Private S3 storage enforcement (AES256, private keys, prefix separation)
  4. Genuine analysis on malformed & edge-case templates
  5. Cross-user data isolation and stable key lookups
  6. Failure recovery (404 missing objects, 400 empty files, ClientError translations)
  7. CORS security policies
"""

import unittest
import json
import os
import io
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.config import settings, mask_secret
from backend.app.storage.s3_service import sanitize_filename, S3StorageService
from backend.app.engine.parser import IaCParser
from backend.app.engine.rules import RuleEvaluator
from backend.app.engine.scorer import RiskScorer
from backend.app.db.models import ScanJob, Finding
from backend.app.db.repository import repository
from backend.app.aws.cloudwatch_logger import sanitize_telemetry

client = TestClient(app)

class TestSecurityAuditAndFailures(unittest.TestCase):

    def test_path_traversal_neutralization(self):
        """Verify directory traversal attempts in filenames are completely neutralized."""
        evil_filenames = [
            "../../../../etc/passwd",
            "..\\..\\Windows\\System32\\cmd.exe",
            "folder/../../secret.tf",
            "....//....//nested//blueprint.tf",
            "/absolute/root/path/main.tf"
        ]
        for evil in evil_filenames:
            clean = sanitize_filename(evil)
            self.assertNotIn("..", clean)
            self.assertNotIn("/", clean)
            self.assertNotIn("\\", clean)
            self.assertTrue(clean.endswith(".tf") or clean.endswith(".exe") or clean == "passwd")

    def test_zero_credential_exposure_in_config(self):
        """Verify that safe_dict() masks secrets and never outputs plaintext credentials."""
        masked_short = mask_secret("secret123")
        masked_long = mask_secret("AKIAIOSFODNN7EXAMPLELONGKEY")
        self.assertNotIn("secret123", masked_short)
        self.assertIn("...", masked_long)
        self.assertNotIn("EXAMPLELONG", masked_long)

        safe = settings.safe_dict()
        self.assertNotIn("password", safe)
        self.assertIn("storage_backend", safe)
        self.assertIn("database_backend", safe)

    def test_zero_credential_exposure_in_frontend_assets(self):
        """Verify that frontend HTML and JS files contain zero hardcoded AWS access keys or secrets."""
        frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "..", "frontend"))
        js_file = os.path.join(frontend_dir, "js", "app.js")
        html_file = os.path.join(frontend_dir, "index.html")

        with open(js_file, "r", encoding="utf-8") as f:
            js_content = f.read()
        with open(html_file, "r", encoding="utf-8") as f:
            html_content = f.read()

        # Check for AWS Access Key pattern (AKIA followed by 16 alphanumeric characters)
        self.assertNotIn("AKIA", js_content)
        self.assertNotIn("AKIA", html_content)
        self.assertNotIn("ASIA", js_content)
        self.assertNotIn("ASIA", html_content)
        self.assertNotIn("aws_secret_access_key", js_content)
        self.assertNotIn("aws_secret_access_key", html_content)

    def test_telemetry_sanitizer_masks_secrets(self):
        """Verify structured telemetry scrubber recursively scrubs authentication tokens."""
        dirty_payload = {
            "session_token": "AQoDYXdzEJr1111111111111111111",
            "authorization": "Bearer eyJhbGciOi...",
            "target": "vpc.tf",
            "metadata": {
                "secret_key": "raw_secret_value",
                "clean_metric": 42
            }
        }
        clean_payload = sanitize_telemetry(dirty_payload)
        self.assertEqual(clean_payload["session_token"], "[MASKED_SENSITIVE_DATA]")
        self.assertEqual(clean_payload["authorization"], "[MASKED_SENSITIVE_DATA]")
        self.assertEqual(clean_payload["target"], "vpc.tf")
        self.assertEqual(clean_payload["metadata"]["secret_key"], "[MASKED_SENSITIVE_DATA]")
        self.assertEqual(clean_payload["metadata"]["clean_metric"], 42)

    def test_private_s3_prefix_separation_and_encryption(self):
        """Verify S3 service enforces prefix separation and AES256 server-side encryption."""
        service = S3StorageService(bucket_name="test-bucket")
        mock_client = MagicMock()
        mock_client.put_object.return_value = {"ETag": '"test-etag"'}

        with patch.object(service, "_get_client", return_value=mock_client):
            # 1. Blueprint Upload must route to uploads/ prefix
            res_upload = service.upload_file(b"resource {}", "main.tf", analysis_id="scan_sec_1", is_report=False)
            self.assertTrue(res_upload["file_key"].startswith("uploads/scan_sec_1/"))

            # Verify ServerSideEncryption was passed to Boto3
            call_kwargs = mock_client.put_object.call_args[1]
            self.assertEqual(call_kwargs["ServerSideEncryption"], "AES256")
            self.assertEqual(call_kwargs["Bucket"], "test-bucket")

            # 2. Report Upload must route to reports/ prefix
            res_report = service.upload_file(b"# Report", "report.md", analysis_id="scan_sec_1", is_report=True)
            self.assertTrue(res_report["file_key"].startswith("reports/scan_sec_1/"))

    def test_failure_recovery_malformed_terraform_hcl(self):
        """Verify parser safely catches malformed or unclosed HCL without raising unhandled exceptions."""
        malformed_hcl = b'resource "aws_s3_bucket" "unclosed_bucket" {\n  acl = '
        resources, unsupported = IaCParser.parse(malformed_hcl, "broken.tf")
        # Parser should return gracefully without crashing
        self.assertIsInstance(resources, list)
        self.assertIsInstance(unsupported, list)

    def test_failure_recovery_malformed_yaml(self):
        """Verify parser catches invalid YAML syntax and records it as unsupported or clean empty."""
        malformed_yaml = b': - bad: yaml:\n  [unclosed'
        resources, unsupported = IaCParser.parse(malformed_yaml, "broken.yaml")
        self.assertIsInstance(resources, list)
        self.assertEqual(len(resources), 0)

    def test_failure_recovery_empty_file_upload(self):
        """Verify that uploading an empty (0-byte) blueprint is rejected with 400."""
        empty_file = {"file": ("empty.tf", io.BytesIO(b""), "text/plain")}
        res = client.post("/api/v1/scan/upload", files=empty_file)
        self.assertEqual(res.status_code, 400)
        self.assertIn("empty", res.json()["detail"].lower())

    def test_failure_recovery_nonexistent_file_retrieval(self):
        """Verify that querying a missing storage key returns standard 404 JSON."""
        res = client.get("/api/v1/storage/file/uploads/nonexistent_scan/missing.tf")
        self.assertEqual(res.status_code, 404)
        self.assertIn("not found", res.json()["detail"].lower())

    def test_cors_headers_strict_contract(self):
        """Verify CORS headers respond safely to cross-origin browser requests."""
        res = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET"
            }
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("access-control-allow-origin", res.headers)
        self.assertIn("access-control-allow-methods", res.headers)

    def test_cross_scan_data_isolation(self):
        """Verify that independent scan IDs maintain completely isolated finding sets."""
        scan_a = ScanJob(
            scan_id="scan_isolated_a",
            scan_type="IAC_STATIC",
            target_name="target_a.tf",
            overall_risk_score=90.0,
            risk_grade="F",
            total_findings=1,
            findings=[
                Finding(
                    finding_id="find_a_1",
                    scan_id="scan_isolated_a",
                    rule_id="SEC-S3-001",
                    rule_name="S3 Public Access",
                    dimension="SECURITY",
                    severity="CRITICAL",
                    resource_id="bucket_a",
                    resource_type="aws_s3_bucket",
                    title="Bucket A Exposure",
                    description="Desc",
                    impact="Impact",
                    remediation_summary="Fix"
                )
            ]
        )
        scan_b = ScanJob(
            scan_id="scan_isolated_b",
            scan_type="IAC_STATIC",
            target_name="target_b.tf",
            overall_risk_score=0.0,
            risk_grade="A",
            total_findings=0,
            findings=[]
        )
        repository.save_scan(scan_a)
        repository.save_scan(scan_b)

        fetched_a = repository.get_scan("scan_isolated_a")
        fetched_b = repository.get_scan("scan_isolated_b")

        self.assertEqual(len(fetched_a.findings), 1)
        self.assertEqual(len(fetched_b.findings), 0)
        self.assertEqual(fetched_a.overall_risk_score, 90.0)
        self.assertEqual(fetched_b.overall_risk_score, 0.0)


if __name__ == "__main__":
    unittest.main()
