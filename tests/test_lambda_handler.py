"""
CloudGuardAI - Unit Tests for AWS Lambda Asynchronous Analysis Worker
Tests:
  1. S3 Event notification handler (s3:ObjectCreated:* on uploads/)
  2. Direct JSON invocation payload
  3. Recursive trigger prevention (blocking reports/ prefix)
  4. Idempotent execution (returning cached result on re-runs)
  5. Error state persistence (marking scan FAILED on retrieval error)
  6. Asynchronous REST endpoint (POST /api/v1/scan/async)
"""

import unittest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import io
import json
import uuid

from backend.app.main import app
from backend.app.lambda_handler import lambda_handler, process_analysis_job
from backend.app.storage.manager import storage_manager
from backend.app.db.repository import repository

SAMPLE_TF = b"""
resource "aws_s3_bucket" "test_vault" {
  bucket = "test-vault"
  acl    = "private"
  server_side_encryption_configuration = "AES256"
}
"""

class TestLambdaHandler(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.test_id = f"test_{uuid.uuid4().hex[:8]}"
        self.store_res = storage_manager.store_file(
            content=SAMPLE_TF,
            filename="lambda_test.tf",
            analysis_id=self.test_id,
            is_report=False
        )
        self.file_key = self.store_res["file_key"]

    def test_s3_event_trigger(self):
        """Simulates an S3:ObjectCreated:* event notification."""
        s3_event = {
            "Records": [
                {
                    "eventSource": "aws:s3",
                    "eventName": "ObjectCreated:Put",
                    "s3": {
                        "bucket": {"name": "cloudguardai-test-bucket"},
                        "object": {"key": self.file_key}
                    }
                }
            ]
        }
        res = lambda_handler(s3_event, context=None)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        self.assertEqual(body["mode"], "S3_EVENT")
        self.assertEqual(body["results"][0]["status"], "SUCCESS")
        self.assertEqual(body["results"][0]["analysis_id"], self.test_id)

    def test_direct_json_invocation(self):
        """Tests direct invocation with a JSON payload."""
        event = {
            "file_key": self.file_key,
            "analysis_id": self.test_id
        }
        res = lambda_handler(event, context=None)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        self.assertIn(body["status"], ["SUCCESS", "ALREADY_COMPLETED"])

    def test_recursive_trigger_prevention(self):
        """Verifies that events for keys in reports/ are blocked to prevent recursive loops."""
        event = {
            "file_key": f"reports/{self.test_id}/audit_report.pdf"
        }
        res = lambda_handler(event, context=None)
        body = json.loads(res["body"])
        self.assertEqual(body["status"], "SKIPPED")
        self.assertIn("Recursive trigger blocked", body["message"])

    def test_idempotent_execution(self):
        """Verifies that re-running on a completed job returns cached result."""
        # Run first time
        first_id = f"idemp_{uuid.uuid4().hex[:8]}"
        process_analysis_job(self.file_key, first_id)
        # Run second time
        second_run = process_analysis_job(self.file_key, first_id)
        self.assertEqual(second_run["status"], "ALREADY_COMPLETED")

    def test_error_handling_nonexistent_key(self):
        """Verifies missing file marks scan as FAILED without throwing an unhandled exception."""
        fail_id = f"fail_{uuid.uuid4().hex[:8]}"
        result = process_analysis_job("uploads/scan_missing/nonexistent.tf", fail_id)
        self.assertEqual(result["status"], "FAILED")

        saved = repository.get_scan(fail_id)
        self.assertIsNotNone(saved)
        self.assertEqual(saved.status, "FAILED")

    def test_async_rest_api_endpoint(self):
        """Verifies POST /api/v1/scan/async returns HTTP 202 Accepted."""
        files = {
            "file": ("async_infra.tf", io.BytesIO(SAMPLE_TF), "text/plain")
        }
        resp = self.client.post("/api/v1/scan/async", files=files)
        self.assertEqual(resp.status_code, 202)
        data = resp.json()
        self.assertEqual(data["status"], "PENDING")
        self.assertTrue(data["scan_id"].startswith("scan_async_"))

if __name__ == "__main__":
    unittest.main()
