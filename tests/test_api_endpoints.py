"""
CloudGuardAI - API Endpoint Integration Tests
Tests health status, storage upload route, file download route, and UI serving.
"""

import unittest
from fastapi.testclient import TestClient
import io

from backend.app.main import app

class TestAPIEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_health_check_endpoint(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "HEALTHY")
        self.assertIn("storage_backend", data)
        self.assertIn("aws", data)

    def test_storage_status_endpoint(self):
        response = self.client.get("/api/v1/storage/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("active_backend", data)
        self.assertIn("s3_health", data)

    def test_template_upload_and_download(self):
        tf_content = b'resource "aws_s3_bucket" "test_bucket" {\n  bucket = "my-bucket"\n}\n'
        files = {
            "file": ("main.tf", io.BytesIO(tf_content), "text/plain")
        }
        data = {
            "template_type": "auto"
        }

        # 1. Upload
        upload_resp = self.client.post("/api/v1/storage/upload", files=files, data=data)
        self.assertEqual(upload_resp.status_code, 200)
        res_data = upload_resp.json()
        self.assertTrue(res_data["success"])
        meta = res_data["data"]
        self.assertEqual(meta["filename"], "main.tf")
        self.assertTrue(meta["file_key"].startswith("uploads/"))

        # 2. Retrieve file via API
        file_key = meta["file_key"]
        get_resp = self.client.get(f"/api/v1/storage/file/{file_key}")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.content, tf_content)

    def test_upload_invalid_extension_rejected(self):
        files = {
            "file": ("exploit.exe", io.BytesIO(b"binary data"), "application/octet-stream")
        }
        resp = self.client.post("/api/v1/storage/upload", files=files)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unsupported file type", resp.json()["detail"])

    def test_serve_frontend_index(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("CloudGuardAI", resp.text)
        self.assertIn("coastal.css", resp.text)

if __name__ == "__main__":
    unittest.main()
