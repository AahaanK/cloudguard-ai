"""
CloudGuardAI - Unit Tests for Amazon S3 Storage Service & Unified Fallback
Uses mocked Boto3 clients to verify encryption, file validation, presigned URLs,
safe object keys, and local resilient fallback without touching live cloud resources.
"""

import unittest
from unittest.mock import MagicMock, patch
import botocore.exceptions
import os

from backend.app.storage.s3_service import S3StorageService, sanitize_filename
from backend.app.storage.local_storage import LocalStorageService
from backend.app.storage.manager import StorageManager

class TestS3StorageService(unittest.TestCase):

    def setUp(self):
        self.service = S3StorageService(bucket_name="cloudguardai-test-bucket")

    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("main.tf"), "main.tf")
        self.assertEqual(sanitize_filename("my cloud$infra?.tf"), "my_cloud_infra_.tf")

    def test_file_type_validation_accepted(self):
        # Valid Terraform and CloudFormation
        name, ctype = self.service.validate_file("main.tf", b"resource \"aws_s3_bucket\" \"b\" {}")
        self.assertEqual(name, "main.tf")
        self.assertEqual(ctype, "text/plain")

        name, ctype = self.service.validate_file("template.yaml", b"AWSTemplateFormatVersion: '2010-09-09'")
        self.assertEqual(ctype, "application/x-yaml")

        name, ctype = self.service.validate_file("infra.tf.json", b"{}")
        self.assertEqual(ctype, "application/json")

    def test_file_type_validation_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.service.validate_file("malicious.exe", b"MZ...")
        self.assertIn("Unsupported file type", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            self.service.validate_file("empty.tf", b"")
        self.assertIn("empty", str(ctx.exception))

        oversized = b"A" * (11 * 1024 * 1024)
        with self.assertRaises(ValueError) as ctx:
            self.service.validate_file("large.tf", oversized)
        self.assertIn("exceeds maximum", str(ctx.exception))

    @patch("backend.app.storage.s3_service.aws_session_manager.get_client")
    def test_s3_upload_success_with_encryption(self, mock_get_client):
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3
        mock_s3.generate_presigned_url.return_value = "https://s3.amazonaws.com/test-bucket/uploads/123/main.tf?AWSAccessKeyId=..."

        content = b'resource "aws_s3_bucket" "test" {}'
        res = self.service.upload_file(content=content, filename="main.tf", analysis_id="test_analysis_123")

        self.assertEqual(res["bucket"], "cloudguardai-test-bucket")
        self.assertEqual(res["file_key"], "uploads/test_analysis_123/main.tf")
        self.assertTrue(res["encrypted"])
        self.assertEqual(res["storage_backend"], "s3")
        self.assertIn("presigned_url", res)

        # Assert put_object called with ServerSideEncryption='AES256'
        mock_s3.put_object.assert_called_once()
        call_kwargs = mock_s3.put_object.call_args[1]
        self.assertEqual(call_kwargs["ServerSideEncryption"], "AES256")
        self.assertEqual(call_kwargs["Bucket"], "cloudguardai-test-bucket")
        self.assertEqual(call_kwargs["Key"], "uploads/test_analysis_123/main.tf")

    @patch("backend.app.storage.s3_service.aws_session_manager.get_client")
    def test_s3_upload_handles_nosuchbucket(self, mock_get_client):
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3
        mock_s3.put_object.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "NoSuchBucket", "Message": "The specified bucket does not exist"}},
            "PutObject"
        )

        with self.assertRaises(RuntimeError) as ctx:
            self.service.upload_file(content=b"content", filename="main.tf")
        self.assertIn("NoSuchBucket", str(ctx.exception))

    @patch("backend.app.storage.s3_service.aws_session_manager.get_client")
    def test_presigned_download_url_generation(self, mock_get_client):
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3
        mock_s3.generate_presigned_url.return_value = "https://s3.amazonaws.com/test-presigned-url"

        url = self.service.generate_presigned_download_url("uploads/123/main.tf", expiration_seconds=600)
        self.assertEqual(url, "https://s3.amazonaws.com/test-presigned-url")
        mock_s3.generate_presigned_url.assert_called_once_with(
            ClientMethod="get_object",
            Params={"Bucket": "cloudguardai-test-bucket", "Key": "uploads/123/main.tf"},
            ExpiresIn=600
        )

class TestStorageManagerFallback(unittest.TestCase):

    def setUp(self):
        self.manager = StorageManager()
        # Force fallback to local
        self.manager.prefer_s3 = False

    def test_local_storage_store_and_retrieve(self):
        content = b'resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }'
        result = self.manager.store_file(content=content, filename="vpc.tf", analysis_id="test_local_999")

        self.assertEqual(result["storage_backend"], "local")
        self.assertTrue(result["file_key"].startswith("uploads/test_local_999/vpc.tf"))

        # Retrieve file
        read_content, ctype = self.manager.retrieve_file(result["file_key"])
        self.assertEqual(read_content, content)
        self.assertEqual(ctype, "text/plain")

if __name__ == "__main__":
    unittest.main()
