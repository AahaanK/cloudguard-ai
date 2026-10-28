"""
CloudGuardAI - Unit & Integration Tests for AWS Credential Diagnostics & Status Synchronization
[MOCKED TESTS] Uses mocked AWS STS and Boto3 sessions to verify all diagnostic branches
without requiring live AWS infrastructure.
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import botocore.exceptions
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.aws.session_manager import AWSSessionManager


class TestAWSCredentialDiagnostics(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.manager = AWSSessionManager()

    def test_mocked_no_credentials_available(self):
        """Verifies clear NO_CREDENTIALS diagnosis when environment and profiles are empty."""
        with patch.dict(os.environ, {}, clear=True), \
             patch("os.path.exists", return_value=False), \
             patch("backend.app.aws.session_manager.boto3.Session") as mock_sess:
            
            mock_client = MagicMock()
            mock_client.get_caller_identity.side_effect = botocore.exceptions.NoCredentialsError()
            mock_sess.return_value.client.return_value = mock_client
            mock_sess.return_value.region_name = "us-east-1"

            res = self.manager.verify_identity(force_refresh=True)
            self.assertFalse(res["authenticated"])
            self.assertEqual(res["status"], "NO_CREDENTIALS")
            self.assertEqual(res["error_code"], "NoCredentialsError")
            self.assertIn("No AWS credentials detected", res["message"])
            self.assertIn("PowerShell", res["actionable_guidance"])
            self.assertIsNone(res["account_id"])

    def test_mocked_temporary_asia_key_missing_session_token(self):
        """Verifies immediate detection when ASIA temporary key is provided without session token."""
        env_vars = {
            "AWS_ACCESS_KEY_ID": "ASIAEXAMPLEKEY12345",
            "AWS_SECRET_ACCESS_KEY": "mocksecret1234567890",
            "AWS_REGION": "us-east-1"
        }
        # Explicitly omit AWS_SESSION_TOKEN
        with patch.dict(os.environ, env_vars, clear=True):
            detection = self.manager.detect_credential_provider()
            self.assertTrue(detection["is_temporary_key"])
            self.assertTrue(detection["missing_session_token"])

            res = self.manager.verify_identity(force_refresh=True)
            self.assertFalse(res["authenticated"])
            self.assertEqual(res["status"], "MISSING_SESSION_TOKEN")
            self.assertEqual(res["error_code"], "MissingSessionToken")
            self.assertIn("AWS_SESSION_TOKEN", res["message"])
            self.assertIn("AWS Academy", res["actionable_guidance"])

    def test_mocked_expired_temporary_credentials(self):
        """Verifies distinct EXPIRED_CREDENTIALS diagnosis when STS returns ExpiredToken."""
        with patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "ASIAEXPIRED", "AWS_SECRET_ACCESS_KEY": "sec", "AWS_SESSION_TOKEN": "tok"}):
            with patch.object(self.manager, "get_session") as mock_sess:
                mock_sts = MagicMock()
                mock_sts.get_caller_identity.side_effect = botocore.exceptions.ClientError(
                    {"Error": {"Code": "ExpiredToken", "Message": "The security token included in the request is expired"}},
                    "GetCallerIdentity"
                )
                mock_sess.return_value.client.return_value = mock_sts
                mock_sess.return_value.region_name = "us-east-1"

                res = self.manager.verify_identity(force_refresh=True)
                self.assertFalse(res["authenticated"])
                self.assertEqual(res["status"], "EXPIRED_CREDENTIALS")
                self.assertEqual(res["error_code"], "ExpiredToken")
                self.assertIn("AWS Academy Learner Lab", res["actionable_guidance"])

    def test_mocked_invalid_credentials_error(self):
        """Verifies distinct INVALID_CREDENTIALS diagnosis on InvalidClientTokenId."""
        with patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "AKIAINVALID", "AWS_SECRET_ACCESS_KEY": "bad"}):
            with patch.object(self.manager, "get_session") as mock_sess:
                mock_sts = MagicMock()
                mock_sts.get_caller_identity.side_effect = botocore.exceptions.ClientError(
                    {"Error": {"Code": "InvalidClientTokenId", "Message": "The security token is invalid"}},
                    "GetCallerIdentity"
                )
                mock_sess.return_value.client.return_value = mock_sts
                mock_sess.return_value.region_name = "us-east-1"

                res = self.manager.verify_identity(force_refresh=True)
                self.assertFalse(res["authenticated"])
                self.assertEqual(res["status"], "INVALID_CREDENTIALS")
                self.assertEqual(res["error_code"], "InvalidClientTokenId")
                self.assertIn("invalid or unrecognized", res["actionable_guidance"])

    def test_mocked_permission_denied_sts(self):
        """Verifies distinct PERMISSION_DENIED when identity is active but GetCallerIdentity is rejected."""
        with patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "AKIALOCKED", "AWS_SECRET_ACCESS_KEY": "secret"}):
            with patch.object(self.manager, "get_session") as mock_sess:
                mock_sts = MagicMock()
                mock_sts.get_caller_identity.side_effect = botocore.exceptions.ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Not authorized on sts:GetCallerIdentity"}},
                    "GetCallerIdentity"
                )
                mock_sess.return_value.client.return_value = mock_sts
                mock_sess.return_value.region_name = "us-east-1"

                res = self.manager.verify_identity(force_refresh=True)
                self.assertFalse(res["authenticated"])
                self.assertEqual(res["status"], "PERMISSION_DENIED")
                self.assertEqual(res["error_code"], "AccessDenied")

    def test_mocked_sts_connection_failure(self):
        """Verifies CONNECTION_ERROR on endpoint failure or offline network without crashing."""
        with patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "AKIANETWORK", "AWS_SECRET_ACCESS_KEY": "secret"}):
            with patch.object(self.manager, "get_session") as mock_sess:
                mock_sts = MagicMock()
                mock_sts.get_caller_identity.side_effect = botocore.exceptions.EndpointConnectionError(
                    endpoint_url="https://sts.us-east-1.amazonaws.com"
                )
                mock_sess.return_value.client.return_value = mock_sts
                mock_sess.return_value.region_name = "us-east-1"

                res = self.manager.verify_identity(force_refresh=True)
                self.assertFalse(res["authenticated"])
                self.assertEqual(res["status"], "CONNECTION_ERROR")
                self.assertIn("Unable to reach AWS STS endpoint", res["message"])

    def test_mocked_successful_identity_verification(self):
        """Verifies CONFIGURED_VERIFIED when STS GetCallerIdentity succeeds."""
        with patch.dict(os.environ, {
            "AWS_ACCESS_KEY_ID": "ASIAVALIDACADEMY",
            "AWS_SECRET_ACCESS_KEY": "valid_secret_12345",
            "AWS_SESSION_TOKEN": "valid_session_token_67890",
            "AWS_REGION": "us-east-1"
        }):
            with patch.object(self.manager, "get_session") as mock_sess:
                mock_sts = MagicMock()
                mock_sts.get_caller_identity.return_value = {
                    "Arn": "arn:aws:sts::123456789012:assumed-role/LabRole/aws-session",
                    "Account": "123456789012",
                    "UserId": "AROAVALID:aws-session"
                }
                mock_sess.return_value.client.return_value = mock_sts
                mock_sess.return_value.region_name = "us-east-1"

                res = self.manager.verify_identity(force_refresh=True)
                self.assertTrue(res["authenticated"])
                self.assertEqual(res["status"], "CONFIGURED_VERIFIED")
                self.assertEqual(res["account_id"], "123456789012")
                self.assertEqual(res["arn"], "arn:aws:sts::123456789012:assumed-role/LabRole/aws-session")
                self.assertTrue(res["is_lab_role"])
                self.assertIsNone(res["error_code"])
                self.assertIn("active and verified", res["message"])

    def test_mocked_no_secret_leakage_in_api(self):
        """Verifies secrets are strictly omitted from /api/v1/health and /api/v1/aws/status."""
        test_secret = "SUPER_SECRET_VALUE_DO_NOT_LEAK_9999"
        test_token = "LONG_SECRET_SESSION_TOKEN_DO_NOT_LEAK_8888"

        with patch.dict(os.environ, {
            "AWS_ACCESS_KEY_ID": "AKIALEAKTEST",
            "AWS_SECRET_ACCESS_KEY": test_secret,
            "AWS_SESSION_TOKEN": test_token
        }):
            # Test /api/v1/aws/status
            res_status = self.client.get("/api/v1/aws/status")
            self.assertEqual(res_status.status_code, 200)
            text_status = res_status.text
            self.assertNotIn(test_secret, text_status)
            self.assertNotIn(test_token, text_status)

            # Test /api/aws/status (convenience alias)
            res_alias = self.client.get("/api/aws/status")
            self.assertEqual(res_alias.status_code, 200)

            # Test /api/v1/health
            res_health = self.client.get("/api/v1/health")
            self.assertEqual(res_health.status_code, 200)
            text_health = res_health.text
            self.assertNotIn(test_secret, text_health)
            self.assertNotIn(test_token, text_health)

    def test_mocked_refresh_endpoint(self):
        """Verifies POST /api/v1/aws/refresh returns updated diagnostics."""
        res = self.client.post("/api/v1/aws/refresh")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("status", data)
        self.assertIn("authenticated", data)
        self.assertIn("actionable_guidance", data)


if __name__ == "__main__":
    unittest.main()
