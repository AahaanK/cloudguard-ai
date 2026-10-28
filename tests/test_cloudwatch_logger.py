"""
CloudGuardAI - Amazon CloudWatch Audit Logging Unit Tests
Tests telemetry sanitization (masking credentials/tokens), local fallback,
and CloudWatch Logs delivery with mock Boto3 clients.
"""

import unittest
from unittest.mock import patch, MagicMock
import botocore.exceptions

from backend.app.aws.cloudwatch_logger import CloudWatchAuditLogger, sanitize_telemetry

class TestCloudWatchLogger(unittest.TestCase):

    def setUp(self):
        self.logger = CloudWatchAuditLogger()

    def test_sanitize_telemetry_masks_credentials(self):
        """Verify sensitive keys are never exposed in log payloads."""
        raw_payload = {
            "target": "vpc.tf",
            "access_key": "AKIA12345678EXAMPLE",
            "session_token": "AQoDYXdzEJr11111111",
            "password": "SuperSecretPassword123!",
            "nested": {
                "secret_key": "TopSecretValue",
                "risk_score": 75.0
            }
        }
        clean = sanitize_telemetry(raw_payload)
        self.assertEqual(clean["target"], "vpc.tf")
        self.assertEqual(clean["access_key"], "[MASKED_SENSITIVE_DATA]")
        self.assertEqual(clean["session_token"], "[MASKED_SENSITIVE_DATA]")
        self.assertEqual(clean["password"], "[MASKED_SENSITIVE_DATA]")
        self.assertEqual(clean["nested"]["secret_key"], "[MASKED_SENSITIVE_DATA]")
        self.assertEqual(clean["nested"]["risk_score"], 75.0)

    @patch("backend.app.aws.cloudwatch_logger.aws_session_manager.verify_identity")
    def test_log_audit_event_offline_fallback(self, mock_identity):
        """When unauthenticated, log event delivers to local stdout without errors."""
        mock_identity.return_value = {"authenticated": False}
        res = self.logger.log_audit_event("SCAN_STARTED", "scan_123", {"target": "main.tf"})
        self.assertTrue(res["logged"])
        self.assertEqual(res["destination"], "LOCAL_STDOUT")

    @patch("backend.app.aws.cloudwatch_logger.aws_session_manager.verify_identity")
    def test_log_audit_event_cloudwatch_success(self, mock_identity):
        """When authenticated, attempts delivery to CloudWatch Logs."""
        mock_identity.return_value = {"authenticated": True, "account_id": "123456789012"}

        mock_client = MagicMock()
        mock_client.create_log_group.return_value = {}
        mock_client.create_log_stream.return_value = {}
        mock_client.put_log_events.return_value = {"nextSequenceToken": "token123"}

        with patch.object(self.logger, "_get_client", return_value=mock_client):
            self.logger._stream_initialized = False
            res = self.logger.log_audit_event("SCAN_COMPLETED", "scan_456", {"risk_score": 10.0})
            self.assertTrue(res["logged"])
            self.assertEqual(res["destination"], "CLOUDWATCH")
            self.assertTrue(mock_client.put_log_events.called)

    @patch("backend.app.aws.cloudwatch_logger.aws_session_manager.verify_identity")
    def test_log_audit_event_learner_lab_access_denied_fallback(self, mock_identity):
        """When AWS Academy blocks logs:PutLogEvents, falls back gracefully."""
        mock_identity.return_value = {"authenticated": True, "account_id": "123456789012"}

        mock_client = MagicMock()
        mock_client.create_log_group.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Not authorized under LabRole"}},
            "CreateLogGroup"
        )
        mock_client.put_log_events.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Not authorized under LabRole"}},
            "PutLogEvents"
        )

        with patch.object(self.logger, "_get_client", return_value=mock_client):
            self.logger._stream_initialized = False
            res = self.logger.log_audit_event("SCAN_COMPLETED", "scan_789", {"risk_score": 50.0})
            self.assertTrue(res["logged"])
            self.assertEqual(res["destination"], "LOCAL_FALLBACK")


if __name__ == "__main__":
    unittest.main()
