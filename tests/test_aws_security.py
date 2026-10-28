"""
CloudGuardAI - Unit Tests for AWS Configuration, Credential Masking & Error Handling
"""

import unittest
from unittest.mock import MagicMock
import botocore.exceptions

from backend.app.config import AWSConfig, AppConfig, mask_secret
from backend.app.aws.error_handler import parse_aws_error
from backend.app.aws.session_manager import AWSSessionManager

class TestAWSSecurity(unittest.TestCase):

    def test_mask_secret(self):
        self.assertEqual(mask_secret(None), "Not Set")
        self.assertEqual(mask_secret(""), "Not Set")
        self.assertEqual(mask_secret("short"), "***")
        
        secret = "AKIAIOSFODNN7EXAMPLE"
        masked = mask_secret(secret, 4, 4)
        self.assertTrue(masked.startswith("AKIA...MPLE"))
        self.assertNotIn("IOSFODNN7EXA", masked)

    def test_config_safe_dict_no_leak(self):
        aws = AWSConfig(
            access_key_id="ASIAXYZ1234567890ABC",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="AQoDYXdzEJr...VERYLONGSESSIONTOKEN",
            region="us-east-1"
        )
        safe = aws.safe_dict()
        
        # Verify secrets are masked
        self.assertNotIn("wJalrXUtnFEMI", str(safe))
        self.assertNotIn("VERYLONGSESSIONTOKEN", str(safe))
        self.assertEqual(safe["secret_access_key"], "Configured (Masked)")
        self.assertEqual(safe["session_token"], "Configured (Masked)")
        self.assertTrue(aws.is_temporary)

    def test_error_handling_expired_token(self):
        mock_error = botocore.exceptions.ClientError(
            error_response={"Error": {"Code": "ExpiredToken", "Message": "The security token included in the request is expired"}},
            operation_name="GetCallerIdentity"
        )
        parsed = parse_aws_error(mock_error, "sts:GetCallerIdentity")
        self.assertEqual(parsed["error_type"], "SESSION_EXPIRED")
        self.assertEqual(parsed["code"], "ExpiredToken")
        self.assertIn("AWS Details", parsed["remediation"])

    def test_error_handling_access_denied_labrole(self):
        mock_error = botocore.exceptions.ClientError(
            error_response={"Error": {"Code": "AccessDenied", "Message": "User is not authorized to perform: iam:CreateRole on resource because of LabRole boundary"}},
            operation_name="iam:CreateRole"
        )
        parsed = parse_aws_error(mock_error, "iam:CreateRole")
        self.assertEqual(parsed["error_type"], "PERMISSION_DENIED")
        self.assertIn("LabRole", parsed["remediation"])

    def test_error_handling_bedrock_unavailable(self):
        mock_error = botocore.exceptions.ClientError(
            error_response={"Error": {"Code": "ModelNotReadyException", "Message": "Foundation model access is not enabled"}},
            operation_name="bedrock:InvokeModel"
        )
        parsed = parse_aws_error(mock_error, "bedrock:InvokeModel")
        self.assertEqual(parsed["error_type"], "BEDROCK_UNAVAILABLE")
        self.assertIn("deterministic engine", parsed["remediation"])

    def test_session_manager_offline_resilience(self):
        mgr = AWSSessionManager()
        identity = mgr.verify_identity(force_refresh=True)
        # Should gracefully return dict with authenticated=False, not throw an unhandled exception
        self.assertIsInstance(identity, dict)
        self.assertIn("authenticated", identity)

if __name__ == "__main__":
    unittest.main()
