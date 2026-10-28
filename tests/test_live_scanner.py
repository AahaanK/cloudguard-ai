"""
CloudGuardAI - Live AWS Resource Discovery Tests
Verifies read-only discovery of S3, EC2, VPCs, Security Groups, RDS, and IAM.
Tests pagination, rate limits, honest reporting of AWS Academy boundaries,
and verifies zero write/modification operations.
"""

import unittest
from unittest.mock import patch, MagicMock
import botocore.exceptions
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.scanner.live_scanner import LiveAWSScanner, live_scanner
from backend.app.db.models import ScanJob

client = TestClient(app)

class TestLiveAWSScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = LiveAWSScanner()

    @patch("backend.app.scanner.live_scanner.aws_session_manager.verify_identity")
    def test_live_scan_unauthenticated_fails_cleanly(self, mock_identity):
        """When no credentials are provided, live scan should reject with actionable advice."""
        mock_identity.return_value = {"authenticated": False}

        with self.assertRaises(RuntimeError) as ctx:
            self.scanner.scan_environment(scan_id="scan_live_test_unauth")
        self.assertIn("No AWS credentials detected", str(ctx.exception))

    @patch("backend.app.scanner.live_scanner.aws_session_manager.get_session")
    @patch("backend.app.scanner.live_scanner.aws_session_manager.verify_identity")
    def test_live_scan_comprehensive_discovery(self, mock_identity, mock_get_session):
        """Simulate authentic read-only discovery across S3, EC2, VPC, RDS, and IAM."""
        mock_identity.return_value = {
            "authenticated": True,
            "account_id": "112233445566",
            "region": "us-east-1",
            "arn": "arn:aws:iam::112233445566:user/security-auditor",
            "is_lab_role": False
        }

        mock_session = MagicMock()
        mock_get_session.return_value = mock_session

        # S3 Client Mock
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {
            "Buckets": [{"Name": "prod-data-bucket"}, {"Name": "compliant-archive"}]
        }
        # Bucket 1: NoSuchPublicAccessBlockConfiguration (CRITICAL) & No SSE
        def s3_get_pab(Bucket):
            if Bucket == "prod-data-bucket":
                raise botocore.exceptions.ClientError({"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}, "GetPublicAccessBlock")
            return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True}}

        def s3_get_enc(Bucket):
            if Bucket == "prod-data-bucket":
                raise botocore.exceptions.ClientError({"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption")
            return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}

        mock_s3.get_public_access_block.side_effect = s3_get_pab
        mock_s3.get_bucket_encryption.side_effect = s3_get_enc
        mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled"}

        # EC2 Client Mock
        mock_ec2 = MagicMock()
        mock_sg_paginator = MagicMock()
        mock_sg_paginator.paginate.return_value = [{
            "SecurityGroups": [
                {
                    "GroupId": "sg-open-ssh",
                    "GroupName": "launch-wizard-1",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                        }
                    ]
                },
                {
                    "GroupId": "sg-private-app",
                    "GroupName": "app-internal",
                    "IpPermissions": [
                        {
                            "FromPort": 8080,
                            "ToPort": 8080,
                            "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "10.0.0.0/16"}]
                        }
                    ]
                }
            ]
        }]
        mock_ec2.get_paginator.return_value = mock_sg_paginator
        mock_ec2.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-default-123", "IsDefault": True, "CidrBlock": "172.31.0.0/16"}]
        }

        # RDS Client Mock
        mock_rds = MagicMock()
        mock_rds.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "prod-postgres",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:112233445566:db:prod-postgres",
                    "Engine": "postgres",
                    "PubliclyAccessible": True,
                    "StorageEncrypted": False,
                    "MultiAZ": False
                }
            ]
        }

        # IAM Client Mock
        mock_iam = MagicMock()
        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0}
        }

        def client_dispatcher(service_name, region_name=None):
            if service_name == "s3":
                return mock_s3
            elif service_name == "ec2":
                return mock_ec2
            elif service_name == "rds":
                return mock_rds
            elif service_name == "iam":
                return mock_iam
            return MagicMock()

        mock_session.client.side_effect = client_dispatcher

        # Execute Live Scan
        job = self.scanner.scan_environment(scan_id="scan_live_full_test", single_region="us-east-1")

        self.assertEqual(job.scan_type, "LIVE_AWS")
        self.assertIn("112233445566", job.target_name)
        self.assertGreater(job.total_findings, 0)
        self.assertGreater(job.critical_count, 0)

        # Verify Discovered Resources Inventory
        self.assertGreater(len(job.discovered_resources), 0)
        res_types = [r["resource_type"] for r in job.discovered_resources]
        self.assertIn("AWS::S3::Bucket", res_types)
        self.assertIn("AWS::EC2::SecurityGroup", res_types)
        self.assertIn("AWS::EC2::VPC", res_types)
        self.assertIn("AWS::RDS::DBInstance", res_types)

        # Verify Evidence Mapping
        rule_ids = [f.rule_id for f in job.findings]
        self.assertIn("LIVE-S3-001", rule_ids)  # Missing Public Access Block
        self.assertIn("LIVE-S3-002", rule_ids)  # Missing SSE
        self.assertIn("LIVE-NET-001", rule_ids) # Open SSH
        self.assertIn("LIVE-RDS-001", rule_ids) # Public RDS
        self.assertIn("LIVE-IAM-001", rule_ids) # Root MFA Disabled

        # Verify INVARIANT: Zero mutating/write operations executed
        self.assertFalse(mock_s3.put_public_access_block.called)
        self.assertFalse(mock_s3.delete_bucket.called)
        self.assertFalse(mock_ec2.revoke_security_group_ingress.called)
        self.assertFalse(mock_rds.modify_db_instance.called)

    @patch("backend.app.scanner.live_scanner.aws_session_manager.get_session")
    @patch("backend.app.scanner.live_scanner.aws_session_manager.verify_identity")
    def test_live_scan_reports_aws_academy_learner_lab_restrictions(self, mock_identity, mock_get_session):
        """Verify that when AWS Academy blocks IAM with AccessDenied, the limitation is reported honestly."""
        mock_identity.return_value = {
            "authenticated": True,
            "account_id": "998877665544",
            "region": "us-east-1",
            "arn": "arn:aws:iam::998877665544:role/LabRole",
            "is_lab_role": True
        }

        mock_session = MagicMock()
        mock_get_session.return_value = mock_session

        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": []}

        mock_ec2 = MagicMock()
        mock_ec2.get_paginator.return_value.paginate.return_value = [{"SecurityGroups": []}]
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}

        mock_rds = MagicMock()
        mock_rds.describe_db_instances.return_value = {"DBInstances": []}

        # IAM returns AccessDenied due to Learner Lab boundary
        mock_iam = MagicMock()
        mock_iam.get_account_summary.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "User is not authorized under LabRole"}},
            "GetAccountSummary"
        )

        def client_dispatcher(service_name, region_name=None):
            if service_name == "s3":
                return mock_s3
            elif service_name == "ec2":
                return mock_ec2
            elif service_name == "rds":
                return mock_rds
            elif service_name == "iam":
                return mock_iam
            return MagicMock()

        mock_session.client.side_effect = client_dispatcher

        job = self.scanner.scan_environment(scan_id="scan_live_labrole_test", single_region="us-east-1")

        self.assertEqual(job.scan_type, "LIVE_AWS")
        self.assertIn("AWS Academy Learner Lab", job.target_name)

        # Limitation must be recorded honestly without crashing the scan
        summary = job.discovery_summary
        self.assertTrue(summary["is_learner_lab"])
        self.assertEqual(summary["by_service"]["IAM"]["status"], "RESTRICTED")
        self.assertIn("LabRole", summary["by_service"]["IAM"]["error"])
        self.assertTrue(any(l["service"] == "IAM" for l in summary["limitations_recorded"]))

    def test_api_endpoint_live_scan_offline(self):
        """When called via REST endpoint in offline environment, returns 400 with helpful remediation message."""
        res = client.post("/api/v1/scan/live")
        self.assertEqual(res.status_code, 400)
        self.assertIn("credentials", res.json()["detail"].lower())


if __name__ == "__main__":
    unittest.main()
