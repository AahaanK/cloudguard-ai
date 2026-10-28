"""
CloudGuardAI - Unit Tests for DynamoDB Persistence Service & Resilient Fallback
Tests:
  1. DynamoDB PutItem serialization (float to Decimal) & S3 key referencing
  2. DynamoDB GetItem deserialization back to Pydantic models
  3. Scan pagination with LastEvaluatedKey
  4. Safe status transitions with ConditionExpression
  5. Automatic fallback to SQLite when DynamoDB is offline or table is unprovisioned
"""

import unittest
from unittest.mock import MagicMock, patch
from decimal import Decimal
import botocore.exceptions

from backend.app.db.models import ScanJob, Finding
from backend.app.db.dynamodb_service import DynamoDBService, _convert_floats_to_decimals, _convert_decimals_to_floats
from backend.app.db.repository import DatabaseManager

class TestDynamoDBPersistence(unittest.TestCase):

    def setUp(self):
        self.service = DynamoDBService(table_name="cloudguardai_scans_test")

    def test_float_to_decimal_conversion(self):
        data = {
            "score": 68.5,
            "counts": {"crit": 2},
            "subtotals": [12.4, 5.0]
        }
        converted = _convert_floats_to_decimals(data)
        self.assertIsInstance(converted["score"], Decimal)
        self.assertEqual(converted["score"], Decimal("68.50"))
        self.assertIsInstance(converted["subtotals"][0], Decimal)

        restored = _convert_decimals_to_floats(converted)
        self.assertIsInstance(restored["score"], float)
        self.assertEqual(restored["score"], 68.5)

    @patch("backend.app.db.dynamodb_service.aws_session_manager.get_session")
    def test_save_scan_in_dynamodb(self, mock_get_session):
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session
        mock_resource = MagicMock()
        mock_session.resource.return_value = mock_resource
        mock_table = MagicMock()
        mock_resource.Table.return_value = mock_table

        scan = ScanJob(
            scan_id="scan_test_100",
            target_name="main.tf",
            overall_risk_score=75.0,
            risk_grade="D",
            total_findings=2,
            critical_count=1,
            high_count=1,
            findings=[
                Finding(
                    finding_id="find_001",
                    scan_id="scan_test_100",
                    rule_id="SEC-S3-001",
                    rule_name="S3 Public Read",
                    dimension="SECURITY",
                    severity="CRITICAL",
                    resource_id="aws_s3_bucket.data",
                    resource_type="aws_s3_bucket",
                    title="Public Bucket",
                    description="Open to world",
                    impact="Data leak",
                    remediation_summary="Make private"
                )
            ]
        )

        saved = self.service.save_scan(scan, owner_id="123456789012")
        self.assertEqual(saved.scan_id, "scan_test_100")

        # Verify put_item call
        mock_table.put_item.assert_called_once()
        put_kwargs = mock_table.put_item.call_args[1]
        item = put_kwargs["Item"]
        self.assertEqual(item["scan_id"], "scan_test_100")
        self.assertEqual(item["owner_id"], "123456789012")
        self.assertIsInstance(item["overall_risk_score"], Decimal)
        # S3 report references stored
        self.assertIn("report_keys", item)
        self.assertEqual(item["report_keys"]["json"], "reports/scan_test_100/report.json")

    @patch("backend.app.db.dynamodb_service.aws_session_manager.get_session")
    def test_get_scan_from_dynamodb(self, mock_get_session):
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session
        mock_resource = MagicMock()
        mock_session.resource.return_value = mock_resource
        mock_table = MagicMock()
        mock_resource.Table.return_value = mock_table

        mock_table.get_item.return_value = {
            "Item": {
                "scan_id": "scan_test_100",
                "scan_type": "IAC_STATIC",
                "target_name": "main.tf",
                "status": "COMPLETED",
                "overall_risk_score": Decimal("75.0"),
                "risk_grade": "D",
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "dimension_scores": {},
                "unsupported_constructs": [],
                "storage_backend": "s3",
                "created_at": "2026-10-29T00:00:00Z",
                "findings": []
            }
        }

        scan = self.service.get_scan("scan_test_100")
        self.assertIsNotNone(scan)
        self.assertEqual(scan.scan_id, "scan_test_100")
        self.assertEqual(scan.overall_risk_score, 75.0)

    @patch("backend.app.db.dynamodb_service.aws_session_manager.get_session")
    def test_list_scans_pagination(self, mock_get_session):
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session
        mock_resource = MagicMock()
        mock_session.resource.return_value = mock_resource
        mock_table = MagicMock()
        mock_resource.Table.return_value = mock_table

        mock_table.scan.return_value = {
            "Items": [
                {
                    "scan_id": "scan_001",
                    "scan_type": "IAC_STATIC",
                    "target_name": "infra1.tf",
                    "status": "COMPLETED",
                    "overall_risk_score": Decimal("20.0"),
                    "risk_grade": "A",
                    "total_findings": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "storage_backend": "s3",
                    "created_at": "2026-10-29T01:00:00Z"
                }
            ],
            "LastEvaluatedKey": {"scan_id": "scan_001"}
        }

        scans, next_key = self.service.list_scans(limit=10)
        self.assertEqual(len(scans), 1)
        self.assertEqual(next_key, "scan_001")
        mock_table.scan.assert_called_once()
        self.assertIn("ProjectionExpression", mock_table.scan.call_args[1])

    @patch("backend.app.db.dynamodb_service.aws_session_manager.get_session")
    def test_safe_status_transition_conditional(self, mock_get_session):
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session
        mock_resource = MagicMock()
        mock_session.resource.return_value = mock_resource
        mock_table = MagicMock()
        mock_resource.Table.return_value = mock_table

        self.service.update_status(
            scan_id="scan_100",
            new_status="COMPLETED",
            expected_old_status="PROCESSING"
        )
        mock_table.update_item.assert_called_once()
        update_args = mock_table.update_item.call_args[1]
        self.assertIn("ConditionExpression", update_args)
        self.assertEqual(update_args["ExpressionAttributeValues"][":expected_st"], "PROCESSING")

class TestDatabaseManagerFallback(unittest.TestCase):

    def test_manager_falls_back_to_sqlite(self):
        manager = DatabaseManager()
        # In test environment, DynamoDB table cloudguardai_scans is not provisioned
        self.assertFalse(manager.should_use_dynamodb)

        scan = ScanJob(
            scan_id="scan_sqlite_fallback_test",
            target_name="fallback.tf",
            overall_risk_score=15.0,
            risk_grade="A"
        )
        saved = manager.save_scan(scan)
        self.assertEqual(saved.scan_id, "scan_sqlite_fallback_test")

        retrieved = manager.get_scan("scan_sqlite_fallback_test")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.scan_id, "scan_sqlite_fallback_test")

        status = manager.status()
        self.assertEqual(status["active_backend"], "sqlite")

if __name__ == "__main__":
    unittest.main()
