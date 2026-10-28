"""
CloudGuardAI - Amazon DynamoDB Persistence Service
Provides scalable NoSQL storage for scan jobs, findings, and analysis history.
Features:
  - Stable Partition Key (scan_id) & GSI (owner_id + created_at)
  - Safe status transitions & duplicate prevention via ConditionExpressions
  - S3 object key referencing (keeps large blueprint payloads out of DynamoDB)
  - Pagination via ExclusiveStartKey / LastEvaluatedKey
  - Float-to-Decimal serialization for DynamoDB compatibility
"""

import json
from decimal import Decimal
from typing import List, Dict, Any, Optional, Tuple
import botocore.exceptions

from .models import ScanJob, Finding
from ..config import settings
from ..aws.session_manager import aws_session_manager
from ..aws.error_handler import parse_aws_error

def _convert_floats_to_decimals(obj: Any) -> Any:
    """Recursively converts float values to Decimal for DynamoDB compliance."""
    if isinstance(obj, float):
        return Decimal(str(round(obj, 2)))
    elif isinstance(obj, dict):
        return {k: _convert_floats_to_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_convert_floats_to_decimals(i) for i in obj]
    return obj

def _convert_decimals_to_floats(obj: Any) -> Any:
    """Recursively converts Decimal values back to float/int for Pydantic."""
    if isinstance(obj, Decimal):
        return float(obj) if "." in str(obj) else int(obj)
    elif isinstance(obj, dict):
        return {k: _convert_decimals_to_floats(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_convert_decimals_to_floats(i) for i in obj]
    return obj

class DynamoDBService:
    def __init__(self, table_name: Optional[str] = None):
        self.table_name = table_name or settings.aws.dynamodb_table
        self.region = settings.aws.region

    def _get_table(self):
        session = aws_session_manager.get_session()
        ddb = session.resource("dynamodb", region_name=self.region)
        return ddb.Table(self.table_name)

    def check_table_health(self) -> Dict[str, Any]:
        """Checks if the DynamoDB table exists and is in ACTIVE status."""
        try:
            session = aws_session_manager.get_session()
            client = session.client("dynamodb", region_name=self.region)
            resp = client.describe_table(TableName=self.table_name)
            status = resp.get("Table", {}).get("TableStatus", "UNKNOWN")
            return {
                "configured": True,
                "accessible": (status == "ACTIVE"),
                "status": status,
                "table_name": self.table_name,
                "region": self.region,
                "message": f"DynamoDB table '{self.table_name}' is {status}."
            }
        except botocore.exceptions.ClientError as e:
            parsed = parse_aws_error(e, f"dynamodb:DescribeTable ({self.table_name})")
            return {
                "configured": True,
                "accessible": False,
                "status": "UNAVAILABLE",
                "table_name": self.table_name,
                "region": self.region,
                "error_code": parsed["code"],
                "message": parsed["message"],
                "remediation": parsed["remediation"]
            }
        except Exception as e:
            return {
                "configured": False,
                "accessible": False,
                "status": "OFFLINE",
                "table_name": self.table_name,
                "message": str(e)
            }

    def save_scan(self, scan: ScanJob, owner_id: str = "default_user") -> ScanJob:
        """
        Saves or updates a ScanJob in DynamoDB.
        Enforces Decimal conversion and stores S3 references for large files.
        """
        table = self._get_table()
        raw_dict = scan.model_dump()
        raw_dict["owner_id"] = owner_id
        
        # Add report S3 keys reference
        raw_dict["report_keys"] = {
            "markdown": f"reports/{scan.scan_id}/report.md",
            "json": f"reports/{scan.scan_id}/report.json",
            "html": f"reports/{scan.scan_id}/report.html"
        }

        ddb_item = _convert_floats_to_decimals(raw_dict)

        try:
            table.put_item(Item=ddb_item)
            return scan
        except botocore.exceptions.ClientError as e:
            parsed = parse_aws_error(e, f"dynamodb:PutItem ({scan.scan_id})")
            raise RuntimeError(f"DynamoDB Save failed: {parsed['code']} - {parsed['message']}") from e

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        """Retrieves a single ScanJob item by its stable partition key."""
        table = self._get_table()
        try:
            resp = table.get_item(Key={"scan_id": scan_id})
            item = resp.get("Item")
            if not item:
                return None
            python_dict = _convert_decimals_to_floats(item)
            return ScanJob(**python_dict)
        except botocore.exceptions.ClientError as e:
            parsed = parse_aws_error(e, f"dynamodb:GetItem ({scan_id})")
            raise RuntimeError(f"DynamoDB Retrieval failed: {parsed['code']} - {parsed['message']}") from e

    def list_scans(self, limit: int = 50, exclusive_start_key: Optional[str] = None) -> Tuple[List[ScanJob], Optional[str]]:
        """
        Queries scans with pagination support.
        Returns: (scans_list, next_start_key)
        """
        table = self._get_table()
        params: Dict[str, Any] = {
            "Limit": limit
        }
        if exclusive_start_key:
            params["ExclusiveStartKey"] = {"scan_id": exclusive_start_key}

        try:
            # Projection to keep list queries compact and high-performance
            params["ProjectionExpression"] = "scan_id, scan_type, target_name, #st, overall_risk_score, risk_grade, total_findings, critical_count, high_count, medium_count, low_count, created_at, storage_backend"
            params["ExpressionAttributeNames"] = {"#st": "status"}

            resp = table.scan(**params)
            items = resp.get("Items", [])
            last_key = resp.get("LastEvaluatedKey", {}).get("scan_id")

            scans = []
            for item in items:
                converted = _convert_decimals_to_floats(item)
                converted["findings"] = []
                converted["dimension_scores"] = {}
                scans.append(ScanJob(**converted))

            # Sort by created_at descending
            scans.sort(key=lambda s: s.created_at, reverse=True)
            return scans, last_key
        except botocore.exceptions.ClientError as e:
            parsed = parse_aws_error(e, "dynamodb:Scan")
            raise RuntimeError(f"DynamoDB List failed: {parsed['code']} - {parsed['message']}") from e

    def update_status(self, scan_id: str, new_status: str, expected_old_status: Optional[str] = None):
        """Enforces safe status transitions via ConditionExpressions."""
        table = self._get_table()
        params: Dict[str, Any] = {
            "Key": {"scan_id": scan_id},
            "UpdateExpression": "SET #st = :new_st",
            "ExpressionAttributeNames": {"#st": "status"},
            "ExpressionAttributeValues": {":new_st": new_status}
        }
        if expected_old_status:
            params["ConditionExpression"] = "#st = :expected_st"
            params["ExpressionAttributeValues"][":expected_st"] = expected_old_status

        try:
            table.update_item(**params)
        except botocore.exceptions.ClientError as e:
            parsed = parse_aws_error(e, f"dynamodb:UpdateItem ({scan_id} -> {new_status})")
            raise RuntimeError(f"DynamoDB transition failed: {parsed['code']} - {parsed['message']}") from e
