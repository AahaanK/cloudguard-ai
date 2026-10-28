"""
CloudGuardAI - Amazon CloudWatch Audit Logging Service
Delivers structured, non-leaking operational and security telemetry to Amazon CloudWatch Logs.
Never logs credentials, session tokens, passwords, or raw uploaded template code.
Falls back gracefully to local structured stdout logging when offline or restricted by IAM boundaries.
"""

import json
import time
import logging
from typing import Dict, Any, Optional
import botocore.exceptions

from ..config import settings
from .session_manager import aws_session_manager
from .error_handler import parse_aws_error

logger = logging.getLogger("cloudguard.audit")

SENSITIVE_KEYS = {
    "password", "secret", "token", "access_key", "session_token",
    "authorization", "raw_content", "template_body", "credentials"
}

def sanitize_telemetry(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively masks sensitive data in log payloads."""
    clean: Dict[str, Any] = {}
    for k, v in payload.items():
        if any(s in k.lower() for s in SENSITIVE_KEYS):
            clean[k] = "[MASKED_SENSITIVE_DATA]"
        elif isinstance(v, dict):
            clean[k] = sanitize_telemetry(v)
        elif isinstance(v, list):
            clean[k] = [sanitize_telemetry(i) if isinstance(i, dict) else i for i in v]
        else:
            clean[k] = v
    return clean

class CloudWatchAuditLogger:
    def __init__(self):
        self.log_group = settings.aws.cloudwatch_log_group
        self._client = None
        self._stream_initialized = False
        self._current_stream = f"audit-{time.strftime('%Y-%m-%d')}"

    def _get_client(self):
        if self._client is None:
            self._client = aws_session_manager.get_client("logs")
        return self._client

    def _ensure_group_and_stream(self, client) -> bool:
        if self._stream_initialized:
            return True
        try:
            # 1. Ensure Log Group
            try:
                client.create_log_group(logGroupName=self.log_group)
            except botocore.exceptions.ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code not in ("ResourceAlreadyExistsException", "AccessDeniedException"):
                    pass

            # 2. Ensure Log Stream
            try:
                client.create_log_stream(logGroupName=self.log_group, logStreamName=self._current_stream)
            except botocore.exceptions.ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code not in ("ResourceAlreadyExistsException", "AccessDeniedException"):
                    pass

            self._stream_initialized = True
            return True
        except Exception:
            return False

    def log_audit_event(self, event_type: str, scan_id: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Emits a structured audit event to CloudWatch Logs (with local stdout fallback).
        """
        raw_details = details or {}
        safe_details = sanitize_telemetry(raw_details)

        event_record = {
            "timestamp": time.time(),
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "service": "CloudGuardAI",
            "event_type": event_type,
            "scan_id": scan_id,
            "details": safe_details
        }

        # Check AWS connectivity
        identity = aws_session_manager.verify_identity()
        if not identity.get("authenticated", False):
            logger.info(json.dumps(event_record))
            return {"logged": True, "destination": "LOCAL_STDOUT", "event_type": event_type}

        try:
            client = self._get_client()
            if not self._ensure_group_and_stream(client):
                logger.info(json.dumps(event_record))
                return {"logged": True, "destination": "LOCAL_STDOUT", "event_type": event_type}

            event_record["aws_account_id"] = identity.get("account_id")
            event_record["aws_region"] = settings.aws.region

            client.put_log_events(
                logGroupName=self.log_group,
                logStreamName=self._current_stream,
                logEvents=[
                    {
                        "timestamp": int(time.time() * 1000),
                        "message": json.dumps(event_record)
                    }
                ]
            )
            return {"logged": True, "destination": "CLOUDWATCH", "event_type": event_type}

        except botocore.exceptions.ClientError as ce:
            parsed = parse_aws_error(ce, f"logs:PutLogEvents ({self.log_group})")
            logger.warning(f"CloudWatch logging fallback: {parsed['message']}")
            logger.info(json.dumps(event_record))
            return {"logged": True, "destination": "LOCAL_FALLBACK", "event_type": event_type, "note": parsed["message"]}
        except Exception as ex:
            logger.info(json.dumps(event_record))
            return {"logged": True, "destination": "LOCAL_FALLBACK", "event_type": event_type, "note": str(ex)}

cloudwatch_logger = CloudWatchAuditLogger()
