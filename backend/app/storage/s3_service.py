"""
CloudGuardAI - Amazon S3 Storage Service
Implements secure object storage for infrastructure templates and analysis reports:
  - Private objects with SSE-S3 encryption (AES256)
  - Short-lived presigned URLs for secure authorized downloads AND direct-to-S3 uploads
  - Strict file-type validation & size limits
  - Resilient error handling for missing buckets and expired credentials
"""

import os
import re
import hashlib
import uuid
from typing import Dict, Any, Tuple, Optional
import botocore.exceptions

from ..config import settings
from ..aws.session_manager import aws_session_manager
from ..aws.error_handler import parse_aws_error

ALLOWED_IAC_EXTENSIONS = {".tf", ".tf.json", ".json", ".yaml", ".yml"}
ALLOWED_REPORT_EXTENSIONS = {".pdf", ".json", ".md", ".csv"}
MAX_IAC_FILE_SIZE_BYTES = 10 * 1024 * 1024   # 10 MB
MAX_REPORT_FILE_SIZE_BYTES = 25 * 1024 * 1024 # 25 MB

def sanitize_filename(filename: str) -> str:
    """Removes path traversals and unsafe characters from filenames."""
    base = os.path.basename(filename).strip()
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', base)
    if not sanitized or sanitized.startswith('.'):
        sanitized = f"template_{uuid.uuid4().hex[:8]}.tf"
    return sanitized

def detect_content_type(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".tf.json") or lower.endswith(".json"):
        return "application/json"
    if lower.endswith(".yaml") or lower.endswith(".yml"):
        return "application/x-yaml"
    if lower.endswith(".tf"):
        return "text/plain"
    if lower.endswith(".pdf"):
        return "application/pdf"
    if lower.endswith(".md"):
        return "text/markdown"
    return "application/octet-stream"

class S3StorageService:
    def __init__(self, bucket_name: Optional[str] = None):
        self.bucket_name = bucket_name or settings.aws.s3_bucket
        self.region = settings.aws.region

    def _get_client(self):
        return aws_session_manager.get_client("s3", region_name=self.region)

    def validate_file(self, filename: str, content: bytes, is_report: bool = False) -> Tuple[str, str]:
        sanitized = sanitize_filename(filename)
        _, ext = os.path.splitext(sanitized.lower())
        
        if sanitized.lower().endswith(".tf.json"):
            ext = ".tf.json"

        allowed = ALLOWED_REPORT_EXTENSIONS if is_report else ALLOWED_IAC_EXTENSIONS
        if ext not in allowed:
            allowed_str = ", ".join(sorted(allowed))
            raise ValueError(f"Unsupported file type '{ext}'. Allowed extensions: {allowed_str}")

        max_size = MAX_REPORT_FILE_SIZE_BYTES if is_report else MAX_IAC_FILE_SIZE_BYTES
        if len(content) == 0:
            raise ValueError("File content is empty (0 bytes).")
        if len(content) > max_size:
            max_mb = max_size // (1024 * 1024)
            raise ValueError(f"File size exceeds maximum permitted limit ({max_mb} MB).")

        content_type = detect_content_type(sanitized)
        return sanitized, content_type

    def generate_presigned_upload_url(
        self,
        filename: str,
        analysis_id: Optional[str] = None,
        expiration_seconds: int = 900
    ) -> Dict[str, Any]:
        """
        Generates a presigned URL allowing direct-to-S3 client uploads via HTTP PUT.
        Bypasses API Gateway 10 MB payload limits and eliminates proxy latency.
        """
        if not self.bucket_name:
            raise ValueError("S3 bucket name is not configured in settings (S3_BUCKET_NAME).")

        sanitized_name = sanitize_filename(filename)
        _, ext = os.path.splitext(sanitized_name.lower())
        if sanitized_name.lower().endswith(".tf.json"):
            ext = ".tf.json"
        if ext not in ALLOWED_IAC_EXTENSIONS:
            raise ValueError(f"Unsupported file type '{ext}'.")

        analysis_id = analysis_id or f"scan_{uuid.uuid4().hex[:12]}"
        file_key = f"uploads/{analysis_id}/{sanitized_name}"
        content_type = detect_content_type(sanitized_name)

        s3 = self._get_client()
        try:
            url = s3.generate_presigned_url(
                ClientMethod="put_object",
                Params={
                    "Bucket": self.bucket_name,
                    "Key": file_key,
                    "ContentType": content_type,
                    "ServerSideEncryption": "AES256"
                },
                ExpiresIn=expiration_seconds
            )
            return {
                "upload_mode": "DIRECT_S3",
                "upload_url": url,
                "file_key": file_key,
                "analysis_id": analysis_id,
                "bucket": self.bucket_name,
                "filename": sanitized_name,
                "content_type": content_type,
                "http_method": "PUT",
                "required_headers": {
                    "Content-Type": content_type,
                    "x-amz-server-side-encryption": "AES256"
                },
                "expires_in_seconds": expiration_seconds
            }
        except botocore.exceptions.ClientError as e:
            parsed = parse_aws_error(e, f"generate_presigned_upload_url ({file_key})")
            raise RuntimeError(f"Failed to generate upload URL: {parsed['message']}") from e

    def upload_file(
        self,
        content: bytes,
        filename: str,
        analysis_id: Optional[str] = None,
        is_report: bool = False
    ) -> Dict[str, Any]:
        """Uploads an object to S3 with AES256 server-side encryption."""
        if not self.bucket_name:
            raise ValueError("S3 bucket name is not configured in settings (S3_BUCKET_NAME).")

        sanitized_name, content_type = self.validate_file(filename, content, is_report)
        analysis_id = analysis_id or f"analysis_{uuid.uuid4().hex}"
        prefix = "reports" if is_report else "uploads"
        file_key = f"{prefix}/{analysis_id}/{sanitized_name}"
        sha256 = hashlib.sha256(content).hexdigest()

        s3 = self._get_client()
        try:
            s3.put_object(
                Bucket=self.bucket_name,
                Key=file_key,
                Body=content,
                ContentType=content_type,
                ServerSideEncryption="AES256",
                Metadata={
                    "sha256": sha256,
                    "original_filename": sanitized_name,
                    "analysis_id": analysis_id,
                    "cloudguard_version": "1.0.0"
                },
                Tagging=f"Project=CloudGuardAI&AnalysisId={analysis_id}&ManagedBy=CloudGuardAI"
            )

            presigned_url = self.generate_presigned_download_url(file_key, expiration_seconds=900)

            return {
                "file_key": file_key,
                "bucket": self.bucket_name,
                "filename": sanitized_name,
                "analysis_id": analysis_id,
                "size_bytes": len(content),
                "sha256": sha256,
                "content_type": content_type,
                "storage_backend": "s3",
                "presigned_url": presigned_url,
                "encrypted": True
            }

        except botocore.exceptions.ClientError as e:
            parsed = parse_aws_error(e, f"s3:PutObject ({file_key})")
            raise RuntimeError(f"S3 Upload failed: {parsed['code']} - {parsed['message']}") from e

    def download_file(self, file_key: str) -> Tuple[bytes, str]:
        if not self.bucket_name:
            raise ValueError("S3 bucket name is not configured.")

        s3 = self._get_client()
        try:
            resp = s3.get_object(Bucket=self.bucket_name, Key=file_key)
            content = resp["Body"].read()
            content_type = resp.get("ContentType", detect_content_type(file_key))
            return content, content_type
        except botocore.exceptions.ClientError as e:
            parsed = parse_aws_error(e, f"s3:GetObject ({file_key})")
            raise RuntimeError(f"S3 Download failed: {parsed['code']} - {parsed['message']}") from e

    def generate_presigned_download_url(
        self,
        file_key: str,
        expiration_seconds: int = 900,
        download_filename: Optional[str] = None
    ) -> str:
        if not self.bucket_name:
            raise ValueError("S3 bucket name is not configured.")

        s3 = self._get_client()
        params = {
            "Bucket": self.bucket_name,
            "Key": file_key
        }
        if download_filename:
            safe_dl = sanitize_filename(download_filename)
            params["ResponseContentDisposition"] = f'attachment; filename="{safe_dl}"'

        try:
            return s3.generate_presigned_url(
                ClientMethod="get_object",
                Params=params,
                ExpiresIn=expiration_seconds
            )
        except botocore.exceptions.ClientError as e:
            parsed = parse_aws_error(e, f"generate_presigned_url ({file_key})")
            raise RuntimeError(f"Failed to generate presigned URL: {parsed['message']}") from e

    def check_bucket_health(self) -> Dict[str, Any]:
        if not self.bucket_name:
            return {
                "configured": False,
                "accessible": False,
                "message": "S3 bucket name not set in settings."
            }

        s3 = self._get_client()
        try:
            s3.head_bucket(Bucket=self.bucket_name)
            return {
                "configured": True,
                "accessible": True,
                "bucket": self.bucket_name,
                "region": self.region,
                "message": "S3 bucket accessible and verified."
            }
        except botocore.exceptions.ClientError as e:
            parsed = parse_aws_error(e, f"s3:HeadBucket ({self.bucket_name})")
            return {
                "configured": True,
                "accessible": False,
                "bucket": self.bucket_name,
                "region": self.region,
                "error_code": parsed["code"],
                "message": parsed["message"],
                "remediation": parsed["remediation"]
            }
