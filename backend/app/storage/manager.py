"""
CloudGuardAI - Unified Storage Manager
Coordinates between Amazon S3 and Local Filesystem storage.
Supports direct-to-S3 presigned uploads to bypass API Gateway 10 MB limits.
"""

from typing import Dict, Any, Tuple, Optional
import logging
import uuid
import os

from ..config import settings
from .s3_service import S3StorageService, sanitize_filename
from .local_storage import LocalStorageService

logger = logging.getLogger("cloudguard.storage")

class StorageManager:
    def __init__(self):
        self.local_service = LocalStorageService(base_dir=settings.storage_local_dir)
        self.s3_service = S3StorageService(bucket_name=settings.aws.s3_bucket)
        self.prefer_s3 = (settings.storage_backend == "s3" and bool(settings.aws.s3_bucket))

    def generate_upload_url(self, filename: str, analysis_id: Optional[str] = None, expiration_seconds: int = 900) -> Dict[str, Any]:
        """
        Generates an authorized direct upload URL.
        If S3 is configured, returns a presigned S3 PUT URL.
        If in local fallback mode, points directly to the backend upload endpoint.
        """
        # Validate file extension regardless of backend
        safe_name = sanitize_filename(filename)
        _, ext = os.path.splitext(safe_name.lower())
        if safe_name.lower().endswith(".tf.json"):
            ext = ".tf.json"
        from .s3_service import ALLOWED_IAC_EXTENSIONS
        if ext not in ALLOWED_IAC_EXTENSIONS:
            raise ValueError(f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_IAC_EXTENSIONS))}")

        if self.prefer_s3:
            try:
                res = self.s3_service.generate_presigned_upload_url(
                    filename=safe_name,
                    analysis_id=analysis_id,
                    expiration_seconds=expiration_seconds
                )
                res["storage_backend"] = "s3"
                res["bypass_note"] = "API Gateway 10 MB payload limit bypassed via direct S3 upload"
                return res
            except Exception as e:
                logger.warning(f"Failed to generate S3 presigned upload URL ({str(e)}). Using local route.")

        # Local fallback upload contract
        analysis_id = analysis_id or f"scan_{uuid.uuid4().hex[:12]}"
        file_key = f"uploads/{analysis_id}/{safe_name}"
        return {
            "upload_mode": "DIRECT_BACKEND",
            "upload_url": "/api/v1/storage/upload",
            "file_key": file_key,
            "analysis_id": analysis_id,
            "filename": safe_name,
            "http_method": "POST",
            "required_headers": {},
            "expires_in_seconds": expiration_seconds,
            "storage_backend": "local",
            "bypass_note": "API Gateway payload bypass contract supported via streaming direct upload"
        }

    def store_file(
        self,
        content: bytes,
        filename: str,
        analysis_id: Optional[str] = None,
        is_report: bool = False
    ) -> Dict[str, Any]:
        if self.prefer_s3:
            try:
                return self.s3_service.upload_file(
                    content=content,
                    filename=filename,
                    analysis_id=analysis_id,
                    is_report=is_report
                )
            except Exception as e:
                logger.warning(f"S3 storage unavailable ({str(e)}). Falling back to local storage.")

        sanitized_name, content_type = self.s3_service.validate_file(filename, content, is_report)
        analysis_id = analysis_id or f"analysis_{sanitized_name[:8]}"
        prefix = "reports" if is_report else "uploads"
        file_key = f"{prefix}/{analysis_id}/{sanitized_name}"

        local_res = self.local_service.save_file(file_key, content, content_type)
        return {
            "file_key": file_key,
            "filename": sanitized_name,
            "analysis_id": analysis_id,
            "size_bytes": local_res["size_bytes"],
            "sha256": local_res["sha256"],
            "content_type": content_type,
            "storage_backend": "local",
            "presigned_url": f"/api/v1/storage/file/{file_key}",
            "encrypted": False
        }

    def retrieve_file(self, file_key: str) -> Tuple[bytes, str]:
        clean_key = file_key.replace("\\", "/").lstrip("/")
        if self.local_service.file_exists(clean_key):
            return self.local_service.read_file(clean_key)

        if self.prefer_s3 or settings.aws.s3_bucket:
            return self.s3_service.download_file(clean_key)

        raise FileNotFoundError(f"Requested object '{clean_key}' not found in any storage backend.")

    def get_download_url(self, file_key: str, expiration_seconds: int = 900) -> str:
        clean_key = file_key.replace("\\", "/").lstrip("/")
        if self.prefer_s3 and not self.local_service.file_exists(clean_key):
            try:
                return self.s3_service.generate_presigned_download_url(clean_key, expiration_seconds)
            except Exception:
                pass
        return f"/api/v1/storage/file/{clean_key}"

    def status(self) -> Dict[str, Any]:
        s3_health = self.s3_service.check_bucket_health()
        return {
            "active_backend": "s3" if (self.prefer_s3 and s3_health.get("accessible")) else "local",
            "configured_mode": settings.storage_backend,
            "s3_health": s3_health,
            "local_storage_path": self.local_service.base_dir
        }

storage_manager = StorageManager()
