"""
CloudGuardAI - Local Filesystem Storage Service
Provides atomic local file persistence mirroring the S3 key hierarchy.
Serves as the resilient fallback for offline execution, student labs, and local testing.
"""

import os
import hashlib
from typing import Tuple, Dict, Any, Optional

class LocalStorageService:
    def __init__(self, base_dir: str = "./storage"):
        self.base_dir = os.path.abspath(base_dir)
        self.uploads_dir = os.path.join(self.base_dir, "uploads")
        self.reports_dir = os.path.join(self.base_dir, "reports")
        os.makedirs(self.uploads_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

    def save_file(self, file_key: str, content: bytes, content_type: str = "text/plain") -> Dict[str, Any]:
        """Saves content to the relative path matching file_key."""
        clean_key = file_key.replace("\\", "/").lstrip("/")
        full_path = os.path.join(self.base_dir, clean_key)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        # Atomic write
        temp_path = f"{full_path}.tmp"
        with open(temp_path, "wb") as f:
            f.write(content)
        os.replace(temp_path, full_path)

        sha256 = hashlib.sha256(content).hexdigest()
        return {
            "file_key": clean_key,
            "full_path": full_path,
            "size_bytes": len(content),
            "sha256": sha256,
            "storage_backend": "local"
        }

    def read_file(self, file_key: str) -> Tuple[bytes, str]:
        """Reads content and guesses MIME type from file_key."""
        clean_key = file_key.replace("\\", "/").lstrip("/")
        full_path = os.path.join(self.base_dir, clean_key)

        if not os.path.exists(full_path):
            raise FileNotFoundError(f"File not found in local storage: {clean_key}")

        with open(full_path, "rb") as f:
            content = f.read()

        content_type = "text/plain"
        if clean_key.endswith(".json") or clean_key.endswith(".tf.json"):
            content_type = "application/json"
        elif clean_key.endswith(".yaml") or clean_key.endswith(".yml"):
            content_type = "application/x-yaml"
        elif clean_key.endswith(".pdf"):
            content_type = "application/pdf"
        elif clean_key.endswith(".md"):
            content_type = "text/markdown"

        return content, content_type

    def file_exists(self, file_key: str) -> bool:
        clean_key = file_key.replace("\\", "/").lstrip("/")
        full_path = os.path.join(self.base_dir, clean_key)
        return os.path.isfile(full_path)

    def delete_file(self, file_key: str) -> bool:
        clean_key = file_key.replace("\\", "/").lstrip("/")
        full_path = os.path.join(self.base_dir, clean_key)
        if os.path.isfile(full_path):
            os.remove(full_path)
            return True
        return False
