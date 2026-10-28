"""
CloudGuardAI - Validated Configuration Manager
Loads configuration from environment variables with safe defaults and zero secret exposure.
"""

import os
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator

def mask_secret(value: Optional[str], show_prefix: int = 4, show_suffix: int = 4) -> str:
    """Masks sensitive credentials while preserving diagnosis utility."""
    if not value:
        return "Not Set"
    cleaned = value.strip()
    if len(cleaned) <= show_prefix + show_suffix:
        return "***"
    return f"{cleaned[:show_prefix]}...{cleaned[-show_suffix:]} (len: {len(cleaned)})"

def load_dotenv_file(filepath: Optional[str] = None, override: bool = False):
    """Safely loads key-value pairs from a local .env file into os.environ."""
    candidates = [filepath] if filepath else [
        ".env",
        os.path.join(os.path.dirname(__file__), "..", "..", ".env"),
        os.path.join(os.getcwd(), ".env")
    ]
    for cand in candidates:
        if cand and os.path.exists(cand):
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if (override or k not in os.environ) and v:
                            os.environ[k] = v
                break
            except Exception:
                pass

class AWSConfig(BaseModel):
    region: str = Field(default="us-east-1", description="Target AWS Region")
    access_key_id: Optional[str] = Field(default=None, description="AWS Access Key ID")
    secret_access_key: Optional[str] = Field(default=None, description="AWS Secret Access Key")
    session_token: Optional[str] = Field(default=None, description="AWS Session Token for temporary STS credentials")
    profile_name: Optional[str] = Field(default=None, description="Local AWS Profile Name")
    s3_bucket: Optional[str] = Field(default=None, description="S3 bucket for templates and reports")
    dynamodb_table: str = Field(default="cloudguardai_scans", description="DynamoDB table for scan persistence")
    bedrock_model_id: str = Field(default="anthropic.claude-3-haiku-20240307-v1:0", description="Amazon Bedrock Foundation Model ID")
    cloudwatch_log_group: str = Field(default="/cloudguardai/audit-logs", description="Amazon CloudWatch Logs group for audit events")

    @field_validator("region")
    @classmethod
    def validate_region(cls, v: str) -> str:
        valid_regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
        cleaned = v.strip().lower()
        if cleaned not in valid_regions:
            # We allow it with a warning, default is us-east-1 for Learner Lab
            return cleaned
        return cleaned

    @property
    def is_configured(self) -> bool:
        """Returns True if minimum credentials exist via env or local profile."""
        if self.profile_name:
            return True
        return bool(self.access_key_id and self.secret_access_key)

    @property
    def is_temporary(self) -> bool:
        """Returns True if using STS temporary credentials (e.g. AWS Academy Learner Lab)."""
        if self.access_key_id and self.access_key_id.startswith("ASIA"):
            return True
        return bool(self.session_token)

    def safe_dict(self) -> Dict[str, Any]:
        """Returns configuration dictionary with strictly masked secrets for logging and API safe delivery."""
        return {
            "region": self.region,
            "access_key_id": mask_secret(self.access_key_id),
            "secret_access_key": "Configured (Masked)" if self.secret_access_key else "Not Set",
            "session_token": "Configured (Masked)" if self.session_token else "Not Set",
            "is_temporary_session": self.is_temporary,
            "profile_name": self.profile_name or "default",
            "s3_bucket": self.s3_bucket or "Local Storage Active",
            "dynamodb_table": self.dynamodb_table,
            "bedrock_model_id": self.bedrock_model_id
        }

class AppConfig(BaseModel):
    app_name: str = "CloudGuardAI"
    app_env: str = Field(default="development", description="development | staging | production")
    host: str = "127.0.0.1"
    port: int = 8000
    storage_backend: str = Field(default="local", description="'local' or 's3'")
    database_backend: str = Field(default="sqlite", description="'sqlite' or 'dynamodb'")
    remediation_backend: str = Field(default="hybrid", description="'hybrid', 'bedrock', or 'deterministic'")
    storage_local_dir: str = Field(default="./storage", description="Base directory for local file storage")
    aws: AWSConfig = Field(default_factory=AWSConfig)

    def safe_dict(self) -> Dict[str, Any]:
        return {
            "app_name": self.app_name,
            "app_env": self.app_env,
            "host": self.host,
            "port": self.port,
            "storage_backend": self.storage_backend,
            "database_backend": self.database_backend,
            "remediation_backend": self.remediation_backend,
            "aws": self.aws.safe_dict()
        }

def load_config() -> AppConfig:
    """Loads and validates configuration from environment variables and optional .env file."""
    load_dotenv_file()

    # Read AWS env vars
    aws_cfg = AWSConfig(
        region=os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", "us-east-1")),
        access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        session_token=os.getenv("AWS_SESSION_TOKEN"),
        profile_name=os.getenv("AWS_PROFILE"),
        s3_bucket=os.getenv("S3_BUCKET_NAME"),
        dynamodb_table=os.getenv("DYNAMODB_TABLE_NAME", "cloudguardai_scans"),
        bedrock_model_id=os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
    )

    # Determine storage and DB modes based on credential availability
    storage_mode = os.getenv("STORAGE_BACKEND")
    if not storage_mode:
        storage_mode = "s3" if (aws_cfg.is_configured and aws_cfg.s3_bucket) else "local"

    db_mode = os.getenv("DATABASE_BACKEND")
    if not db_mode:
        db_mode = "dynamodb" if aws_cfg.is_configured else "sqlite"

    remediation_mode = os.getenv("REMEDIATION_BACKEND", "hybrid")

    return AppConfig(
        app_name="CloudGuardAI",
        app_env=os.getenv("APP_ENV", "development"),
        host=os.getenv("HOST", os.getenv("APP_HOST", "0.0.0.0")),
        port=int(os.getenv("PORT", os.getenv("APP_PORT", "8000"))),
        storage_backend=storage_mode,
        database_backend=db_mode,
        remediation_backend=remediation_mode,
        storage_local_dir=os.getenv("STORAGE_LOCAL_DIR", "./storage"),
        aws=aws_cfg
    )

def refresh_config() -> AppConfig:
    """Refreshes the global settings singleton dynamically."""
    global settings
    load_dotenv_file(override=True)
    settings = load_config()
    return settings

# Global singleton
settings = load_config()
