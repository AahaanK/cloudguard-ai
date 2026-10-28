"""
CloudGuardAI - AWS SDK Session & Credential Provider Manager
Utilizes the standard AWS SDK credential provider chain:
  1. Explicit Environment Variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
  2. Local Shared Credentials File (~/.aws/credentials)
  3. Local Config File (~/.aws/config)
  4. IAM Execution Roles / Instance Metadata Service (IMDS / ECS / Lambda)
"""

import boto3
import botocore.exceptions
from typing import Dict, Any, Optional
from ..config import settings, mask_secret

class AWSSessionManager:
    """Thread-safe AWS Session and Client provider."""

    def __init__(self):
        self._session: Optional[boto3.Session] = None
        self._cached_identity: Optional[Dict[str, Any]] = None

    def get_session(self) -> boto3.Session:
        """Returns or instantiates a Boto3 Session using the SDK credential provider chain."""
        if self._session is None:
            kwargs = {}
            if settings.aws.profile_name:
                kwargs["profile_name"] = settings.aws.profile_name
            if settings.aws.region:
                kwargs["region_name"] = settings.aws.region
            
            # If explicit credentials were provided via environment, Boto3 will automatically
            # detect them. But if passed in settings, pass them as overrides:
            if settings.aws.access_key_id and settings.aws.secret_access_key:
                kwargs["aws_access_key_id"] = settings.aws.access_key_id
                kwargs["aws_secret_access_key"] = settings.aws.secret_access_key
                if settings.aws.session_token:
                    kwargs["aws_session_token"] = settings.aws.session_token

            self._session = boto3.Session(**kwargs)
        return self._session

    def reset_session(self):
        """Resets the cached session, useful when credentials are refreshed."""
        self._session = None
        self._cached_identity = None

    def get_client(self, service_name: str, region_name: Optional[str] = None, client_config: Optional[Any] = None):
        """Creates a Boto3 client for a given service."""
        session = self.get_session()
        region = region_name or settings.aws.region
        kwargs: Dict[str, Any] = {"region_name": region}
        if client_config is not None:
            kwargs["config"] = client_config
        return session.client(service_name, **kwargs)

    def verify_identity(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Calls STS GetCallerIdentity to verify AWS connectivity and credentials.
        Never exposes raw secrets; returns masked diagnostics.
        """
        if self._cached_identity and not force_refresh:
            return self._cached_identity

        session = self.get_session()
        region = session.region_name or settings.aws.region
        
        try:
            sts = session.client("sts", region_name=region)
            caller = sts.get_caller_identity()
            
            arn = caller.get("Arn", "Unknown")
            account = caller.get("Account", "Unknown")
            user_id = caller.get("UserId", "Unknown")
            is_lab_role = "LabRole" in arn or "voclabs" in arn

            result = {
                "authenticated": True,
                "account_id": account,
                "arn": arn,
                "user_id": user_id,
                "region": region,
                "is_lab_role": is_lab_role,
                "message": "AWS credentials active and verified."
            }
            self._cached_identity = result
            return result

        except botocore.exceptions.NoCredentialsError:
            return {
                "authenticated": False,
                "account_id": None,
                "arn": None,
                "region": region,
                "is_lab_role": False,
                "error_code": "NoCredentialsError",
                "message": "No AWS credentials found. Local Resilient Mode active."
            }
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            msg = e.response.get("Error", {}).get("Message", str(e))
            return {
                "authenticated": False,
                "account_id": None,
                "arn": None,
                "region": region,
                "is_lab_role": False,
                "error_code": code,
                "message": f"AWS authentication failed: {code} - {msg}"
            }
        except Exception as e:
            return {
                "authenticated": False,
                "account_id": None,
                "arn": None,
                "region": region,
                "is_lab_role": False,
                "error_code": "UnknownException",
                "message": f"Unexpected error: {str(e)}"
            }

aws_session_manager = AWSSessionManager()
