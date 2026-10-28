"""
CloudGuardAI - AWS SDK Session & Credential Provider Manager
Utilizes the standard AWS SDK credential provider chain:
  1. Explicit Environment Variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
  2. Local Shared Credentials File (~/.aws/credentials)
  3. Local Config File (~/.aws/config)
  4. IAM Execution Roles / Instance Metadata Service (IMDS / ECS / Lambda)

Never exposes raw secrets; provides rich, actionable diagnostic information.
"""

import os
import time
import boto3
import botocore.config
import botocore.exceptions
from typing import Dict, Any, Optional

from ..config import settings, refresh_config, mask_secret


class AWSSessionManager:
    """Thread-safe AWS Session and Client provider with intelligent credential diagnostic checks."""

    def __init__(self):
        self._session: Optional[boto3.Session] = None
        self._cached_identity: Optional[Dict[str, Any]] = None
        self._cache_timestamp: float = 0.0
        self._cache_ttl_seconds: float = 60.0

    def detect_credential_provider(self) -> Dict[str, Any]:
        """
        Inspects the runtime environment to determine which credential provider is active
        or available without executing remote AWS network calls.
        """
        env_key = os.getenv("AWS_ACCESS_KEY_ID")
        env_secret = os.getenv("AWS_SECRET_ACCESS_KEY")
        env_token = os.getenv("AWS_SESSION_TOKEN")
        profile_env = os.getenv("AWS_PROFILE") or getattr(settings.aws, "profile_name", None)

        has_env_keys = bool(env_key and env_secret)
        is_temporary_key = bool(env_key and env_key.strip().startswith("ASIA"))
        missing_session_token = is_temporary_key and not env_token

        # Check for local AWS credentials file (~/.aws/credentials)
        home = os.path.expanduser("~")
        creds_file = os.path.join(home, ".aws", "credentials")
        config_file = os.path.join(home, ".aws", "config")
        has_credentials_file = os.path.exists(creds_file)
        has_config_file = os.path.exists(config_file)

        provider_type = "NONE"
        if has_env_keys:
            provider_type = "ENVIRONMENT_VARIABLES"
        elif profile_env:
            provider_type = "AWS_CLI_PROFILE"
        elif has_credentials_file:
            provider_type = "SHARED_CREDENTIALS_FILE"
        elif os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") or os.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"):
            provider_type = "CONTAINER_ROLE"
        elif os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
            provider_type = "LAMBDA_EXECUTION_ROLE"

        return {
            "provider_type": provider_type,
            "has_environment_keys": has_env_keys,
            "is_temporary_key": is_temporary_key,
            "has_session_token": bool(env_token),
            "missing_session_token": missing_session_token,
            "active_profile": profile_env or ("default" if has_credentials_file else None),
            "has_credentials_file": has_credentials_file,
            "has_config_file": has_config_file,
            "region": os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", settings.aws.region))
        }

    def get_session(self) -> boto3.Session:
        """Returns or instantiates a Boto3 Session using the SDK credential provider chain."""
        if self._session is None:
            region = os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", settings.aws.region))
            profile = os.getenv("AWS_PROFILE") or getattr(settings.aws, "profile_name", None)

            kwargs: Dict[str, Any] = {}
            if region:
                kwargs["region_name"] = region
            if profile:
                kwargs["profile_name"] = profile

            env_key = os.getenv("AWS_ACCESS_KEY_ID")
            env_secret = os.getenv("AWS_SECRET_ACCESS_KEY")
            env_token = os.getenv("AWS_SESSION_TOKEN")

            if env_key and env_secret:
                kwargs["aws_access_key_id"] = env_key.strip()
                kwargs["aws_secret_access_key"] = env_secret.strip()
                if env_token:
                    kwargs["aws_session_token"] = env_token.strip()

            self._session = boto3.Session(**kwargs)
        return self._session

    def reset_session(self) -> Dict[str, Any]:
        """
        Flushes cached session, reloads .env file and environment variables,
        and clears cached identity to allow dynamic credential updates without server restarts.
        """
        self._session = None
        self._cached_identity = None
        self._cache_timestamp = 0.0
        refresh_config()
        return self.verify_identity(force_refresh=True)

    def get_client(self, service_name: str, region_name: Optional[str] = None, client_config: Optional[Any] = None):
        """Creates a Boto3 client for a given service."""
        session = self.get_session()
        region = region_name or session.region_name or settings.aws.region
        kwargs: Dict[str, Any] = {"region_name": region}
        if client_config is not None:
            kwargs["config"] = client_config
        return session.client(service_name, **kwargs)

    def verify_identity(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Calls STS GetCallerIdentity with a bounded timeout to verify AWS connectivity.
        Distinguishes:
          - NO_CREDENTIALS: No credentials configured.
          - MISSING_SESSION_TOKEN: Temporary ASIA key lacks AWS_SESSION_TOKEN.
          - EXPIRED_CREDENTIALS: Temporary session (e.g. AWS Academy Learner Lab) has expired.
          - INVALID_CREDENTIALS: Keys or tokens are malformed or unrecognized.
          - PERMISSION_DENIED: Access denied calling sts:GetCallerIdentity.
          - CONNECTION_ERROR: Network/DNS unreachable.
          - CONFIGURED_VERIFIED: Identity successfully verified.
        """
        now = time.time()
        if self._cached_identity and not force_refresh and (now - self._cache_timestamp < self._cache_ttl_seconds):
            return self._cached_identity

        detection = self.detect_credential_provider()
        region = detection["region"]

        # Fast diagnostic for temporary ASIA key missing session token
        if detection["missing_session_token"]:
            result = {
                "status": "MISSING_SESSION_TOKEN",
                "authenticated": False,
                "provider_type": detection["provider_type"],
                "account_id": None,
                "arn": None,
                "region": region,
                "is_lab_role": False,
                "error_code": "MissingSessionToken",
                "message": "Temporary AWS key detected (starts with ASIA) but AWS_SESSION_TOKEN is missing.",
                "actionable_guidance": (
                    "AWS Academy Learner Lab generates temporary credentials that require AWS_SESSION_TOKEN. "
                    "Copy the session token from your AWS Details modal and set $env:AWS_SESSION_TOKEN in PowerShell."
                )
            }
            self._cached_identity = result
            self._cache_timestamp = now
            return result

        # Bounded STS client configuration
        fast_config = botocore.config.Config(
            connect_timeout=4,
            read_timeout=4,
            retries={"max_attempts": 1}
        )

        try:
            session = self.get_session()
            effective_region = session.region_name or region or "us-east-1"
            sts = session.client("sts", region_name=effective_region, config=fast_config)
            caller = sts.get_caller_identity()

            arn = caller.get("Arn", "Unknown")
            account = caller.get("Account", "Unknown")
            user_id = caller.get("UserId", "Unknown")
            is_lab_role = "LabRole" in arn or "voclabs" in arn

            result = {
                "status": "CONFIGURED_VERIFIED",
                "authenticated": True,
                "provider_type": detection["provider_type"],
                "account_id": account,
                "arn": arn,
                "user_id": user_id,
                "region": effective_region,
                "is_lab_role": is_lab_role,
                "error_code": None,
                "message": (
                    f"AWS credentials active and verified ({'AWS Academy LabRole' if is_lab_role else 'Standard IAM'})."
                ),
                "actionable_guidance": "Identity confirmed. You can now execute live read-only AWS resource audits."
            }
            self._cached_identity = result
            self._cache_timestamp = now
            return result

        except botocore.exceptions.NoCredentialsError:
            result = {
                "status": "NO_CREDENTIALS",
                "authenticated": False,
                "provider_type": "NONE",
                "account_id": None,
                "arn": None,
                "region": region,
                "is_lab_role": False,
                "error_code": "NoCredentialsError",
                "message": "No AWS credentials detected in environment, ~/.aws/credentials, or IAM role.",
                "actionable_guidance": (
                    "To enable live AWS audits, set your credentials in PowerShell ($env:AWS_ACCESS_KEY_ID), "
                    "add them to a local .env file, or configure your ~/.aws/credentials profile."
                )
            }
            self._cached_identity = result
            self._cache_timestamp = now
            return result

        except botocore.exceptions.PartialCredentialsError:
            result = {
                "status": "INCOMPLETE_CREDENTIALS",
                "authenticated": False,
                "provider_type": detection["provider_type"],
                "account_id": None,
                "arn": None,
                "region": region,
                "is_lab_role": False,
                "error_code": "PartialCredentialsError",
                "message": "Incomplete credentials. Both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required.",
                "actionable_guidance": "Ensure both access key and secret access key are supplied."
            }
            self._cached_identity = result
            self._cache_timestamp = now
            return result

        except botocore.exceptions.ClientError as e:
            err = e.response.get("Error", {})
            code = err.get("Code", "ClientError")
            msg = err.get("Message", str(e))

            if code in ("ExpiredToken", "RequestExpired", "InvalidToken"):
                status_code = "EXPIRED_CREDENTIALS"
                guidance = (
                    "Your temporary AWS Academy Learner Lab session has expired. Open your AWS Academy Learner Lab, "
                    "click 'AWS Details', and copy updated credentials into your PowerShell session or .env file, "
                    "then click 'Refresh Credentials'."
                )
            elif code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                status_code = "INVALID_CREDENTIALS"
                guidance = (
                    "The provided AWS Access Key ID or Secret Access Key is invalid or unrecognized by AWS. "
                    "Check that the keys are copied accurately."
                )
            elif code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                status_code = "PERMISSION_DENIED"
                guidance = "The active AWS identity does not have permission to execute sts:GetCallerIdentity."
            else:
                status_code = "AWS_CLIENT_ERROR"
                guidance = f"AWS ClientError ({code}): {msg}"

            result = {
                "status": status_code,
                "authenticated": False,
                "provider_type": detection["provider_type"],
                "account_id": None,
                "arn": None,
                "region": region,
                "is_lab_role": False,
                "error_code": code,
                "message": f"AWS authentication failed: {code} - {msg}",
                "actionable_guidance": guidance
            }
            self._cached_identity = result
            self._cache_timestamp = now
            return result

        except (botocore.exceptions.EndpointConnectionError, botocore.exceptions.ConnectTimeoutError, botocore.exceptions.ReadTimeoutError) as net_err:
            result = {
                "status": "CONNECTION_ERROR",
                "authenticated": False,
                "provider_type": detection["provider_type"],
                "account_id": None,
                "arn": None,
                "region": region,
                "is_lab_role": False,
                "error_code": type(net_err).__name__,
                "message": f"Unable to reach AWS STS endpoint in region '{region}'. Network or DNS failure.",
                "actionable_guidance": "Verify internet connectivity and confirm the selected AWS region is reachable."
            }
            self._cached_identity = result
            self._cache_timestamp = now
            return result

        except Exception as ex:
            result = {
                "status": "ERROR",
                "authenticated": False,
                "provider_type": detection["provider_type"],
                "account_id": None,
                "arn": None,
                "region": region,
                "is_lab_role": False,
                "error_code": type(ex).__name__,
                "message": f"Unexpected diagnostic error: {str(ex)}",
                "actionable_guidance": "Inspect backend logs for additional context."
            }
            self._cached_identity = result
            self._cache_timestamp = now
            return result


# Global Singleton Instance
aws_session_manager = AWSSessionManager()
