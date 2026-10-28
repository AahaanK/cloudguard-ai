"""
CloudGuardAI - AWS Permission & Error Handling System
Translates AWS SDK ClientErrors into user-friendly diagnostics,
detects Learner Lab boundaries, and prevents secret exposure in stack traces.
"""

from typing import Dict, Any, Optional
import botocore.exceptions

def parse_aws_error(error: Exception, operation_context: str = "") -> Dict[str, Any]:
    """
    Analyzes an AWS SDK exception, provides context-aware troubleshooting advice,
    and returns a clean, non-leaking JSON-serializable dictionary.
    """
    if isinstance(error, botocore.exceptions.NoCredentialsError):
        return {
            "error_type": "AUTHENTICATION_REQUIRED",
            "code": "NoCredentialsError",
            "operation": operation_context,
            "message": "AWS credentials were not found in the environment, credentials file, or instance metadata.",
            "remediation": "Provide credentials via environment variables ($env:AWS_ACCESS_KEY_ID) or continue using Local Resilient Mode."
        }

    if isinstance(error, botocore.exceptions.PartialCredentialsError):
        return {
            "error_type": "INCOMPLETE_CREDENTIALS",
            "code": "PartialCredentialsError",
            "operation": operation_context,
            "message": "Incomplete AWS credentials. Both Access Key ID and Secret Access Key must be specified.",
            "remediation": "Check that both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are defined."
        }

    if isinstance(error, botocore.exceptions.ClientError):
        err_response = error.response.get("Error", {})
        code = err_response.get("Code", "ClientError")
        raw_msg = err_response.get("Message", str(error))

        # Check for Session Expiration (Crucial for AWS Academy Learner Lab)
        if code in ("ExpiredToken", "RequestExpired", "InvalidToken"):
            return {
                "error_type": "SESSION_EXPIRED",
                "code": code,
                "operation": operation_context,
                "message": "Your temporary AWS Academy Learner Lab session has expired.",
                "remediation": "Open your AWS Academy Learner Lab console, click 'AWS Details', and refresh your $env:AWS_SESSION_TOKEN."
            }

        # Check for Permission / IAM Boundaries
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            is_lab = "LabRole" in raw_msg or "learner" in raw_msg.lower() or "boundary" in raw_msg.lower()
            advice = (
                "Your AWS Academy LabRole does not permit this action. CloudGuardAI will fall back to local execution."
                if is_lab else
                "Ensure your IAM User or Role has the required policy attached (see aws_permissions/cloudguard_least_privilege_policy.json)."
            )
            return {
                "error_type": "PERMISSION_DENIED",
                "code": code,
                "operation": operation_context,
                "message": f"Access denied during {operation_context}: {raw_msg}",
                "remediation": advice
            }

        # Check for Region / Opt-in issues
        if code in ("OptInRequired", "UnrecognizedClientException"):
            return {
                "error_type": "REGION_OR_KEY_INVALID",
                "code": code,
                "operation": operation_context,
                "message": f"Region or Account mismatch during {operation_context}.",
                "remediation": "Ensure region is set to 'us-east-1' (the standard region for AWS Academy)."
            }

        # Bedrock-specific permission issues
        if "bedrock" in operation_context.lower() or "ModelNotReadyException" in code:
            return {
                "error_type": "BEDROCK_UNAVAILABLE",
                "code": code,
                "operation": operation_context,
                "message": "Amazon Bedrock foundation model is not enabled or accessible in this AWS account.",
                "remediation": "CloudGuardAI will automatically provide comprehensive remediation advice using its built-in deterministic engine."
            }

        return {
            "error_type": "AWS_CLIENT_ERROR",
            "code": code,
            "operation": operation_context,
            "message": raw_msg,
            "remediation": "Inspect AWS service health and parameters."
        }

    # Catch-all
    return {
        "error_type": "SYSTEM_ERROR",
        "code": type(error).__name__,
        "operation": operation_context,
        "message": str(error),
        "remediation": "Review application logs."
    }
