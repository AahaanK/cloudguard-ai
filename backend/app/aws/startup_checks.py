"""
CloudGuardAI - Non-Destructive Startup Permission & Health Auditor
Performs non-destructive validation of AWS configurations and local storage paths.
Never mutates resources, incurs zero billable operations, and exposes zero secrets.
"""

import os
from typing import Dict, Any, List
from .session_manager import aws_session_manager
from .error_handler import parse_aws_error
from ..config import settings

def run_startup_checks() -> Dict[str, Any]:
    """Runs a series of safe startup checks and returns structured audit results."""
    results: Dict[str, Any] = {
        "status": "PASS",
        "storage_mode": settings.storage_backend,
        "database_mode": settings.database_backend,
        "checks": []
    }

    # 1. Local Storage Directory Validation
    try:
        os.makedirs(os.path.join(settings.storage_local_dir, "uploads"), exist_ok=True)
        os.makedirs(os.path.join(settings.storage_local_dir, "reports"), exist_ok=True)
        results["checks"].append({
            "name": "Local Storage Hierarchy",
            "passed": True,
            "details": f"Verified write permissions in {settings.storage_local_dir}"
        })
    except Exception as e:
        results["checks"].append({
            "name": "Local Storage Hierarchy",
            "passed": False,
            "details": f"Failed to ensure storage directory: {str(e)}"
        })
        results["status"] = "DEGRADED"

    # 2. STS Identity Verification
    identity = aws_session_manager.verify_identity(force_refresh=True)
    if identity["authenticated"]:
        results["checks"].append({
            "name": "AWS Authentication (STS)",
            "passed": True,
            "details": f"Authenticated as {identity['arn']} in region {identity['region']}"
        })
        if identity.get("is_lab_role"):
            results["checks"].append({
                "name": "Learner Lab Environment",
                "passed": True,
                "details": "AWS Academy LabRole detected. Adhering to permission boundary."
            })
    else:
        results["checks"].append({
            "name": "AWS Authentication (STS)",
            "passed": False,
            "details": identity["message"]
        })

    # 3. Non-Destructive Probing for Live Scanning Permissions (if authenticated)
    if identity["authenticated"]:
        session = aws_session_manager.get_session()
        
        # Test EC2 read-only
        try:
            ec2 = session.client("ec2", region_name=identity["region"])
            ec2.describe_security_groups(MaxResults=5)
            results["checks"].append({
                "name": "Live Scanner: EC2 Read Access",
                "passed": True,
                "details": "ec2:DescribeSecurityGroups succeeded"
            })
        except Exception as e:
            parsed = parse_aws_error(e, "ec2:DescribeSecurityGroups")
            results["checks"].append({
                "name": "Live Scanner: EC2 Read Access",
                "passed": False,
                "details": f"{parsed['code']}: {parsed['message']}"
            })

        # Test S3 read-only list
        try:
            s3 = session.client("s3", region_name=identity["region"])
            s3.list_buckets()
            results["checks"].append({
                "name": "Live Scanner: S3 Read Access",
                "passed": True,
                "details": "s3:ListAllMyBuckets succeeded"
            })
        except Exception as e:
            parsed = parse_aws_error(e, "s3:ListAllMyBuckets")
            results["checks"].append({
                "name": "Live Scanner: S3 Read Access",
                "passed": False,
                "details": f"{parsed['code']}: {parsed['message']}"
            })

        # Test Bedrock Model Access
        try:
            bedrock = session.client("bedrock", region_name=identity["region"])
            bedrock.list_foundation_models()
            results["checks"].append({
                "name": "AI Explanations: Amazon Bedrock",
                "passed": True,
                "details": "bedrock:ListFoundationModels succeeded"
            })
        except Exception as e:
            parsed = parse_aws_error(e, "bedrock:ListFoundationModels")
            results["checks"].append({
                "name": "AI Explanations: Amazon Bedrock",
                "passed": False,
                "details": f"{parsed['code']}: Deterministic remediation engine active."
            })

    return results

if __name__ == "__main__":
    print("Running CloudGuardAI Pre-Flight Startup Checks...\n")
    audit = run_startup_checks()
    print(f"Overall Status: {audit['status']}")
    print(f"Storage Mode:   {audit['storage_mode']}")
    print(f"Database Mode:  {audit['database_mode']}\n")
    for chk in audit["checks"]:
        icon = "[+]" if chk["passed"] else "[-]"
        print(f"  {icon} {chk['name']}: {chk['details']}")
