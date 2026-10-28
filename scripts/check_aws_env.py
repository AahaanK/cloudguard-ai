"""
CloudGuardAI - AWS Environment & Credential Verification Utility
Inspects AWS SDK, active credentials, region configuration, and STS identity.
NEVER prints secret tokens or credentials to console or log.
"""

import os
import sys
import shutil

def mask_credential(val: str, prefix_len=4, suffix_len=4) -> str:
    if not val:
        return "Not Set"
    if len(val) <= prefix_len + suffix_len:
        return "***"
    return f"{val[:prefix_len]}...{val[-suffix_len:]} (length {len(val)})"

def inspect_environment():
    print("=" * 65)
    print("  CloudGuardAI - AWS Integration & Environment Audit")
    print("=" * 65)
    
    # 1. Python Runtime
    py_ver = sys.version.split()[0]
    print(f"[*] Python Runtime:       {py_ver} ({sys.executable})")
    
    # 2. AWS SDK (Boto3)
    try:
        import boto3
        import botocore
        print(f"[*] AWS Python SDK:       boto3 v{boto3.__version__} / botocore v{botocore.__version__}")
    except ImportError:
        print("[!] AWS Python SDK:       NOT INSTALLED (Run: python -m pip install boto3)")
        return
        
    # 3. AWS CLI Check
    aws_cli_path = shutil.which("aws")
    if aws_cli_path:
        print(f"[*] AWS CLI Path:         {aws_cli_path}")
    else:
        print("[-] AWS CLI:              Not detected in PATH (Python SDK / Boto3 can still operate directly)")

    # 4. Environment Variables Inspection (Safe / Masked)
    print("\n--- Credential Provider & Configuration Status ---")
    has_env_key = bool(os.environ.get("AWS_ACCESS_KEY_ID"))
    has_env_secret = bool(os.environ.get("AWS_SECRET_ACCESS_KEY"))
    has_env_token = bool(os.environ.get("AWS_SESSION_TOKEN"))
    env_region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")

    print(f"  • AWS_ACCESS_KEY_ID:     {'Set (' + mask_credential(os.environ.get('AWS_ACCESS_KEY_ID', '')) + ')' if has_env_key else 'Not Set'}")
    print(f"  • AWS_SECRET_ACCESS_KEY: {'Configured (Masked)' if has_env_secret else 'Not Set'}")
    print(f"  • AWS_SESSION_TOKEN:     {'Present (Temporary Lab Session)' if has_env_token else 'Not Set (Static or Missing)'}")
    print(f"  • AWS Region (Env):      {env_region if env_region else 'Not configured in env'}")

    # 5. ~/.aws file checks
    home_dir = os.path.expanduser("~")
    aws_folder = os.path.join(home_dir, ".aws")
    cred_file = os.path.join(aws_folder, "credentials")
    config_file = os.path.join(aws_folder, "config")
    
    print(f"  • ~/.aws Directory:      {'Found' if os.path.isdir(aws_folder) else 'Not Found'}")
    print(f"  • ~/.aws/credentials:    {'Present' if os.path.isfile(cred_file) else 'Not Present'}")
    print(f"  • ~/.aws/config:         {'Present' if os.path.isfile(config_file) else 'Not Present'}")

    # 6. Active Identity Verification via STS
    print("\n--- Active AWS STS Identity Verification ---")
    try:
        session = boto3.Session()
        sts_client = session.client("sts", region_name=env_region or "us-east-1")
        caller_id = sts_client.get_caller_identity()
        
        arn = caller_id.get("Arn", "Unknown")
        account = caller_id.get("Account", "Unknown")
        user_id = caller_id.get("UserId", "Unknown")
        
        print(f"[+] STS Verification:    SUCCESSFUL")
        print(f"  • AWS Account ID:       {account}")
        print(f"  • Caller Identity ARN:  {arn}")
        print(f"  • Effective User/Role:  {user_id}")
        
        if "LabRole" in arn or "voclabs" in arn:
            print("  • Lab Environment:      CONFIRMED (AWS Academy Learner Lab detected)")
            print("  • Note:                 Custom IAM role creation is restricted. Service executions rely on LabRole.")
        else:
            print("  • Lab Environment:      Standard IAM User / Role")
            
        # Check Region
        region = session.region_name or "us-east-1"
        print(f"  • Active Region:        {region}")
        if region != "us-east-1":
            print(f"  [!] Note: AWS Academy Learner Labs typically restrict resource provisioning to us-east-1.")

    except botocore.exceptions.NoCredentialsError:
        print("[-] STS Verification:    NO CREDENTIALS DETECTED")
        print("    CloudGuardAI will operate in Local Resilient Mode with mocked AWS resources.")
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        msg = e.response.get("Error", {}).get("Message", str(e))
        print(f"[!] STS Verification FAILED: {code}")
        print(f"    Details: {msg}")
        if "ExpiredToken" in code:
            print("    [!] Your temporary AWS Academy Learner Lab session has EXPIRED.")
            print("        Please re-launch your lab and refresh AWS_SESSION_TOKEN.")
    except Exception as e:
        print(f"[!] Error verifying identity: {str(e)}")

    print("=" * 65 + "\n")

if __name__ == "__main__":
    inspect_environment()
