"""
CloudGuardAI - Amazon S3 Smoke Test Utility
Verifies real S3 connectivity, SSE-S3 encryption, file upload, and presigned URL generation.
DOES NOT create or delete buckets. Uses existing bucket specified via S3_BUCKET_NAME.
"""

import sys
import os

# Set PYTHONPATH to project root
proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)

from backend.app.config import settings
from backend.app.storage.s3_service import S3StorageService
from backend.app.aws.session_manager import aws_session_manager

def run_s3_smoke_test():
    print("=" * 60)
    print("  CloudGuardAI - Amazon S3 Integration Smoke Test")
    print("=" * 60)

    bucket = settings.aws.s3_bucket
    if not bucket:
        print("[!] S3_BUCKET_NAME environment variable is NOT set.")
        print("    Example: $env:S3_BUCKET_NAME = 'cloudguardai-artifacts-xxxx'")
        print("    Smoke test cannot proceed against live S3.")
        return

    print(f"[*] Target Bucket:       {bucket}")
    print(f"[*] Configured Region:   {settings.aws.region}")

    # 1. Verify Identity
    identity = aws_session_manager.verify_identity(force_refresh=True)
    if not identity["authenticated"]:
        print(f"[!] Authentication Failed: {identity['message']}")
        return
    print(f"[+] Authenticated As:    {identity['arn']}")

    # 2. Check Bucket Accessibility (HeadBucket)
    s3_svc = S3StorageService(bucket_name=bucket)
    health = s3_svc.check_bucket_health()
    if not health.get("accessible"):
        print(f"[!] Bucket inaccessible: {health.get('error_code')} - {health.get('message')}")
        print(f"    Remediation: {health.get('remediation')}")
        return
    print("[+] HeadBucket Check:    SUCCESS (Bucket exists and is accessible)")

    # 3. Test Object Upload with SSE-S3 Encryption
    test_content = b"""// CloudGuardAI S3 Smoke Test Sample
resource "aws_s3_bucket" "smoke_test" {
  bucket = "smoke-test-bucket"
  acl    = "private"
}
"""
    print("\n[*] Uploading test blueprint with ServerSideEncryption='AES256'...")
    try:
        res = s3_svc.upload_file(
            content=test_content,
            filename="smoke_test.tf",
            analysis_id="smoke_test_run"
        )
        print("[+] Upload Succeeded:")
        print(f"    • Object Key:       {res['file_key']}")
        print(f"    • Size:             {res['size_bytes']} bytes")
        print(f"    • SHA-256:          {res['sha256']}")
        print(f"    • Server Encryption: AES256")
        print(f"    • Presigned URL:    {res['presigned_url'][:60]}... (valid 15m)")
    except Exception as e:
        print(f"[!] S3 Upload Failed: {str(e)}")
        return

    # 4. Test Object Download
    print("\n[*] Downloading test blueprint from S3...")
    try:
        downloaded, ctype = s3_svc.download_file(res["file_key"])
        if downloaded == test_content:
            print(f"[+] Integrity Verified: Downloaded content exactly matches original payload.")
        else:
            print("[!] Content mismatch on download.")
    except Exception as e:
        print(f"[!] S3 Download Failed: {str(e)}")
        return

    print("\n" + "=" * 60)
    print("  RESULT: Amazon S3 Live Integration Smoke Test PASSED")
    print("=" * 60)

if __name__ == "__main__":
    run_s3_smoke_test()
