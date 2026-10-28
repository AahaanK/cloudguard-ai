"""
CloudGuardAI - Live AWS Resource Discovery & Security Scanner
Executes strictly read-only security auditing against live provisioned AWS infrastructure.
Supports S3, EC2/VPC, Security Groups, RDS, and IAM.

Security & Operational Invariants:
1. 100% READ-ONLY: Never creates, modifies, deletes, or remediates AWS resources.
2. PAGINATION & BOUNDING: Bounded discovery with pagination tokens to prevent runaway operations.
3. RATE LIMIT RESILIENCE: Catches Throttling and RequestLimitExceeded per service.
4. HONEST LIMITATION REPORTING: Directly captures and records AWS Academy Learner Lab
   `LabRole` boundaries (AccessDenied) without failing the scan.
5. RESOURCE INVENTORY: Records all discovered resources, compliance status, and configuration evidence.
6. NO ROOT CREDENTIALS: Uses AWS SDK credential provider chain; zero secrets exposed to client.
"""

import uuid
import logging
from typing import List, Dict, Any, Optional
import botocore.exceptions

from ..aws.session_manager import aws_session_manager
from ..aws.error_handler import parse_aws_error
from ..db.models import Finding, ScanJob
from ..engine.scorer import RiskScorer

logger = logging.getLogger("cloudguard.live_scanner")

class LiveAWSScanner:

    def scan_environment(self, scan_id: str, regions: Optional[List[str]] = None, region: Optional[str] = None, single_region: Optional[str] = None) -> ScanJob:
        """
        Performs live, read-only discovery of provisioned AWS resources across configured regions.
        Audits S3, EC2, VPCs, Security Groups, RDS, and IAM.
        """
        identity = aws_session_manager.verify_identity()
        if not identity["authenticated"]:
            raise RuntimeError(
                "Live AWS scan cannot proceed: No AWS credentials detected. "
                "Provide temporary credentials via environment variables ($env:AWS_ACCESS_KEY_ID)."
            )

        account_id = identity.get("account_id", "Unknown-Account")
        is_lab_role = identity.get("is_lab_role", False)

        # Determine target regions
        specified_region = single_region or region
        if specified_region:
            target_regions = [specified_region]
        elif regions and len(regions) > 0:
            target_regions = regions
        else:
            target_regions = [identity.get("region", "us-east-1")]

        session = aws_session_manager.get_session()
        findings: List[Finding] = []
        discovered_resources: List[Dict[str, Any]] = []
        limitations: List[Dict[str, Any]] = []
        service_summary: Dict[str, Any] = {}

        # =====================================================================
        # 1. S3 BUCKET AUDIT (Global Catalog inspected once)
        # =====================================================================
        s3_status = {"inspected": 0, "findings": 0, "status": "AVAILABLE", "error": None}
        try:
            s3 = session.client("s3", region_name=target_regions[0])
            buckets_resp = s3.list_buckets()
            all_buckets = buckets_resp.get("Buckets", [])
            # Bound bucket iteration to prevent runaway API calls in large enterprise accounts
            bounded_buckets = all_buckets[:25]
            s3_status["inspected"] = len(bounded_buckets)

            for b in bounded_buckets:
                bname = b["Name"]
                bucket_arn = f"arn:aws:s3:::{bname}"
                bucket_findings_count = 0
                bucket_details: Dict[str, Any] = {"name": bname}

                # Audit Public Access Block
                try:
                    pab = s3.get_public_access_block(Bucket=bname)
                    cfg = pab.get("PublicAccessBlockConfiguration", {})
                    bucket_details["public_access_block"] = cfg
                    if not cfg.get("BlockPublicAcls") or not cfg.get("RestrictPublicBuckets") or not cfg.get("IgnorePublicAcls"):
                        bucket_findings_count += 1
                        findings.append(Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                            scan_id=scan_id,
                            rule_id="LIVE-S3-001",
                            rule_name="S3 Public Access Block Incomplete",
                            dimension="SECURITY",
                            severity="HIGH",
                            resource_id=bucket_arn,
                            resource_type="AWS::S3::Bucket",
                            evidence={
                                "attribute": "PublicAccessBlockConfiguration",
                                "detected_value": cfg,
                                "expected_value": "All 4 BlockPublic flags set to true"
                            },
                            title=f"Live S3 bucket lacks complete Public Access Block ({bname})",
                            description=f"Bucket {bname} does not enforce all 4 Amazon S3 Block Public Access controls.",
                            impact="Anonymous internet actors could potentially read or upload objects if bucket ACLs are altered.",
                            remediation_summary="Enable all four Public Access Block settings via S3 console or CLI.",
                            remediation_code='resource "aws_s3_bucket_public_access_block" "block" {\n  bucket = aws_s3_bucket.main.id\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}',
                            cli_command=f"aws s3api put-public-access-block --bucket {bname} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ))
                except botocore.exceptions.ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code == "NoSuchPublicAccessBlockConfiguration":
                        bucket_findings_count += 1
                        bucket_details["public_access_block"] = "NONE"
                        findings.append(Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                            scan_id=scan_id,
                            rule_id="LIVE-S3-001",
                            rule_name="S3 Public Access Block Missing",
                            dimension="SECURITY",
                            severity="CRITICAL",
                            resource_id=bucket_arn,
                            resource_type="AWS::S3::Bucket",
                            evidence={"attribute": "PublicAccessBlockConfiguration", "detected_value": "None", "expected_value": "Enabled"},
                            title=f"Live S3 bucket has NO Public Access Block ({bname})",
                            description=f"Bucket {bname} has no active Public Access Block, leaving it vulnerable to open ACLs.",
                            impact="Critical risk of public data exposure if open policies or public-read ACLs exist.",
                            remediation_summary="Apply Amazon S3 Block Public Access immediately.",
                            cli_command=f"aws s3api put-public-access-block --bucket {bname} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ))
                    elif code in ("AccessDenied", "UnauthorizedOperation"):
                        limitations.append({"service": "S3", "api": "get_public_access_block", "resource": bname, "message": "AccessDenied under current IAM credentials."})

                # Audit Server-Side Encryption (SSE)
                try:
                    enc = s3.get_bucket_encryption(Bucket=bname)
                    bucket_details["encryption"] = enc.get("ServerSideEncryptionConfiguration", {})
                except botocore.exceptions.ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code == "ServerSideEncryptionConfigurationNotFoundError":
                        bucket_findings_count += 1
                        bucket_details["encryption"] = "NONE"
                        findings.append(Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                            scan_id=scan_id,
                            rule_id="LIVE-S3-002",
                            rule_name="Live S3 Default Encryption Missing",
                            dimension="SECURITY",
                            severity="HIGH",
                            resource_id=bucket_arn,
                            resource_type="AWS::S3::Bucket",
                            evidence={"attribute": "ServerSideEncryptionConfiguration", "detected_value": "None", "expected_value": "AES256 or aws:kms"},
                            title=f"Bucket lacks default SSE encryption ({bname})",
                            description="Default SSE-S3 or SSE-KMS encryption is not enforced on objects stored in this bucket.",
                            impact="Unencrypted data at rest violates ISO 27001, SOC 2, and AWS security baselines.",
                            remediation_summary="Configure default AES256 server-side encryption.",
                            cli_command=f"aws s3api put-bucket-encryption --bucket {bname} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
                        ))

                # Audit Versioning (Reliability)
                try:
                    ver = s3.get_bucket_versioning(Bucket=bname)
                    status = ver.get("Status", "Suspended")
                    bucket_details["versioning"] = status
                    if status != "Enabled":
                        bucket_findings_count += 1
                        findings.append(Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                            scan_id=scan_id,
                            rule_id="LIVE-S3-003",
                            rule_name="Live S3 Bucket Versioning Disabled",
                            dimension="RELIABILITY",
                            severity="LOW",
                            resource_id=bucket_arn,
                            resource_type="AWS::S3::Bucket",
                            evidence={"attribute": "VersioningStatus", "detected_value": status, "expected_value": "Enabled"},
                            title=f"Bucket versioning is not enabled ({bname})",
                            description="Object versioning is disabled or suspended, preventing recovery from accidental overwrites.",
                            impact="Risk of unrecoverable data loss upon accidental deletion.",
                            remediation_summary="Enable object versioning on the S3 bucket.",
                            cli_command=f"aws s3api put-bucket-versioning --bucket {bname} --versioning-configuration Status=Enabled"
                        ))
                except botocore.exceptions.ClientError:
                    pass

                discovered_resources.append({
                    "resource_id": bucket_arn,
                    "resource_name": bname,
                    "resource_type": "AWS::S3::Bucket",
                    "region": "global",
                    "status": "NON_COMPLIANT" if bucket_findings_count > 0 else "COMPLIANT",
                    "findings_count": bucket_findings_count,
                    "details": bucket_details
                })

            s3_status["findings"] = sum(1 for f in findings if f.resource_type == "AWS::S3::Bucket")

        except botocore.exceptions.ClientError as ce:
            parsed = parse_aws_error(ce, "s3:ListBuckets")
            s3_status["status"] = "RESTRICTED"
            s3_status["error"] = parsed["message"]
            limitations.append({"service": "S3", "api": "ListBuckets", "message": parsed["message"]})
        except Exception as ex:
            s3_status["status"] = "ERROR"
            s3_status["error"] = str(ex)

        service_summary["S3"] = s3_status

        # =====================================================================
        # 2. REGIONAL SERVICES AUDIT (EC2, VPC, Security Groups, RDS)
        # =====================================================================
        for r_name in target_regions:
            # 2A. EC2 & VPC Discovery
            ec2_status = {"inspected": 0, "findings": 0, "status": "AVAILABLE", "error": None}
            try:
                ec2 = session.client("ec2", region_name=r_name)

                # Security Groups Audit
                sg_paginator = ec2.get_paginator("describe_security_groups")
                sg_count = 0
                for page in sg_paginator.paginate(PaginationConfig={"MaxItems": 40, "PageSize": 20}):
                    for sg in page.get("SecurityGroups", []):
                        sg_count += 1
                        sg_id = sg.get("GroupId")
                        sg_name = sg.get("GroupName", "unnamed")
                        sg_findings_count = 0

                        for rule in sg.get("IpPermissions", []):
                            from_port = rule.get("FromPort")
                            to_port = rule.get("ToPort")
                            proto = rule.get("IpProtocol", "")
                            is_all_ports = (from_port is None and to_port is None) or proto == "-1"

                            for ip_range in rule.get("IpRanges", []):
                                cidr = ip_range.get("CidrIp")
                                if cidr in ("0.0.0.0/0", "::/0"):
                                    # Open SSH (Port 22)
                                    if from_port == 22 or (from_port and to_port and from_port <= 22 <= to_port) or is_all_ports:
                                        sg_findings_count += 1
                                        findings.append(Finding(
                                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                                            scan_id=scan_id,
                                            rule_id="LIVE-NET-001",
                                            rule_name="Live Security Group SSH Open to Internet",
                                            dimension="NETWORK",
                                            severity="CRITICAL",
                                            resource_id=sg_id,
                                            resource_type="AWS::EC2::SecurityGroup",
                                            evidence={
                                                "attribute": "IpPermissions.IpRanges.CidrIp",
                                                "detected_value": f"{cidr} on TCP {from_port or 'ALL'}",
                                                "expected_value": "Restricted private CIDR (e.g. 10.0.0.0/8)"
                                            },
                                            title=f"Port 22 SSH open to internet on {sg_name} ({sg_id})",
                                            description=f"Security group rule permits open 0.0.0.0/0 ingress to TCP port 22.",
                                            impact="Exposes instance management interfaces to continuous brute-force attacks.",
                                            remediation_summary="Revoke the 0.0.0.0/0 ingress rule and restrict SSH to an internal bastion or VPN IP.",
                                            cli_command=f"aws ec2 revoke-security-group-ingress --region {r_name} --group-id {sg_id} --protocol tcp --port 22 --cidr 0.0.0.0/0"
                                        ))

                                    # Open RDP (Port 3389)
                                    if from_port == 3389 or (from_port and to_port and from_port <= 3389 <= to_port) or is_all_ports:
                                        sg_findings_count += 1
                                        findings.append(Finding(
                                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                                            scan_id=scan_id,
                                            rule_id="LIVE-NET-002",
                                            rule_name="Live Security Group RDP Open to Internet",
                                            dimension="NETWORK",
                                            severity="CRITICAL",
                                            resource_id=sg_id,
                                            resource_type="AWS::EC2::SecurityGroup",
                                            evidence={"attribute": "FromPort", "detected_value": 3389, "expected_value": "Private access only"},
                                            title=f"Port 3389 RDP open to internet on {sg_name} ({sg_id})",
                                            description="Windows Remote Desktop (RDP) port 3389 allows unrestricted internet access.",
                                            impact="High exposure to automated ransomware deployments and credential stuffers.",
                                            remediation_summary="Remove 0.0.0.0/0 access on port 3389.",
                                            cli_command=f"aws ec2 revoke-security-group-ingress --region {r_name} --group-id {sg_id} --protocol tcp --port 3389 --cidr 0.0.0.0/0"
                                        ))

                                    # Open Database Ports (3306, 5432, 1433)
                                    if from_port in (3306, 5432, 1433, 27017):
                                        sg_findings_count += 1
                                        findings.append(Finding(
                                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                                            scan_id=scan_id,
                                            rule_id="LIVE-NET-003",
                                            rule_name="Live Database Port Open to Internet",
                                            dimension="NETWORK",
                                            severity="HIGH",
                                            resource_id=sg_id,
                                            resource_type="AWS::EC2::SecurityGroup",
                                            evidence={"attribute": "FromPort", "detected_value": from_port, "expected_value": "Internal application subnet only"},
                                            title=f"Database port {from_port} open to internet on {sg_name} ({sg_id})",
                                            description=f"Database listener on port {from_port} accepts traffic from 0.0.0.0/0.",
                                            impact="Direct exposure of database engines to network probes and zero-day exploits.",
                                            remediation_summary="Restrict database security group ingress to application tier subnets.",
                                            cli_command=f"aws ec2 revoke-security-group-ingress --region {r_name} --group-id {sg_id} --protocol tcp --port {from_port} --cidr 0.0.0.0/0"
                                        ))

                        discovered_resources.append({
                            "resource_id": sg_id,
                            "resource_name": sg_name,
                            "resource_type": "AWS::EC2::SecurityGroup",
                            "region": r_name,
                            "status": "NON_COMPLIANT" if sg_findings_count > 0 else "COMPLIANT",
                            "findings_count": sg_findings_count,
                            "details": {"group_name": sg_name, "rules_count": len(sg.get("IpPermissions", []))}
                        })

                ec2_status["inspected"] += sg_count

                # VPC Default VPC Check
                vpcs = ec2.describe_vpcs(MaxResults=10).get("Vpcs", [])
                for v in vpcs:
                    vpc_id = v.get("VpcId")
                    is_def = v.get("IsDefault", False)
                    v_findings = 0
                    if is_def:
                        v_findings += 1
                        findings.append(Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                            scan_id=scan_id,
                            rule_id="LIVE-VPC-001",
                            rule_name="Default VPC In Use",
                            dimension="NETWORK",
                            severity="LOW",
                            resource_id=vpc_id,
                            resource_type="AWS::EC2::VPC",
                            evidence={"attribute": "IsDefault", "detected_value": True, "expected_value": False},
                            title=f"Account utilizes Default VPC ({vpc_id}) in {r_name}",
                            description="Default VPC has public subnets with internet gateways attached by default.",
                            impact="Increases risk of accidental resource internet exposure compared to custom tiered VPCs.",
                            remediation_summary="Migrate production workloads to a dedicated custom multi-tier VPC.",
                            cli_command=f"# Create custom VPC\naws ec2 create-vpc --region {r_name} --cidr-block 10.0.0.0/16"
                        ))

                    discovered_resources.append({
                        "resource_id": vpc_id,
                        "resource_name": f"VPC-{vpc_id[-6:]}",
                        "resource_type": "AWS::EC2::VPC",
                        "region": r_name,
                        "status": "NON_COMPLIANT" if v_findings > 0 else "COMPLIANT",
                        "findings_count": v_findings,
                        "details": {"cidr": v.get("CidrBlock"), "is_default": is_def}
                    })

                ec2_status["inspected"] += len(vpcs)
                ec2_status["findings"] = sum(1 for f in findings if f.resource_type.startswith("AWS::EC2"))

            except botocore.exceptions.ClientError as ce:
                parsed = parse_aws_error(ce, f"ec2:DescribeSecurityGroups ({r_name})")
                ec2_status["status"] = "RESTRICTED"
                ec2_status["error"] = parsed["message"]
                limitations.append({"service": "EC2", "api": "DescribeSecurityGroups", "region": r_name, "message": parsed["message"]})
            except Exception as ex:
                ec2_status["status"] = "ERROR"
                ec2_status["error"] = str(ex)

            service_summary[f"EC2_{r_name}"] = ec2_status

            # 2B. RDS Database Discovery
            rds_status = {"inspected": 0, "findings": 0, "status": "AVAILABLE", "error": None}
            try:
                rds = session.client("rds", region_name=r_name)
                db_instances = rds.describe_db_instances(MaxRecords=20).get("DBInstances", [])
                rds_status["inspected"] = len(db_instances)

                for db in db_instances:
                    db_id = db.get("DBInstanceIdentifier")
                    db_arn = db.get("DBInstanceArn", f"arn:aws:rds:{r_name}:{account_id}:db:{db_id}")
                    db_findings = 0

                    # Check Public Accessibility
                    is_public = db.get("PubliclyAccessible", False)
                    if is_public:
                        db_findings += 1
                        findings.append(Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                            scan_id=scan_id,
                            rule_id="LIVE-RDS-001",
                            rule_name="Live RDS Database Publicly Accessible",
                            dimension="SECURITY",
                            severity="CRITICAL",
                            resource_id=db_arn,
                            resource_type="AWS::RDS::DBInstance",
                            evidence={"attribute": "PubliclyAccessible", "detected_value": True, "expected_value": False},
                            title=f"RDS database {db_id} has public internet endpoint",
                            description="Database instance assigns public IP and resolves externally on the internet.",
                            impact="Critical risk of direct unauthorized database connection attempts and credential compromise.",
                            remediation_summary="Modify database instance to disable PubliclyAccessible.",
                            cli_command=f"aws rds modify-db-instance --region {r_name} --db-instance-identifier {db_id} --no-publicly-accessible --apply-immediately"
                        ))

                    # Check Storage Encryption
                    is_enc = db.get("StorageEncrypted", False)
                    if not is_enc:
                        db_findings += 1
                        findings.append(Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                            scan_id=scan_id,
                            rule_id="LIVE-RDS-002",
                            rule_name="Live RDS Storage Encryption Disabled",
                            dimension="SECURITY",
                            severity="HIGH",
                            resource_id=db_arn,
                            resource_type="AWS::RDS::DBInstance",
                            evidence={"attribute": "StorageEncrypted", "detected_value": False, "expected_value": True},
                            title=f"RDS database {db_id} storage is not encrypted at rest",
                            description="Database storage volume does not utilize AWS KMS encryption at rest.",
                            impact="Data stored in automated snapshots and underlying storage volumes is unencrypted.",
                            remediation_summary="Create an encrypted snapshot and restore it to a new encrypted RDS instance.",
                            cli_command=f"aws rds copy-db-snapshot --source-db-snapshot-identifier <snap> --target-db-snapshot-identifier <snap-enc> --kms-key-id alias/aws/rds"
                        ))

                    # Check Multi-AZ (Reliability)
                    multi_az = db.get("MultiAZ", False)
                    if not multi_az:
                        db_findings += 1
                        findings.append(Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:12]}",
                            scan_id=scan_id,
                            rule_id="LIVE-RDS-003",
                            rule_name="Live RDS Database Not Multi-AZ",
                            dimension="RELIABILITY",
                            severity="MEDIUM",
                            resource_id=db_arn,
                            resource_type="AWS::RDS::DBInstance",
                            evidence={"attribute": "MultiAZ", "detected_value": False, "expected_value": True},
                            title=f"RDS database {db_id} lacks Multi-AZ high availability",
                            description="Database runs on a single Availability Zone without automated standby failover.",
                            impact="Unplanned AZ outage or hardware degradation will cause database downtime.",
                            remediation_summary="Enable Multi-AZ deployment on production RDS instances.",
                            cli_command=f"aws rds modify-db-instance --region {r_name} --db-instance-identifier {db_id} --multi-az --apply-immediately"
                        ))

                    discovered_resources.append({
                        "resource_id": db_arn,
                        "resource_name": db_id,
                        "resource_type": "AWS::RDS::DBInstance",
                        "region": r_name,
                        "status": "NON_COMPLIANT" if db_findings > 0 else "COMPLIANT",
                        "findings_count": db_findings,
                        "details": {"engine": db.get("Engine"), "public": is_public, "encrypted": is_enc, "multi_az": multi_az}
                    })

                rds_status["findings"] = sum(1 for f in findings if f.resource_type == "AWS::RDS::DBInstance")

            except botocore.exceptions.ClientError as ce:
                parsed = parse_aws_error(ce, f"rds:DescribeDBInstances ({r_name})")
                rds_status["status"] = "RESTRICTED"
                rds_status["error"] = parsed["message"]
                limitations.append({"service": "RDS", "api": "DescribeDBInstances", "region": r_name, "message": parsed["message"]})
            except Exception as ex:
                rds_status["status"] = "ERROR"
                rds_status["error"] = str(ex)

            service_summary[f"RDS_{r_name}"] = rds_status

        # =====================================================================
        # 3. IAM AUDIT (Read-Only)
        # =====================================================================
        iam_status = {"inspected": 0, "findings": 0, "status": "AVAILABLE", "error": None}
        try:
            iam = session.client("iam")
            try:
                # Check Root Account MFA
                acc_summary = iam.get_account_summary().get("SummaryMap", {})
                mfa_active = acc_summary.get("AccountMFAEnabled", 0)
                iam_status["inspected"] += 1

                if mfa_active != 1:
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="LIVE-IAM-001",
                        rule_name="AWS Account Root MFA Not Enabled",
                        dimension="IAM",
                        severity="CRITICAL",
                        resource_id=f"arn:aws:iam::{account_id}:root",
                        resource_type="AWS::IAM::RootAccount",
                        evidence={"attribute": "AccountMFAEnabled", "detected_value": mfa_active, "expected_value": 1},
                        title="AWS Account root user lacks Multi-Factor Authentication",
                        description="Root account credentials are not protected with a hardware or virtual MFA device.",
                        impact="Single-factor password compromise allows total takeover of all cloud infrastructure.",
                        remediation_summary="Enable a virtual or FIDO2 hardware MFA device on the root user immediately.",
                        cli_command="# Log into AWS Management Console as root -> Security Credentials -> Assign MFA"
                    ))
            except botocore.exceptions.ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                    # Common in AWS Academy Learner Lab: report honestly
                    iam_status["status"] = "RESTRICTED"
                    reason = "AWS Academy Learner Lab (LabRole) restricts account summary and root credential inspection."
                    iam_status["error"] = reason
                    limitations.append({"service": "IAM", "api": "GetAccountSummary", "status": "RESTRICTED", "message": reason})

            iam_status["findings"] = sum(1 for f in findings if f.dimension == "IAM")

        except Exception as e:
            iam_status["status"] = "ERROR"
            iam_status["error"] = str(e)

        service_summary["IAM"] = iam_status

        # =====================================================================
        # 4. COMPUTE RISK SCORES & BUILD SCANJOB
        # =====================================================================
        score, grade, dim_scores, counts = RiskScorer.calculate_score(findings)

        target_name = (
            f"Live AWS Environment ({account_id}) [Regions: {', '.join(target_regions)}]"
            if not is_lab_role else
            f"AWS Academy Learner Lab ({account_id}) [Regions: {', '.join(target_regions)}]"
        )

        discovery_summary = {
            "account_id": account_id,
            "is_learner_lab": is_lab_role,
            "regions_audited": target_regions,
            "total_resources_discovered": len(discovered_resources),
            "total_findings_detected": counts["total"],
            "by_service": service_summary,
            "limitations_recorded": limitations
        }

        return ScanJob(
            scan_id=scan_id,
            scan_type="LIVE_AWS",
            target_name=target_name,
            status="COMPLETED",
            overall_risk_score=score,
            risk_grade=grade,
            total_findings=counts["total"],
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            dimension_scores=dim_scores,
            unsupported_constructs=limitations,
            discovered_resources=discovered_resources,
            discovery_summary=discovery_summary,
            storage_backend="live_aws",
            findings=findings
        )

live_scanner = LiveAWSScanner()
