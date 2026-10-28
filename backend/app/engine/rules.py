"""
CloudGuardAI - 7-Dimension Security & Architecture Rule Catalog
Evaluates normalized resources across all seven dimensions and produces
detailed findings with structured evidence, rationale, impact, and remediations.
"""

import uuid
from typing import List, Dict, Any, Optional
from .parser import NormalizedResource
from ..db.models import Finding

class RuleEvaluator:

    @staticmethod
    def evaluate(resources: List[NormalizedResource], scan_id: str) -> List[Finding]:
        findings: List[Finding] = []

        for r in resources:
            r_type = r.resource_type.lower()
            p = r.properties
            raw_repr = (str(p.get("_raw_hcl", "")) + " " + str(p)).lower()

            # ==========================================
            # DIMENSION 1: SECURITY
            # ==========================================
            # SEC-S3-001: Public Read/Write S3 Bucket
            if "s3" in r_type and "bucket" in r_type:
                acl = str(p.get("acl", p.get("AccessControl", ""))).lower()
                if acl in ("public-read", "public-read-write"):
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="SEC-S3-001",
                        rule_name="S3 Bucket Public Read/Write Access",
                        dimension="SECURITY",
                        severity="CRITICAL",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "acl",
                            "detected_value": acl,
                            "expected_value": "private"
                        },
                        title=f"Public access granted on S3 bucket ({r.resource_id})",
                        description=f"Bucket specifies '{acl}' ACL allowing unauthorized anonymous internet access.",
                        impact="High risk of confidential data exfiltration, regulatory penalties (GDPR/HIPAA), and unauthorized modifications.",
                        remediation_summary="Set bucket ACL to 'private' and attach an aws_s3_bucket_public_access_block.",
                        remediation_code='resource "aws_s3_bucket_public_access_block" "block" {\n  bucket = ' + r.resource_id + '.id\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}',
                        cli_command=f"aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        line_number=r.line_number
                    ))

                # SEC-S3-002: Missing Default S3 Encryption
                if not p.get("server_side_encryption_configuration") and not p.get("BucketEncryption"):
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="SEC-S3-002",
                        rule_name="S3 Bucket Server-Side Encryption Missing",
                        dimension="SECURITY",
                        severity="HIGH",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "server_side_encryption_configuration",
                            "detected_value": "None",
                            "expected_value": "AES256 or aws:kms"
                        },
                        title=f"Server-side encryption missing on S3 bucket ({r.resource_id})",
                        description="Bucket does not declare default AES256 or KMS server-side encryption.",
                        impact="Stored objects may be written in plaintext, violating security baselines and compliance mandates.",
                        remediation_summary="Enable default server-side encryption using AES256 or AWS KMS.",
                        remediation_code='resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {\n  bucket = ' + r.resource_id + '.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}',
                        cli_command="aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'",
                        line_number=r.line_number
                    ))

            # SEC-RDS-001: Publicly Accessible RDS
            if "db_instance" in r_type or "rds" in r_type:
                publicly_acc = p.get("publicly_accessible", p.get("PubliclyAccessible", False))
                if publicly_acc is True or str(publicly_acc).lower() == "true":
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="SEC-RDS-001",
                        rule_name="RDS Database Publicly Accessible",
                        dimension="SECURITY",
                        severity="CRITICAL",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "publicly_accessible",
                            "detected_value": True,
                            "expected_value": False
                        },
                        title=f"Public accessibility enabled on database ({r.resource_id})",
                        description="Database instance assigns public IP and resolves externally on the internet.",
                        impact="Direct exposure of database engines to network probes, brute force attacks, and zero-day exploits.",
                        remediation_summary="Set publicly_accessible = false and host within private subnets.",
                        remediation_code='publicly_accessible = false',
                        cli_command="aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible",
                        line_number=r.line_number
                    ))

            # SEC-EBS-001: Unencrypted EBS Volume
            if "ebs_volume" in r_type or "volume" in r_type:
                if p.get("encrypted") is False:
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="SEC-EBS-001",
                        rule_name="EBS Volume Encryption Disabled",
                        dimension="SECURITY",
                        severity="HIGH",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "encrypted",
                            "detected_value": False,
                            "expected_value": True
                        },
                        title=f"EBS volume without encryption at rest ({r.resource_id})",
                        description="The volume was explicitly defined with 'encrypted = false'.",
                        impact="Data in transit between EC2 and EBS, as well as volume snapshots, remain unencrypted.",
                        remediation_summary="Set encrypted = true on aws_ebs_volume.",
                        remediation_code='encrypted = true',
                        line_number=r.line_number
                    ))

            # ==========================================
            # DIMENSION 2: IAM
            # ==========================================
            # IAM-POL-001: Wildcard Action Allowed
            if "iam" in r_type and ("policy" in r_type or "role" in r_type):
                policy_text = str(p.get("policy", p.get("PolicyDocument", ""))).lower()
                if '"action": "*"' in policy_text or "'action': '*'" in policy_text or '"action": ["*"]' in policy_text or '"*"' in str(p.get("Action", "")):
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="IAM-POL-001",
                        rule_name="IAM Policy Wildcard Action Allowed",
                        dimension="IAM",
                        severity="CRITICAL",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "Action",
                            "detected_value": "*",
                            "expected_value": "Specific scoped actions (e.g. s3:GetObject)"
                        },
                        title=f"Full administrative wildcard Action (*) granted ({r.resource_id})",
                        description="Policy statement contains Action: '*' with Effect: Allow, violating least-privilege.",
                        impact="Grants excessive privileges across all AWS services, allowing complete account takeover.",
                        remediation_summary="Scope Action down to specific required service APIs.",
                        remediation_code='Action = [\n  "s3:GetObject",\n  "s3:PutObject"\n]',
                        line_number=r.line_number
                    ))

            # ==========================================
            # DIMENSION 3: NETWORK
            # ==========================================
            if "security_group" in r_type:
                # NET-SG-001: Open SSH Ingress (Port 22)
                if "0.0.0.0/0" in raw_repr and ("22" in raw_repr or "from_port" in raw_repr):
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="NET-SG-001",
                        rule_name="Security Group Port 22 Open to 0.0.0.0/0",
                        dimension="NETWORK",
                        severity="CRITICAL",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "ingress.cidr_blocks",
                            "detected_value": "0.0.0.0/0 on port 22",
                            "expected_value": "Restricted corporate CIDR"
                        },
                        title=f"SSH administration port 22 open to entire internet ({r.resource_id})",
                        description="Security group allows unrestricted inbound TCP 22 access from 0.0.0.0/0.",
                        impact="Allows internet-wide brute force attacks, credential stuffing, and unauthorized shell access.",
                        remediation_summary="Restrict ingress CIDR to corporate VPN or bastion host IP.",
                        remediation_code='cidr_blocks = ["10.0.0.0/16"] # Restrict to internal CIDR',
                        cli_command="aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0",
                        line_number=r.line_number
                    ))

                # NET-SG-002: Open RDP Ingress (Port 3389)
                if "0.0.0.0/0" in raw_repr and "3389" in raw_repr:
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="NET-SG-002",
                        rule_name="Security Group Port 3389 RDP Open to 0.0.0.0/0",
                        dimension="NETWORK",
                        severity="CRITICAL",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "ingress.cidr_blocks",
                            "detected_value": "0.0.0.0/0 on port 3389",
                            "expected_value": "Restricted corporate CIDR"
                        },
                        title=f"Windows Remote Desktop (RDP) port 3389 open to entire internet ({r.resource_id})",
                        description="Security group allows unrestricted inbound TCP 3389 access from 0.0.0.0/0.",
                        impact="High vulnerability to automated ransomware propagation and brute force attacks.",
                        remediation_summary="Restrict RDP port 3389 to private network or management VPN.",
                        remediation_code='cidr_blocks = ["10.0.0.0/16"] # Restrict to internal CIDR',
                        cli_command="aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 3389 --cidr 0.0.0.0/0",
                        line_number=r.line_number
                    ))

            # ==========================================
            # DIMENSION 4: CONFIGURATION
            # ==========================================
            # CFG-RDS-001: RDS Deletion Protection Disabled
            if "db_instance" in r_type or "rds" in r_type:
                if p.get("deletion_protection") is False or str(p.get("DeletionProtection", "")).lower() == "false":
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="CFG-RDS-001",
                        rule_name="RDS Deletion Protection Disabled",
                        dimension="CONFIGURATION",
                        severity="MEDIUM",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "deletion_protection",
                            "detected_value": False,
                            "expected_value": True
                        },
                        title=f"Database deletion protection disabled ({r.resource_id})",
                        description="deletion_protection is set to false, allowing accidental database deletion.",
                        impact="Accidental or malicious terraform destroy or API calls can permanently terminate data.",
                        remediation_summary="Set deletion_protection = true.",
                        remediation_code='deletion_protection = true',
                        line_number=r.line_number
                    ))

            # ==========================================
            # DIMENSION 5: RELIABILITY
            # ==========================================
            # REL-RDS-001: Single-AZ Database
            if "db_instance" in r_type or "rds" in r_type:
                if p.get("multi_az") is False or str(p.get("MultiAZ", "")).lower() == "false":
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="REL-RDS-001",
                        rule_name="RDS Single-AZ Deployment",
                        dimension="RELIABILITY",
                        severity="MEDIUM",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "multi_az",
                            "detected_value": False,
                            "expected_value": True
                        },
                        title=f"Database deployed without Multi-AZ redundancy ({r.resource_id})",
                        description="RDS instance lacks automated failover standby replica in another availability zone.",
                        impact="Hardware failure or AZ outage will cause complete database unavailability.",
                        remediation_summary="Enable multi_az = true for production databases.",
                        remediation_code='multi_az = true',
                        line_number=r.line_number
                    ))

            # ==========================================
            # DIMENSION 6: PERFORMANCE
            # ==========================================
            # PRF-EC2-001: Burstable Instance in Production
            if "instance" in r_type:
                itype = str(p.get("instance_type", p.get("InstanceType", ""))).lower()
                if itype.startswith("t2.") or itype.startswith("t3."):
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="PRF-EC2-001",
                        rule_name="Burstable Instance Used for Production Workload",
                        dimension="PERFORMANCE",
                        severity="LOW",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "instance_type",
                            "detected_value": itype,
                            "expected_value": "M5/C5/R5 sustained compute family"
                        },
                        title=f"Burstable instance type selected ({r.resource_id})",
                        description=f"Instance uses {itype} burstable credit model.",
                        impact="CPU exhaustion during unexpected spikes causes severe latency and performance degradation.",
                        remediation_summary="Upgrade to M5, C5, or compute-optimized instance types.",
                        remediation_code='instance_type = "m5.large"',
                        line_number=r.line_number
                    ))

            # ==========================================
            # DIMENSION 7: COST
            # ==========================================
            # CST-EC2-001: Oversized Expensive Instance
            if "instance" in r_type:
                itype = str(p.get("instance_type", p.get("InstanceType", ""))).lower()
                if any(k in itype for k in ["8xlarge", "12xlarge", "16xlarge", "24xlarge", "metal"]):
                    findings.append(Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:12]}",
                        scan_id=scan_id,
                        rule_id="CST-EC2-001",
                        rule_name="Unconstrained Oversized Compute Instance",
                        dimension="COST",
                        severity="MEDIUM",
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        evidence={
                            "attribute": "instance_type",
                            "detected_value": itype,
                            "expected_value": "Right-sized compute family"
                        },
                        title=f"Extremely high-cost instance type declared ({r.resource_id})",
                        description=f"Instance {itype} incurs thousands of dollars in monthly cloud spend.",
                        impact="Excessive unutilized compute headroom causing massive cloud budget wastage.",
                        remediation_summary="Right-size compute instance based on CloudWatch metric averages.",
                        remediation_code='instance_type = "c5.2xlarge"',
                        line_number=r.line_number
                    ))

        return findings
