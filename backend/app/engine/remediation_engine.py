"""
CloudGuardAI - Intelligent Infrastructure-as-Code Remediation Engine
Generates context-aware, surgically targeted IaC corrections for Terraform and CloudFormation.
Preserves existing resource identifiers, variable references, and unrelated infrastructure.
Produces unified diff previews, security rationale, and operational side-effect disclosures.
"""

import re
import difflib
import uuid
from typing import Dict, Any, List, Optional, Tuple
from ..db.models import Finding

class RemediationEngine:

    @staticmethod
    def generate_remediation(finding: Finding, blueprint_content: str, filename: str) -> Dict[str, Any]:
        """
        Generates a context-aware remediation proposal for a specific finding.
        Returns a rich remediation preview payload with unified diff and validation-ready blocks.
        """
        lower_name = filename.lower()
        is_tf = lower_name.endswith(".tf")
        is_cfn = lower_name.endswith((".yaml", ".yml", ".json")) and not lower_name.endswith(".tf.json")
        is_tf_json = lower_name.endswith(".tf.json")

        rule_id = finding.rule_id
        res_id = finding.resource_id
        res_type = finding.resource_type

        # Extract base resource name if format is res_type.res_name (e.g. aws_s3_bucket.leak_bucket -> leak_bucket)
        if "." in res_id:
            res_name = res_id.split(".", 1)[-1]
        else:
            res_name = res_id

        if is_tf:
            return RemediationEngine._remediate_terraform(finding, blueprint_content, res_type, res_name, rule_id)
        elif is_cfn:
            return RemediationEngine._remediate_cloudformation(finding, blueprint_content, res_type, res_name, rule_id, lower_name)
        elif is_tf_json:
            return RemediationEngine._remediate_terraform_json(finding, blueprint_content, res_type, res_name, rule_id)
        else:
            # Fallback for generic formats
            return RemediationEngine._fallback_remediation(finding)

    @staticmethod
    def _remediate_terraform(
        finding: Finding,
        blueprint_content: str,
        res_type: str,
        res_name: str,
        rule_id: str
    ) -> Dict[str, Any]:
        """Generates precision Terraform HCL remediations."""
        lines = blueprint_content.splitlines()
        res_id = finding.resource_id
        block_info = RemediationEngine._locate_tf_resource_block(lines, res_type, res_name)

        if not block_info:
            # Resource block not found directly, create standard additive fix
            return RemediationEngine._fallback_remediation(finding)

        start_line, end_line, original_block = block_info
        orig_text = "\n".join(lines[start_line - 1:end_line])

        proposed_text = orig_text
        explanation = ""
        security_improvement = ""
        side_effects = ""
        change_description = ""
        companion_block: Optional[str] = None

        # -------------------------------------------------------------
        # SEC-S3-001: S3 Public ACL
        # -------------------------------------------------------------
        if rule_id == "SEC-S3-001":
            # 1. Update ACL to private
            if re.search(r'acl\s*=\s*["\']public-read(?:-write)?["\']', proposed_text, re.IGNORECASE):
                proposed_text = re.sub(
                    r'acl\s*=\s*["\']public-read(?:-write)?["\']',
                    'acl = "private"',
                    proposed_text,
                    flags=re.IGNORECASE
                )
                change_description = f"Replaced public ACL with 'private' on {res_id}."
            else:
                # Add acl = "private" if missing
                insert_idx = proposed_text.find("{") + 1
                proposed_text = proposed_text[:insert_idx] + '\n  acl    = "private"' + proposed_text[insert_idx:]
                change_description = f"Enforced acl = 'private' on {res_id}."

            # 2. Generate companion public access block if not already in blueprint
            pab_decl = f'resource "aws_s3_bucket_public_access_block"'
            if pab_decl not in blueprint_content:
                companion_block = (
                    f'\nresource "aws_s3_bucket_public_access_block" "{res_name}_pab" {{\n'
                    f'  bucket                  = {res_type}.{res_name}.id\n'
                    f'  block_public_acls       = true\n'
                    f'  block_public_policy     = true\n'
                    f'  ignore_public_acls      = true\n'
                    f'  restrict_public_buckets = true\n'
                    f'}}'
                )
                change_description += f" Attached aws_s3_bucket_public_access_block with all 4 protections enabled."

            explanation = (
                f"Bucket '{res_id}' allowed unauthenticated internet users to view or tamper with objects. "
                "Enforcing private ACL and public access block prevents accidental data leaks."
            )
            security_improvement = "Eliminates anonymous internet read/write access. Satisfies CIS AWS Benchmark 2.1.5."
            side_effects = (
                "Anonymous web users will receive HTTP 403 Forbidden. Ensure legitimate clients utilize IAM roles, "
                "signed URLs, or CloudFront Origin Access Controls (OAC) to read objects."
            )

        # -------------------------------------------------------------
        # SEC-S3-002: S3 Server-Side Encryption
        # -------------------------------------------------------------
        elif rule_id == "SEC-S3-002":
            # Attach companion aws_s3_bucket_server_side_encryption_configuration
            companion_block = (
                f'\nresource "aws_s3_bucket_server_side_encryption_configuration" "{res_name}_encryption" {{\n'
                f'  bucket = {res_type}.{res_name}.id\n'
                f'  rule {{\n'
                f'    apply_server_side_encryption_by_default {{\n'
                f'      sse_algorithm = "AES256"\n'
                f'    }}\n'
                f'  }}\n'
                f'}}'
            )
            change_description = f"Attached aws_s3_bucket_server_side_encryption_configuration enforcing default AES256 encryption."
            explanation = (
                f"Objects written to '{res_id}' were not explicitly governed by an encryption configuration. "
                "Explicit IaC encryption configuration ensures cryptographic compliance and prevents plaintext writes."
            )
            security_improvement = "Enforces AES-256 encryption at rest for all stored objects. Satisfies SOC2 and HIPAA requirements."
            side_effects = "Minimal. Transparent server-side encryption with Amazon S3 managed keys incurs no performance penalty."

        # -------------------------------------------------------------
        # SEC-S3-003: S3 Public Access Block Missing
        # -------------------------------------------------------------
        elif rule_id == "SEC-S3-003":
            if "aws_s3_bucket_public_access_block" in res_type:
                proposed_text = re.sub(r'block_public_acls\s*=\s*false', 'block_public_acls       = true', proposed_text, flags=re.IGNORECASE)
                proposed_text = re.sub(r'block_public_policy\s*=\s*false', 'block_public_policy     = true', proposed_text, flags=re.IGNORECASE)
                proposed_text = re.sub(r'ignore_public_acls\s*=\s*false', 'ignore_public_acls      = true', proposed_text, flags=re.IGNORECASE)
                proposed_text = re.sub(r'restrict_public_buckets\s*=\s*false', 'restrict_public_buckets = true', proposed_text, flags=re.IGNORECASE)
                change_description = f"Updated existing {res_id} with all 4 public access block protections set to true."
            else:
                companion_block = (
                    f'\nresource "aws_s3_bucket_public_access_block" "{res_name}_public_access_block" {{\n'
                    f'  bucket                  = {res_type}.{res_name}.id\n'
                    f'  block_public_acls       = true\n'
                    f'  block_public_policy     = true\n'
                    f'  ignore_public_acls      = true\n'
                    f'  restrict_public_buckets = true\n'
                    f'}}'
                )
                change_description = f"Attached aws_s3_bucket_public_access_block enforcing 4-point public lock."
            explanation = "Missing Public Access Block leaves the bucket susceptible to future misconfigurations or permissive bucket policies."
            security_improvement = "Enforces centralized defense-in-depth against public exposure at the bucket level."
            side_effects = "Any future attempts to grant public access via ACL or policy will be rejected by AWS APIs."

        # -------------------------------------------------------------
        # NET-SG-001: Port 22 SSH Open to 0.0.0.0/0
        # -------------------------------------------------------------
        elif rule_id == "NET-SG-001":
            if "0.0.0.0/0" in proposed_text:
                # Target the ingress block on port 22 specifically if possible
                if re.search(r'22', proposed_text):
                    proposed_text = re.sub(
                        r'(from_port\s*=\s*22[\s\S]*?cidr_blocks\s*=\s*\[\s*)["\']0\.0\.0\.0/0["\'](\s*\])',
                        r'\g<1>"10.0.0.0/16"\g<2>',
                        proposed_text
                    )
                if '10.0.0.0/16' not in proposed_text:
                    proposed_text = re.sub(
                        r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]',
                        'cidr_blocks = ["10.0.0.0/16"] # Restricted corporate CIDR',
                        proposed_text,
                        count=1
                    )
                change_description = "Restricted ingress CIDR from 0.0.0.0/0 to internal subnet 10.0.0.0/16."
            explanation = "SSH port 22 exposed to 0.0.0.0/0 invites automated brute-force attacks, port scans, and credential stuffing."
            security_improvement = "Limits administrative TCP access strictly to authorized internal or VPN address spaces."
            side_effects = "Administrators attempting direct SSH from home IPs without VPN will be blocked. Use AWS Systems Manager Session Manager or corporate bastion host."

        # -------------------------------------------------------------
        # NET-SG-002: Port 3389 RDP Open to 0.0.0.0/0
        # -------------------------------------------------------------
        elif rule_id == "NET-SG-002":
            if "0.0.0.0/0" in proposed_text:
                proposed_text = re.sub(
                    r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]',
                    'cidr_blocks = ["10.0.0.0/16"] # Restricted corporate CIDR',
                    proposed_text
                )
                change_description = "Restricted RDP port 3389 ingress CIDR to internal 10.0.0.0/16."
            explanation = "RDP open to the public internet is the primary initial access vector for enterprise ransomware gangs."
            security_improvement = "Closes public internet RDP surface. Complies with PCI-DSS Requirement 1.3."
            side_effects = "Remote desktop users must connect through corporate VPN or AWS Client VPN."

        # -------------------------------------------------------------
        # SEC-RDS-001: RDS Database Publicly Accessible
        # -------------------------------------------------------------
        elif rule_id == "SEC-RDS-001":
            if re.search(r'publicly_accessible\s*=\s*true', proposed_text, re.IGNORECASE):
                proposed_text = re.sub(
                    r'publicly_accessible\s*=\s*true',
                    'publicly_accessible = false',
                    proposed_text,
                    flags=re.IGNORECASE
                )
                change_description = "Set publicly_accessible = false on database instance."
            else:
                insert_idx = proposed_text.find("{") + 1
                proposed_text = proposed_text[:insert_idx] + '\n  publicly_accessible = false' + proposed_text[insert_idx:]
                change_description = "Added publicly_accessible = false."

            explanation = "Database assigned a public IP and allowed direct internet network connectivity."
            security_improvement = "Isolates database engine within private VPC subnets with zero public ingress routing."
            side_effects = "Direct database clients from outside the VPC must use a bastion host or database proxy (AWS RDS Proxy)."

        # -------------------------------------------------------------
        # CFG-RDS-001: RDS Deletion Protection Disabled
        # -------------------------------------------------------------
        elif rule_id == "CFG-RDS-001":
            if re.search(r'deletion_protection\s*=\s*false', proposed_text, re.IGNORECASE):
                proposed_text = re.sub(
                    r'deletion_protection\s*=\s*false',
                    'deletion_protection = true',
                    proposed_text,
                    flags=re.IGNORECASE
                )
                change_description = "Set deletion_protection = true."
            else:
                insert_idx = proposed_text.find("{") + 1
                proposed_text = proposed_text[:insert_idx] + '\n  deletion_protection = true' + proposed_text[insert_idx:]
                change_description = "Added deletion_protection = true."

            explanation = "Disabling deletion protection risks catastrophic irreversible data loss from accidental terraform destroy."
            security_improvement = "Prevents accidental or unauthorized deletion of production databases."
            side_effects = "Before deliberately destroying the database in the future, deletion_protection must be explicitly set to false."

        # -------------------------------------------------------------
        # REL-RDS-001: RDS Single-AZ Deployment
        # -------------------------------------------------------------
        elif rule_id == "REL-RDS-001":
            if re.search(r'multi_az\s*=\s*false', proposed_text, re.IGNORECASE):
                proposed_text = re.sub(
                    r'multi_az\s*=\s*false',
                    'multi_az = true',
                    proposed_text,
                    flags=re.IGNORECASE
                )
                change_description = "Set multi_az = true."
            else:
                insert_idx = proposed_text.find("{") + 1
                proposed_text = proposed_text[:insert_idx] + '\n  multi_az = true' + proposed_text[insert_idx:]
                change_description = "Added multi_az = true."

            explanation = "Single-AZ database instances lack automated failover during physical datacenter or availability zone outages."
            security_improvement = "Provisions synchronous standby replica in a second availability zone with automatic failover."
            side_effects = "RDS storage and instance hourly pricing will double to account for the standby instance."

        # -------------------------------------------------------------
        # SEC-EBS-001: EBS Volume Encryption Disabled
        # -------------------------------------------------------------
        elif rule_id == "SEC-EBS-001":
            if re.search(r'encrypted\s*=\s*false', proposed_text, re.IGNORECASE):
                proposed_text = re.sub(
                    r'encrypted\s*=\s*false',
                    'encrypted = true',
                    proposed_text,
                    flags=re.IGNORECASE
                )
                change_description = "Set encrypted = true."
            else:
                insert_idx = proposed_text.find("{") + 1
                proposed_text = proposed_text[:insert_idx] + '\n  encrypted = true' + proposed_text[insert_idx:]
                change_description = "Added encrypted = true."

            explanation = "Unencrypted block storage volumes expose data blocks and snapshots to unauthorized inspection."
            security_improvement = "Enforces cryptographic encryption at rest for EBS volume blocks and subsequent snapshots."
            side_effects = "Existing unencrypted volumes cannot be toggled in-place; they must be recreated from encrypted snapshots."

        # -------------------------------------------------------------
        # IAM-POL-001: IAM Wildcard Action
        # -------------------------------------------------------------
        elif rule_id == "IAM-POL-001":
            # Replace Action: "*" or Action = "*" with scoped service actions
            iam_action_pattern = r'(\\?\"?Action\\?\"?\s*[:=]\s*)(?:\\?\"\*\\?\"|\[\s*\\?\"\*\\?\"\s*\])'
            if re.search(iam_action_pattern, proposed_text, re.IGNORECASE):
                m = re.search(iam_action_pattern, proposed_text, re.IGNORECASE)
                delimiter_prefix = m.group(1)
                if ":" in delimiter_prefix and '\\"' in delimiter_prefix:
                    proposed_text = re.sub(
                        iam_action_pattern,
                        r'\g<1>[\"s3:GetObject\", \"s3:ListBucket\"]',
                        proposed_text,
                        flags=re.IGNORECASE
                    )
                else:
                    proposed_text = re.sub(
                        iam_action_pattern,
                        r'\g<1>["s3:GetObject", "s3:ListBucket"]',
                        proposed_text,
                        flags=re.IGNORECASE
                    )
                change_description = "Scoped Action: '*' down to specific least-privilege actions (s3:GetObject, s3:ListBucket)."
            elif '"Action": "*"' in proposed_text or '\\"Action\\": \\"*\\"' in proposed_text:
                proposed_text = proposed_text.replace('"Action": "*"', '"Action": ["s3:GetObject", "s3:ListBucket"]')
                proposed_text = proposed_text.replace('\\"Action\\": \\"*\\"', '\\"Action\\": [\\"s3:GetObject\\", \\"s3:ListBucket\\"]')
                change_description = "Scoped Action: '*' down to specific least-privilege actions (s3:GetObject, s3:ListBucket)."
            explanation = "Unrestricted wildcard Action ('*') grants full administrator control, allowing privilege escalation and account compromise."
            security_improvement = "Enforces least-privilege access by allowing only necessary read APIs."
            side_effects = "Applications calling other AWS APIs will encounter AccessDenied unless their actions are explicitly added."

        # -------------------------------------------------------------
        # PRF-EC2-001: Burstable Instance
        # -------------------------------------------------------------
        elif rule_id == "PRF-EC2-001":
            proposed_text = re.sub(
                r'instance_type\s*=\s*["\']t[234]g?\.[^"\']+["\']',
                'instance_type = "m5.large"',
                proposed_text,
                flags=re.IGNORECASE
            )
            change_description = "Upgraded burstable compute to sustained compute family (m5.large)."
            explanation = "Burstable instances degrade in performance once CPU credits are exhausted during traffic peaks."
            security_improvement = "Guarantees sustained, dedicated compute allocation without CPU throttling."
            side_effects = "Hourly instance cost is higher than burstable t2/t3 instances."

        # -------------------------------------------------------------
        # CST-EC2-001: Oversized Expensive Instance
        # -------------------------------------------------------------
        elif rule_id == "CST-EC2-001":
            proposed_text = re.sub(
                r'instance_type\s*=\s*["\'][^"\']*(?:8xlarge|12xlarge|16xlarge|24xlarge|metal)["\']',
                'instance_type = "c5.2xlarge"',
                proposed_text,
                flags=re.IGNORECASE
            )
            change_description = "Right-sized oversized instance to c5.2xlarge."
            explanation = "Over-provisioned compute capacity consumes budget without proportional workload utilization."
            security_improvement = "Constrains compute spending and reduces excessive idle capacity."
            side_effects = "Verify application memory/CPU requirements before downsizing in production."

        # Build combined proposal if companion block is attached
        full_proposed = proposed_text
        if companion_block:
            full_proposed = proposed_text + "\n" + companion_block

        # Generate Unified Diff
        diff_lines = list(difflib.unified_diff(
            orig_text.splitlines(keepends=True),
            full_proposed.splitlines(keepends=True),
            fromfile=f"original/{res_id}",
            tofile=f"remediated/{res_id}",
            n=2
        ))
        diff_str = "".join(diff_lines)

        return {
            "remediation_id": f"rem_{uuid.uuid4().hex[:10]}",
            "finding_id": finding.finding_id,
            "rule_id": rule_id,
            "resource_id": res_id,
            "resource_type": res_type,
            "format": "terraform",
            "start_line": start_line,
            "end_line": end_line,
            "original_snippet": orig_text,
            "proposed_snippet": full_proposed,
            "companion_resource_added": bool(companion_block),
            "companion_snippet": companion_block,
            "diff": diff_str,
            "change_description": change_description,
            "explanation": explanation,
            "security_improvement": security_improvement,
            "side_effects": side_effects,
            "status": "Fix Generated"
        }

    @staticmethod
    def _locate_cfn_resource_block(lines: List[str], res_name: str) -> Optional[Tuple[int, int, int]]:
        """
        Locates a CloudFormation resource in YAML lines.
        Returns (start_line, end_line, base_indent) 1-indexed.
        """
        target_re = re.compile(rf'^\s*{re.escape(res_name)}\s*:\s*$')
        start_idx = None
        base_indent = 0
        for i, line in enumerate(lines):
            if target_re.match(line):
                start_idx = i
                base_indent = len(line) - len(line.lstrip())
                break
        if start_idx is None:
            return None

        end_idx = len(lines) - 1
        for i in range(start_idx + 1, len(lines)):
            line = lines[i]
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base_indent:
                end_idx = i - 1
                break

        return (start_idx + 1, end_idx + 1, base_indent)

    @staticmethod
    def _remediate_cloudformation(
        finding: Finding,
        blueprint_content: str,
        res_type: str,
        res_name: str,
        rule_id: str,
        filename_lower: str
    ) -> Dict[str, Any]:
        """Generates precision CloudFormation YAML/JSON remediations."""
        res_id = finding.resource_id
        is_yaml = filename_lower.endswith((".yaml", ".yml"))
        lines = blueprint_content.splitlines()
        cfn_loc = RemediationEngine._locate_cfn_resource_block(lines, res_name) if is_yaml else None

        orig_text = finding.actual_config or finding.evidence.get("detected_value", "")
        proposed_snippet = ""
        explanation = ""
        security_improvement = ""
        side_effects = ""
        start_line = finding.line_number or 1
        end_line = finding.line_number or 1

        if is_yaml and cfn_loc:
            b_start, b_end, b_indent = cfn_loc
            prop_indent = " " * (b_indent + 4)
            sub_indent = " " * (b_indent + 6)

            if rule_id == "SEC-S3-001":
                target_idx = None
                for idx in range(b_start - 1, b_end):
                    if re.search(r'AccessControl\s*:', lines[idx], re.IGNORECASE):
                        target_idx = idx
                        break
                if target_idx is not None:
                    start_line = target_idx + 1
                    end_line = target_idx + 1
                    orig_text = lines[target_idx]
                    proposed_snippet = (
                        f"{prop_indent}AccessControl: Private\n"
                        f"{prop_indent}PublicAccessBlockConfiguration:\n"
                        f"{sub_indent}BlockPublicAcls: true\n"
                        f"{sub_indent}BlockPublicPolicy: true\n"
                        f"{sub_indent}IgnorePublicAcls: true\n"
                        f"{sub_indent}RestrictPublicBuckets: true"
                    )
                else:
                    start_line = b_start + 2
                    end_line = b_start + 2
                    orig_text = lines[b_start + 1] if len(lines) > b_start + 1 else ""
                    proposed_snippet = (
                        f"{prop_indent}AccessControl: Private\n"
                        f"{prop_indent}PublicAccessBlockConfiguration:\n"
                        f"{sub_indent}BlockPublicAcls: true\n"
                        f"{sub_indent}BlockPublicPolicy: true\n"
                        f"{sub_indent}IgnorePublicAcls: true\n"
                        f"{sub_indent}RestrictPublicBuckets: true\n"
                        f"{orig_text}"
                    )
                explanation = "Replaces public access with Private AccessControl and adds PublicAccessBlockConfiguration."
                security_improvement = "Protects bucket from unauthorized public access."
                side_effects = "Anonymous HTTP requests will be denied."

            elif rule_id == "NET-SG-001":
                target_idx = None
                for idx in range(b_start - 1, b_end):
                    if re.search(r'0\.0\.0\.0/0', lines[idx]):
                        target_idx = idx
                        break
                if target_idx is not None:
                    start_line = target_idx + 1
                    end_line = target_idx + 1
                    orig_text = lines[target_idx]
                    proposed_snippet = re.sub(r'0\.0\.0\.0/0', '10.0.0.0/16', orig_text)
                explanation = "Restricts SSH port 22 access to internal corporate CIDR (10.0.0.0/16)."
                security_improvement = "Eliminates global ingress attack surface on port 22."
                side_effects = "Users connecting from outside 10.0.0.0/16 must use VPN or bastion."

            elif rule_id == "SEC-RDS-001":
                target_idx = None
                for idx in range(b_start - 1, b_end):
                    if re.search(r'PubliclyAccessible\s*:\s*true', lines[idx], re.IGNORECASE):
                        target_idx = idx
                        break
                if target_idx is not None:
                    start_line = target_idx + 1
                    end_line = target_idx + 1
                    orig_text = lines[target_idx]
                    proposed_snippet = re.sub(r'true', 'false', orig_text, flags=re.IGNORECASE)
                explanation = "Sets PubliclyAccessible to false to isolate database."
                security_improvement = "Closes public network route to database."
                side_effects = "Direct public access to DB is revoked."

            elif rule_id == "IAM-POL-001":
                target_idx = None
                for idx in range(b_start - 1, b_end):
                    if re.search(r'Action\s*:\s*(\*|["\']\*["\'])', lines[idx], re.IGNORECASE):
                        target_idx = idx
                        break
                if target_idx is not None:
                    start_line = target_idx + 1
                    end_line = target_idx + 1
                    orig_text = lines[target_idx]
                    proposed_snippet = f"{prop_indent}Action:\n{sub_indent}- 's3:GetObject'\n{sub_indent}- 's3:ListBucket'"
                explanation = "Replaces wildcard Action with scoped read-only S3 actions."
                security_improvement = "Enforces least privilege by revoking admin wildcard."
                side_effects = "Callers requiring other AWS permissions must specify them explicitly."

            else:
                proposed_snippet = finding.remediation_code or finding.expected_config or ""
                explanation = finding.description
                security_improvement = finding.remediation_summary
                side_effects = "Ensure downstream applications are updated."

        else:
            if rule_id == "SEC-S3-001":
                proposed_snippet = '"AccessControl": "Private",\n"PublicAccessBlockConfiguration": {\n  "BlockPublicAcls": true,\n  "BlockPublicPolicy": true,\n  "IgnorePublicAcls": true,\n  "RestrictPublicBuckets": true\n}'
                explanation = "Replaces public access with Private AccessControl and adds PublicAccessBlockConfiguration."
                security_improvement = "Protects bucket from unauthorized public access."
                side_effects = "Anonymous HTTP requests will be denied."
            elif rule_id == "SEC-RDS-001":
                proposed_snippet = '"PubliclyAccessible": false'
                explanation = "Sets PubliclyAccessible to false to isolate database."
                security_improvement = "Closes public network route to database."
                side_effects = "Direct public access to DB is revoked."
            elif rule_id == "IAM-POL-001":
                proposed_snippet = '"Action": ["s3:GetObject", "s3:ListBucket"]'
                explanation = "Replaces wildcard Action with scoped read-only S3 actions."
                security_improvement = "Enforces least privilege by revoking admin wildcard."
                side_effects = "Callers requiring other AWS permissions must specify them explicitly."
            else:
                proposed_snippet = finding.remediation_code or finding.expected_config or ""
                explanation = finding.description
                security_improvement = finding.remediation_summary
                side_effects = "Ensure downstream applications are updated."

        diff_str = f"--- original/{res_id}\n+++ remediated/{res_id}\n- {orig_text}\n+ {proposed_snippet}"

        return {
            "remediation_id": f"rem_{uuid.uuid4().hex[:10]}",
            "finding_id": finding.finding_id,
            "rule_id": rule_id,
            "resource_id": res_id,
            "resource_type": res_type,
            "format": "cloudformation",
            "start_line": start_line,
            "end_line": end_line,
            "original_snippet": str(orig_text),
            "proposed_snippet": proposed_snippet,
            "companion_resource_added": False,
            "diff": diff_str,
            "change_description": f"Remediated {rule_id} on CloudFormation resource {res_id}.",
            "explanation": explanation,
            "security_improvement": security_improvement,
            "side_effects": side_effects,
            "status": "Fix Generated"
        }

    @staticmethod
    def _remediate_terraform_json(finding: Finding, blueprint_content: str, res_type: str, res_name: str, rule_id: str) -> Dict[str, Any]:
        return RemediationEngine._remediate_cloudformation(finding, blueprint_content, res_type, res_name, rule_id, "template.json")

    @staticmethod
    def _fallback_remediation(finding: Finding) -> Dict[str, Any]:
        """Provides a safe deterministic fallback when AST block cannot be isolated."""
        code_fix = finding.remediation_code or finding.expected_config or ""
        return {
            "remediation_id": f"rem_{uuid.uuid4().hex[:10]}",
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "resource_id": finding.resource_id,
            "resource_type": finding.resource_type,
            "format": "terraform",
            "start_line": finding.line_number or 1,
            "end_line": (finding.line_number or 1) + 4,
            "original_snippet": finding.actual_config or "Omitted or insecure configuration",
            "proposed_snippet": code_fix,
            "companion_resource_added": False,
            "diff": f"--- original\n+++ remediated\n+ {code_fix}",
            "change_description": f"Recommended fix for {finding.rule_id}.",
            "explanation": finding.description,
            "security_improvement": finding.remediation_summary,
            "side_effects": "Review configuration before deployment.",
            "status": "Fix Generated"
        }

    @staticmethod
    def _locate_tf_resource_block(lines: List[str], res_type: str, res_name: str) -> Optional[Tuple[int, int, str]]:
        """
        Locates the 1-indexed (start_line, end_line, raw_text) of a Terraform resource block.
        Properly handles nested braces.
        """
        pattern = re.compile(rf'resource\s+["\']{re.escape(res_type)}["\']\s+["\']{re.escape(res_name)}["\']\s*\{{')
        start_idx = -1
        depth = 0

        for idx, line in enumerate(lines):
            if start_idx == -1:
                if pattern.search(line):
                    start_idx = idx
                    depth = line.count("{") - line.count("}")
                    if depth <= 0:
                        return (start_idx + 1, idx + 1, line)
            else:
                depth += line.count("{") - line.count("}")
                if depth <= 0:
                    end_idx = idx
                    block_text = "\n".join(lines[start_idx:end_idx + 1])
                    return (start_idx + 1, end_idx + 1, block_text)

        return None

    @staticmethod
    def apply_staged_remediations(
        original_blueprint: str,
        staged_remediations: Dict[str, Dict[str, Any]],
        filename: str
    ) -> str:
        """
        Applies approved remediations to generate the candidate corrected blueprint.
        Applies changes in reverse line order to preserve line coordinates.
        Never overwrites the original file on disk.
        """
        if not staged_remediations:
            return original_blueprint

        # Sort remediations descending by start_line
        rems = list(staged_remediations.values())
        rems.sort(key=lambda r: r.get("start_line", 0), reverse=True)

        lines = original_blueprint.splitlines()

        for rem in rems:
            start_line = rem.get("start_line")
            end_line = rem.get("end_line")
            proposed = rem.get("proposed_snippet")

            if start_line is not None and end_line is not None and proposed:
                # Replace the block lines with proposed lines
                proposed_lines = proposed.splitlines()
                lines[start_line - 1:end_line] = proposed_lines

        return "\n".join(lines)
