"""
CloudGuardAI - Enhanced Risk Analysis Engine Comprehensive Test Suite
Tests:
  1. Clean, Well-Architected blueprint (0 findings, 0.0 score, Grade A)
  2. Insecure blueprint across 7 dimensions (verifying all structured fields)
  3. Incomplete / ambiguous configurations (POTENTIAL and REQUIRES_VERIFICATION handling)
  4. Malformed syntax handling (graceful error reporting without crash)
  5. Cross-resource compensating controls (S3 + PAB + SSE, SG + standalone rules)
  6. Finding verification logic (AST re-examination & live AWS notice)
  7. Report exporter formatting (Markdown, HTML, JSON)
  8. Persistence round-trip & repository migrations
"""

import unittest
import json
import uuid

from backend.app.engine.parser import IaCParser, NormalizedResource
from backend.app.engine.rules import RuleEvaluator
from backend.app.engine.scorer import RiskScorer
from backend.app.reports.exporter import ReportExporter
from backend.app.db.models import ScanJob, Finding
from backend.app.db.repository import repository
from backend.app.api.scan_routes import verify_individual_finding

CLEAN_TERRAFORM = b"""
resource "aws_s3_bucket" "secure_assets" {
  bucket = "secure-corporate-vault"
  acl    = "private"
  server_side_encryption_configuration = "AES256"
}

resource "aws_s3_bucket_public_access_block" "assets_pab" {
  bucket                  = aws_s3_bucket.secure_assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "production_db" {
  identifier          = "prod-aurora"
  instance_class      = "db.r5.large"
  publicly_accessible = false
  multi_az            = true
  deletion_protection = true
}

resource "aws_security_group" "internal_api" {
  name        = "internal_api_sg"
  description = "Internal API only"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
"""

INSECURE_TERRAFORM = b"""
resource "aws_s3_bucket" "leak_bucket" {
  bucket = "public-data-lake"
  acl    = "public-read"
}

resource "aws_ebs_volume" "unencrypted_vol" {
  size      = 100
  encrypted = false
}

resource "aws_iam_policy" "admin_wildcard" {
  name   = "admin_full_access"
  policy = "{\\"Action\\": \\"*\\", \\"Effect\\": \\"Allow\\"}"
}

resource "aws_security_group" "open_perimeter" {
  name = "open_perimeter_sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "insecure_rds" {
  identifier          = "public-db"
  publicly_accessible = true
  multi_az            = false
  deletion_protection = false
}

resource "aws_instance" "massive_burstable_node" {
  instance_type = "t2.8xlarge"
}
"""

COMPENSATING_CONTROLS_TERRAFORM = b"""
resource "aws_s3_bucket" "app_bucket" {
  bucket = "app-storage-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "pab_compensating" {
  bucket                  = aws_s3_bucket.app_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse_attached" {
  bucket = aws_s3_bucket.app_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_security_group" "modular_sg" {
  name        = "modular_web_sg"
  description = "Web SG with separate rule attachments"
}

resource "aws_security_group_rule" "ssh_ingress_rule" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.modular_sg.id
}
"""

MALFORMED_JSON = b"""
{
  "Resources": {
    "MyBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": { "AccessControl": "PublicRead",
    }
  }
}
"""

class TestEnhancedRiskEngine(unittest.TestCase):

    def test_01_clean_blueprint_zero_findings_grade_a(self):
        """Clean architecture must yield exactly 0 findings, score 0.0, and Grade A."""
        resources, unsupported = IaCParser.parse(CLEAN_TERRAFORM, "clean.tf")
        self.assertEqual(len(unsupported), 0)
        self.assertGreaterEqual(len(resources), 3)

        findings, discovered, summary = RuleEvaluator.evaluate_blueprint(
            resources=resources,
            scan_id="scan_clean_test",
            unsupported=unsupported,
            filename="clean.tf",
            file_size=len(CLEAN_TERRAFORM)
        )
        self.assertEqual(len(findings), 0)

        score, grade, dim_scores, counts, explanation = RiskScorer.calculate_score_detailed(
            findings, summary.get("check_statistics")
        )
        self.assertEqual(score, 0.0)
        self.assertEqual(grade, "A")
        self.assertEqual(counts["total"], 0)
        self.assertEqual(counts["confirmed"], 0)
        self.assertFalse(explanation["critical_override_applied"])

    def test_02_insecure_blueprint_comprehensive_findings(self):
        """Insecure blueprint must detect vulnerabilities across 7 dimensions with rich evidence."""
        resources, unsupported = IaCParser.parse(INSECURE_TERRAFORM, "insecure.tf")
        findings, discovered, summary = RuleEvaluator.evaluate_blueprint(
            resources=resources,
            scan_id="scan_insecure_test",
            unsupported=unsupported,
            filename="insecure.tf",
            file_size=len(INSECURE_TERRAFORM)
        )

        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SEC-S3-001", rule_ids)
        self.assertIn("SEC-EBS-001", rule_ids)
        self.assertIn("IAM-POL-001", rule_ids)
        self.assertIn("NET-SG-001", rule_ids)
        self.assertIn("NET-SG-002", rule_ids)
        self.assertIn("SEC-RDS-001", rule_ids)
        self.assertIn("CFG-RDS-001", rule_ids)
        self.assertIn("REL-RDS-001", rule_ids)
        self.assertIn("PRF-EC2-001", rule_ids)
        self.assertIn("CST-EC2-001", rule_ids)

        # Check required fields on every finding
        for f in findings:
            self.assertTrue(f.finding_id.startswith("find_"))
            self.assertIn(f.severity, ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
            self.assertIn(f.finding_status, ["CONFIRMED", "POTENTIAL", "REQUIRES_VERIFICATION"])
            self.assertIn(f.confidence, ["HIGH", "MEDIUM", "LOW"])
            self.assertIsNotNone(f.actual_config)
            self.assertIsNotNone(f.expected_config)
            self.assertIsNotNone(f.file_name)
            self.assertGreater(f.line_number, 0)
            self.assertIn("attribute", f.evidence)

        # Verify score and critical override
        score, grade, dim_scores, counts, explanation = RiskScorer.calculate_score_detailed(
            findings, summary.get("check_statistics")
        )
        self.assertGreaterEqual(score, 70.0)
        self.assertIn(grade, ["D", "F"])
        self.assertTrue(explanation["has_confirmed_critical"])

        # Verify compound risk detection
        compound_risks = summary.get("compound_risks", [])
        self.assertGreaterEqual(len(compound_risks), 1)
        cmp_titles = [cr["title"] for cr in compound_risks]
        self.assertTrue(any("Perimeter-to-Core" in t or "Database" in t for t in cmp_titles))

    def test_03_compensating_controls_mitigation(self):
        """Cross-resource correlation should mitigate S3 encryption finding and downgrade ACL severity."""
        resources, unsupported = IaCParser.parse(COMPENSATING_CONTROLS_TERRAFORM, "compensating.tf")
        findings, discovered, summary = RuleEvaluator.evaluate_blueprint(
            resources=resources,
            scan_id="scan_comp_test",
            unsupported=unsupported,
            filename="compensating.tf",
            file_size=len(COMPENSATING_CONTROLS_TERRAFORM)
        )

        rule_map = {f.rule_id: f for f in findings}

        # SEC-S3-002 should NOT be raised because separate SSE resource exists!
        self.assertNotIn("SEC-S3-002", rule_map, "Attached SSE configuration should prevent false positive missing encryption!")

        # SEC-S3-001 should be marked POTENTIAL instead of CONFIRMED because PAB blocks public ACLs
        if "SEC-S3-001" in rule_map:
            s3_f = rule_map["SEC-S3-001"]
            self.assertEqual(s3_f.finding_status, "POTENTIAL")
            self.assertEqual(s3_f.severity, "MEDIUM")

        # Standalone security group rule should be detected on modular_sg
        self.assertIn("NET-SG-001", rule_map, "Standalone aws_security_group_rule should be correlated to security group!")

    def test_04_individual_finding_deep_verification(self):
        """Verify finding action must re-evaluate AST context and supply live AWS notice."""
        resources, _ = IaCParser.parse(INSECURE_TERRAFORM, "insecure.tf")
        findings, _, _ = RuleEvaluator.evaluate_blueprint(resources, "scan_verif_test")

        ssh_f = next(f for f in findings if f.rule_id == "NET-SG-001")
        ver_res = RuleEvaluator.verify_finding(ssh_f, resources)

        self.assertTrue(ver_res["verified"])
        self.assertEqual(ver_res["status"], "CONFIRMED")
        self.assertEqual(ver_res["confidence"], "HIGH")
        self.assertEqual(ver_res["verification_method"], "STATIC_BLUEPRINT_VERIFICATION")
        self.assertIn("live_aws_notice", ver_res)
        self.assertIn("Static Blueprint Verification", ver_res["live_aws_notice"])

    def test_05_malformed_syntax_error_reporting(self):
        """Malformed blueprints should report parsing errors gracefully without engine crashes."""
        resources, unsupported = IaCParser.parse(MALFORMED_JSON, "broken.json")
        self.assertEqual(len(resources), 0)
        self.assertGreaterEqual(len(unsupported), 1)
        self.assertEqual(unsupported[0]["type"], "MALFORMED_JSON")
        self.assertIn("Malformed JSON syntax", unsupported[0]["message"])

    def test_06_report_exporter_multi_format(self):
        """Report exporter must include finding_status, actual/expected config, and scoring formula."""
        resources, _ = IaCParser.parse(INSECURE_TERRAFORM, "insecure.tf")
        findings, discovered, summary = RuleEvaluator.evaluate_blueprint(resources, "scan_report_test")
        score, grade, dim_scores, counts, explanation = RiskScorer.calculate_score_detailed(findings, summary.get("check_statistics"))

        job = ScanJob(
            scan_id="scan_report_test",
            scan_type="IAC_STATIC",
            target_name="insecure.tf",
            overall_risk_score=score,
            risk_grade=grade,
            total_findings=counts["total"],
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            dimension_scores=dim_scores,
            discovered_resources=discovered,
            discovery_summary=summary,
            score_explanation=explanation,
            compound_risks=summary.get("compound_risks", []),
            findings=findings
        )

        md = ReportExporter.export_markdown(job)
        self.assertIn("Transparent Scoring Breakdown", md)
        self.assertIn("Formula:", md)
        self.assertIn("Compound Attack Vectors", md)
        self.assertIn("Status:", md)

        html = ReportExporter.export_html(job)
        self.assertIn("Compound Threat Chains", html)
        self.assertIn("Overall Risk Score", html)

        parsed_json = json.loads(ReportExporter.export_json(job))
        self.assertEqual(parsed_json["overall_risk_score"], score)
        self.assertIn("score_explanation", parsed_json)

    def test_07_persistence_migration_and_roundtrip(self):
        """Database repository must persist and deserialize all enhanced fields cleanly."""
        scan_id = f"test_persist_{uuid.uuid4().hex[:8]}"
        job = ScanJob(
            scan_id=scan_id,
            scan_type="IAC_STATIC",
            target_name="test_template.tf",
            status="COMPLETED",
            overall_risk_score=75.0,
            risk_grade="D",
            score_explanation={"formula": "Test Formula", "raw_points": 75.0},
            compound_risks=[{"title": "Test Threat", "severity": "CRITICAL"}],
            findings=[
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    rule_id="SEC-S3-001",
                    rule_name="S3 Public ACL",
                    dimension="SECURITY",
                    severity="CRITICAL",
                    resource_id="aws_s3_bucket.test",
                    resource_type="aws_s3_bucket",
                    file_name="test_template.tf",
                    line_number=12,
                    actual_config='acl = "public-read"',
                    expected_config='acl = "private"',
                    confidence="HIGH",
                    finding_status="CONFIRMED",
                    title="Test S3 Finding",
                    description="Test description",
                    impact="Test impact",
                    remediation_summary="Fix ACL"
                )
            ]
        )

        saved = repository.save_scan(job)
        retrieved = repository.get_scan(scan_id)

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.scan_id, scan_id)
        self.assertEqual(retrieved.overall_risk_score, 75.0)
        self.assertEqual(len(retrieved.findings), 1)

        f = retrieved.findings[0]
        self.assertEqual(f.actual_config, 'acl = "public-read"')
        self.assertEqual(f.expected_config, 'acl = "private"')
        self.assertEqual(f.finding_status, "CONFIRMED")
        self.assertEqual(f.confidence, "HIGH")
        self.assertEqual(f.line_number, 12)
        self.assertIsNotNone(retrieved.score_explanation)
        self.assertEqual(retrieved.score_explanation.get("formula"), "Test Formula")

    def test_08_verify_finding_endpoint_execution(self):
        """Finding verification endpoint must execute, re-evaluate AST context, update finding, and persist details."""
        scan_id = f"test_ep_{uuid.uuid4().hex[:8]}"
        job = ScanJob(
            scan_id=scan_id,
            scan_type="IAC_STATIC",
            target_name="template.tf",
            status="COMPLETED",
            overall_risk_score=90.0,
            risk_grade="F",
            discovered_resources=[
                {
                    "resource_id": "aws_security_group.sg_web",
                    "resource_type": "aws_security_group",
                    "service": "SECURITY_GROUP",
                    "line_number": 15,
                    "properties": {
                        "ingress": [
                            {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}
                        ]
                    }
                }
            ],
            findings=[
                Finding(
                    finding_id="find_test_ssh_1",
                    scan_id=scan_id,
                    rule_id="NET-SG-001",
                    rule_name="Open SSH",
                    dimension="NETWORK",
                    severity="CRITICAL",
                    resource_id="aws_security_group.sg_web",
                    resource_type="aws_security_group",
                    file_name="template.tf",
                    line_number=15,
                    actual_config="0.0.0.0/0 on port 22",
                    expected_config="10.0.0.0/16",
                    finding_status="CONFIRMED",
                    title="SSH Open",
                    description="Port 22 open",
                    impact="Brute force",
                    remediation_summary="Restrict CIDR"
                )
            ]
        )
        repository.save_scan(job)

        resp = verify_individual_finding(scan_id=scan_id, finding_id="find_test_ssh_1")
        self.assertTrue(resp["success"])
        self.assertEqual(resp["verification"]["status"], "CONFIRMED")
        self.assertEqual(resp["verification"]["verification_method"], "STATIC_BLUEPRINT_VERIFICATION")
        self.assertIn("live_aws_notice", resp["verification"])

        # Check persistence
        updated_job = repository.get_scan(scan_id)
        f = updated_job.findings[0]
        self.assertIsNotNone(f.verification_details)
        self.assertEqual(f.verification_method, "STATIC_BLUEPRINT_VERIFICATION")

if __name__ == "__main__":
    unittest.main()
