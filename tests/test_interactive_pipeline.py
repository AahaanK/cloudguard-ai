"""
Tests for CloudGuardAI 7-Stage Interactive Infrastructure Analysis Pipeline,
Resource Relationship Graph Discovery, and Discovery Summary Telemetry.
"""

import unittest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.engine.parser import IaCParser
from backend.app.engine.rules import RuleEvaluator

client = TestClient(app)

class TestInteractivePipeline(unittest.TestCase):

    def test_sample_blueprint_endpoint(self):
        """Verifies GET /api/v1/scan/sample-blueprint returns valid template."""
        res = client.get("/api/v1/scan/sample-blueprint")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["filename"], "production_cloud_stack.tf")
        self.assertIn("aws_vpc", data["content"])
        self.assertIn("aws_security_group", data["content"])
        self.assertIn("aws_s3_bucket", data["content"])
        self.assertGreater(data["size_bytes"], 100)

    def test_resource_relationship_discovery(self):
        """Verifies inter-resource dependencies are correctly linked."""
        tf_code = """
        resource "aws_vpc" "main_vpc" {
          cidr_block = "10.0.0.0/16"
        }
        resource "aws_subnet" "web_subnet" {
          vpc_id = aws_vpc.main_vpc.id
          cidr_block = "10.0.1.0/24"
        }
        resource "aws_security_group" "web_sg" {
          vpc_id = aws_vpc.main_vpc.id
        }
        resource "aws_instance" "web_node" {
          subnet_id = aws_subnet.web_subnet.id
          security_groups = [aws_security_group.web_sg.id]
        }
        """
        resources, unsupported = IaCParser.parse(tf_code.encode("utf-8"), "test_arch.tf")
        self.assertEqual(len(resources), 4)

        res_by_id = {r.resource_id: r for r in resources}
        self.assertEqual(res_by_id["aws_vpc.main_vpc"].service, "VPC")
        self.assertEqual(res_by_id["aws_subnet.web_subnet"].service, "VPC")
        self.assertEqual(res_by_id["aws_security_group.web_sg"].service, "SECURITY_GROUP")
        self.assertEqual(res_by_id["aws_instance.web_node"].service, "EC2")

        # Check relationships
        self.assertIn("aws_vpc.main_vpc", res_by_id["aws_subnet.web_subnet"].relationships)
        self.assertIn("aws_vpc.main_vpc", res_by_id["aws_security_group.web_sg"].relationships)
        self.assertIn("aws_subnet.web_subnet", res_by_id["aws_instance.web_node"].relationships)
        self.assertIn("aws_security_group.web_sg", res_by_id["aws_instance.web_node"].relationships)

    def test_end_to_end_upload_with_discovery_telemetry(self):
        """Verifies end-to-end blueprint upload populates discovered_resources and discovery_summary."""
        sample_res = client.get("/api/v1/scan/sample-blueprint")
        self.assertEqual(sample_res.status_code, 200)
        sample_content = sample_res.json()["content"]

        upload_res = client.post(
            "/api/v1/scan/upload",
            files={"file": ("production_cloud_stack.tf", sample_content.encode("utf-8"), "application/octet-stream")},
            data={"template_type": "auto"}
        )
        self.assertEqual(upload_res.status_code, 200)
        body = upload_res.json()
        self.assertTrue(body["success"])
        scan = body["data"]

        # Check discovered_resources
        disc_resources = scan.get("discovered_resources", [])
        self.assertGreaterEqual(len(disc_resources), 6)

        # Check service classification
        services_found = {r["service"] for r in disc_resources}
        self.assertTrue({"VPC", "SECURITY_GROUP", "EC2", "S3", "RDS", "IAM"}.issubset(services_found))

        # Check checks_evaluated on each resource
        for r in disc_resources:
            self.assertIn("checks_evaluated", r)
            self.assertGreater(len(r["checks_evaluated"]), 0)
            self.assertIn(r["status"], ["PASSED", "FAILED"])

        # Check discovery_summary
        summary = scan.get("discovery_summary", {})
        self.assertIn("pipeline_stages", summary)
        self.assertEqual(len(summary["pipeline_stages"]), 7)

        stats = summary.get("check_statistics", {})
        self.assertGreater(stats.get("total_checks", 0), 5)
        self.assertGreater(stats.get("passed_checks", 0), 0)
        self.assertGreater(stats.get("failed_checks", 0), 0)

        events = summary.get("pipeline_events", [])
        self.assertGreater(len(events), 10)
        stages_emitted = {e["stage"] for e in events}
        self.assertTrue({"VALIDATION", "PARSING", "INVENTORY", "INSPECTION", "EVALUATION", "SCORING", "REPORTING"}.issubset(stages_emitted))

        # Retrieve via GET /api/v1/scan/{scan_id} and verify persistence
        scan_id = scan["scan_id"]
        get_res = client.get(f"/api/v1/scan/{scan_id}")
        self.assertEqual(get_res.status_code, 200)
        retrieved_scan = get_res.json()["data"]
        self.assertEqual(len(retrieved_scan["discovered_resources"]), len(disc_resources))
        self.assertEqual(len(retrieved_scan["discovery_summary"]["pipeline_stages"]), 7)

if __name__ == "__main__":
    unittest.main()
