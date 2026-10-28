"""
CloudGuardAI - AWS API Gateway & Lambda Handler Contract Tests
Verifies the Mangum Lambda handler against simulated AWS API Gateway HTTP API v2
events, CORS preflights, error handling, and the direct-to-S3 payload bypass contract.
"""

import unittest
import json
from unittest.mock import patch, MagicMock

from backend.app.main import handler, app
from fastapi.testclient import TestClient

client = TestClient(app)

class TestAPIGatewayContracts(unittest.TestCase):

    def setUp(self):
        self.context = MagicMock()
        self.context.aws_request_id = "test-request-id-12345"
        self.context.function_name = "cloudguard-api-gateway"
        self.context.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:cloudguard-api-gateway"
        self.context.memory_limit_in_mb = "512"
        self.context.get_remaining_time_in_millis.return_value = 28000

    def test_api_gateway_v2_health_route(self):
        """Simulate AWS API Gateway HTTP API v2 GET /api/v1/health event."""
        event = {
            "version": "2.0",
            "routeKey": "GET /api/v1/health",
            "rawPath": "/api/v1/health",
            "rawQueryString": "",
            "headers": {
                "accept": "application/json",
                "host": "xyz.execute-api.us-east-1.amazonaws.com",
                "x-forwarded-proto": "https"
            },
            "requestContext": {
                "accountId": "123456789012",
                "apiId": "xyz",
                "domainName": "xyz.execute-api.us-east-1.amazonaws.com",
                "stage": "$default",
                "http": {
                    "method": "GET",
                    "path": "/api/v1/health",
                    "protocol": "HTTP/1.1",
                    "sourceIp": "198.51.100.1",
                    "userAgent": "Amazon-API-Gateway"
                },
                "requestId": "test-request-id-12345",
                "timeEpoch": 1698500000000
            },
            "isBase64Encoded": False
        }

        response = handler(event, self.context)

        self.assertEqual(response["statusCode"], 200)
        self.assertIn("content-type", response.get("headers", {}))
        
        body = json.loads(response["body"])
        self.assertEqual(body["status"], "HEALTHY")
        self.assertEqual(body["app_name"], "CloudGuardAI")
        self.assertIn("aws", body)

    def test_api_gateway_cors_headers(self):
        """Test CORS headers on endpoints to ensure browser access works without origin issues."""
        response = client.get("/api/v1/health", headers={"Origin": "https://cloudguard.internal"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("access-control-allow-origin", response.headers)
        self.assertEqual(response.headers["access-control-allow-origin"], "https://cloudguard.internal")

    def test_api_gateway_cors_preflight(self):
        """Test API Gateway OPTIONS preflight request handling."""
        event = {
            "version": "2.0",
            "routeKey": "OPTIONS /api/v1/storage/upload-url",
            "rawPath": "/api/v1/storage/upload-url",
            "rawQueryString": "",
            "headers": {
                "origin": "http://localhost:3000",
                "access-control-request-method": "POST",
                "access-control-request-headers": "content-type"
            },
            "requestContext": {
                "http": {
                    "method": "OPTIONS",
                    "path": "/api/v1/storage/upload-url",
                    "protocol": "HTTP/1.1",
                    "sourceIp": "127.0.0.1"
                }
            },
            "isBase64Encoded": False
        }

        response = handler(event, self.context)
        self.assertEqual(response["statusCode"], 200)
        headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
        self.assertIn("access-control-allow-origin", headers)

    def test_api_gateway_404_error_contract(self):
        """Test that unknown endpoints return standard 404 JSON through Mangum."""
        event = {
            "version": "2.0",
            "routeKey": "GET /api/v1/nonexistent",
            "rawPath": "/api/v1/nonexistent",
            "rawQueryString": "",
            "headers": {},
            "requestContext": {
                "http": {
                    "method": "GET",
                    "path": "/api/v1/nonexistent",
                    "protocol": "HTTP/1.1",
                    "sourceIp": "127.0.0.1"
                }
            },
            "isBase64Encoded": False
        }

        response = handler(event, self.context)
        self.assertEqual(response["statusCode"], 404)
        body = json.loads(response["body"])
        self.assertIn("detail", body)

    def test_direct_s3_upload_url_contract(self):
        """
        Verify the direct upload URL contract (API Gateway 10 MB payload limit bypass).
        Clients request an upload URL, receive an S3 presigned PUT URL / local route,
        and post directly to storage instead of through the API Gateway payload proxy.
        """
        response = client.post(
            "/api/v1/storage/upload-url",
            data={"filename": "enterprise_vpc.tf", "expires_in": 900}
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("data", data)
        upload_meta = data["data"]
        self.assertIn("upload_url", upload_meta)
        self.assertIn("file_key", upload_meta)
        self.assertIn("storage_backend", upload_meta)
        self.assertIn("expires_in_seconds", upload_meta)
        self.assertIn("bypass_note", upload_meta)
        self.assertTrue(upload_meta["file_key"].startswith("uploads/"))
        self.assertTrue(upload_meta["file_key"].endswith("enterprise_vpc.tf"))

    def test_direct_s3_upload_invalid_extension(self):
        """Verify upload-url endpoint rejects unsupported file types immediately."""
        response = client.post(
            "/api/v1/storage/upload-url",
            data={"filename": "malicious_script.exe"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("detail", response.json())


if __name__ == "__main__":
    unittest.main()
