# CloudGuardAI — API Gateway & Lambda Hosting Specification

## 1. Hosting Model Evaluation & Architecture

CloudGuardAI is architected for dual-target deployment:
1. **Serverless Production (Amazon API Gateway + AWS Lambda via Mangum):**
   - **Why Serverless:** CloudGuardAI exhibits an on-demand, event-driven traffic pattern. Serverless scales to zero, eliminating idle hourly compute charges and minimizing costs in academic and student lab environments.
   - **Mangum Adapter:** Uses `Mangum` to wrap the FastAPI ASGI application, allowing the identical codebase to run both as a local server (`uvicorn`) and as an AWS Lambda handler behind API Gateway.
2. **Alternative Hosting (ECS Fargate / App Runner / EC2):**
   - For enterprise teams requiring 24/7 continuous connections, heavy websockets, or uploads exceeding 100 MB in a single connection, the application container can run on AWS App Runner or ECS Fargate. However, Serverless remains the recommended model due to its zero-idle-cost profile.

---

## 2. API Gateway Constraints & Direct-to-S3 Upload Bypass

| Constraint | API Gateway Limit | CloudGuardAI Architecture Mitigation |
| :--- | :--- | :--- |
| **Payload Size** | **10 MB** hard limit | **Direct-to-S3 Presigned Uploads (`POST /api/v1/storage/upload-url`):** Large templates bypass API Gateway entirely. The client requests a presigned S3 PUT URL and uploads directly to S3 (supporting files up to 100 MB), completely circumventing the 10 MB payload limit and avoiding double-hop latency. |
| **Integration Timeout** | **29 seconds** hard limit | Synchronous evaluations complete in $< 1.5$ seconds. For very large multi-thousand-line templates, the asynchronous worker (`POST /api/v1/scan/async` or S3 Event) executes decoupled with a 60-second timeout. |
| **CORS** | Browser cross-origin preflight | Configured natively in FastAPI middleware: `Allow-Origins: *`, `Allow-Methods: GET, POST, OPTIONS`, `Allow-Headers: *`. |

---

## 3. Complete API Gateway Routes & Schema Catalog

```
                                    Amazon API Gateway (HTTP API v2)
                                                   │
                ┌──────────────────────────────────┴──────────────────────────────────┐
                ▼                                                                     ▼
        /api/v1/storage/*                                                      /api/v1/scan/*
  ├── POST /upload-url (Direct S3 URL)                                   ├── POST /upload (Sync Scan)
  ├── POST /upload     (Direct Gateway)                                  ├── POST /async  (202 Async)
  ├── GET  /file/{key} (Content Stream)                                  ├── POST /analyze-stored
  ├── GET  /download-url (Presigned URL)                                 ├── POST /live   (Read-Only AWS)
  └── GET  /status     (Storage Health)                                  ├── GET  /metrics/summary
                                                                         ├── GET  /scans  (History)
                                                                         ├── GET  /{id}   (Findings)
                                                                         └── GET  /{id}/report
```

### 3.1 Direct-to-S3 Upload Flow
1. **Client requests presigned S3 URL:**
   `POST /api/v1/storage/upload-url` with `filename="main.tf"`
2. **Gateway returns:**
   ```json
   {
     "success": true,
     "data": {
       "upload_mode": "DIRECT_S3",
       "upload_url": "https://bucket.s3.amazonaws.com/uploads/scan_xxx/main.tf?AWSAccessKeyId=...",
       "file_key": "uploads/scan_xxx/main.tf",
       "analysis_id": "scan_xxx",
       "http_method": "PUT",
       "required_headers": {
         "Content-Type": "text/plain",
         "x-amz-server-side-encryption": "AES256"
       },
       "expires_in_seconds": 900
     }
   }
   ```
3. **Client uploads file directly to S3 via HTTP PUT.**
4. **Client triggers analysis:**
   `POST /api/v1/scan/analyze-stored` with `file_key="uploads/scan_xxx/main.tf"`

---

## 4. Standard Error Response Schema

All API endpoints return predictable, machine-readable JSON error structures:

```json
{
  "detail": "Descriptive error message",
  "error_type": "AUTHENTICATION_REQUIRED | PERMISSION_DENIED | VALIDATION_ERROR | RESOURCE_NOT_FOUND",
  "code": "ClientError | NoSuchBucket | ExpiredToken",
  "remediation": "Clear, actionable instruction to resolve the issue"
}
```

---

## 5. Serverless SAM Deployment Template

> [!IMPORTANT]
> CloudGuardAI does **NOT** deploy cloud resources automatically.
> When you choose to deploy API Gateway and Lambda in your AWS account, use this SAM specification:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: CloudGuardAI Serverless API Gateway & Worker Stack

Parameters:
  ArtifactsBucketName:
    Type: String
    Default: cloudguardai-artifacts-us-east-1

Resources:
  # HTTP API Gateway
  CloudGuardHttpApi:
    Type: AWS::Serverless::HttpApi
    Properties:
      CorsConfiguration:
        AllowOrigins:
          - "*"
        AllowMethods:
          - GET
          - POST
          - OPTIONS
        AllowHeaders:
          - "*"

  # FastAPI Web API Handler
  CloudGuardApiFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: cloudguard-api-backend
      Handler: backend.app.main.handler
      Runtime: python3.12
      CodeUri: .
      MemorySize: 512
      Timeout: 25
      Role: !Sub "arn:aws:iam::${AWS::AccountId}:role/LabRole"
      Environment:
        Variables:
          S3_BUCKET_NAME: !Ref ArtifactsBucketName
          DYNAMODB_TABLE_NAME: cloudguardai_scans
          STORAGE_BACKEND: s3
          DATABASE_BACKEND: dynamodb
      Events:
        ApiRootEvent:
          Type: HttpApi
          Properties:
            ApiId: !Ref CloudGuardHttpApi
            Path: /{proxy+}
            Method: ANY
```

---

## 6. Local Testing Instructions

Test the API Gateway contracts and Direct-to-S3 endpoint locally:

```bash
# 1. Test direct upload URL endpoint
curl -X POST "http://127.0.0.1:8000/api/v1/storage/upload-url" -F "filename=production.tf"

# 2. Run automated API contracts test suite
$env:PYTHONPATH = "C:\Users\HP\.gemini\antigravity\scratch\cloudguard-ai"
python tests/test_api_gateway_contracts.py
```
