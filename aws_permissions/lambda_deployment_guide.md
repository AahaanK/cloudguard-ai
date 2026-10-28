# CloudGuardAI — AWS Lambda Asynchronous Analysis Architecture & Deployment Guide

## 1. Architectural Evaluation & Fit

In CloudGuardAI, asynchronous analysis is utilized to evaluate large multi-tier infrastructure configurations without blocking web API threads or risking HTTP client gateway timeouts:

```
[Developer / Web UI]
        │
        ▼ (1) Upload Blueprint
[Amazon S3 Bucket] (uploads/{analysis_id}/main.tf)
        │
        ▼ (2) S3 Event Notification (s3:ObjectCreated:*)
              Filter: Prefix = "uploads/" (Strictly avoids reports/)
[AWS Lambda Worker] (cloudguard-worker)
        │
        ├── (3) Retrieve Blueprint & Parse AST
        ├── (4) Evaluate 7-Dimension Rules
        ├── (5) Compute Risk Score & Grade
        │
        ▼ (6) Persist Scan State & Findings
[Amazon DynamoDB / Repository] (cloudguardai_scans)
```

### Critical S3 Recursive Trigger Prevention:
S3 Event Notifications are filtered **strictly on the prefix `uploads/`**.
Audit reports are deposited into `reports/`.
Because the Lambda worker ignores any key outside `uploads/`, recursive invocation loops (Lambda generating a report which triggers another Lambda) are mathematically prevented.

---

## 2. Resource Specifications

| Setting | Value | Rationale |
| :--- | :--- | :--- |
| **Handler** | `backend.app.lambda_handler.lambda_handler` | Unified event dispatcher supporting S3 events and direct JSON payloads. |
| **Runtime** | `Python 3.12` or `Python 3.14` | Matches modern Python runtime environment. |
| **Memory** | `512 MB` | Provides sufficient heap space for AST parsing of large multi-thousand-line templates while optimizing Lambda CPU allocation. |
| **Timeout** | `60 seconds` | Standard templates evaluate in $< 1.5$ seconds; 60s provides ample headroom for complex dependency graphs. |
| **Ephemeral Storage** | `512 MB` | Standard `/tmp` space. |
| **Payload Limits** | $< 256 \text{ KB}$ | Direct event carries only S3 bucket and object key metadata; file payload is fetched from S3. |

---

## 3. AWS Academy Learner Lab Execution Boundary

In an **AWS Academy Learner Lab**:
- Custom IAM role creation is disabled (`iam:CreateRole` is explicitly denied).
- The Lambda function must be configured with the pre-existing role:
  `arn:aws:iam::<Account-ID>:role/LabRole`
- If Lambda deployment is blocked in your course environment, CloudGuardAI's FastAPI backend features a built-in asynchronous worker (`POST /api/v1/scan/async` using `BackgroundTasks`) that runs the exact same `process_analysis_job` routine in-process.

---

## 4. CloudFormation / SAM Serverless Template

> [!IMPORTANT]
> CloudGuardAI does **NOT** automatically deploy infrastructure. When you choose to deploy to your AWS account, use the following template:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: CloudGuardAI Serverless Analysis Engine

Parameters:
  ArtifactsBucketName:
    Type: String
    Default: cloudguardai-artifacts-us-east-1

Resources:
  CloudGuardAnalysisFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: cloudguard-analysis-worker
      Handler: backend.app.lambda_handler.lambda_handler
      Runtime: python3.12
      CodeUri: .
      MemorySize: 512
      Timeout: 60
      Role: !Sub "arn:aws:iam::${AWS::AccountId}:role/LabRole"
      Environment:
        Variables:
          S3_BUCKET_NAME: !Ref ArtifactsBucketName
          DYNAMODB_TABLE_NAME: cloudguardai_scans
          STORAGE_BACKEND: s3
          DATABASE_BACKEND: dynamodb
      Events:
        BlueprintUploadEvent:
          Type: S3
          Properties:
            Bucket: !Ref ArtifactsBucket
            Events: s3:ObjectCreated:*
            Filter:
              S3Key:
                Rules:
                  - Name: prefix
                    Value: uploads/

  ArtifactsBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref ArtifactsBucketName
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
```

---

## 5. Local Development Path

For local testing without AWS Lambda or LocalStack:
```bash
# Direct Python CLI test
python -c "from backend.app.lambda_handler import process_analysis_job; print(process_analysis_job('uploads/scan_sample/main.tf'))"

# Asynchronous HTTP API test
curl -X POST "http://127.0.0.1:8000/api/v1/scan/async" -F "file=@sample.tf"
```
