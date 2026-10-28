# CloudGuardAI — Enterprise Cloud Infrastructure Risk Analysis Platform

**CloudGuardAI** is a dual-mode cloud security posture management (CSPM) and infrastructure-as-code (IaC) risk analysis platform. It analyzes Terraform and CloudFormation blueprints across **7 Well-Architected dimensions**, executes authentic read-only live discovery of AWS resources, and generates production-grade remediation code using deterministic rule evaluation with optional Amazon Bedrock foundation model synthesis.

---

## 1. Verified Architecture

CloudGuardAI implements a resilient dual-mode operational architecture designed for seamless local development and production serverless cloud deployment:

```
+--------------------------------------------------------------------------------------------------+
|                                     BROWSER USER INTERFACE                                       |
|                  Permanent Coastal Theme: #287FA3 Cerulean | #DCC9A8 Sand Beige                  |
+-------------------------------------------------+------------------------------------------------+
                                                  |
                                (HTTPS REST & Presigned S3 PUT)
                                                  |
                                                  v
+--------------------------------------------------------------------------------------------------+
|                                   BACKEND APPLICATION LAYER                                      |
|                                                                                                  |
|   Serverless Gateway: AWS API Gateway HTTP API v2  <-->  AWS Lambda (Mangum + FastAPI)           |
|   Local Resilient Runtime: Localhost Uvicorn Server                                              |
|                                                                                                  |
|   +--------------------------+  +--------------------------+  +-------------------------------+  |
|   | IaC AST Parser Engine    |  | 7-Dimension Rule Engine  |  | Live AWS Discovery Scanner    |  |
|   | • Terraform HCL / JSON   |  | • Security      • Cost   |  | • S3 Public Access & SSE      |  |
|   | • CloudFormation YAML    |  | • IAM           • Perf   |  | • EC2 Ports (22, 3389, DB)   |  |
|   | • Unsupported quarantine |  | • Network       • Rel    |  | • Default VPC Detection       |  |
|   | • Code injection defense |  | • Configuration          |  | • RDS Public Endpoints & Enc  |  |
|   +--------------------------+  +--------------------------+  +-------------------------------+  |
+-----------------------------------+--------------------------------------+-----------------------+
                                    |                                      |
        +---------------------------+-----------+             +------------+-------------+
        |                                       |             |                          |
        v                                       v             v                          v
+-----------------------+     +-------------------+     +-------------+     +--------------------+
|  STORAGE SUBSYSTEM    |     |  DATABASE LAYER   |     |     AI      |     |     TELEMETRY      |
| • AWS S3 (AES256)     |     | • AWS DynamoDB    |     | • Bedrock   |     | • AWS CloudWatch   |
|   - uploads/ prefix   |     |   - Scans table   |     |   Claude 3  |     |   /cloudguardai/   |
|   - reports/ prefix   |     |   - Pay-Per-Req   |     |   Titan     |     |   audit-logs       |
| • Local Disk Fallback |     | • SQLite Fallback |     | • Rule Fall |     | • Stdout Scrubber  |
+-----------------------+     +-------------------+     +-------------+     +--------------------+
```

### Architectural Highlights
- **Serverless Scale-to-Zero**: Powered by AWS Lambda and Amazon API Gateway HTTP API v2. When idle, cloud cost is exactly **\$0.00/month**.
- **Direct S3 Upload Bypass**: Bypasses API Gateway's 10 MB payload limit via short-lived presigned S3 PUT URLs (`POST /api/v1/storage/upload-url`).
- **Graceful Local Fallback**: Automatically switches to SQLite (`./storage/cloudguard.db`) and atomic local filesystem storage (`./storage/`) when AWS credentials or buckets are unconfigured.
- **AWS Academy Learner Lab Compatibility**: Enforces full compatibility with pre-existing `LabRole` constraints without requiring forbidden IAM role creation (`iam:CreateRole`).

---

## 2. Permanent Coastal Design System

CloudGuardAI strictly adheres to an enterprise cybersecurity visual standard:

- **Cerulean Blue (`#287FA3`)**: Primary actions, active navigation states, and risk score numbers.
- **Sand Beige (`#DCC9A8` / `#F4EFE6`)**: Table headers, subtle card surfaces, and neutral boundaries.
- **Charcoal (`#202A30`)**: Body typography, bold headings, and high-contrast labels.
- **Warm Off-White (`#F3F1EB`)**: Canvas background.
- **Pure White (`#FFFFFF`)**: Card surfaces and data table rows.
- **Design Invariants**: Standard rectangular controls (`border-radius: 3px`), thin borders (`1px solid #E2DDD5`), clean monospace code blocks, and zero AI visual tropes (no glowing dots, neon gradients, glassmorphism, or floating chatbot avatars).

---

## 3. Local Setup & Quickstart

### Prerequisites
- Python 3.10 or higher (Verified on Python 3.14.8).
- Git.

### 1. Clone & Enter Repository
```bash
git clone <repository-url>
cd cloudguard-ai
```

### 2. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 3. Verify Local & AWS Environment
```bash
python scripts/check_aws_env.py
```
*If AWS credentials are not configured, CloudGuardAI will safely report that it is running in **Local Resilient Fallback Mode**.*

### 4. Start the Application Server
```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser at **`http://127.0.0.1:8000/`**.

---

## 4. Configuration & Environment Variables

Create a local `.env` file based on `.env.example`:

```env
# Server & Environment
APP_NAME=CloudGuardAI
APP_ENV=development
HOST=127.0.0.1
PORT=8000

# Backend Modes (Auto-detects or manual override)
STORAGE_BACKEND=local       # 'local' or 's3'
DATABASE_BACKEND=sqlite     # 'sqlite' or 'dynamodb'
REMEDIATION_BACKEND=hybrid  # 'hybrid', 'bedrock', or 'deterministic'

# AWS Configuration (Leave blank for Local Resilient Mode)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_SESSION_TOKEN=          # Required for AWS Academy Learner Lab
S3_BUCKET_NAME=
DYNAMODB_TABLE_NAME=cloudguardai_scans
AWS_BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0
CLOUDWATCH_LOG_GROUP=/cloudguardai/audit-logs
```

---

## 5. Automated Testing Runbook

CloudGuardAI includes **80 automated tests across 13 test suites** providing 100% test pass fidelity across all modules:

### Run All Tests
```bash
python -m unittest discover -s tests -p "test_*.py"
```

### Test Suites Breakdown
| Test Suite | Tests | Purpose |
| :--- | :---: | :--- |
| `tests/test_api_endpoints.py` | 5 | REST API health, storage routes, UI index serving |
| `tests/test_api_gateway_contracts.py` | 6 | Mangum Lambda handler, HTTP API v2 events, CORS preflight, S3 upload bypass |
| `tests/test_aws_security.py` | 6 | STS caller verification, masked secret logging, permission probe |
| `tests/test_bedrock_ai.py` | 10 | Claude 3 Haiku, Titan, prompt injection containment, response validation, timeouts |
| `tests/test_cloudwatch_logger.py` | 4 | Structured audit telemetry, recursive credential scrubber, stdout fallback |
| `tests/test_dynamodb_persistence.py` | 6 | DynamoDB `cloudguardai_scans` table, Decimal conversion, state transitions |
| `tests/test_full_workflow.py` | 1 | End-to-end blueprint upload -> parsing -> scoring -> DB persistence |
| `tests/test_lambda_handler.py` | 6 | Asynchronous S3 event trigger, recursive trigger blocking, idempotency |
| `tests/test_live_scanner.py` | 4 | Read-only live discovery of S3, EC2, RDS, IAM; LabRole boundary handling |
| `tests/test_report_export.py` | 8 | Markdown, HTML, JSON report generation, private S3 storage, presigned URLs |
| `tests/test_risk_pipeline.py` | 6 | 7-dimension Well-Architected rules, AST parsing, risk scoring |
| `tests/test_s3_storage.py` | 7 | S3 uploads, AES256 encryption, extension validation, presigned downloads |
| `tests/test_security_audit_and_failures.py` | 11 | Path traversal defense, 0-byte upload rejection, cross-scan data isolation |

---

## 6. Live AWS Smoke Testing

Live AWS tests require active temporary or permanent AWS credentials and are cleanly separated from mocked unit tests:

1. **Verify Credentials & STS Identity**:
   ```powershell
   $env:AWS_ACCESS_KEY_ID = "ASIA..."
   $env:AWS_SECRET_ACCESS_KEY = "..."
   $env:AWS_SESSION_TOKEN = "..."
   python scripts/check_aws_env.py
   ```
2. **Execute Live Amazon S3 Smoke Test**:
   ```powershell
   $env:S3_BUCKET_NAME = "my-approved-cloudguard-bucket"
   python scripts/s3_smoke_test.py
   ```
   *Verifies `HeadBucket`, uploads a test blueprint with `ServerSideEncryption="AES256"`, generates a presigned download URL, and downloads the file to verify round-trip integrity.*

---

## 7. Cloud Deployment Runbook

### A. Render Cloud Web Service Deployment (1-Click Blueprint)

CloudGuardAI includes native configuration for zero-downtime deployment on [Render](https://render.com) using a single consolidated web service architecture that serves both the FastAPI REST API and the coastal UI frontend from a unified origin.

#### 1. Configuration Files Included
- **`render.yaml`**: Infrastructure-as-code Blueprint defining the service, Python runtime, build command, dynamic port binding, healthcheck endpoint, and environment variables.
- **`Dockerfile`**: Hardened container specification with dynamic `$PORT` support and health checks.

#### 2. Deploy via Render Blueprint (Recommended)
1. Push this repository to your GitHub or GitLab account:
   ```bash
   git remote add origin https://github.com/<your-username>/cloudguardai.git
   git push -u origin main
   ```
2. Log in to [Render Dashboard](https://dashboard.render.com).
3. Click **New +** -> **Blueprint**.
4. Connect your `cloudguardai` repository. Render automatically reads `render.yaml` and configures:
   - **Service Name**: `cloudguardai`
   - **Runtime**: Python 3.11
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path**: `/api/v1/health`
5. *(Optional AWS Connection)*: In the Environment Variables settings, add your AWS credentials if you wish to connect real AWS S3/DynamoDB storage:
   - `AWS_ACCESS_KEY_ID`: `<your-key>`
   - `AWS_SECRET_ACCESS_KEY`: `<your-secret>`
   - `AWS_SESSION_TOKEN`: `<session-token-if-temporary>`
   - `S3_BUCKET_NAME`: `<your-private-s3-bucket>`
   *(If omitted, CloudGuardAI seamlessly defaults to internal local storage and SQLite persistence).*
6. Click **Apply**. Render will build and deploy the application.
7. Your live public URL will be generated: `https://cloudguardai.onrender.com` (or your chosen service slug).

#### 3. Live Endpoint Verification on Render
Once deployed, probe the live deployment:
```bash
# Verify Health & AWS Boundary Detection
curl https://<your-service>.onrender.com/api/v1/health

# Verify Web UI
curl -I https://<your-service>.onrender.com/
```

---

### B. AWS Serverless Deployment (SAM / CloudFormation)

> [!IMPORTANT]
> **Zero Unapproved Deployment Policy**:
> Do not execute live deployments or create billable cloud resources without explicit user/instructor approval.

### Infrastructure-as-Code Template
The verified template is located at [**`aws_permissions/template.yaml`**](file:///C:/Users/HP/.gemini/antigravity/scratch/cloudguard-ai/aws_permissions/template.yaml).

### Standard Commercial AWS Deployment
```bash
sam build -t aws_permissions/template.yaml
sam deploy --guided \
  --stack-name cloudguardai-production \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

### AWS Academy Learner Lab Deployment
AWS Academy forbids `iam:CreateRole`. The template automatically detects and uses the existing `LabRole`:
```bash
sam build -t aws_permissions/template.yaml
sam deploy \
  --stack-name cloudguardai-lab \
  --parameter-overrides ExecutionRoleArn="" Environment="production" \
  --region us-east-1
```

### Health Check Verification
After deployment, query the generated API Gateway endpoint:
```bash
curl https://<api-id>.execute-api.us-east-1.amazonaws.com/api/v1/health
```

---

## 8. Rollback & Safe Resource Teardown

To completely clean up all provisioned AWS resources and eliminate all recurring or idle billing:

### 1. Delete the SAM / CloudFormation Stack
```bash
sam delete --stack-name cloudguardai-production --region us-east-1
```

### 2. Empty & Remove Artifact S3 Bucket
*(If the bucket contains persisted templates or audit reports, CloudFormation will retain the bucket to prevent data loss. Empty it manually before deletion):*
```bash
aws s3 rm s3://cloudguardai-artifacts-<account-id>-us-east-1 --recursive
aws s3 rb s3://cloudguardai-artifacts-<account-id>-us-east-1
```

### 3. Verify Complete Deletion
```bash
aws cloudformation describe-stacks --stack-name cloudguardai-production
# Should return ValidationError: Stack ... does not exist
```

---

## 9. Known Limitations & Failure Recovery

| Boundary / Condition | Root Cause | CloudGuardAI Recovery Mechanism |
| :--- | :--- | :--- |
| **AWS Academy LabRole Blocks Bedrock** | Service Control Policy prohibits `bedrock:InvokeModel` | Catches `AccessDeniedException` and immediately delivers the deterministic Well-Architected remediation rule. |
| **AWS Academy Blocks IAM Account Summary** | `iam:GetAccountSummary` not authorized in LabRole | Catches error, records it in `limitations_recorded`, and reports it honestly in the UI without failing the scan. |
| **S3 Bucket Unconfigured / Missing** | `S3_BUCKET_NAME` not specified in `.env` | Automatically routes file storage to atomic local filesystem storage (`./storage/`). |
| **DynamoDB Table Not Provisioned** | AWS offline or table uncreated | Automatically initializes and persists all scans and findings into SQLite (`./storage/cloudguard.db`). |
| **Large Blueprint Uploads (>10 MB)** | AWS API Gateway payload size limit | Generates a presigned S3 upload URL (`/api/v1/storage/upload-url`) for direct client-to-S3 streaming. |
| **Malformed Infrastructure Code** | Syntax error in HCL / YAML | Quarantined in `unsupported_constructs`; valid resources are parsed and evaluated. |

---

## 10. Comprehensive Feature Matrix

| Feature / Capability | Implemented | Locally Tested | Tested vs Real AWS | Deployed | Mocked | Blocked (Learner Lab) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **FastAPI REST API & Static UI** | [x] | [x] | [x] | [ ] | [ ] | [ ] |
| **Terraform HCL / JSON AST Parser** | [x] | [x] | [ ] | [ ] | [ ] | [ ] |
| **CloudFormation YAML/JSON Parser** | [x] | [x] | [ ] | [ ] | [ ] | [ ] |
| **7-Dimension Well-Architected Rules** | [x] | [x] | [ ] | [ ] | [ ] | [ ] |
| **Deterministic Risk Scorer (0-100, A-F)** | [x] | [x] | [ ] | [ ] | [ ] | [ ] |
| **Local Filesystem Storage Fallback** | [x] | [x] | [ ] | [ ] | [ ] | [ ] |
| **Amazon S3 Storage (AES256, Private)** | [x] | [x] | [x]* | [ ] | [x] | [ ] |
| **Direct S3 Upload Bypass (10 MB Limit)** | [x] | [x] | [ ] | [ ] | [x] | [ ] |
| **SQLite Persistence Fallback** | [x] | [x] | [ ] | [ ] | [ ] | [ ] |
| **Amazon DynamoDB Persistence** | [x] | [x] | [ ] | [ ] | [x] | [ ] |
| **AWS Lambda Serverless Handler (Mangum)**| [x] | [x] | [ ] | [ ] | [x] | [ ] |
| **Lambda Async Worker (S3 Trigger)** | [x] | [x] | [ ] | [ ] | [x] | [ ] |
| **Live AWS S3 Discovery** | [x] | [x] | [x] | [ ] | [x] | [ ] |
| **Live AWS EC2 Security Groups Discovery** | [x] | [x] | [x] | [ ] | [x] | [ ] |
| **Live AWS Default VPC Discovery** | [x] | [x] | [x] | [ ] | [x] | [ ] |
| **Live AWS RDS Database Discovery** | [x] | [x] | [ ] | [ ] | [x] | [ ] |
| **Live AWS IAM Root MFA Discovery** | [x] | [x] | [ ] | [ ] | [x] | [x] (LabRole SCP) |
| **Amazon Bedrock AI Synthesis (Claude 3)** | [x] | [x] | [ ] | [ ] | [x] | [x] (LabRole SCP) |
| **Prompt Injection Quarantining** | [x] | [x] | [ ] | [ ] | [ ] | [ ] |
| **Amazon CloudWatch Audit Logging** | [x] | [x] | [ ] | [ ] | [x] | [x] (LabRole SCP) |
| **Multi-Format Reports (MD, JSON, HTML)** | [x] | [x] | [ ] | [ ] | [ ] | [ ] |
| **Presigned S3 Report Download URLs** | [x] | [x] | [ ] | [ ] | [x] | [ ] |
| **Coastal Enterprise UI Design System** | [x] | [x] | [x] | [ ] | [ ] | [ ] |

*\* Tested against live AWS environment using non-destructive check and smoke test utilities.*
