# CloudGuardAI — Amazon DynamoDB Table Schema & Provisioning Guide

## 1. Table Architecture & Design Rationale

CloudGuardAI utilizes Amazon DynamoDB for fast, document-based storage of scan jobs, risk scores, finding references, and audit history.

- **Primary Partition Key:** `scan_id` (String, e.g. `scan_4f8b2c91a3e2`)
- **Global Secondary Index (GSI):** `OwnerCreatedAtIndex`
  - Partition Key: `owner_id` (String, e.g. AWS Account ID or user reference)
  - Sort Key: `created_at` (String, ISO 8601 UTC timestamp)
- **Billing Mode:** `PAY_PER_REQUEST` (On-Demand Capacity — zero idle cost, scales automatically).
- **Object Storage Separation:** Raw Terraform/CloudFormation templates and exported PDF reports are stored in **Amazon S3**. DynamoDB stores only the S3 object key references (`file_key`, `report_keys`), keeping DynamoDB item sizes well below the 400 KB limit.

---

## 2. Table Schema Definition

```
Table: cloudguardai_scans
├── Primary Key:
│   └── Partition Key (PK): scan_id (String)
├── Global Secondary Index (OwnerCreatedAtIndex):
│   ├── Partition Key: owner_id (String)
│   ├── Sort Key: created_at (String)
│   └── ProjectionType: ALL
└── Item Attributes:
    ├── scan_id (String, PK)
    ├── owner_id (String, GSI PK)
    ├── scan_type (String: "IAC_STATIC" | "LIVE_AWS")
    ├── target_name (String: "production-infra.tf")
    ├── status (String: "PENDING" | "PROCESSING" | "COMPLETED" | "FAILED")
    ├── overall_risk_score (Number: 0.0 - 100.0)
    ├── risk_grade (String: "A" | "B" | "C" | "D" | "F")
    ├── total_findings (Number)
    ├── critical_count (Number)
    ├── high_count (Number)
    ├── medium_count (Number)
    ├── low_count (Number)
    ├── dimension_scores (Map: { security: 25.0, iam: 15.0, ... })
    ├── unsupported_constructs (List)
    ├── file_key (String: "uploads/scan_xxx/main.tf")
    ├── report_keys (Map: { markdown: "reports/...", json: "reports/..." })
    ├── storage_backend (String: "s3" | "local")
    ├── findings (List of Finding Maps with Evidence & Remediations)
    ├── created_at (String: "2026-10-29T01:00:00Z")
    └── completed_at (String: "2026-10-29T01:00:04Z")
```

---

## 3. Required IAM Permissions

To operate DynamoDB, the execution role (`LabRole` in AWS Academy) requires:

```json
{
  "Effect": "Allow",
  "Action": [
    "dynamodb:PutItem",
    "dynamodb:GetItem",
    "dynamodb:UpdateItem",
    "dynamodb:DeleteItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:DescribeTable"
  ],
  "Resource": [
    "arn:aws:dynamodb:*:*:table/cloudguardai_*",
    "arn:aws:dynamodb:*:*:table/cloudguardai_*/index/*"
  ]
}
```

---

## 4. Manual Provisioning Instructions (Requires Your Approval)

> [!IMPORTANT]
> CloudGuardAI does **NOT** automatically deploy or provision cloud resources without explicit user approval.
> When you wish to create the table in your AWS account, run the following command in your terminal:

```bash
aws dynamodb create-table \
    --table-name cloudguardai_scans \
    --attribute-definitions \
        AttributeName=scan_id,AttributeType=S \
        AttributeName=owner_id,AttributeType=S \
        AttributeName=created_at,AttributeType=S \
    --key-schema \
        AttributeName=scan_id,KeyType=HASH \
    --global-secondary-indexes \
        "[{\"IndexName\": \"OwnerCreatedAtIndex\", \"KeySchema\": [{\"AttributeName\":\"owner_id\",\"KeyType\":\"HASH\"},{\"AttributeName\":\"created_at\",\"KeyType\":\"RANGE\"}], \"Projection\":{\"ProjectionType\":\"ALL\"}}]" \
    --billing-mode PAY_PER_REQUEST \
    --region us-east-1
```

### CloudFormation Resource Snippet:
```yaml
CloudGuardScansTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: cloudguardai_scans
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - AttributeName: scan_id
        AttributeType: S
      - AttributeName: owner_id
        AttributeType: S
      - AttributeName: created_at
        AttributeType: S
    KeySchema:
      - AttributeName: scan_id
        KeyType: HASH
    GlobalSecondaryIndexes:
      - IndexName: OwnerCreatedAtIndex
        KeySchema:
          - AttributeName: owner_id
            KeyType: HASH
          - AttributeName: created_at
            KeyType: RANGE
        Projection:
          ProjectionType: ALL
```

---

## 5. Resilient Fallback Layer

If DynamoDB is unprovisioned, inaccessible, or restricted in your student lab environment, CloudGuardAI's `DatabaseManager` automatically routes persistence to the local SQLite database (`storage/cloudguard.db`), which provides identical querying and schema validation with zero downtime or errors.
