# CloudGuardAI — AWS Academy Learner Lab IAM & Permissions Guide

## 1. The Learner Lab Permission Boundary
In an **AWS Academy Learner Lab**:
- Students are granted temporary credentials associated with a pre-configured IAM role named **`LabRole`** (or an assumed role under `voclabs`).
- Students **CANNOT** create new IAM users, groups, or custom IAM roles (`iam:CreateRole`, `iam:CreatePolicy`, `iam:AttachRolePolicy` are explicitly denied).
- Custom Lambda functions or service executions must specify the existing role ARN:
  `arn:aws:iam::<Account-ID>:role/LabRole`
- Any attempt to attach `AdministratorAccess` or modify trust boundaries will result in an `AccessDeniedException`.

## 2. CloudGuardAI's Least-Privilege Compliance
CloudGuardAI is architected to operate strictly within these boundaries:
1. **Zero IAM Mutations:** CloudGuardAI never calls `iam:Create*` or `iam:Put*` at runtime.
2. **Read-Only Resource Scanning:** The Live Scanner invokes only read-only `Describe*`, `Get*`, and `List*` APIs, which are already permitted by `LabRole`.
3. **Scoped S3 Buckets:** Buckets should be prefixed with `cloudguardai-artifacts-` in `us-east-1`.
4. **On-Demand DynamoDB:** Tables named `cloudguardai_scans` work on-demand without provisioned capacity.
5. **Bedrock Resiliency:** If Bedrock model invocation is restricted by your Academy account's policy boundary, CloudGuardAI detects the `AccessDeniedException` or `ResourceNotFoundException` and automatically routes remediation requests through its built-in deterministic remediation engine.
