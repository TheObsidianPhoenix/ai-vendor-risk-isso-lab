# infrastructure/

Terraform code that defines Counterpart's AWS resources. **Nothing here has been deployed.** Every pull request checks it automatically, and the first deployment waits for the AWS account decision (D-11) and a cost review. Steps are in the [deploy runbook](../docs/architecture/deploy-runbook.md).

## Layout

```
bootstrap/                  Applied once by hand: Terraform state bucket + keyless GitHub access (OIDC)
environments/dev/           Calls the modules with dev settings; its state lives in the state bucket
modules/
  shared/aws/secure-bucket  The one S3 bucket recipe every bucket uses, so no bucket can miss a control
  security/aws              The project's KMS key
  storage/aws               Quarantine and documents buckets
  logging/aws               Object Lock audit bucket and the CloudTrail trail
  data/aws                  vendors, assessments and decisions tables
  monitoring/aws            Security alert rules, alert topic, monthly budget
```

Modules are named by what they do, not by AWS service, so another cloud's version could sit beside each `aws/` folder later (Phase 2 architecture, section 11).

## What's built so far: the foundation layer

| Module | Creates | Key controls |
|---|---|---|
| security | 1 KMS key + alias | Yearly rotation; 30-day deletion wait; key policy limited to this account and named AWS services (SC-12, SC-28) |
| storage | `quarantine` and `documents` buckets | Private, KMS-encrypted, TLS-only, versioned; quarantine empties after 1 day (AC-3, SC-8, SC-28) |
| logging | `audit` bucket, CloudTrail trail | Object Lock (governance, 30 days); deny on deleting audit objects; all-region trail with log file validation (AU-9, AU-11) |
| data | 3 DynamoDB tables | KMS encryption, point-in-time recovery, deletion protection; decisions in their own table (HR-01) |
| monitoring | Alert topic, 4 alert rules, budget | Alerts when CloudTrail, the key, bucket protections or table protections change; email at $5 and $10 (SI-4, CA-7) |
| bootstrap | State bucket, GitHub OIDC, 2 roles | No access keys anywhere. Pull requests get read-only; only `main` can deploy, and only `counterpart-*` resources (AC-6, CM-3, IA-5) |

**Still to come, layer by layer:** sign-in (Cognito), the web front end (CloudFront), the API and application functions (API Gateway, Lambda, ECR, SQS), and Bedrock access. Each layer adds its own deploy permissions in the same pull request, so every widening of access is reviewed.

## Checks on every pull request

The **Terraform checks** job in `.github/workflows/security-checks.yml`:

1. `terraform fmt`: consistent formatting
2. `terraform validate`: each root configuration is valid against the pinned AWS provider
3. **Checkov**: 200+ security checks. Any failure blocks the merge.

Rules this lab deliberately doesn't meet are skipped *inline*, next to the resource, with the reason (for example, no cross-region replication because of decision D-10). That makes every exception visible in code review and traceable to the POA&M.

**Proof the scan works:** before merging, the public access block was weakened on purpose. Checkov failed with 9 findings across all three buckets, and the change was reverted (commit history on the pull request).

## Rules

- No credentials and no `terraform.tfvars` with real values are committed (`.gitignore`); `terraform.tfvars.example` shows the shape.
- State lives in the encrypted, versioned state bucket, never in Git. The bucket name is passed at `terraform init`, not written in the code.
- Provider versions are pinned (`~> 6.69`). The lock file (`.terraform.lock.hcl`) is committed at first deployment, when `terraform init` runs against the real registry.
