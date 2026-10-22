# Deploy Runbook: Foundation Layer

| | |
|---|---|
| **System** | Counterpart, Meridian Trust Labs (fictional) |
| **Covers** | `infrastructure/bootstrap` and `infrastructure/environments/dev` (foundation layer) |
| **Status** | Stage 0 decisions made 2026-10-22 (guardrail check remains). **Nothing deployed yet** |
| **Builds on** | [Phase 2 Architecture](phase-2-architecture.md), sections 10 to 13 |

## What the foundation layer costs

| Item | While idle, per month | Notes |
|---|---|---|
| KMS customer managed key | $1.00 | The only fixed cost |
| S3 storage (state, audit logs, a few test files) | Under $0.10 | Bucket Keys cut KMS request charges |
| DynamoDB (3 tables, on-demand) | Pennies | No charge for capacity when idle; point-in-time recovery is billed per GB stored |
| CloudTrail | $0 for the first trail | **A second trail is billed.** The Phase 0 console trail is deleted in Stage 4, once this one is logging |
| EventBridge rules, SNS email, Budgets | $0 at this volume | Re-verify Budgets: the first two budgets are free, and one already exists from Phase 0 |
| **Total** | **About $1.10** | Well under the $10 a month target, with alerts at $5 and $10 |

Prices are from the Phase 2 estimate (checked 2026-10-08). Re-check them on the AWS pricing pages for US East (Ohio) before Stage 1.

## Stage 0: Decision gate (you decide)

These must be settled before anything is created. Record each answer in the Phase 2 architecture document, section 13.

- [x] **D-11: upgrade the account to the paid plan.** Done 2026-10-22, with a **$20 monthly spend limit**.
- [x] **D-11: whether to activate advanced features.** Decided: **not activated** (irreversible, and it removes the spend limit).
- [ ] **Guardrails allow what we need.** Confirm the account's managed policies don't block: KMS customer managed keys, S3 Object Lock, CloudTrail, DynamoDB, EventBridge, Budgets, and creating an IAM OIDC provider and roles. The quickest real test is Stage 1's `terraform plan`, which fails clearly on anything blocked.
- [x] **Budget alarms are on** before the upgrade (Phase 0 zero-spend budget).

## Stage 1: Bootstrap (once, by hand, in AWS CloudShell)

CloudShell is a terminal inside the AWS console, already signed in as you. Nothing gets installed on your Mac.

1. Sign in to the console for the **ai vendor risk isso lab** project, region **US East (Ohio)**. Open **CloudShell** from the toolbar (the `>_` icon).
2. Install Terraform, checking the download's fingerprint:
   ```bash
   V=1.16.6
   curl -sSLO https://releases.hashicorp.com/terraform/$V/terraform_${V}_linux_amd64.zip
   curl -sSLO https://releases.hashicorp.com/terraform/$V/terraform_${V}_SHA256SUMS
   grep linux_amd64 terraform_${V}_SHA256SUMS | sha256sum -c -   # must say OK
   unzip -o terraform_${V}_linux_amd64.zip -d ~/bin && terraform version
   ```
3. Get the code and look before touching anything:
   ```bash
   git clone https://github.com/TheObsidianPhoenix/ai-vendor-risk-isso-lab.git
   cd ai-vendor-risk-isso-lab/infrastructure/bootstrap
   terraform init
   terraform plan -out bootstrap.plan
   ```
   Read the plan. It should create about 14 resources: the state bucket and its settings, one OIDC provider, two roles and their policies. **Nothing should be changed or destroyed.**
4. If the plan matches, apply exactly that plan: `terraform apply bootstrap.plan`
5. Write down the three outputs (`terraform output`): the state bucket name and the two role ARNs.
6. Keep `terraform.tfstate` in this folder. CloudShell keeps your home folder, but download a copy too (**Actions → Download file**) and store it somewhere private. It holds no passwords, but it does name your account.

Evidence to capture (redact the account number): the plan summary line, the outputs, and the OIDC role's trust policy in the IAM console showing the `repo:...:ref:refs/heads/main` condition.

## Stage 2: Connect GitHub (no keys)

In the repository, open **Settings → Secrets and variables → Actions → New repository secret** and add:

| Secret | Value |
|---|---|
| `AWS_PLAN_ROLE_ARN` | `plan_role_arn` output |
| `AWS_DEPLOY_ROLE_ARN` | `deploy_role_arn` output |
| `TF_STATE_BUCKET` | `state_bucket` output |

These aren't passwords, but they include your account number, and this repository's workflow logs are public. Secrets keep them masked. There are still **no AWS access keys anywhere**: GitHub trades a signed token for credentials that expire within the hour.

## Stage 3: Plan on pull requests, apply on merge

A follow-up pull request adds the deploy workflow:

- **On every pull request:** it assumes the read-only plan role and posts `terraform plan`, showing exactly what would change.
- **On merge to `main`:** it assumes the deploy role and runs `terraform apply` of that reviewed change, behind a GitHub **environment** with you as the required approver. That gives two human gates: the PR review and the deploy approval.

Add **Terraform checks** to the `protect-main` ruleset's required status checks, so a failed scan blocks merging.

## Stage 4: After the first apply

- [ ] Click the confirmation link in the **AWS Notification** email, or alerts won't arrive.
- [ ] CloudTrail console: the `counterpart-dev-trail` shows **Logging: On**, with log file validation enabled.
- [ ] **Delete the Phase 0 console trail**, so there's one trail and one bill. Capture a screenshot of the trail list first, as evidence.
- [ ] Test an alert: in the CloudTrail console, stop and restart logging on the Terraform trail. The **cloudtrail-tampering** email should arrive within minutes. Capture it as evidence that monitoring works.
- [ ] S3 console: each `counterpart-dev-*` bucket shows **Block all public access: On** and **Default encryption: SSE-KMS**. The audit bucket shows **Object Lock: Enabled, Governance, 30 days**.
- [ ] Commit `.terraform.lock.hcl` from the first real `terraform init` (pins provider checksums).

## Known follow-ups

| Item | Why |
|---|---|
| IAM-change and root sign-in alerts | AWS delivers these events only in us-east-1, so those rules must live there. Check the account's region guardrails first |
| S3 data events for the documents bucket | Records every read of vendor files; billed per event, so turn on once the app is live |
| Move the bootstrap state into the state bucket | Today it's a local file you keep safe |

## Tearing the lab down later

Order matters, because the audit trail is built to resist deletion:

1. Remove the `DenyAuditDeletion` statement through a reviewed pull request, and wait out the 30-day Object Lock.
2. Turn off DynamoDB deletion protection through a pull request, then `terraform destroy`.
3. The KMS key is scheduled for deletion with a 30-day wait. Once it's gone, any copy of the encrypted data anywhere is permanently unreadable (crypto-shredding, Phase 2, section 8).
