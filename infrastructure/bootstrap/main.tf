# Bootstrap: applied once, by hand, before anything else (Phase 2, section 10).
#
# Creates the two things every later deployment depends on:
#
#   1. The tf-state bucket, where Terraform keeps its record of what exists.
#   2. Keyless access for GitHub Actions (OIDC). GitHub proves which repository
#      and branch a workflow came from with a signed token, and AWS hands back
#      credentials that expire within the hour. No access keys exist anywhere.
#
#      github-plan:   any pull request in this repository. Read-only, so a PR
#                     can show what it WOULD change, but can't change anything.
#      github-deploy: only the main branch, so only reviewed, merged code can
#                     change the account (CM-3, change control).
#
# Its own state stays local (in this folder, git-ignored), because the state
# bucket doesn't exist until this runs. Keep that file safe, or re-import.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.69"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "counterpart"
      ManagedBy = "terraform-bootstrap"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  repo       = var.github_repository
  oidc_host  = "token.actions.githubusercontent.com"
}

# ---------------------------------------------------------------------------
# 1. Terraform state bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "state" {
  # Accepted gaps, each recorded for the POA&M:
  # checkov:skip=CKV_AWS_18: Server access logs cost per request; CloudTrail records bucket-level changes (Phase 2, section 5.10)
  # checkov:skip=CKV_AWS_144: Single region by design (decision D-10); versioning covers accidental deletion
  # checkov:skip=CKV2_AWS_62: No event notifications needed yet
  # checkov:skip=CKV_AWS_145: Uses the AWS managed S3 KMS key, because the project's own key is created later by Terraform from this state
  bucket_prefix = "counterpart-tf-state-"
  force_destroy = false
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled" # Every past state is kept, so a bad run can be rolled back
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      # The AWS managed S3 key: free, and available before the project's own
      # key exists. The project key is created later, by Terraform, from here.
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "keep-90-days-of-history"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
  depends_on = [aws_s3_bucket_versioning.state]
}

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket     = aws_s3_bucket.state.id
  policy     = data.aws_iam_policy_document.state_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.state]
}

# ---------------------------------------------------------------------------
# 2. GitHub Actions OIDC: keyless, short-lived credentials
# ---------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "trust_plan" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      # Pull requests in this repository only. GitHub doesn't give these
      # tokens to pull requests from forks.
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${local.repo}:pull_request"]
    }
  }
}

data "aws_iam_policy_document" "trust_deploy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      # The main branch only: code that passed review and every required check
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${local.repo}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "plan" {
  name                 = "counterpart-github-plan"
  description          = "Read-only: lets pull requests show what Terraform would change"
  assume_role_policy   = data.aws_iam_policy_document.trust_plan.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_read_only" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "plan_limits" {
  # ReadOnlyAccess could read objects in any bucket. A pull request has no
  # reason to read vendor documents or audit records, so that is denied.
  statement {
    sid     = "NoReadingProjectData"
    effect  = "Deny"
    actions = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = [
      "arn:${local.partition}:s3:::counterpart-*-quarantine-*/*",
      "arn:${local.partition}:s3:::counterpart-*-documents-*/*",
      "arn:${local.partition}:s3:::counterpart-*-audit-*/*",
    ]
  }
  statement {
    sid       = "NoReadingTableItems"
    effect    = "Deny"
    actions   = ["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan"]
    resources = ["arn:${local.partition}:dynamodb:*:${local.account_id}:table/counterpart-*"]
  }
  # Plans read and lock state, which needs these on the state bucket only
  statement {
    sid       = "UseStateLock"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/*.tflock"]
  }
}

resource "aws_iam_role_policy" "plan_limits" {
  name   = "limits"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_limits.json
}

resource "aws_iam_role" "deploy" {
  name                 = "counterpart-github-deploy"
  description          = "Applies reviewed Terraform from the main branch"
  assume_role_policy   = data.aws_iam_policy_document.trust_deploy.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "deploy" {
  name   = "deploy-counterpart"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}
