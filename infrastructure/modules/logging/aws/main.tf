# Audit trail (Phase 2, sections 5.10 and 9; SR-16; AU-2, AU-9, AU-11, AU-12).
#
#   audit bucket: application audit events and CloudTrail log files, under
#                 Object Lock (governance mode, 30 days), so nothing in it can
#                 be changed or deleted during the retention period.
#   CloudTrail:   one trail for all regions, with log file integrity
#                 validation, so a deleted or edited log file can be detected.
#
# The trail created by hand in Phase 0 is replaced by this one, so there is a
# single source of truth (Phase 2, section 12.5). After this trail is running,
# the console trail is deleted. That step is in docs/architecture/deploy-runbook.md.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  trail_name = "${var.name}-trail"
  trail_arn  = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}

data "aws_iam_policy_document" "cloudtrail_writes" {
  statement {
    sid       = "CloudTrailChecksBucket"
    actions   = ["s3:GetBucketAcl"]
    resources = [module.audit.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWritesLogs"
    actions   = ["s3:PutObject"]
    resources = ["${module.audit.arn}/cloudtrail/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # Nobody, including administrators, may delete audit objects. Object Lock
  # already blocks it for 30 days; this deny makes it explicit and also covers
  # objects whose lock has expired. Lifecycle expiry isn't affected. Tearing
  # down the lab means removing this statement first, on purpose, through a PR.
  # (Bypassing governance mode needs s3:BypassGovernanceRetention, which no
  # role in this project is given.)
  statement {
    sid     = "DenyAuditDeletion"
    effect  = "Deny"
    actions = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = [
      module.audit.arn,
      "${module.audit.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

module "audit" {
  source           = "../../shared/aws/secure-bucket"
  name_prefix      = "${var.name}-audit-"
  purpose          = "Application audit events and CloudTrail logs (Object Lock)"
  kms_key_arn      = var.kms_key_arn
  object_lock_days = var.object_lock_days
  # Kept a little longer than the lock, then removed, so the lab doesn't grow forever
  expire_days             = var.audit_retention_days
  noncurrent_version_days = var.object_lock_days + 1
  # Terraform builds this from the bucket's ARN after the bucket exists; the
  # module merges it with its TLS-only rule into the one bucket policy.
  extra_policy_json = data.aws_iam_policy_document.cloudtrail_writes.json
  tags              = var.tags
}

resource "aws_cloudtrail" "this" {
  # checkov:skip=CKV_AWS_252: Alerts come from EventBridge rules on CloudTrail events (monitoring module), not per-file SNS notices
  # checkov:skip=CKV2_AWS_10: Same reason: EventBridge replaces a CloudWatch Logs subscription, with no log ingestion cost
  name                          = local.trail_name
  s3_bucket_name                = module.audit.id
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = true
  include_global_service_events = true # IAM and sign-in events
  enable_log_file_validation    = true # Digest files prove logs weren't changed
  kms_key_id                    = var.kms_key_arn
  tags                          = var.tags

  # Management events only. Data events (every S3 read) cost extra per event
  # and are a candidate for later, scoped to the documents bucket.
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [module.audit]
}
