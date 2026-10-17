# One private, encrypted S3 bucket with the project's baseline controls.
# Every bucket in the project is built from this module, so the controls are
# written once and can't be forgotten on a new bucket.
#
# Baseline (Phase 2 architecture, section 5.6):
#   - Block Public Access, all four settings (AC-3, CM-6)
#   - Object ownership enforced: no ACLs, only policies decide access
#   - Encryption at rest with the project's KMS key (SC-28)
#   - A bucket policy that refuses any request not using TLS (SC-8)
#   - Versioning on, so overwritten or deleted objects can be recovered

resource "aws_s3_bucket" "this" {
  # Accepted gaps, each recorded for the POA&M:
  # checkov:skip=CKV_AWS_18: Server access logs cost per request; CloudTrail records bucket-level changes (Phase 2, section 5.10)
  # checkov:skip=CKV_AWS_144: Single region by design (decision D-10); versioning covers accidental deletion
  # checkov:skip=CKV2_AWS_62: No event notifications needed yet; the intake trigger is added with the application functions
  # A prefix, not a fixed name: AWS adds a unique suffix, so no account ID is
  # needed in the name (bucket names are public and global).
  bucket_prefix       = var.name_prefix
  object_lock_enabled = var.object_lock_days > 0
  force_destroy       = false # Terraform refuses to delete a bucket that still holds objects

  tags = merge(var.tags, { Purpose = var.purpose })
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true # Fewer KMS calls, so lower cost; same protection
  }
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  count  = var.object_lock_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.this.id
  rule {
    default_retention {
      # Governance mode (decision D-05): stops deletion and changes for the
      # retention period, but an administrator with a special permission can
      # override it, so the lab can be torn down. Production: COMPLIANCE.
      mode = "GOVERNANCE"
      days = var.object_lock_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  # checkov:skip=CKV_AWS_300: False positive. The abort-incomplete-uploads rule below sets 1 day; Checkov misreads rule lists that include a dynamic block (the bootstrap bucket's identical static rule passes)
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  dynamic "rule" {
    for_each = var.expire_days > 0 ? [var.expire_days] : []
    content {
      id     = "expire-current-objects"
      status = "Enabled"
      filter {}
      expiration {
        days = rule.value
      }
    }
  }

  rule {
    id     = "clean-up-old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

data "aws_iam_policy_document" "this" {
  # Refuse anything sent without TLS, from anyone, including the account itself
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*",
    ]
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

  # Extra statements from the calling module (for example, CloudTrail's write access)
  source_policy_documents = var.extra_policy_json == null ? [] : [var.extra_policy_json]
}

resource "aws_s3_bucket_policy" "this" {
  bucket     = aws_s3_bucket.this.id
  policy     = data.aws_iam_policy_document.this.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}
