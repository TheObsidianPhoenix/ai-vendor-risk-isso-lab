# Document storage (Phase 2, section 5.6 and section 8).
#
#   quarantine: uploads land here before the intake scanner checks them.
#               Deleted after 1 day whether or not they were checked.
#   documents:  files that passed intake, plus their extracted text.
#               Kept for the retention period, then deleted by lifecycle rule.
#
# Which application role may read or write each bucket is granted in that
# role's own IAM policy (the api module), not here, so each role's access
# can be reviewed in one place.

module "quarantine" {
  source           = "../../shared/aws/secure-bucket"
  name_prefix      = "${var.name}-quarantine-"
  purpose          = "Untrusted uploads awaiting intake checks"
  kms_key_arn      = var.kms_key_arn
  expire_days      = 1
  tags             = var.tags
  object_lock_days = 0
}

module "documents" {
  source                  = "../../shared/aws/secure-bucket"
  name_prefix             = "${var.name}-documents-"
  purpose                 = "Vendor documents that passed intake, and extracted text"
  kms_key_arn             = var.kms_key_arn
  expire_days             = var.document_retention_days
  noncurrent_version_days = 30
  tags                    = var.tags
}
