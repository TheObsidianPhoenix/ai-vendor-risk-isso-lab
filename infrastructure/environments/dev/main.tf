# Counterpart, dev environment: the foundation layer.
#
# What this creates (and nothing else yet):
#   security   one KMS key that encrypts everything below
#   storage    quarantine and documents buckets
#   logging    Object Lock audit bucket and the CloudTrail trail
#   data       vendors, assessments and decisions tables
#   monitoring security alert rules, alert topic, monthly budget
#
# Sign-in (Cognito), the web front end, the API and the application functions
# come in the next layer. See infrastructure/README.md for the order and costs.

locals {
  name = "counterpart-${var.environment}"
}

module "security" {
  source = "../../modules/security/aws"
  name   = local.name
}

module "storage" {
  source      = "../../modules/storage/aws"
  name        = local.name
  kms_key_arn = module.security.kms_key_arn
}

module "logging" {
  source      = "../../modules/logging/aws"
  name        = local.name
  kms_key_arn = module.security.kms_key_arn
}

module "data" {
  source      = "../../modules/data/aws"
  name        = local.name
  kms_key_arn = module.security.kms_key_arn
}

module "monitoring" {
  source      = "../../modules/monitoring/aws"
  name        = local.name
  kms_key_arn = module.security.kms_key_arn
  alert_email = var.alert_email
}
