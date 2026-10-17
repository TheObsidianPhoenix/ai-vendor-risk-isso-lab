output "kms_alias" {
  description = "Alias of the project's data key."
  value       = module.security.kms_alias
}

output "buckets" {
  description = "The project's S3 buckets."
  value = {
    quarantine = module.storage.quarantine_bucket.id
    documents  = module.storage.documents_bucket.id
    audit      = module.logging.audit_bucket.id
  }
}

output "tables" {
  description = "The project's DynamoDB tables."
  value       = { for key, table in module.data.tables : key => table.name }
}

output "security_alert_rules" {
  description = "Account changes that send an alert."
  value       = module.monitoring.security_alert_rules
}
