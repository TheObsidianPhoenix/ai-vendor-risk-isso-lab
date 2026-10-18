output "quarantine_bucket" {
  description = "Name and ARN of the quarantine bucket."
  value       = { id = module.quarantine.id, arn = module.quarantine.arn }
}

output "documents_bucket" {
  description = "Name and ARN of the documents bucket."
  value       = { id = module.documents.id, arn = module.documents.arn }
}
