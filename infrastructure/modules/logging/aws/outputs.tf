output "audit_bucket" {
  description = "Name and ARN of the Object Lock audit bucket."
  value       = { id = module.audit.id, arn = module.audit.arn }
}

output "trail_arn" {
  description = "ARN of the CloudTrail trail."
  value       = aws_cloudtrail.this.arn
}
